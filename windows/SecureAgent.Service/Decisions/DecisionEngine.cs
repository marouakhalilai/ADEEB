using Microsoft.Extensions.Logging;
using SecureAgent.Contracts.Ipc;
using SecureAgent.Core.Abstractions;
using SecureAgent.Core.Domain;
using SecureAgent.Core.Policy;
using SecureAgent.Infrastructure.Repositories;
using SecureAgent.Service.Logging;

namespace SecureAgent.Service.Decisions;

/// <summary>
/// Turns activations and verification claims into decisions, sessions and audit records.
/// </summary>
/// <remarks>
/// <para>
/// This is the only component that authorises anything. The broker reports; the policy
/// engine evaluates; this decides and records. Nothing else in the product opens a session
/// or applies an enforcement action.
/// </para>
/// <para>
/// It sits in the service, not the broker, because the broker runs as the interactive user.
/// A broker that could decide for itself would be an adversary deciding whether to let
/// itself in.
/// </para>
/// </remarks>
public sealed class DecisionEngine
{
    private readonly IPolicyEngine _policy;
    private readonly IPolicyRepository _policies;
    private readonly IAuditRepository _audit;
    private readonly IAuthSessionStore _sessions;
    private readonly ISystemClock _clock;
    private readonly ILogger<DecisionEngine> _logger;

    // Tracks consecutive failures per policy so severity can escalate on a repeated
    // attempt rather than treating the tenth failure like the first.
    private readonly Dictionary<Guid, int> _consecutiveFailures = [];
    private readonly Lock _failureGate = new();

    // Correlates an in-flight verification with the activation that triggered it.
    private readonly Dictionary<string, PendingVerification> _pending = [];
    private readonly Lock _pendingGate = new();

    /// <summary>Creates the engine.</summary>
    public DecisionEngine(
        IPolicyEngine policy,
        IPolicyRepository policies,
        IAuditRepository audit,
        IAuthSessionStore sessions,
        ISystemClock clock,
        ILogger<DecisionEngine> logger)
    {
        _policy = policy;
        _policies = policies;
        _audit = audit;
        _sessions = sessions;
        _clock = clock;
        _logger = logger;
    }

    private sealed record PendingVerification(
        ApplicationPolicy Policy,
        AppRef App,
        int WindowsSessionId);

    /// <summary>
    /// Handles a foreground activation reported by the broker.
    /// </summary>
    /// <returns>
    /// A verify request when the user must be checked, a decision when the answer is already
    /// known, or null when nothing applies and nothing should happen at all.
    /// </returns>
    public async Task<IpcMessage?> OnAppActivatedAsync(AppActivatedMessage message, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(message);

        var policies = await _policies.GetAllAsync(ct);

        var context = new ActivationContext
        {
            FileName = message.App.FileName,
            ExecutablePath = null,
            PublisherCn = message.App.PublisherCn,
            WindowsSessionId = message.WindowsSessionId,
            ProcessId = message.ProcessId,
            WindowTitle = message.App.WindowTitle,
            LocalTime = _clock.UtcNow.ToLocalTime(),
            MonotonicTicks = _clock.Ticks,
        };

        var decision = _policy.Evaluate(context, policies, _sessions);

        // The overwhelming majority of foreground changes land here. Nothing is logged and
        // no hardware is touched: a security agent that wrote a record for every window
        // switch would fill the disk and drown the events that matter.
        if (decision.Kind == DecisionKind.NotProtected)
        {
            return null;
        }

        var app = message.App with { MatchKind = decision.MatchedBy };
        var policy = decision.Policy!;

        ServiceLog.ActivationDecided(
            _logger, app.FileName, decision.Kind, policy.DisplayName, decision.MatchedBy);

        switch (decision.Kind)
        {
            case DecisionKind.AllowFromSession:
                return new DecisionMessage
                {
                    CorrelationId = message.CorrelationId,
                    Outcome = Outcome.Allowed,
                    Action = EnforcementAction.None,
                };

            case DecisionKind.DenyNoAuthorizedUsers:
                await RecordAsync(
                    EventKind.VerificationFailed,
                    Severity.High,
                    Outcome.Denied,
                    policy,
                    app,
                    message.WindowsSessionId,
                    VerifierKind.None,
                    ConfidenceBucket.None,
                    ToEnforcement(policy.OnFailure),
                    null,
                    ct);

                return new DecisionMessage
                {
                    CorrelationId = message.CorrelationId,
                    Outcome = Outcome.Denied,
                    Action = ToEnforcement(policy.OnFailure),
                    UserFacingReason = "No one is authorised for this application.",
                };

            case DecisionKind.VerificationRequired:
                lock (_pendingGate)
                {
                    _pending[message.CorrelationId] =
                        new PendingVerification(policy, app, message.WindowsSessionId);
                }

                await RecordAsync(
                    EventKind.VerificationRequested,
                    Severity.Info,
                    Outcome.NotApplicable,
                    policy,
                    app,
                    message.WindowsSessionId,
                    VerifierKind.None,
                    ConfidenceBucket.None,
                    EnforcementAction.None,
                    null,
                    ct);

                return new VerifyRequestMessage
                {
                    CorrelationId = message.CorrelationId,
                    MinimumAssurance = policy.MinimumAssurance,
                    TimeoutMs = 30_000,
                    Interactive = true,
                    AuthorizedUserIds = policy.AuthorizedUserIds,
                    AccountUserId = await ResolveAccountIdentityAsync(policy, ct),
                    AppDisplayName = policy.DisplayName,
                };

            default:
                return null;
        }
    }

    /// <summary>
    /// Handles a verification verdict claimed by the broker.
    /// </summary>
    /// <remarks>
    /// The claim is validated, never trusted: the identity must be one the policy
    /// authorises, and the assurance achieved must meet what the policy requires. A broker
    /// that reports a match for an unauthorised identity gets a denial and an audit record.
    /// </remarks>
    public async Task<IpcMessage?> OnVerificationResultAsync(
        VerificationResultMessage message,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(message);

        PendingVerification? pending;
        lock (_pendingGate)
        {
            _pending.Remove(message.CorrelationId, out pending);
        }

        if (pending is null)
        {
            // A result for an activation we never asked about. Either a stale reply after a
            // restart, or a broker inventing traffic. Neither is actionable.
            return null;
        }

        var policy = pending.Policy;

        ServiceLog.VerificationCompleted(
            _logger, message.Outcome, pending.App.FileName,
            message.Verifier, message.ElapsedMs);

        switch (message.Outcome)
        {
            case VerificationOutcomeDto.Match
                when IsClaimAcceptable(message, policy):
                return await AllowAsync(message, pending, ct);

            case VerificationOutcomeDto.Match:
                // Claimed a match the policy does not admit: wrong identity, or an assurance
                // level below what the policy demands.
                return await DenyAsync(
                    message, pending, "Verified identity is not authorised for this application.", ct);

            case VerificationOutcomeDto.NoMatch:
                return await DenyAsync(message, pending, "Not recognised.", ct);

            case VerificationOutcomeDto.Inconclusive:
                // An empty chair is not an intruder. Log it and leave the application alone.
                await RecordAsync(
                    EventKind.VerificationInconclusive,
                    Severity.Notice,
                    Outcome.Degraded,
                    policy,
                    pending.App,
                    pending.WindowsSessionId,
                    message.Verifier,
                    message.Confidence,
                    EnforcementAction.None,
                    message.ElapsedMs,
                    ct);

                return new DecisionMessage
                {
                    CorrelationId = message.CorrelationId,
                    Outcome = Outcome.Degraded,
                    Action = EnforcementAction.None,
                };

            case VerificationOutcomeDto.Unavailable:
                return await HandleUnavailableAsync(message, pending, ct);

            default:
                return null;
        }
    }

    /// <summary>
    /// Finds the authorised identity bound to a Windows account, if any.
    /// </summary>
    /// <remarks>
    /// Windows Hello proves that the account owner is present; it does not say who that is
    /// in our terms. This resolves the mapping so a Hello success can be attributed to an
    /// enrolled identity. When no authorised identity is bound to a Windows account, null is
    /// returned and the Hello rung reports itself unavailable — better than attributing a
    /// success to an arbitrary identity.
    /// </remarks>
    private async Task<Guid?> ResolveAccountIdentityAsync(ApplicationPolicy policy, CancellationToken ct)
    {
        var users = await _policies.GetUsersAsync(ct);

        return users
            .FirstOrDefault(u => u.WindowsSid is not null && policy.AuthorizedUserIds.Contains(u.Id))
            ?.Id;
    }

    /// <summary>
    /// Whether a claimed match satisfies the policy.
    /// </summary>
    private static bool IsClaimAcceptable(VerificationResultMessage message, ApplicationPolicy policy) =>
        message.MatchedUserId is { } user
        && policy.AuthorizedUserIds.Contains(user)
        && message.Assurance >= policy.MinimumAssurance;

    private async Task<IpcMessage> AllowAsync(
        VerificationResultMessage message,
        PendingVerification pending,
        CancellationToken ct)
    {
        var policy = pending.Policy;
        var now = _clock.Ticks;

        _sessions.Open(new AuthSession
        {
            PolicyId = policy.Id,
            UserId = message.MatchedUserId!.Value,
            WindowsSessionId = pending.WindowsSessionId,
            Verifier = message.Verifier,
            Assurance = message.Assurance,
            OpenedAtTicks = now,
            ExpiresAtTicks = now + (long)policy.SessionTtl.TotalMilliseconds,
            LastPresenceTicks = now,
        });

        ResetFailures(policy.Id);

        await RecordAsync(
            EventKind.VerificationSucceeded,
            Severity.Info,
            Outcome.Allowed,
            policy,
            pending.App,
            pending.WindowsSessionId,
            message.Verifier,
            message.Confidence,
            EnforcementAction.None,
            message.ElapsedMs,
            ct,
            message.MatchedUserId);

        return new DecisionMessage
        {
            CorrelationId = message.CorrelationId,
            Outcome = Outcome.Allowed,
            Action = EnforcementAction.None,
        };
    }

    private async Task<IpcMessage> DenyAsync(
        VerificationResultMessage message,
        PendingVerification pending,
        string reason,
        CancellationToken ct)
    {
        var policy = pending.Policy;
        var failures = RecordFailure(policy.Id);

        // Severity escalates once the policy's threshold is crossed. One failed check is
        // routine; the fourth in a row is a different event and should page differently.
        var severity = failures >= policy.MaxFailuresBeforeEscalation
            ? Severity.Critical
            : Severity.High;

        var action = ToEnforcement(policy.OnFailure);

        await RecordAsync(
            EventKind.VerificationFailed,
            severity,
            Outcome.Denied,
            policy,
            pending.App,
            pending.WindowsSessionId,
            message.Verifier,
            message.Confidence,
            action,
            message.ElapsedMs,
            ct);

        ServiceLog.EnforcementApplied(_logger, action, pending.App.FileName, reason);

        return new DecisionMessage
        {
            CorrelationId = message.CorrelationId,
            Outcome = Outcome.Denied,
            Action = action,
            UserFacingReason = reason,
        };
    }

    /// <summary>
    /// Applies the policy's answer to "no verifier could run".
    /// </summary>
    /// <remarks>
    /// A distinct branch from failure on purpose. A camera held by a video call is not an
    /// intruder, and treating it as one is how a security product gets uninstalled — but
    /// silently allowing is how one becomes theatre. The policy decides, and either way the
    /// event is recorded as <see cref="Outcome.Degraded"/> so telemetry can show how often
    /// the fleet is running without real protection.
    /// </remarks>
    private async Task<IpcMessage> HandleUnavailableAsync(
        VerificationResultMessage message,
        PendingVerification pending,
        CancellationToken ct)
    {
        var policy = pending.Policy;

        var (outcome, action, reason) = policy.OnVerifierUnavailable switch
        {
            UnavailableAction.Enforce => (
                Outcome.Denied,
                ToEnforcement(policy.OnFailure),
                "Verification is unavailable and this application requires it."),
            UnavailableAction.RequirePin => (
                Outcome.Denied,
                ToEnforcement(policy.OnFailure),
                "Verification is unavailable. A PIN is required."),
            _ => (
                Outcome.Degraded,
                EnforcementAction.None,
                "Verification unavailable; access allowed and recorded."),
        };

        await RecordAsync(
            EventKind.VerifierUnavailable,
            outcome == Outcome.Denied ? Severity.Warning : Severity.Notice,
            outcome,
            policy,
            pending.App,
            pending.WindowsSessionId,
            message.Verifier,
            ConfidenceBucket.None,
            action,
            message.ElapsedMs,
            ct);

        return new DecisionMessage
        {
            CorrelationId = message.CorrelationId,
            Outcome = outcome,
            Action = action,
            UserFacingReason = reason,
        };
    }

    /// <summary>Drops every session for a Windows terminal session that changed state.</summary>
    public async Task OnSessionChangedAsync(SessionChangedMessage message, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(message);

        var dropped = _sessions.CloseAllForWindowsSession(message.WindowsSessionId);
        if (dropped == 0)
        {
            return;
        }

        await RecordAsync(
            EventKind.SessionChanged,
            Severity.Info,
            Outcome.NotApplicable,
            null,
            null,
            message.WindowsSessionId,
            VerifierKind.None,
            ConfidenceBucket.None,
            EnforcementAction.None,
            null,
            ct);
    }

    /// <summary>Refreshes or drops a session after a continuous presence check.</summary>
    public Task OnPresencePingAsync(PresencePingMessage message, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(message);

        if (message.Present)
        {
            _sessions.RefreshPresence(message.PolicyId, message.WindowsSessionId, _clock.Ticks);
        }
        else
        {
            _sessions.Close(message.PolicyId, message.WindowsSessionId);
        }

        return Task.CompletedTask;
    }

    private static EnforcementAction ToEnforcement(FailureAction action) => action switch
    {
        FailureAction.Overlay => EnforcementAction.Overlay,
        FailureAction.Minimize => EnforcementAction.Minimize,
        FailureAction.LockApp => EnforcementAction.LockApp,
        FailureAction.LockWorkstation => EnforcementAction.LockWorkstation,
        _ => EnforcementAction.Overlay,
    };

    private int RecordFailure(Guid policyId)
    {
        lock (_failureGate)
        {
            var next = _consecutiveFailures.GetValueOrDefault(policyId) + 1;
            _consecutiveFailures[policyId] = next;
            return next;
        }
    }

    private void ResetFailures(Guid policyId)
    {
        lock (_failureGate)
        {
            _consecutiveFailures.Remove(policyId);
        }
    }

    private async Task RecordAsync(
        EventKind kind,
        Severity severity,
        Outcome outcome,
        ApplicationPolicy? policy,
        AppRef? app,
        int windowsSessionId,
        VerifierKind verifier,
        ConfidenceBucket confidence,
        EnforcementAction action,
        int? elapsedMs,
        CancellationToken ct,
        Guid? userId = null)
    {
        await _audit.AppendAsync(
            new SecurityEvent
            {
                Id = Ulid.NewUlid(),
                Timestamp = _clock.UtcNow,
                WindowsSessionId = windowsSessionId,
                Kind = kind,
                Severity = severity,
                Outcome = outcome,
                PolicyId = policy?.Id,
                UserId = userId,
                App = app,
                Verifier = verifier,
                Confidence = confidence,
                Action = action,
                ElapsedMs = elapsedMs,
            },
            ct);
    }
}
