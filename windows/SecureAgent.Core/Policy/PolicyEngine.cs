using SecureAgent.Core.Domain;

namespace SecureAgent.Core.Policy;

/// <summary>Evaluates an activation against the policy set.</summary>
public interface IPolicyEngine
{
    /// <summary>Decides what must happen about one foreground activation.</summary>
    PolicyDecision Evaluate(
        ActivationContext context,
        IReadOnlyList<ApplicationPolicy> policies,
        IAuthSessionStore sessions);
}

/// <summary>
/// The deterministic policy engine.
/// </summary>
/// <remarks>
/// <para>
/// A pure function of its arguments. No I/O, no clock access, no logging, no randomness —
/// the only inputs are the ones passed in, which is what makes the whole decision surface
/// exhaustively testable. This is the component the product's correctness rests on
/// (CLAUDE.md rule 7), and it is the reason <c>SecureAgent.Core</c> has no Windows
/// dependencies.
/// </para>
/// <para>
/// Ordering matters here. The engine answers "not protected" as early and as cheaply as
/// possible, because that is the overwhelming majority of foreground changes on a real
/// desktop and every one of them must cost close to nothing.
/// </para>
/// </remarks>
public sealed class PolicyEngine : IPolicyEngine
{
    /// <inheritdoc />
    public PolicyDecision Evaluate(
        ActivationContext context,
        IReadOnlyList<ApplicationPolicy> policies,
        IAuthSessionStore sessions)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(policies);
        ArgumentNullException.ThrowIfNull(sessions);

        var match = FindStrongestMatch(context, policies);
        if (match is null)
        {
            return PolicyDecision.NotProtected;
        }

        var policy = match.Value.Policy;

        // A policy nobody is authorised for denies rather than allows, and does so without
        // opening a camera: no verification could succeed, so prompting would only train
        // the user to dismiss prompts.
        if (policy.AuthorizedUserIds.Count == 0)
        {
            return new PolicyDecision(
                DecisionKind.DenyNoAuthorizedUsers,
                policy,
                match.Value.MatchedBy,
                policy.MinimumAssurance,
                []);
        }

        var existing = sessions.Find(policy.Id, context.WindowsSessionId);
        if (existing is not null && SessionCovers(existing, policy, context))
        {
            return new PolicyDecision(
                DecisionKind.AllowFromSession,
                policy,
                match.Value.MatchedBy,
                policy.MinimumAssurance,
                policy.AuthorizedUserIds);
        }

        return new PolicyDecision(
            DecisionKind.VerificationRequired,
            policy,
            match.Value.MatchedBy,
            policy.MinimumAssurance,
            policy.AuthorizedUserIds);
    }

    /// <summary>
    /// Whether an existing session still satisfies the policy for this activation.
    /// </summary>
    private static bool SessionCovers(
        AuthSession session,
        ApplicationPolicy policy,
        ActivationContext context)
    {
        // A session belongs to the Windows terminal session it was created in. The store is
        // keyed that way too; this is belt and braces against a lookup bug silently
        // carrying access across a fast user switch.
        if (session.WindowsSessionId != context.WindowsSessionId)
        {
            return false;
        }

        if (!session.IsValidAt(context.MonotonicTicks))
        {
            return false;
        }

        // The identity that opened the session must still be authorised. This is what makes
        // revoking a user take effect immediately rather than at the next TTL expiry.
        if (!policy.AuthorizedUserIds.Contains(session.UserId))
        {
            return false;
        }

        // A session opened at a weaker assurance cannot satisfy a policy that has since
        // been tightened.
        if (session.Assurance < policy.MinimumAssurance)
        {
            return false;
        }

        // Under continuous monitoring, a lapse in confirmed presence invalidates the
        // session even while its TTL still has time left. That is the walk-away case.
        if (policy.Continuous != ContinuousMode.Off
            && session.IsAbsentAt(context.MonotonicTicks, policy.AbsenceGrace))
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Returns the applicable policy matched by the strongest available rule.
    /// </summary>
    /// <remarks>
    /// Strength order is publisher signature, then full path, then file name. Evaluating in
    /// that order means a signed application is recognised by its publisher even when a
    /// weaker file-name policy also exists, and the resolved strength is reported so
    /// telemetry can show how often the fleet is relying on the weak rule.
    /// </remarks>
    private static (ApplicationPolicy Policy, AppMatchKind MatchedBy)? FindStrongestMatch(
        ActivationContext context,
        IReadOnlyList<ApplicationPolicy> policies)
    {
        ReadOnlySpan<AppMatchKind> strengthOrder =
        [
            AppMatchKind.PublisherSignature,
            AppMatchKind.FullPath,
            AppMatchKind.FileName,
        ];

        foreach (var kind in strengthOrder)
        {
            foreach (var policy in policies)
            {
                if (!policy.Enabled || policy.Match.Kind != kind)
                {
                    continue;
                }

                if (!policy.Match.Matches(context))
                {
                    continue;
                }

                // A policy outside its active hours does not apply at all. Note this is
                // checked after matching so that an out-of-hours policy does not mask a
                // weaker policy that is currently in force.
                if (policy.ActiveHours is { } hours && !hours.Contains(context.LocalTime))
                {
                    continue;
                }

                return (policy, kind);
            }
        }

        return null;
    }
}
