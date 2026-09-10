using System.Runtime.Versioning;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecureAgent.Broker.Enforcement;
using SecureAgent.Broker.Ipc;
using SecureAgent.Broker.Logging;
using SecureAgent.Broker.Monitoring;
using SecureAgent.Broker.Verification;
using SecureAgent.Contracts.Ipc;
using SecureAgent.Core.Abstractions;
using SecureAgent.Core.Domain;

namespace SecureAgent.Broker;

/// <summary>
/// The broker's loop: watch the foreground, report it, verify on demand, enforce.
/// </summary>
/// <remarks>
/// Holds no keys, no templates and no policy. It observes and it obeys — every decision
/// comes from the service, because this process runs with the interactive user's token and
/// the interactive user may be the adversary.
/// </remarks>
[SupportedOSPlatform("windows10.0.17763.0")]
public sealed class BrokerWorker : BackgroundService
{
    private readonly ILogger<BrokerWorker> _logger;
    private readonly ILogger<IpcClient> _ipcLogger;
    private readonly ILoggerFactory _loggerFactory;
    private readonly OverlayHost _overlay;

    private IpcClient? _client;
    private ForegroundWatcher? _watcher;
    private int _windowsSessionId;

    /// <summary>Creates the worker.</summary>
    public BrokerWorker(
        ILogger<BrokerWorker> logger,
        ILogger<IpcClient> ipcLogger,
        ILoggerFactory loggerFactory,
        OverlayHost overlay)
    {
        _logger = logger;
        _ipcLogger = ipcLogger;
        _loggerFactory = loggerFactory;
        _overlay = overlay;
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var self = System.Diagnostics.Process.GetCurrentProcess();
        _windowsSessionId = self.SessionId;

        BrokerLog.BrokerReady(_logger, Environment.ProcessId, _windowsSessionId);

        _overlay.Start();

        _client = new IpcClient("SecureAgent.Ipc", OnServiceMessageAsync, _ipcLogger);

        _watcher = new ForegroundWatcher(OnForegroundChanged, ex => BrokerLog.WatcherFault(_logger, ex));
        _watcher.Start();
        BrokerLog.WatcherStarted(_logger);

        try
        {
            await _client.RunAsync(stoppingToken);
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
    }

    /// <summary>
    /// Reports a foreground change to the service.
    /// </summary>
    /// <remarks>
    /// Fire-and-forget on purpose: this runs on the WinEvent pump thread, and blocking it
    /// would stall every subsequent window event on the desktop.
    /// </remarks>
    private void OnForegroundChanged(ForegroundChange change)
    {
        BrokerLog.ForegroundChanged(_logger, change.FileName, change.ProcessId);

        var message = new AppActivatedMessage
        {
            CorrelationId = Ulid.NewUlid(),
            App = AppRef.FromUntrusted(
                AppMatchKind.FileName,
                change.FileName,
                publisherCn: null,
                pathHash: null,
                windowTitle: change.WindowTitle),
            WindowsSessionId = _windowsSessionId,
            ProcessId = (int)change.ProcessId,
        };

        _ = Task.Run(async () =>
        {
            try
            {
                if (_client is not null)
                {
                    await _client.SendAsync(message, CancellationToken.None);
                }
            }
            catch (Exception ex)
            {
                BrokerLog.WatcherFault(_logger, ex);
            }
        });
    }

    /// <summary>Handles a message pushed by the service.</summary>
    private async Task<IpcMessage?> OnServiceMessageAsync(IpcMessage message, CancellationToken ct) =>
        message switch
        {
            VerifyRequestMessage m => await VerifyAsync(m, ct),
            DecisionMessage m => Enforce(m),
            _ => null,
        };

    /// <summary>
    /// Runs a verification for the service and reports the verdict.
    /// </summary>
    /// <remarks>
    /// The ladder is rebuilt per request because the identity Hello can attest is supplied
    /// by the service each time, and because availability changes: a camera free a moment
    /// ago may be held by a video call now.
    /// </remarks>
    private async Task<IpcMessage?> VerifyAsync(VerifyRequestMessage request, CancellationToken ct)
    {
        var verifiers = new List<IIdentityVerifier>();

        if (request.AccountUserId is { } accountUser)
        {
            verifiers.Add(new WindowsHelloVerifier(
                accountUser, _loggerFactory.CreateLogger<WindowsHelloVerifier>()));
        }

        if (verifiers.Count == 0)
        {
            BrokerLog.NoVerifierAvailable(_logger, request.MinimumAssurance);
            return new VerificationResultMessage
            {
                CorrelationId = request.CorrelationId,
                Outcome = VerificationOutcomeDto.Unavailable,
                Verifier = VerifierKind.None,
                Assurance = AssuranceLevel.Any,
                ElapsedMs = 0,
                Detail = "No enrolled identity is bound to this Windows account.",
            };
        }

        var chain = new VerifierChain(verifiers);
        BrokerLog.VerifiersAvailable(_logger, chain.All.Count, chain.All[0].Kind);

        var result = await chain.VerifyAsync(
            new IdentityChallenge(
                request.AuthorizedUserIds,
                request.MinimumAssurance,
                TimeSpan.FromMilliseconds(request.TimeoutMs),
                request.Interactive),
            ct);

        return new VerificationResultMessage
        {
            CorrelationId = request.CorrelationId,
            Outcome = result.Outcome switch
            {
                VerificationOutcome.Match => VerificationOutcomeDto.Match,
                VerificationOutcome.NoMatch => VerificationOutcomeDto.NoMatch,
                VerificationOutcome.Inconclusive => VerificationOutcomeDto.Inconclusive,
                _ => VerificationOutcomeDto.Unavailable,
            },
            MatchedUserId = result.MatchedUserId,
            Verifier = result.Verifier,
            Assurance = result.Assurance,
            Confidence = result.Confidence,
            LivenessPassed = result.LivenessPassed,
            ElapsedMs = result.ElapsedMs,
            Detail = result.FailureDetail,
        };
    }

    /// <summary>Applies the service's decision.</summary>
    private IpcMessage? Enforce(DecisionMessage decision)
    {
        switch (decision.Action)
        {
            case EnforcementAction.Overlay:
            case EnforcementAction.LockApp:
                BrokerLog.OverlayShown(_logger, decision.UserFacingReason ?? "Access denied");
                _overlay.Show("This application", decision.UserFacingReason ?? "Access denied.");
                break;

            case EnforcementAction.LockWorkstation:
                // Hands enforcement to Windows itself, which is the honest strong action.
                NativeSession.LockWorkStation();
                break;

            case EnforcementAction.None:
            default:
                _overlay.Hide();
                break;
        }

        return null;
    }

    /// <inheritdoc />
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        BrokerLog.BrokerStopping(_logger);

        _watcher?.Dispose();
        _overlay.Stop();

        if (_client is not null)
        {
            await _client.DisposeAsync();
            _client = null;
        }

        await base.StopAsync(cancellationToken);
    }
}
