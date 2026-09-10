using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecureAgent.Contracts.Ipc;
using SecureAgent.Core.Abstractions;
using SecureAgent.Infrastructure.Database;
using SecureAgent.Infrastructure.Repositories;
using SecureAgent.Service.Decisions;
using SecureAgent.Service.Ipc;
using SecureAgent.Service.Logging;

namespace SecureAgent.Service;

/// <summary>
/// The service's long-running loop: verifies the audit chain, then serves the broker.
/// </summary>
public sealed class AgentWorker : BackgroundService
{
    private readonly ILogger<AgentWorker> _logger;
    private readonly ILogger<IpcServer> _ipcLogger;
    private readonly ISystemClock _clock;
    private readonly DecisionEngine _decisions;
    private readonly IAuditRepository _audit;
    private readonly IPolicyRepository _policies;

    private IpcServer? _server;

    /// <summary>Creates the worker.</summary>
    public AgentWorker(
        ILogger<AgentWorker> logger,
        ILogger<IpcServer> ipcLogger,
        ISystemClock clock,
        DecisionEngine decisions,
        IAuditRepository audit,
        IPolicyRepository policies)
    {
        _logger = logger;
        _ipcLogger = ipcLogger;
        _clock = clock;
        _decisions = decisions;
        _audit = audit;
        _policies = policies;
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        ServiceLog.ServiceReady(_logger, _clock.UtcNow, _clock.Ticks);
        ServiceLog.DatabaseReady(_logger, DatabaseBootstrapper.DefaultDatabasePath);

        // Startup reconciliation. A chain that does not verify means either tampering or
        // storage corruption, and both are worth surfacing loudly at Critical rather than
        // discovering weeks later when someone asks for an audit trail.
        var verification = await _audit.VerifyAsync(stoppingToken);
        if (verification.IsIntact)
        {
            var recent = await _audit.RecentAsync(1, stoppingToken);
            ServiceLog.ChainVerified(_logger, recent.Count);
        }
        else
        {
            ServiceLog.ChainVerificationFailed(
                _logger,
                verification.Fault,
                verification.FailedAtIndex,
                verification.FailedAtId);
        }

        var policies = await _policies.GetAllAsync(stoppingToken);
        ServiceLog.PoliciesLoaded(_logger, policies.Count);

        _server = new IpcServer(Program.PipeName, HandleAsync, _ipcLogger);
        _server.Start();
        ServiceLog.IpcListening(_logger, Program.PipeName);

        try
        {
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
    }

    /// <summary>
    /// Dispatches one broker message.
    /// </summary>
    /// <remarks>
    /// Every branch is explicit and the default drops the message. A security service must
    /// not act on traffic it does not recognise, and silently ignoring an unknown message is
    /// the correct response to a broker that is either outdated or hostile.
    /// </remarks>
    private async Task<IpcMessage?> HandleAsync(IpcMessage message, CancellationToken ct) =>
        message switch
        {
            AppActivatedMessage m => await _decisions.OnAppActivatedAsync(m, ct),
            VerificationResultMessage m => await _decisions.OnVerificationResultAsync(m, ct),
            SessionChangedMessage m => await Handle(() => _decisions.OnSessionChangedAsync(m, ct)),
            PresencePingMessage m => await Handle(() => _decisions.OnPresencePingAsync(m, ct)),
            _ => null,
        };

    private static async Task<IpcMessage?> Handle(Func<Task> action)
    {
        await action();
        return null;
    }

    /// <inheritdoc />
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        ServiceLog.ServiceStopping(_logger);

        if (_server is not null)
        {
            await _server.DisposeAsync();
            _server = null;
        }

        await base.StopAsync(cancellationToken);
    }
}
