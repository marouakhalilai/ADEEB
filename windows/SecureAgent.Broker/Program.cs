using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecureAgent.Core.Abstractions;
using SecureAgent.Broker.Logging;
using Serilog;

namespace SecureAgent.Broker;

/// <summary>
/// Entry point for the interactive-session broker.
/// </summary>
/// <remarks>
/// <para>
/// Launched by the core service into each logged-on session; it is not a service itself
/// and must not be installed as one. It exists because a Session 0 service cannot reach
/// the desktop or the camera (plan §00, correction 1).
/// </para>
/// <para>
/// It is the untrusted half of the client. It runs with the user's token, so it holds no
/// encryption keys and no enrolled templates, and it makes no policy decisions — it
/// reports what it observes and does what the service tells it.
/// </para>
/// </remarks>
public static class Program
{
    /// <summary>Runs the broker host.</summary>
    public static async Task<int> Main(string[] args)
    {
        Log.Logger = new LoggerConfiguration()
            .WriteTo.Console()
            .CreateBootstrapLogger();

        try
        {
            var builder = Host.CreateApplicationBuilder(args);

            builder.Services.AddSerilog((services, config) => config
                .ReadFrom.Configuration(builder.Configuration)
                .ReadFrom.Services(services)
                .Enrich.FromLogContext());

            builder.Services.AddSingleton<ISystemClock, SystemClock>();
            builder.Services.AddHostedService<BrokerWorker>();

            await builder.Build().RunAsync();
            return 0;
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "SecureAgent broker terminated unexpectedly");
            return 1;
        }
        finally
        {
            await Log.CloseAndFlushAsync();
        }
    }
}

/// <summary>
/// The broker's loop.
/// </summary>
/// <remarks>
/// A placeholder in Phase 0. Phase 2 adds the <c>SetWinEventHook</c> foreground watcher
/// and the pipe client; Phase 3 adds capture and Windows Hello; Phase 4 adds the overlay.
/// </remarks>
public sealed class BrokerWorker : BackgroundService
{
    private readonly ILogger<BrokerWorker> _logger;

    /// <summary>Creates the worker.</summary>
    public BrokerWorker(ILogger<BrokerWorker> logger) => _logger = logger;

    /// <inheritdoc />
    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // GetCurrentProcess() returns a disposable handle; the session id is read once at
        // startup because it cannot change for the lifetime of this process.
        using var self = System.Diagnostics.Process.GetCurrentProcess();
        BrokerLog.BrokerReady(_logger, Environment.ProcessId, self.SessionId);

        // Phase 2: connect to the service pipe, verify its Authenticode signature, install
        // the foreground hook, and pump messages. A hook needs a message loop in the
        // interactive session, which is precisely why this process exists.
        return Task.CompletedTask;
    }
}
