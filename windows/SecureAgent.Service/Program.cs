using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecureAgent.Core.Abstractions;
using SecureAgent.Service.Logging;
using Serilog;

namespace SecureAgent.Service;

/// <summary>
/// Entry point for the Session 0 core service.
/// </summary>
/// <remarks>
/// Runs as a Windows service under LocalSystem in production and as a console
/// application during development. It never draws UI and never opens a camera — those
/// belong to the broker, on the other side of the Session 0 boundary (CLAUDE.md rule 18).
/// </remarks>
public static class Program
{
    /// <summary>Runs the service host.</summary>
    public static async Task<int> Main(string[] args)
    {
        // Bootstrap logger: catches failures that happen before configuration is read.
        // Without this, a bad config file produces a silent exit, which on a security
        // service means protection quietly stops with no trace of why.
        Log.Logger = new LoggerConfiguration()
            .Enrich.With<BiometricRedactionEnricher>()
            .WriteTo.Console()
            .CreateBootstrapLogger();

        try
        {
            Log.Information("SecureAgent service starting");
            var host = BuildHost(args);
            await host.RunAsync();
            return 0;
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "SecureAgent service terminated unexpectedly");
            return 1;
        }
        finally
        {
            await Log.CloseAndFlushAsync();
        }
    }

    /// <summary>
    /// Composes the host. Separated from <see cref="Main"/> so tests can assert that the
    /// container resolves without starting a service.
    /// </summary>
    public static IHost BuildHost(string[] args)
    {
        var builder = Host.CreateApplicationBuilder(args);

        builder.Services.AddWindowsService(options =>
        {
            options.ServiceName = "SecureAgent";
        });

        builder.Services.AddSerilog((services, config) => config
            .ReadFrom.Configuration(builder.Configuration)
            .ReadFrom.Services(services)
            .Enrich.With<BiometricRedactionEnricher>()
            .Enrich.FromLogContext());

        // Every duration in the security path resolves through this. Registered as a
        // singleton so a test host can substitute a controllable clock (rule 22).
        builder.Services.AddSingleton<ISystemClock, SystemClock>();

        builder.Services.AddHostedService<AgentWorker>();

        return builder.Build();
    }
}

/// <summary>
/// The service's long-running loop.
/// </summary>
/// <remarks>
/// A placeholder in Phase 0. Phase 2 gives it the named-pipe server and the broker
/// supervision loop; Phase 4 wires the policy engine behind it.
/// </remarks>
public sealed class AgentWorker : BackgroundService
{
    private readonly ILogger<AgentWorker> _logger;
    private readonly ISystemClock _clock;

    /// <summary>Creates the worker.</summary>
    public AgentWorker(ILogger<AgentWorker> logger, ISystemClock clock)
    {
        _logger = logger;
        _clock = clock;
    }

    /// <inheritdoc />
    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        ServiceLog.ServiceReady(_logger, _clock.UtcNow, _clock.Ticks);

        // Phase 2: start the IPC server, supervise the broker, begin consuming
        // AppActivated messages. Nothing to do until then.
        return Task.CompletedTask;
    }
}
