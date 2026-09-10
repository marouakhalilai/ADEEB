using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SecureAgent.Core.Abstractions;
using SecureAgent.Core.Policy;
using SecureAgent.Infrastructure.Database;
using SecureAgent.Service.Cli;
using SecureAgent.Service.Decisions;
using SecureAgent.Service.Logging;
using Serilog;

namespace SecureAgent.Service;

/// <summary>
/// Entry point for the Session 0 core service.
/// </summary>
/// <remarks>
/// Runs as a Windows service in production and as a console application during
/// development. It never draws UI and never opens a camera — those belong to the broker,
/// on the other side of the Session 0 boundary (CLAUDE.md rule 18).
/// </remarks>
public static class Program
{
    /// <summary>The named pipe the broker connects to.</summary>
    public const string PipeName = "SecureAgent.Ipc";

    /// <summary>Runs the service, or a CLI command when one is given.</summary>
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
            // Configuration commands run against the same store the service uses, then
            // exit. Keeping them in this executable avoids a second binary that would need
            // its own signing, its own permissions, and its own copy of the schema.
            if (args.Length > 0 && !args[0].StartsWith("--service", StringComparison.Ordinal))
            {
                return await CommandLine.RunAsync(args);
            }

            Log.Information("SecureAgent service starting");
            var host = BuildHost(args);

            await DatabaseBootstrapper.InitializeAsync(host.Services, CancellationToken.None);
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
        // ContentRootPath is pinned to the executable's own directory rather than left to
        // default. HostApplicationBuilder otherwise takes it from the current working
        // directory, which is not the install directory in any of the ways this actually
        // runs: the SCM starts services with a working directory of C:\Windows\System32,
        // and a shortcut or a shell can start it from anywhere.
        //
        // The failure is silent and total. appsettings.json is not found, Serilog is
        // configured from empty configuration, every sink disappears, and the service keeps
        // running while writing no audit trail whatsoever — the one failure mode a security
        // agent must never have.
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        {
            Args = args,
            ContentRootPath = AppContext.BaseDirectory,
        });

        builder.Services.AddWindowsService(options => options.ServiceName = "SecureAgent");

        builder.Services.AddSerilog((services, config) => config
            .ReadFrom.Configuration(builder.Configuration)
            .ReadFrom.Services(services)
            .Enrich.With<BiometricRedactionEnricher>()
            .Enrich.FromLogContext());

        // Every duration in the security path resolves through this, so a test host can
        // substitute a controllable clock (rule 22).
        builder.Services.AddSingleton<ISystemClock, SystemClock>();

        builder.Services.AddSecureAgentDatabase();

        builder.Services.AddSingleton<IPolicyEngine, PolicyEngine>();
        builder.Services.AddSingleton<IAuthSessionStore, InMemoryAuthSessionStore>();
        builder.Services.AddSingleton<DecisionEngine>();

        builder.Services.AddHostedService<AgentWorker>();

        return builder.Build();
    }
}
