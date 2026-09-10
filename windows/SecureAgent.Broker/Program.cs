using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SecureAgent.Broker.Enforcement;
using SecureAgent.Core.Abstractions;
using Serilog;

namespace SecureAgent.Broker;

/// <summary>
/// Entry point for the interactive-session broker.
/// </summary>
/// <remarks>
/// <para>
/// Launched into each logged-on session; it is not a service itself and must not be
/// installed as one. It exists because a Session 0 service cannot reach the desktop or the
/// camera — the correction that shapes the whole client architecture.
/// </para>
/// <para>
/// It is the untrusted half of the client. It runs with the user's token, holds no
/// encryption keys and no enrolled templates, and makes no policy decisions: it reports what
/// it observes and does what the service tells it.
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
            // Pinned to the executable's directory for the same reason as the service: the
            // broker is launched by the service, and inheriting whatever working directory
            // that happened to have would silently strip its logging configuration.
            var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
            {
                Args = args,
                ContentRootPath = AppContext.BaseDirectory,
            });

            builder.Services.AddSerilog((services, config) => config
                .ReadFrom.Configuration(builder.Configuration)
                .ReadFrom.Services(services)
                .Enrich.FromLogContext());

            builder.Services.AddSingleton<ISystemClock, SystemClock>();
            builder.Services.AddSingleton<OverlayHost>();
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
