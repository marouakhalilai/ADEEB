using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureAgent.Infrastructure.Repositories;

namespace SecureAgent.Infrastructure.Database;

/// <summary>Wires the local store into the service's container.</summary>
public static class DatabaseBootstrapper
{
    /// <summary>Default location, under ProgramData so the LocalSystem service owns it.</summary>
    public static string DefaultDatabasePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "SecureAgent",
        "secureagent.db");

    /// <summary>
    /// Registers the DbContext factory and repositories.
    /// </summary>
    /// <remarks>
    /// A context <em>factory</em> rather than a scoped context: the service is a background
    /// worker with no request scope, and several components append audit records from
    /// different call paths. Sharing one context across those would be a threading bug
    /// waiting to happen, since DbContext is not thread-safe.
    /// </remarks>
    /// <param name="services">The container.</param>
    /// <param name="databasePath">Override the database location; defaults to ProgramData.</param>
    public static IServiceCollection AddSecureAgentDatabase(
        this IServiceCollection services,
        string? databasePath = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        var path = databasePath ?? DefaultDatabasePath;
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        services.AddDbContextFactory<SecureAgentDbContext>(options =>
            options.UseSqlite($"Data Source={path}"));

        services.AddSingleton<IAuditRepository, AuditRepository>();
        services.AddSingleton<IPolicyRepository, PolicyRepository>();

        return services;
    }

    /// <summary>
    /// Creates the schema if it is absent.
    /// </summary>
    /// <remarks>
    /// Uses <c>EnsureCreated</c> rather than migrations for now. That is a deliberate
    /// interim choice, not an oversight: migrations need the <c>dotnet-ef</c> tool and a
    /// migration history that is only worth maintaining once the schema has shipped to a
    /// machine that must be upgraded rather than recreated. Before the first real install,
    /// this must become <c>Database.MigrateAsync()</c> with a generated initial migration —
    /// <c>EnsureCreated</c> cannot upgrade an existing database, so shipping it would leave
    /// users stranded on the first schema change.
    /// </remarks>
    public static async Task InitializeAsync(IServiceProvider services, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(services);

        var factory = services.GetRequiredService<IDbContextFactory<SecureAgentDbContext>>();
        await using var db = await factory.CreateDbContextAsync(ct);
        await db.Database.EnsureCreatedAsync(ct);
    }
}
