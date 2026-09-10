using System.Globalization;
using System.Security.Principal;
using Microsoft.Extensions.DependencyInjection;
using SecureAgent.Core.Domain;
using SecureAgent.Infrastructure.Database;
using SecureAgent.Infrastructure.Repositories;

namespace SecureAgent.Service.Cli;

/// <summary>
/// Configuration commands, run against the same local store the service uses.
/// </summary>
/// <remarks>
/// A stopgap until the WinUI dashboard exists, but a deliberate one: policies have to be
/// configurable before the product does anything useful, and a command surface is also what
/// makes the loop scriptable in tests and demos. Every command writes through
/// <see cref="IPolicyRepository"/>, so policy validation applies here exactly as it does
/// everywhere else — the CLI cannot create a policy the engine would refuse.
/// </remarks>
public static class CommandLine
{
    /// <summary>Runs a command and returns a process exit code.</summary>
    public static async Task<int> RunAsync(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        var services = new ServiceCollection();
        services.AddSecureAgentDatabase();
        await using var provider = services.BuildServiceProvider();

        await DatabaseBootstrapper.InitializeAsync(provider, CancellationToken.None);

        var policies = provider.GetRequiredService<IPolicyRepository>();
        var audit = provider.GetRequiredService<IAuditRepository>();
        var ct = CancellationToken.None;

        return args[0].ToLowerInvariant() switch
        {
            "users" => await ListUsersAsync(policies, ct),
            "add-user" => await AddUserAsync(policies, args, ct),
            "protect" => await ProtectAsync(policies, args, ct),
            "unprotect" => await UnprotectAsync(policies, args, ct),
            "policies" => await ListPoliciesAsync(policies, ct),
            "events" => await ListEventsAsync(audit, args, ct),
            "verify-chain" => await VerifyChainAsync(audit, ct),
            "status" => await StatusAsync(policies, audit, ct),
            _ => Usage(),
        };
    }

    private static int Usage()
    {
        Console.WriteLine(
            """
            SecureAgent configuration

              status                        Show what is protected and whether the chain is intact
              users                         List enrolled identities
              add-user <name> [--me]        Create an identity; --me binds it to this Windows account
              protect <exe> --user <id>     Protect an application for an identity
                        [--assurance Any|Biometric|HelloOrIr]
                        [--ttl <seconds>]   Re-verify after this long (default 300)
                        [--on-fail Overlay|Minimize|LockApp|LockWorkstation]
              unprotect <policy-id>         Remove a policy
              policies                      List policies
              events [count]                Show recent audit records (default 20)
              verify-chain                  Verify the audit chain end to end

            Example:
              SecureAgent.Service.exe add-user "Adeeb" --me
              SecureAgent.Service.exe protect notepad.exe --user <id> --assurance HelloOrIr
            """);
        return 1;
    }

    private static async Task<int> ListUsersAsync(IPolicyRepository repo, CancellationToken ct)
    {
        var users = await repo.GetUsersAsync(ct);
        if (users.Count == 0)
        {
            Console.WriteLine("No identities yet. Create one with: add-user \"Your Name\" --me");
            return 0;
        }

        foreach (var u in users)
        {
            var bound = u.WindowsSid is null ? "" : "  (this Windows account)";
            Console.WriteLine($"{u.Id}  {u.DisplayName}{bound}");
        }

        return 0;
    }

    private static async Task<int> AddUserAsync(IPolicyRepository repo, string[] args, CancellationToken ct)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: add-user <name> [--me]");
            return 1;
        }

        // Binding to the current Windows SID is what lets the Windows Hello rung report a
        // success as this identity: Hello attests the account owner, nothing finer.
        string? sid = null;
        if (args.Contains("--me", StringComparer.OrdinalIgnoreCase))
        {
            using var identity = WindowsIdentity.GetCurrent();
            sid = identity.User?.Value;
        }

        var id = await repo.CreateUserAsync(args[1], sid, ct);
        Console.WriteLine($"Created identity {id} for \"{args[1]}\".");

        if (sid is null)
        {
            Console.WriteLine(
                "Note: not bound to a Windows account, so Windows Hello cannot verify it. " +
                "Re-create with --me if you want Hello to work.");
        }

        return 0;
    }

    private static async Task<int> ProtectAsync(IPolicyRepository repo, string[] args, CancellationToken ct)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: protect <exe> --user <id> [options]");
            return 1;
        }

        var exe = args[1].ToLowerInvariant();

        if (!TryGetOption(args, "--user", out var userRaw) || !Guid.TryParse(userRaw, out var userId))
        {
            Console.Error.WriteLine("--user <id> is required. Run 'users' to list identities.");
            return 1;
        }

        var assurance = TryGetOption(args, "--assurance", out var a)
            && Enum.TryParse<AssuranceLevel>(a, true, out var parsedAssurance)
                ? parsedAssurance
                : AssuranceLevel.Biometric;

        var ttl = TryGetOption(args, "--ttl", out var t)
            && int.TryParse(t, CultureInfo.InvariantCulture, out var seconds)
                ? TimeSpan.FromSeconds(seconds)
                : TimeSpan.FromMinutes(5);

        var onFail = TryGetOption(args, "--on-fail", out var f)
            && Enum.TryParse<FailureAction>(f, true, out var parsedFail)
                ? parsedFail
                : FailureAction.Overlay;

        var policy = new ApplicationPolicy
        {
            Id = Guid.NewGuid(),
            DisplayName = exe,
            Match = new AppMatcher(AppMatchKind.FileName, exe),
            AuthorizedUserIds = [userId],
            MinimumAssurance = assurance,
            SessionTtl = ttl,
            OnFailure = onFail,
            Enabled = true,
        };

        try
        {
            await repo.SaveAsync(policy, ct);
        }
        catch (InvalidOperationException ex)
        {
            // Validation rejects configurations that would be misleading rather than merely
            // unusual — a HelloOrIr policy matched on file name, for instance.
            Console.Error.WriteLine(ex.Message);
            return 1;
        }

        Console.WriteLine($"Protecting {exe} (policy {policy.Id}).");
        Console.WriteLine($"  assurance {assurance}, re-verify after {ttl.TotalSeconds:F0}s, on failure {onFail}");
        return 0;
    }

    private static async Task<int> UnprotectAsync(IPolicyRepository repo, string[] args, CancellationToken ct)
    {
        if (args.Length < 2 || !Guid.TryParse(args[1], out var id))
        {
            Console.Error.WriteLine("Usage: unprotect <policy-id>");
            return 1;
        }

        Console.WriteLine(await repo.DeleteAsync(id, ct) ? "Removed." : "No such policy.");
        return 0;
    }

    private static async Task<int> ListPoliciesAsync(IPolicyRepository repo, CancellationToken ct)
    {
        var policies = await repo.GetAllAsync(ct);
        if (policies.Count == 0)
        {
            Console.WriteLine("Nothing is protected yet.");
            return 0;
        }

        foreach (var p in policies)
        {
            var state = p.Enabled ? "on " : "off";
            Console.WriteLine(
                $"[{state}] {p.Match.Value,-24} {p.MinimumAssurance,-12} " +
                $"ttl={p.SessionTtl.TotalSeconds:F0}s  users={p.AuthorizedUserIds.Count}  {p.Id}");
        }

        return 0;
    }

    private static async Task<int> ListEventsAsync(IAuditRepository audit, string[] args, CancellationToken ct)
    {
        var count = args.Length > 1 && int.TryParse(args[1], CultureInfo.InvariantCulture, out var n) ? n : 20;

        var events = await audit.RecentAsync(count, ct);
        if (events.Count == 0)
        {
            Console.WriteLine("No events recorded yet.");
            return 0;
        }

        foreach (var e in events)
        {
            Console.WriteLine(
                $"{e.Timestamp.LocalDateTime:HH:mm:ss}  {e.Severity,-8} {e.Kind,-24} " +
                $"{e.App?.FileName,-18} {e.Outcome,-12} {e.Verifier}");
        }

        return 0;
    }

    private static async Task<int> VerifyChainAsync(IAuditRepository audit, CancellationToken ct)
    {
        var result = await audit.VerifyAsync(ct);

        if (result.IsIntact)
        {
            Console.WriteLine($"Audit chain intact. Head: {result.Head?[..16]}...");
            return 0;
        }

        Console.Error.WriteLine(
            $"AUDIT CHAIN BROKEN: {result.Fault} at index {result.FailedAtIndex} " +
            $"(event {result.FailedAtId}). This indicates tampering or storage corruption.");
        return 2;
    }

    private static async Task<int> StatusAsync(
        IPolicyRepository repo,
        IAuditRepository audit,
        CancellationToken ct)
    {
        var policies = await repo.GetAllAsync(ct);
        var users = await repo.GetUsersAsync(ct);
        var chain = await audit.VerifyAsync(ct);
        var recent = await audit.RecentAsync(5, ct);

        Console.WriteLine($"Store        {DatabaseBootstrapper.DefaultDatabasePath}");
        Console.WriteLine($"Identities   {users.Count}");
        Console.WriteLine($"Policies     {policies.Count} ({policies.Count(p => p.Enabled)} enabled)");
        Console.WriteLine($"Audit chain  {(chain.IsIntact ? "intact" : $"BROKEN ({chain.Fault})")}");

        if (recent.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("Recent:");
            foreach (var e in recent)
            {
                Console.WriteLine($"  {e.Timestamp.LocalDateTime:HH:mm:ss}  {e.Kind}  {e.App?.FileName}");
            }
        }

        return chain.IsIntact ? 0 : 2;
    }

    private static bool TryGetOption(string[] args, string name, out string value)
    {
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
            {
                value = args[i + 1];
                return true;
            }
        }

        value = string.Empty;
        return false;
    }
}
