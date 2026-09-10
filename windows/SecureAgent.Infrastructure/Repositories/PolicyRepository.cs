using Microsoft.EntityFrameworkCore;
using SecureAgent.Core.Domain;
using SecureAgent.Infrastructure.Database;

namespace SecureAgent.Infrastructure.Repositories;

/// <summary>Reads and writes protected-application policies.</summary>
public interface IPolicyRepository
{
    /// <summary>All policies, in the domain shape the engine consumes.</summary>
    Task<IReadOnlyList<ApplicationPolicy>> GetAllAsync(CancellationToken ct);

    /// <summary>Creates or replaces a policy. Rejects one that fails validation.</summary>
    Task SaveAsync(ApplicationPolicy policy, CancellationToken ct);

    /// <summary>Removes a policy and its authorisations.</summary>
    Task<bool> DeleteAsync(Guid id, CancellationToken ct);

    /// <summary>All enrolled identities.</summary>
    Task<IReadOnlyList<UserEntity>> GetUsersAsync(CancellationToken ct);

    /// <summary>Creates an identity and returns its id.</summary>
    Task<Guid> CreateUserAsync(string displayName, string? windowsSid, CancellationToken ct);
}

/// <summary>SQLite-backed policy store.</summary>
public sealed class PolicyRepository : IPolicyRepository
{
    private readonly IDbContextFactory<SecureAgentDbContext> _factory;

    /// <summary>Creates the repository.</summary>
    public PolicyRepository(IDbContextFactory<SecureAgentDbContext> factory) => _factory = factory;

    /// <inheritdoc />
    public async Task<IReadOnlyList<ApplicationPolicy>> GetAllAsync(CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);

        var rows = await db.Policies
            .Include(p => p.AuthorizedUsers)
            .AsNoTracking()
            .ToListAsync(ct);

        return [.. rows.Select(ToDomain)];
    }

    /// <inheritdoc />
    public async Task SaveAsync(ApplicationPolicy policy, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(policy);

        // Validation is enforced at the write boundary rather than trusted to callers. A
        // policy that claims high assurance while resting on a defeatable match rule must
        // never reach storage, because from then on it would look authoritative.
        var problems = policy.Validate();
        if (problems.Count > 0)
        {
            throw new InvalidOperationException(
                "Policy is not valid:" + Environment.NewLine + string.Join(Environment.NewLine, problems));
        }

        await using var db = await _factory.CreateDbContextAsync(ct);

        var existing = await db.Policies
            .Include(p => p.AuthorizedUsers)
            .FirstOrDefaultAsync(p => p.Id == policy.Id, ct);

        if (existing is null)
        {
            existing = new PolicyEntity { Id = policy.Id };
            db.Policies.Add(existing);
        }
        else
        {
            db.PolicyUsers.RemoveRange(existing.AuthorizedUsers);
        }

        existing.DisplayName = policy.DisplayName;
        existing.MatchKind = policy.Match.Kind.ToString();
        existing.MatchValue = policy.Match.Value;
        existing.MinimumAssurance = policy.MinimumAssurance.ToString();
        existing.SessionTtlSeconds = (int)policy.SessionTtl.TotalSeconds;
        existing.AbsenceGraceSeconds = (int)policy.AbsenceGrace.TotalSeconds;
        existing.ContinuousMode = policy.Continuous.ToString();
        existing.OnFailure = policy.OnFailure.ToString();
        existing.OnVerifierUnavailable = policy.OnVerifierUnavailable.ToString();
        existing.MaxFailuresBeforeEscalation = policy.MaxFailuresBeforeEscalation;
        existing.ActiveFromMinute = policy.ActiveHours?.StartMinuteUtcOffset;
        existing.ActiveToMinute = policy.ActiveHours?.EndMinuteUtcOffset;
        existing.Enabled = policy.Enabled;
        existing.AuthorizedUsers = [.. policy.AuthorizedUserIds.Select(
            u => new PolicyUserEntity { PolicyId = policy.Id, UserId = u })];

        await db.SaveChangesAsync(ct);
    }

    /// <inheritdoc />
    public async Task<bool> DeleteAsync(Guid id, CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);

        var existing = await db.Policies.FirstOrDefaultAsync(p => p.Id == id, ct);
        if (existing is null)
        {
            return false;
        }

        db.Policies.Remove(existing);
        await db.SaveChangesAsync(ct);
        return true;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<UserEntity>> GetUsersAsync(CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        return await db.Users.AsNoTracking().ToListAsync(ct);
    }

    /// <inheritdoc />
    public async Task<Guid> CreateUserAsync(string displayName, string? windowsSid, CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);

        var user = new UserEntity
        {
            Id = Guid.NewGuid(),
            DisplayName = displayName,
            WindowsSid = windowsSid,
            CreatedAt = DateTimeOffset.UtcNow,
        };

        db.Users.Add(user);
        await db.SaveChangesAsync(ct);
        return user.Id;
    }

    private static ApplicationPolicy ToDomain(PolicyEntity p) => new()
    {
        Id = p.Id,
        DisplayName = p.DisplayName,
        Match = new AppMatcher(Enum.Parse<AppMatchKind>(p.MatchKind), p.MatchValue),
        AuthorizedUserIds = [.. p.AuthorizedUsers.Select(u => u.UserId)],
        MinimumAssurance = Enum.Parse<AssuranceLevel>(p.MinimumAssurance),
        SessionTtl = TimeSpan.FromSeconds(p.SessionTtlSeconds),
        AbsenceGrace = TimeSpan.FromSeconds(p.AbsenceGraceSeconds),
        Continuous = Enum.Parse<ContinuousMode>(p.ContinuousMode),
        OnFailure = Enum.Parse<FailureAction>(p.OnFailure),
        OnVerifierUnavailable = Enum.Parse<UnavailableAction>(p.OnVerifierUnavailable),
        MaxFailuresBeforeEscalation = p.MaxFailuresBeforeEscalation,
        ActiveHours = p.ActiveFromMinute is { } from && p.ActiveToMinute is { } to
            ? new Schedule(from, to)
            : null,
        Enabled = p.Enabled,
    };
}
