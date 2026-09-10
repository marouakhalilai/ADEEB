using Microsoft.EntityFrameworkCore;
using SecureAgent.Core.Audit;
using SecureAgent.Core.Domain;
using SecureAgent.Infrastructure.Database;

namespace SecureAgent.Infrastructure.Repositories;

/// <summary>Appends to and verifies the local audit chain.</summary>
public interface IAuditRepository
{
    /// <summary>
    /// Seals an event against the current chain head and appends it.
    /// </summary>
    /// <returns>The sealed record, with its sequence, previous hash and hash filled in.</returns>
    Task<SecurityEvent> AppendAsync(SecurityEvent e, CancellationToken ct);

    /// <summary>Verifies the whole local chain.</summary>
    Task<ChainVerification> VerifyAsync(CancellationToken ct);

    /// <summary>Returns the most recent events, newest first, for the dashboard.</summary>
    Task<IReadOnlyList<SecurityEvent>> RecentAsync(int limit, CancellationToken ct);

    /// <summary>The current chain head hash, or null when the chain is empty.</summary>
    Task<string?> HeadAsync(CancellationToken ct);
}

/// <summary>
/// SQLite-backed audit chain.
/// </summary>
/// <remarks>
/// <para>
/// The critical property is that sequence assignment and hash linking happen together and
/// cannot interleave. Two events appended concurrently must not read the same chain head,
/// because both would then claim the same predecessor and one would be silently orphaned —
/// which looks exactly like tampering when the chain is later verified.
/// </para>
/// <para>
/// A process-wide lock is sufficient because the service is the only writer by design: the
/// broker has no database access at all. If that ever stops being true, this needs a
/// database-level guarantee instead, and the assumption is asserted rather than assumed.
/// </para>
/// </remarks>
public sealed class AuditRepository : IAuditRepository, IDisposable
{
    private readonly IDbContextFactory<SecureAgentDbContext> _factory;
    private readonly SemaphoreSlim _appendGate = new(1, 1);
    private bool _disposed;

    /// <summary>Creates the repository.</summary>
    public AuditRepository(IDbContextFactory<SecureAgentDbContext> factory) => _factory = factory;

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _appendGate.Dispose();
        _disposed = true;
    }

    /// <inheritdoc />
    public async Task<SecurityEvent> AppendAsync(SecurityEvent e, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(e);

        await _appendGate.WaitAsync(ct);
        try
        {
            await using var db = await _factory.CreateDbContextAsync(ct);

            var tail = await db.SecurityEvents
                .OrderByDescending(x => x.Sequence)
                .Select(x => new { x.Sequence, x.Hash })
                .FirstOrDefaultAsync(ct);

            var sealedEvent = EventHasher.Seal(e, tail?.Hash);
            var entity = ToEntity(sealedEvent, (tail?.Sequence ?? 0) + 1);

            db.SecurityEvents.Add(entity);
            await db.SaveChangesAsync(ct);

            return sealedEvent;
        }
        finally
        {
            _appendGate.Release();
        }
    }

    /// <inheritdoc />
    public async Task<ChainVerification> VerifyAsync(CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);

        var rows = await db.SecurityEvents
            .OrderBy(x => x.Sequence)
            .AsNoTracking()
            .ToListAsync(ct);

        return AuditChain.Verify([.. rows.Select(FromEntity)]);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<SecurityEvent>> RecentAsync(int limit, CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);

        var rows = await db.SecurityEvents
            .OrderByDescending(x => x.Sequence)
            .Take(limit)
            .AsNoTracking()
            .ToListAsync(ct);

        return [.. rows.Select(FromEntity)];
    }

    /// <inheritdoc />
    public async Task<string?> HeadAsync(CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);

        return await db.SecurityEvents
            .OrderByDescending(x => x.Sequence)
            .Select(x => x.Hash)
            .FirstOrDefaultAsync(ct);
    }

    private static SecurityEventEntity ToEntity(SecurityEvent e, long sequence) => new()
    {
        Id = e.Id,
        Sequence = sequence,
        Timestamp = e.Timestamp,
        WindowsSessionId = e.WindowsSessionId,
        Kind = e.Kind.ToString(),
        Severity = e.Severity.ToString(),
        Outcome = e.Outcome.ToString(),
        PolicyId = e.PolicyId,
        UserId = e.UserId,
        AppFileName = e.App?.FileName,
        AppMatchKind = e.App?.MatchKind.ToString(),
        AppPublisherCn = e.App?.PublisherCn,
        AppWindowTitle = e.App?.WindowTitle,
        Verifier = e.Verifier.ToString(),
        Confidence = e.Confidence.ToString(),
        LivenessPassed = e.LivenessPassed,
        ElapsedMs = e.ElapsedMs,
        Action = e.Action.ToString(),
        PrevHash = e.PrevHash,
        Hash = e.Hash,
        Synced = false,
        MetaJson = null,
    };

    private static SecurityEvent FromEntity(SecurityEventEntity x) => new()
    {
        Id = x.Id,
        Timestamp = x.Timestamp,
        WindowsSessionId = x.WindowsSessionId,
        Kind = Enum.Parse<EventKind>(x.Kind),
        Severity = Enum.Parse<Severity>(x.Severity),
        Outcome = Enum.Parse<Outcome>(x.Outcome),
        PolicyId = x.PolicyId,
        UserId = x.UserId,
        App = x.AppFileName is null
            ? null
            : new AppRef(
                Enum.Parse<AppMatchKind>(x.AppMatchKind ?? nameof(AppMatchKind.Unresolved)),
                x.AppFileName,
                x.AppPublisherCn,
                PathHash: null,
                x.AppWindowTitle),
        Verifier = Enum.Parse<VerifierKind>(x.Verifier),
        Confidence = Enum.Parse<ConfidenceBucket>(x.Confidence),
        LivenessPassed = x.LivenessPassed,
        ElapsedMs = x.ElapsedMs,
        Action = Enum.Parse<EnforcementAction>(x.Action),
        PrevHash = x.PrevHash,
        Hash = x.Hash,
    };
}
