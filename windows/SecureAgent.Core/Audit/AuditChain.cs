using SecureAgent.Core.Domain;

namespace SecureAgent.Core.Audit;

/// <summary>Why a chain failed verification.</summary>
public enum ChainFault
{
    /// <summary>No fault.</summary>
    None,

    /// <summary>A record's stored hash does not match its own content: the record was edited.</summary>
    RecordAltered,

    /// <summary>A record's PrevHash does not match its predecessor: a record was removed or reordered.</summary>
    BrokenLink,

    /// <summary>The first record does not declare the genesis predecessor, or continuity with the expected head was lost.</summary>
    UnexpectedOrigin,
}

/// <summary>The result of verifying a run of audit records.</summary>
/// <param name="Fault">The fault found, or <see cref="ChainFault.None"/>.</param>
/// <param name="FailedAtIndex">Index of the first bad record, or -1 when the chain is intact.</param>
/// <param name="FailedAtId">Id of the first bad record, when there is one.</param>
/// <param name="Head">The hash of the last record, when the chain is intact.</param>
public readonly record struct ChainVerification(
    ChainFault Fault,
    int FailedAtIndex,
    string? FailedAtId,
    string? Head)
{
    /// <summary>True when no fault was found.</summary>
    public bool IsIntact => Fault == ChainFault.None;
}

/// <summary>
/// Verifies hash-chain continuity over a sequence of audit records.
/// </summary>
/// <remarks>
/// Run on the device at startup against the last-known-good head from the control plane,
/// and again server-side on every ingest batch. A fault is itself a reportable security
/// event (<see cref="EventKind.ChainVerificationFailed"/>) — it means either tampering or
/// storage corruption, and both are worth waking someone for.
/// </remarks>
public static class AuditChain
{
    /// <summary>
    /// Verifies a contiguous run of records in chain order.
    /// </summary>
    /// <param name="events">The records, oldest first.</param>
    /// <param name="expectedPrevHash">
    /// The hash the first record must chain from. Pass the last-known-good head when
    /// verifying a continuation, or null when verifying from the beginning of time.
    /// </param>
    public static ChainVerification Verify(
        IReadOnlyList<SecurityEvent> events,
        string? expectedPrevHash = null)
    {
        ArgumentNullException.ThrowIfNull(events);

        if (events.Count == 0)
        {
            return new ChainVerification(ChainFault.None, -1, null, expectedPrevHash);
        }

        var expected = expectedPrevHash ?? EventHasher.GenesisPrevHash;

        for (var i = 0; i < events.Count; i++)
        {
            var e = events[i];

            if (!string.Equals(e.PrevHash, expected, StringComparison.Ordinal))
            {
                var fault = i == 0 ? ChainFault.UnexpectedOrigin : ChainFault.BrokenLink;
                return new ChainVerification(fault, i, e.Id, null);
            }

            if (!EventHasher.IsSelfConsistent(e))
            {
                return new ChainVerification(ChainFault.RecordAltered, i, e.Id, null);
            }

            expected = e.Hash;
        }

        return new ChainVerification(ChainFault.None, -1, null, expected);
    }
}
