namespace SecureAgent.Core.Domain;

/// <summary>
/// One record in the append-only, hash-chained audit log.
/// </summary>
/// <remarks>
/// <para>
/// The chain is what gives the product tamper-<em>evidence</em> in the absence of
/// tamper-prevention: a local administrator can always stop the service, but they cannot
/// quietly remove or edit a record without breaking <see cref="Hash"/> continuity, which
/// the control plane detects on ingest (plan §06).
/// </para>
/// <para>
/// What is deliberately absent from this type: images, embeddings, similarity scores, and
/// full executable paths. See <see cref="ConfidenceBucket"/> for why the score is bucketed.
/// </para>
/// </remarks>
public sealed record SecurityEvent
{
    /// <summary>Client-generated ULID. Primary key everywhere, which makes cloud ingest idempotent.</summary>
    public required string Id { get; init; }

    /// <summary>Wall-clock time, UTC. Display and correlation only — never TTL arithmetic.</summary>
    public required DateTimeOffset Timestamp { get; init; }

    /// <summary>Windows terminal session. Authentication sessions never cross this boundary.</summary>
    public required int WindowsSessionId { get; init; }

    /// <summary>What happened.</summary>
    public required EventKind Kind { get; init; }

    /// <summary>Deterministically assigned. Never rewritten by the advisory layer.</summary>
    public required Severity Severity { get; init; }

    /// <summary>The access outcome.</summary>
    public required Outcome Outcome { get; init; }

    /// <summary>The policy that was evaluated, when the event arose from one.</summary>
    public Guid? PolicyId { get; init; }

    /// <summary>The enrolled identity that matched, or null when unknown or unmatched.</summary>
    public Guid? UserId { get; init; }

    /// <summary>The application involved, in redacted form.</summary>
    public AppRef? App { get; init; }

    /// <summary>Which rung of the ladder produced the result.</summary>
    public VerifierKind Verifier { get; init; } = VerifierKind.None;

    /// <summary>Bucketed match confidence. Never a raw score.</summary>
    public ConfidenceBucket Confidence { get; init; } = ConfidenceBucket.None;

    /// <summary>Whether presentation-attack detection passed, when it ran.</summary>
    public bool? LivenessPassed { get; init; }

    /// <summary>End-to-end duration of the verification, for the latency SLO (plan §11).</summary>
    public int? ElapsedMs { get; init; }

    /// <summary>The enforcement action actually applied.</summary>
    public EnforcementAction Action { get; init; } = EnforcementAction.None;

    /// <summary>
    /// SHA-256 of the preceding record in this device's chain, lower-case hex. Null only
    /// for the genesis record.
    /// </summary>
    public string? PrevHash { get; init; }

    /// <summary>
    /// SHA-256 over the canonical serialization of this record including
    /// <see cref="PrevHash"/>. Computed by <c>EventHasher</c>; never set by hand.
    /// </summary>
    public string Hash { get; init; } = string.Empty;

    /// <summary>
    /// Bounded, low-cardinality supplementary fields. Must not carry embeddings, scores,
    /// image data, or unbounded attacker-controlled text.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Meta { get; init; }
}
