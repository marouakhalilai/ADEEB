using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SecureAgent.Infrastructure.Database;

/// <summary>An enrolled identity.</summary>
public sealed class UserEntity
{
    /// <summary>Primary key.</summary>
    public Guid Id { get; set; }

    /// <summary>Display name shown in the dashboard.</summary>
    [MaxLength(128)]
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>
    /// The Windows account this identity corresponds to, when it maps to one. Needed for
    /// the Windows Hello rung, which verifies the account owner rather than an arbitrary
    /// enrolled face.
    /// </summary>
    [MaxLength(184)]
    public string? WindowsSid { get; set; }

    /// <summary>When the identity was created.</summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>
    /// When the user consented to biometric processing, and to which version of the notice.
    /// Null means no consent has been recorded and no biometric enrolment may take place.
    /// </summary>
    public DateTimeOffset? ConsentAt { get; set; }

    /// <summary>Version of the consent notice that was accepted.</summary>
    [MaxLength(32)]
    public string? ConsentVersion { get; set; }

    /// <summary>Face templates belonging to this identity.</summary>
    public List<FaceTemplateEntity> Templates { get; set; } = [];
}

/// <summary>
/// An encrypted biometric template.
/// </summary>
/// <remarks>
/// Only ciphertext is stored. There is no column here that could hold an image, and the
/// plaintext embedding exists solely inside a template lease during a match.
/// </remarks>
public sealed class FaceTemplateEntity
{
    /// <summary>Primary key.</summary>
    public Guid Id { get; set; }

    /// <summary>Owning identity.</summary>
    public Guid UserId { get; set; }

    /// <summary>Navigation to the owner.</summary>
    public UserEntity? User { get; set; }

    /// <summary>AES-256-GCM ciphertext of the embedding.</summary>
    public byte[] Ciphertext { get; set; } = [];

    /// <summary>Per-record GCM nonce. Never reused.</summary>
    public byte[] Nonce { get; set; } = [];

    /// <summary>GCM authentication tag.</summary>
    public byte[] Tag { get; set; } = [];

    /// <summary>Model that produced the embedding; templates only compare within a model.</summary>
    [MaxLength(64)]
    public string ModelId { get; set; } = string.Empty;

    /// <summary>Model version, so an upgrade forces re-enrolment rather than silent mismatches.</summary>
    [MaxLength(32)]
    public string ModelVersion { get; set; } = string.Empty;

    /// <summary>Embedding dimension, validated on load.</summary>
    public int Dimensions { get; set; }

    /// <summary>Capture quality at enrolment.</summary>
    public float Quality { get; set; }

    /// <summary>When it was enrolled.</summary>
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>A protected application and the rules governing access to it.</summary>
public sealed class PolicyEntity
{
    /// <summary>Primary key.</summary>
    public Guid Id { get; set; }

    /// <summary>Human-readable name.</summary>
    [MaxLength(128)]
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>How the executable is matched, stored as the enum name.</summary>
    [MaxLength(32)]
    public string MatchKind { get; set; } = string.Empty;

    /// <summary>The expected publisher CN, path, or file name.</summary>
    [MaxLength(520)]
    public string MatchValue { get; set; } = string.Empty;

    /// <summary>Weakest acceptable verifier rung, stored as the enum name.</summary>
    [MaxLength(32)]
    public string MinimumAssurance { get; set; } = string.Empty;

    /// <summary>Session lifetime in seconds.</summary>
    public int SessionTtlSeconds { get; set; }

    /// <summary>Absence grace period in seconds.</summary>
    public int AbsenceGraceSeconds { get; set; }

    /// <summary>Continuous verification mode, stored as the enum name.</summary>
    [MaxLength(32)]
    public string ContinuousMode { get; set; } = string.Empty;

    /// <summary>Action on verification failure, stored as the enum name.</summary>
    [MaxLength(32)]
    public string OnFailure { get; set; } = string.Empty;

    /// <summary>Action when no verifier is available, stored as the enum name.</summary>
    [MaxLength(32)]
    public string OnVerifierUnavailable { get; set; } = string.Empty;

    /// <summary>Consecutive failures before severity escalates.</summary>
    public int MaxFailuresBeforeEscalation { get; set; } = 3;

    /// <summary>Start of the active window, minutes past midnight. Null means always active.</summary>
    public int? ActiveFromMinute { get; set; }

    /// <summary>End of the active window, minutes past midnight.</summary>
    public int? ActiveToMinute { get; set; }

    /// <summary>Whether the policy is in force.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Identities authorised for this application.</summary>
    public List<PolicyUserEntity> AuthorizedUsers { get; set; } = [];
}

/// <summary>Join row binding an identity to a policy.</summary>
public sealed class PolicyUserEntity
{
    /// <summary>The policy.</summary>
    public Guid PolicyId { get; set; }

    /// <summary>Navigation to the policy.</summary>
    public PolicyEntity? Policy { get; set; }

    /// <summary>The authorised identity.</summary>
    public Guid UserId { get; set; }

    /// <summary>Navigation to the identity.</summary>
    public UserEntity? User { get; set; }
}

/// <summary>
/// One record in the hash-chained audit log.
/// </summary>
/// <remarks>
/// Append-only by contract. Nothing in the application updates or deletes a row here except
/// the retention job, which trims whole prefixes and records the trim as an event of its own.
/// </remarks>
public sealed class SecurityEventEntity
{
    /// <summary>Client-generated ULID; also the sync idempotency key.</summary>
    [MaxLength(26)]
    public string Id { get; set; } = string.Empty;

    /// <summary>Monotonically increasing insertion order, which defines chain order.</summary>
    public long Sequence { get; set; }

    /// <summary>Wall-clock time, for display and correlation only.</summary>
    public DateTimeOffset Timestamp { get; set; }

    /// <summary>Windows terminal session.</summary>
    public int WindowsSessionId { get; set; }

    /// <summary>Event kind, stored as the enum name.</summary>
    [MaxLength(48)]
    public string Kind { get; set; } = string.Empty;

    /// <summary>Severity, stored as the enum name.</summary>
    [MaxLength(16)]
    public string Severity { get; set; } = string.Empty;

    /// <summary>Outcome, stored as the enum name.</summary>
    [MaxLength(16)]
    public string Outcome { get; set; } = string.Empty;

    /// <summary>Policy involved, when any.</summary>
    public Guid? PolicyId { get; set; }

    /// <summary>Identity matched, when any.</summary>
    public Guid? UserId { get; set; }

    /// <summary>Application file name.</summary>
    [MaxLength(260)]
    public string? AppFileName { get; set; }

    /// <summary>How the application was matched.</summary>
    [MaxLength(32)]
    public string? AppMatchKind { get; set; }

    /// <summary>Publisher CN when signed.</summary>
    [MaxLength(256)]
    public string? AppPublisherCn { get; set; }

    /// <summary>Window title: untrusted, opt-in, truncated at capture.</summary>
    [MaxLength(64)]
    public string? AppWindowTitle { get; set; }

    /// <summary>Verifier rung used.</summary>
    [MaxLength(32)]
    public string Verifier { get; set; } = string.Empty;

    /// <summary>Bucketed confidence. Never a raw score.</summary>
    [MaxLength(16)]
    public string Confidence { get; set; } = string.Empty;

    /// <summary>Whether liveness passed, when it ran.</summary>
    public bool? LivenessPassed { get; set; }

    /// <summary>Verification duration, for the latency SLO.</summary>
    public int? ElapsedMs { get; set; }

    /// <summary>Enforcement action applied.</summary>
    [MaxLength(32)]
    public string Action { get; set; } = string.Empty;

    /// <summary>Hash of the preceding record.</summary>
    [MaxLength(64)]
    public string? PrevHash { get; set; }

    /// <summary>Hash over this record's canonical form.</summary>
    [MaxLength(64)]
    public string Hash { get; set; } = string.Empty;

    /// <summary>Whether the record has been synced to the control plane.</summary>
    public bool Synced { get; set; }

    /// <summary>Bounded supplementary fields as JSON. Never biometric material.</summary>
    [Column(TypeName = "TEXT")]
    public string? MetaJson { get; set; }
}
