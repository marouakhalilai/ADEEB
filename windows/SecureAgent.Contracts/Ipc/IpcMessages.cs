using System.Text.Json.Serialization;
using SecureAgent.Core.Domain;

namespace SecureAgent.Contracts.Ipc;

/// <summary>
/// The message set carried over the named pipe between the Session 0 service and the
/// interactive-session broker.
/// </summary>
/// <remarks>
/// <para>
/// This is the most security-sensitive interface in the product (plan §02). Two invariants
/// are load-bearing and are the reason the types are shaped this way:
/// </para>
/// <list type="number">
/// <item>
/// <b>Frames never cross.</b> The broker sends a <see cref="FaceEmbedding"/> — a fixed-size
/// float vector — never an image. A compromised broker therefore cannot exfiltrate camera
/// data through this channel, and the service never has to hold a frame.
/// </item>
/// <item>
/// <b>Templates never cross.</b> The service holds the enrolled templates and returns only
/// a verdict. A compromised broker cannot read them, which is why matching happens on the
/// privileged side even though the camera is on the unprivileged side.
/// </item>
/// </list>
/// <para>
/// Every message is length-capped before deserialization: the pipe is reachable by the
/// interactive user, so an unbounded allocation here is a denial-of-service against the
/// security service itself.
/// </para>
/// </remarks>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "$kind")]
[JsonDerivedType(typeof(AppActivatedMessage), "app-activated")]
[JsonDerivedType(typeof(EmbeddingMessage), "embedding")]
[JsonDerivedType(typeof(VerificationResultMessage), "verification-result")]
[JsonDerivedType(typeof(VerifyRequestMessage), "verify-request")]
[JsonDerivedType(typeof(DecisionMessage), "decision")]
[JsonDerivedType(typeof(PresencePingMessage), "presence-ping")]
[JsonDerivedType(typeof(SessionChangedMessage), "session-changed")]
public abstract record IpcMessage
{
    /// <summary>Correlates a response with its request, and ties both to one audit record.</summary>
    public required string CorrelationId { get; init; }
}

// ---------------------------------------------------------------------------
// Broker -> Service
// ---------------------------------------------------------------------------

/// <summary>
/// A protected-candidate application came to the foreground. Sent for every foreground
/// change; the service decides whether it is interesting.
/// </summary>
/// <remarks>
/// The broker deliberately does no policy evaluation. It cannot be trusted to decide what
/// is protected — it runs as the user, who may be the adversary.
/// </remarks>
public sealed record AppActivatedMessage : IpcMessage
{
    /// <summary>The resolved application, already normalised as untrusted input.</summary>
    public required AppRef App { get; init; }

    /// <summary>Windows terminal session the activation happened in.</summary>
    public required int WindowsSessionId { get; init; }

    /// <summary>Process id at the time of resolution. May already be dead; the service must tolerate that.</summary>
    public required int ProcessId { get; init; }
}

/// <summary>
/// The result of a capture-and-embed cycle, in response to a <see cref="VerifyRequestMessage"/>.
/// </summary>
public sealed record EmbeddingMessage : IpcMessage
{
    /// <summary>
    /// The embedding, or null when no usable face was captured. Null is
    /// <see cref="Outcome.Degraded"/> territory, not a denial — an empty chair is not an
    /// intruder (plan §04).
    /// </summary>
    public FaceEmbedding? Embedding { get; init; }

    /// <summary>Why the capture produced nothing, when it did not.</summary>
    public CaptureFailure Failure { get; init; } = CaptureFailure.None;

    /// <summary>Whether presentation-attack detection passed. Null when it did not run.</summary>
    public bool? LivenessPassed { get; init; }

    /// <summary>Wall time spent in capture, for the latency SLO.</summary>
    public required int ElapsedMs { get; init; }
}

/// <summary>Why a capture cycle yielded no embedding.</summary>
public enum CaptureFailure
{
    /// <summary>No failure — an embedding is present.</summary>
    None,

    /// <summary>No face found in any frame of the burst. Treated as absence, not denial.</summary>
    NoFaceDetected,

    /// <summary>A face was found but every frame failed the quality gate: blur, size, or pose.</summary>
    QualityTooLow,

    /// <summary>Presentation-attack detection rejected the capture.</summary>
    LivenessFailed,

    /// <summary>Another process holds the camera. Fires often in the field — see the degraded matrix.</summary>
    CameraInUse,

    /// <summary>Windows camera privacy settings deny access, or there is no capture device.</summary>
    CameraUnavailable,

    /// <summary>The model failed to load or execute. Fails the feature closed, never silently open.</summary>
    EngineFault,

    /// <summary>The capture exceeded its deadline.</summary>
    Timeout,
}

// ---------------------------------------------------------------------------
// Service -> Broker
// ---------------------------------------------------------------------------

/// <summary>Asks the broker to capture and embed a face.</summary>
public sealed record VerifyRequestMessage : IpcMessage
{
    /// <summary>The minimum rung the policy will accept, which decides whether Hello alone suffices.</summary>
    public required AssuranceLevel MinimumAssurance { get; init; }

    /// <summary>Hard deadline. The broker must answer, even if only with a <see cref="CaptureFailure.Timeout"/>.</summary>
    public required int TimeoutMs { get; init; }

    /// <summary>Whether the user should see a "verifying" affordance, or the check is silent.</summary>
    public required bool Interactive { get; init; }

    /// <summary>
    /// Identities that would satisfy the policy.
    /// </summary>
    /// <remarks>
    /// Sent because the broker has no database access — by design, since it runs as the
    /// interactive user. These are opaque identifiers, not secrets, and the service
    /// re-checks any claimed match against the policy anyway: telling the broker what would
    /// be acceptable does not let it grant itself anything.
    /// </remarks>
    public IReadOnlyList<Guid> AuthorizedUserIds { get; init; } = [];

    /// <summary>
    /// The identity bound to the signed-in Windows account, when one exists.
    /// </summary>
    /// <remarks>
    /// Windows Hello attests the account owner and returns no identity of its own, so the
    /// broker needs to be told which enrolled identity a Hello success corresponds to.
    /// Null when no enrolled identity is bound to this Windows account, in which case the
    /// Hello rung reports itself unavailable rather than guessing.
    /// </remarks>
    public Guid? AccountUserId { get; init; }

    /// <summary>The application being protected, for the prompt and the overlay.</summary>
    public string? AppDisplayName { get; init; }
}

/// <summary>The verdict, and what the broker should do about it.</summary>
public sealed record DecisionMessage : IpcMessage
{
    /// <summary>The access outcome.</summary>
    public required Outcome Outcome { get; init; }

    /// <summary>The enforcement action to apply.</summary>
    public required EnforcementAction Action { get; init; }

    /// <summary>
    /// A short, non-technical reason for the overlay. Drawn from a fixed set of strings —
    /// never assembled from device input, and never from a model.
    /// </summary>
    public string? UserFacingReason { get; init; }
}

/// <summary>
/// A verdict from a verifier that performs its own matching.
/// </summary>
/// <remarks>
/// <para>
/// Two shapes of verifier exist, and they report differently on purpose:
/// </para>
/// <list type="bullet">
/// <item>
/// The local face pipeline sends an <see cref="EmbeddingMessage"/>, because the templates it
/// must be compared against live on the service side and must never enter the broker.
/// </item>
/// <item>
/// Windows Hello and the PIN rung send this, because the match happens inside Windows or
/// against a hash the service holds — there is no embedding to hand over, and the broker is
/// reporting an outcome rather than evidence.
/// </item>
/// </list>
/// <para>
/// The service still decides. A broker claiming <c>Match</c> is a claim, not an
/// authorisation: the service checks it against the policy's authorised identities and its
/// required assurance before opening a session.
/// </para>
/// </remarks>
public sealed record VerificationResultMessage : IpcMessage
{
    /// <summary>What the verifier determined.</summary>
    public required VerificationOutcomeDto Outcome { get; init; }

    /// <summary>The identity claimed, when one was recognised.</summary>
    public Guid? MatchedUserId { get; init; }

    /// <summary>Which rung answered.</summary>
    public required VerifierKind Verifier { get; init; }

    /// <summary>The assurance actually achieved.</summary>
    public required AssuranceLevel Assurance { get; init; }

    /// <summary>Bucketed confidence. Never a raw score.</summary>
    public ConfidenceBucket Confidence { get; init; } = ConfidenceBucket.None;

    /// <summary>Whether presentation-attack detection passed, when it ran.</summary>
    public bool? LivenessPassed { get; init; }

    /// <summary>Duration, for the latency SLO.</summary>
    public required int ElapsedMs { get; init; }

    /// <summary>Short non-sensitive reason for the audit record.</summary>
    public string? Detail { get; init; }
}

/// <summary>
/// Wire form of the verification outcome.
/// </summary>
/// <remarks>
/// Mirrors the Core enum rather than referencing it, so the wire contract can be versioned
/// independently of the internal type.
/// </remarks>
public enum VerificationOutcomeDto
{
    /// <summary>An authorised identity was recognised.</summary>
    Match,

    /// <summary>Someone was present and was not authorised.</summary>
    NoMatch,

    /// <summary>No usable answer. An empty chair is not an intruder.</summary>
    Inconclusive,

    /// <summary>No verifier could run at all.</summary>
    Unavailable,
}

/// <summary>
/// Reports that the user is still present, during continuous monitoring.
/// </summary>
/// <remarks>
/// Sent by the broker only while a protected application holds the foreground and the user
/// has been active recently. The service refreshes the session's presence timestamp; it
/// does not extend the TTL, so continuous monitoring cannot keep a session alive past its
/// lifetime.
/// </remarks>
public sealed record PresencePingMessage : IpcMessage
{
    /// <summary>The policy whose session is being refreshed.</summary>
    public required Guid PolicyId { get; init; }

    /// <summary>Windows terminal session.</summary>
    public required int WindowsSessionId { get; init; }

    /// <summary>Whether presence was confirmed. False drops the session.</summary>
    public required bool Present { get; init; }
}

/// <summary>
/// The Windows session changed state: lock, unlock, logoff, disconnect or user switch.
/// </summary>
/// <remarks>
/// Every one of these drops all authentication sessions for that terminal session. A locked
/// or switched desktop is a different person until proven otherwise.
/// </remarks>
public sealed record SessionChangedMessage : IpcMessage
{
    /// <summary>Windows terminal session that changed.</summary>
    public required int WindowsSessionId { get; init; }

    /// <summary>What happened.</summary>
    public required SessionChangeKind Change { get; init; }
}

/// <summary>Kinds of Windows session state change that invalidate authentication.</summary>
public enum SessionChangeKind
{
    /// <summary>Desktop locked.</summary>
    Locked,

    /// <summary>Desktop unlocked.</summary>
    Unlocked,

    /// <summary>User logged off.</summary>
    LoggedOff,

    /// <summary>Remote session disconnected.</summary>
    Disconnected,

    /// <summary>Fast user switch away from this session.</summary>
    SwitchedAway,
}

// ---------------------------------------------------------------------------
// Payloads
// ---------------------------------------------------------------------------

/// <summary>
/// A face embedding in transit. Not persisted in this form: the service encrypts before
/// storage and discards the plaintext.
/// </summary>
/// <param name="Vector">The embedding. Length must equal the model's declared dimension.</param>
/// <param name="ModelId">Which model produced it — an embedding is only comparable to templates from the same model.</param>
/// <param name="ModelVersion">Model version, so a model upgrade can trigger re-enrolment rather than silent mismatches.</param>
/// <param name="Quality">Capture quality, used to prefer the best frame of a burst.</param>
public sealed record FaceEmbedding(
    float[] Vector,
    string ModelId,
    string ModelVersion,
    float Quality)
{
    /// <summary>Hard cap on accepted vector length, enforced before allocation on the receiving side.</summary>
    public const int MaxDimensions = 1024;
}
