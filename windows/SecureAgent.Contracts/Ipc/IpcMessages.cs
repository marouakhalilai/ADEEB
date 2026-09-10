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
