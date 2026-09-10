using SecureAgent.Contracts.Ipc;

namespace SecureAgent.Face.Abstractions;

/// <summary>
/// Opens and closes the capture device.
/// </summary>
/// <remarks>
/// Separate from detection so that camera contention — the single most common real-world
/// failure (plan §05) — is reported as its own condition rather than surfacing as "no
/// face found". Those two produce opposite policy outcomes.
/// </remarks>
public interface IFaceCamera : IAsyncDisposable
{
    /// <summary>Whether a usable capture device exists and is permitted right now.</summary>
    ValueTask<CameraAvailability> ProbeAsync(CancellationToken ct);

    /// <summary>
    /// Captures a short burst of frames. The burst exists so that deny decisions can
    /// require agreement across frames (plan §04) without opening the camera repeatedly.
    /// </summary>
    /// <param name="frameCount">Frames to capture, typically 3.</param>
    /// <param name="ct">Cancels the capture; the deadline comes from the policy's verify timeout.</param>
    ValueTask<IReadOnlyList<IFrame>> CaptureBurstAsync(int frameCount, CancellationToken ct);
}

/// <summary>Why a camera is or is not usable.</summary>
public enum CameraAvailability
{
    /// <summary>Ready to capture.</summary>
    Available,

    /// <summary>Another process holds it — commonly a video call.</summary>
    InUse,

    /// <summary>Windows privacy settings deny access to this application.</summary>
    PolicyDenied,

    /// <summary>No capture device is present.</summary>
    NoDevice,
}

/// <summary>
/// One captured frame. Deliberately opaque.
/// </summary>
/// <remarks>
/// The interface exposes no pixel accessor and no save method. Frames exist only inside
/// the broker process, are never written to disk, and never cross the IPC boundary
/// (CLAUDE.md rule 19). Implementations must dispose native buffers eagerly rather than
/// waiting for finalization — a leaked frame is a leaked biometric.
/// </remarks>
public interface IFrame : IDisposable
{
    /// <summary>Frame width in pixels.</summary>
    int Width { get; }

    /// <summary>Frame height in pixels.</summary>
    int Height { get; }
}

/// <summary>Locates faces within a frame.</summary>
public interface IFaceDetector
{
    /// <summary>Returns the detected faces, best first, or an empty list.</summary>
    ValueTask<IReadOnlyList<DetectedFace>> DetectAsync(IFrame frame, CancellationToken ct);
}

/// <summary>
/// A detected face and the measurements the quality gate needs.
/// </summary>
/// <param name="BoxWidth">Face width in pixels. Small faces embed poorly and produce confident wrong answers.</param>
/// <param name="BoxHeight">Face height in pixels.</param>
/// <param name="Sharpness">Laplacian variance over the face region. Low means motion blur.</param>
/// <param name="YawDegrees">Head rotation left/right, from landmarks.</param>
/// <param name="PitchDegrees">Head rotation up/down, from landmarks.</param>
public readonly record struct DetectedFace(
    int BoxWidth,
    int BoxHeight,
    double Sharpness,
    double YawDegrees,
    double PitchDegrees);

/// <summary>Rejects frames unfit for embedding, before they can produce a confident wrong answer.</summary>
public interface IFaceQualityGate
{
    /// <summary>Whether this detection is good enough to embed.</summary>
    bool IsAcceptable(DetectedFace face, out string? reason);
}

/// <summary>Presentation-attack detection.</summary>
/// <remarks>
/// Passive RGB liveness raises the cost of a photo or screen replay; it does not defeat a
/// determined attacker. The high-assurance tier delegates this to Windows Hello and its IR
/// hardware instead (plan §01). Never let a caller treat a pass here as equivalent.
/// </remarks>
public interface ILivenessDetector
{
    /// <summary>Whether the frame appears to show a live subject.</summary>
    ValueTask<bool> IsLiveAsync(IFrame frame, DetectedFace face, CancellationToken ct);
}

/// <summary>Turns a frame region into a comparable vector.</summary>
public interface IFaceEmbedder
{
    /// <summary>Identifies the model, so embeddings are never compared across models.</summary>
    string ModelId { get; }

    /// <summary>Model version, so an upgrade triggers re-enrolment rather than silent mismatches.</summary>
    string ModelVersion { get; }

    /// <summary>Vector length this model produces.</summary>
    int Dimensions { get; }

    /// <summary>Produces the embedding for a detected face.</summary>
    ValueTask<FaceEmbedding> EmbedAsync(IFrame frame, DetectedFace face, CancellationToken ct);
}

/// <summary>
/// Compares an embedding against enrolled templates.
/// </summary>
/// <remarks>
/// Lives on the service side of the IPC boundary: matching needs the decrypted templates,
/// and those must never enter the broker process (plan §02).
/// </remarks>
public interface IFaceMatcher
{
    /// <summary>
    /// Returns the best match across the candidate templates.
    /// </summary>
    /// <param name="probe">The embedding just captured.</param>
    /// <param name="candidates">Decrypted templates for the users the policy authorises.</param>
    /// <param name="threshold">The calibrated operating point, supplied by policy rather than hard-coded.</param>
    MatchResult Match(FaceEmbedding probe, IReadOnlyList<EnrolledTemplate> candidates, double threshold);
}

/// <summary>A decrypted template held transiently in the service during a match.</summary>
/// <param name="UserId">The enrolled identity.</param>
/// <param name="Vector">The template embedding.</param>
/// <param name="ModelId">Model that produced it; must equal the probe's.</param>
public readonly record struct EnrolledTemplate(Guid UserId, float[] Vector, string ModelId);

/// <summary>
/// The outcome of a match.
/// </summary>
/// <remarks>
/// Carries a bucket, not a score. The raw similarity is a biometric proxy and does not
/// leave the matcher (CLAUDE.md rule 25).
/// </remarks>
/// <param name="IsMatch">Whether the best candidate cleared the threshold.</param>
/// <param name="UserId">The matched identity, when there is one.</param>
/// <param name="Confidence">Bucketed distance from the threshold.</param>
public readonly record struct MatchResult(
    bool IsMatch,
    Guid? UserId,
    Core.Domain.ConfidenceBucket Confidence);
