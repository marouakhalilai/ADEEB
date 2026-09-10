using SecureAgent.Core.Domain;

namespace SecureAgent.Core.Abstractions;

/// <summary>Why a verification did not produce a definite answer.</summary>
public enum VerificationOutcome
{
    /// <summary>An authorised identity was recognised.</summary>
    Match,

    /// <summary>Someone was there and was not an authorised identity.</summary>
    NoMatch,

    /// <summary>
    /// The attempt produced no usable answer — nobody in frame, poor quality, or the user
    /// dismissed the prompt. Distinct from <see cref="NoMatch"/> on purpose: an empty chair
    /// is not an intruder, and treating it as one is how a product locks people out of their
    /// own machines.
    /// </summary>
    Inconclusive,

    /// <summary>
    /// No verifier of the required assurance could run at all — camera held elsewhere,
    /// privacy settings, no hardware. The policy's <see cref="UnavailableAction"/> decides
    /// what happens, and it is a different branch from failure.
    /// </summary>
    Unavailable,
}

/// <summary>The result of one verification attempt.</summary>
/// <param name="Outcome">What was determined.</param>
/// <param name="MatchedUserId">The recognised identity, when there is one.</param>
/// <param name="Verifier">Which rung answered.</param>
/// <param name="Assurance">The assurance actually achieved.</param>
/// <param name="Confidence">Bucketed confidence. Never a raw score.</param>
/// <param name="LivenessPassed">Whether presentation-attack detection passed, if it ran.</param>
/// <param name="ElapsedMs">How long it took, for the latency SLO.</param>
/// <param name="FailureDetail">
/// A short, non-sensitive reason for logs. Must never contain biometric data or a score.
/// </param>
public readonly record struct VerificationResult(
    VerificationOutcome Outcome,
    Guid? MatchedUserId,
    VerifierKind Verifier,
    AssuranceLevel Assurance,
    ConfidenceBucket Confidence,
    bool? LivenessPassed,
    int ElapsedMs,
    string? FailureDetail)
{
    /// <summary>Builds an unavailable result.</summary>
    public static VerificationResult Unavailable(VerifierKind kind, string reason) => new(
        VerificationOutcome.Unavailable,
        null,
        kind,
        AssuranceLevel.Any,
        ConfidenceBucket.None,
        null,
        0,
        reason);
}

/// <summary>What a verifier is being asked to establish.</summary>
/// <param name="AuthorizedUserIds">Identities that would satisfy the policy.</param>
/// <param name="MinimumAssurance">The weakest rung the policy accepts.</param>
/// <param name="Timeout">Hard deadline; the verifier must answer within it.</param>
/// <param name="Interactive">
/// Whether the user should see a prompt. False for silent continuous checks, which must not
/// interrupt someone who is working.
/// </param>
public readonly record struct IdentityChallenge(
    IReadOnlyList<Guid> AuthorizedUserIds,
    AssuranceLevel MinimumAssurance,
    TimeSpan Timeout,
    bool Interactive);

/// <summary>
/// One rung of the verifier ladder.
/// </summary>
/// <remarks>
/// The abstraction exists so the product is never tied to one recognition technology
/// (CLAUDE.md rule 2). Windows Hello, a local ONNX pipeline and a PIN all sit behind this,
/// and the decision engine asks for an assurance level rather than naming a mechanism.
/// </remarks>
public interface IIdentityVerifier
{
    /// <summary>Which rung this is.</summary>
    VerifierKind Kind { get; }

    /// <summary>The assurance a successful verification by this rung provides.</summary>
    AssuranceLevel ProvidedAssurance { get; }

    /// <summary>
    /// Whether this verifier can run right now.
    /// </summary>
    /// <remarks>
    /// Probed rather than assumed, and expected to change during a session: a camera can be
    /// taken by another application at any moment.
    /// </remarks>
    ValueTask<bool> IsAvailableAsync(CancellationToken ct);

    /// <summary>Attempts to establish an identity.</summary>
    Task<VerificationResult> VerifyAsync(IdentityChallenge challenge, CancellationToken ct);
}
