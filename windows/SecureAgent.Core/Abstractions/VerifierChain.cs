using SecureAgent.Core.Domain;

namespace SecureAgent.Core.Abstractions;

/// <summary>
/// Picks the best available verifier that satisfies a policy's assurance requirement.
/// </summary>
/// <remarks>
/// <para>
/// The decision engine asks for an assurance level, never for a named mechanism. That
/// indirection is what lets the same policy work on a Surface with an IR camera, a desktop
/// with a plain webcam, and a machine with no camera at all — and what lets the ONNX face
/// engine be added later without touching a single policy or decision path.
/// </para>
/// <para>
/// Ordering is strongest-first, so a machine that has Windows Hello uses it even when a
/// weaker rung would also satisfy the policy. Assurance is a floor, not a target.
/// </para>
/// </remarks>
public sealed class VerifierChain
{
    private readonly IReadOnlyList<IIdentityVerifier> _verifiers;

    /// <summary>Creates a chain over the given verifiers.</summary>
    public VerifierChain(IEnumerable<IIdentityVerifier> verifiers)
    {
        ArgumentNullException.ThrowIfNull(verifiers);

        _verifiers = [.. verifiers.OrderByDescending(v => v.ProvidedAssurance)];
    }

    /// <summary>The rungs present, regardless of current availability.</summary>
    public IReadOnlyList<IIdentityVerifier> All => _verifiers;

    /// <summary>
    /// Returns the strongest currently-available verifier meeting the requirement, or null.
    /// </summary>
    public async Task<IIdentityVerifier?> SelectAsync(AssuranceLevel minimum, CancellationToken ct)
    {
        foreach (var verifier in _verifiers)
        {
            if (verifier.ProvidedAssurance < minimum)
            {
                // The list is sorted strongest-first, so nothing after this can qualify.
                break;
            }

            if (await verifier.IsAvailableAsync(ct))
            {
                return verifier;
            }
        }

        return null;
    }

    /// <summary>
    /// Runs a verification using the strongest available qualifying rung.
    /// </summary>
    /// <remarks>
    /// Deliberately does not fall back to a weaker rung when the chosen one returns
    /// <see cref="VerificationOutcome.NoMatch"/>. Falling back on failure would mean an
    /// unrecognised person could downgrade themselves to a weaker check simply by failing
    /// the strong one, which inverts the purpose of having assurance levels. Fallback
    /// applies only to <em>availability</em>, never to a negative result.
    /// </remarks>
    public async Task<VerificationResult> VerifyAsync(
        IdentityChallenge challenge,
        CancellationToken ct)
    {
        var verifier = await SelectAsync(challenge.MinimumAssurance, ct);
        if (verifier is null)
        {
            return VerificationResult.Unavailable(
                VerifierKind.None,
                $"No verifier available at assurance {challenge.MinimumAssurance}.");
        }

        return await verifier.VerifyAsync(challenge, ct);
    }
}
