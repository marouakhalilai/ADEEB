namespace SecureAgent.Core.Policy;

using SecureAgent.Core.Domain;

/// <summary>What the caller must do next about an activation.</summary>
public enum DecisionKind
{
    /// <summary>No policy applies. Do nothing at all — do not log, do not touch the camera.</summary>
    NotProtected,

    /// <summary>A policy applies and a valid session already covers it.</summary>
    AllowFromSession,

    /// <summary>A policy applies and the user must be verified before access continues.</summary>
    VerificationRequired,

    /// <summary>
    /// A policy applies but nobody is authorised for it, so no verification can succeed.
    /// Denied without touching a camera.
    /// </summary>
    DenyNoAuthorizedUsers,
}

/// <summary>
/// The result of evaluating one activation against the policy set.
/// </summary>
/// <param name="Kind">What must happen next.</param>
/// <param name="Policy">The policy that matched, when one did.</param>
/// <param name="MatchedBy">Which rule resolved the application, for telemetry on match strength.</param>
/// <param name="RequiredAssurance">The weakest verifier rung that will satisfy the policy.</param>
/// <param name="AuthorizedUserIds">Identities the verifier may match against.</param>
public readonly record struct PolicyDecision(
    DecisionKind Kind,
    ApplicationPolicy? Policy,
    AppMatchKind MatchedBy,
    AssuranceLevel RequiredAssurance,
    IReadOnlyList<Guid> AuthorizedUserIds)
{
    /// <summary>Nothing to do.</summary>
    public static PolicyDecision NotProtected { get; } = new(
        DecisionKind.NotProtected,
        null,
        AppMatchKind.Unresolved,
        AssuranceLevel.Any,
        []);

    /// <summary>Whether this decision requires the broker to run a verification.</summary>
    public bool NeedsVerification => Kind == DecisionKind.VerificationRequired;
}
