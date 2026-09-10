namespace SecureAgent.Core.Domain;

/// <summary>
/// How an executable is matched to a policy.
/// </summary>
/// <remarks>
/// Resolution runs strongest-first: publisher signature, then full path, then file name.
/// Matching on file name alone is trivially defeated by copying and renaming a binary, so
/// it is allowed as a convenience for unsigned applications but rejected for
/// <see cref="AssuranceLevel.HelloOrIr"/> policies (see <see cref="ApplicationPolicy.Validate"/>).
/// </remarks>
/// <param name="Kind">Which attribute is being matched.</param>
/// <param name="Value">
/// The expected value: publisher CN, full path, or file name. Compared case-insensitively.
/// </param>
public sealed record AppMatcher(AppMatchKind Kind, string Value)
{
    /// <summary>Whether this matcher accepts the given activation.</summary>
    public bool Matches(ActivationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return Kind switch
        {
            AppMatchKind.PublisherSignature =>
                context.PublisherCn is { } cn && cn.Equals(Value, StringComparison.OrdinalIgnoreCase),
            AppMatchKind.FullPath =>
                context.ExecutablePath is { } p && p.Equals(Value, StringComparison.OrdinalIgnoreCase),
            AppMatchKind.FileName =>
                context.FileName.Equals(Value, StringComparison.OrdinalIgnoreCase),
            _ => false,
        };
    }
}

/// <summary>
/// Restricts a policy to certain hours of the day.
/// </summary>
/// <param name="StartMinuteUtcOffset">Minutes past local midnight when the window opens.</param>
/// <param name="EndMinuteUtcOffset">Minutes past local midnight when it closes.</param>
/// <remarks>
/// A window whose end is before its start wraps past midnight, which is the common case
/// for "protect this outside working hours".
/// </remarks>
public sealed record Schedule(int StartMinuteUtcOffset, int EndMinuteUtcOffset)
{
    /// <summary>Whether <paramref name="localTime"/> falls inside the window.</summary>
    public bool Contains(DateTimeOffset localTime)
    {
        var minute = (localTime.Hour * 60) + localTime.Minute;

        return StartMinuteUtcOffset <= EndMinuteUtcOffset
            ? minute >= StartMinuteUtcOffset && minute < EndMinuteUtcOffset
            : minute >= StartMinuteUtcOffset || minute < EndMinuteUtcOffset;
    }
}

/// <summary>
/// A rule binding an application to the identities allowed to use it and the conditions
/// under which access is granted.
/// </summary>
public sealed record ApplicationPolicy
{
    /// <summary>Stable identifier, referenced by audit records.</summary>
    public required Guid Id { get; init; }

    /// <summary>Human-readable name, shown in the dashboard.</summary>
    public required string DisplayName { get; init; }

    /// <summary>How the executable is recognised.</summary>
    public required AppMatcher Match { get; init; }

    /// <summary>
    /// Identities permitted to use this application. An empty list means nobody is
    /// authorised, which denies rather than allows — a policy with no authorised users is
    /// almost always a configuration mistake, and failing closed makes it visible.
    /// </summary>
    public IReadOnlyList<Guid> AuthorizedUserIds { get; init; } = [];

    /// <summary>The weakest verifier rung this policy accepts.</summary>
    public AssuranceLevel MinimumAssurance { get; init; } = AssuranceLevel.Biometric;

    /// <summary>How long a successful verification stays valid.</summary>
    public TimeSpan SessionTtl { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>How long the user may be absent before the session is dropped.</summary>
    public TimeSpan AbsenceGrace { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Whether and when presence is re-checked after the initial verification.</summary>
    public ContinuousMode Continuous { get; init; } = ContinuousMode.Off;

    /// <summary>What happens when verification fails.</summary>
    public FailureAction OnFailure { get; init; } = FailureAction.Overlay;

    /// <summary>What happens when no verifier of the required assurance is available.</summary>
    public UnavailableAction OnVerifierUnavailable { get; init; } = UnavailableAction.AllowAndWarn;

    /// <summary>Consecutive failures before the event is escalated in severity.</summary>
    public int MaxFailuresBeforeEscalation { get; init; } = 3;

    /// <summary>Optional hours during which the policy applies. Null means always.</summary>
    public Schedule? ActiveHours { get; init; }

    /// <summary>Whether the policy is in force. Disabled policies are ignored entirely.</summary>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// Checks the policy for configurations that are unsafe rather than merely unusual.
    /// </summary>
    /// <remarks>
    /// Called when a policy is created or updated, not on the evaluation hot path. The
    /// point is to reject a policy that would give a false sense of protection — the
    /// dangerous case is a high-assurance policy resting on a match rule that anyone can
    /// defeat by renaming a file.
    /// </remarks>
    /// <returns>An empty list when the policy is sound; otherwise the problems found.</returns>
    public IReadOnlyList<string> Validate()
    {
        var problems = new List<string>();

        if (string.IsNullOrWhiteSpace(Match.Value))
        {
            problems.Add("Match value is empty; the policy would never apply.");
        }

        if (MinimumAssurance == AssuranceLevel.HelloOrIr && Match.Kind == AppMatchKind.FileName)
        {
            problems.Add(
                "A HelloOrIr policy cannot rest on a FileName match: copying and renaming a " +
                "binary defeats it, so the assurance level would be misleading.");
        }

        if (SessionTtl <= TimeSpan.Zero)
        {
            problems.Add("SessionTtl must be positive; a non-positive TTL re-prompts continuously.");
        }

        if (SessionTtl > TimeSpan.FromHours(12))
        {
            problems.Add("SessionTtl over 12 hours effectively disables re-verification.");
        }

        if (AbsenceGrace < TimeSpan.Zero)
        {
            problems.Add("AbsenceGrace cannot be negative.");
        }

        if (MaxFailuresBeforeEscalation < 1)
        {
            problems.Add("MaxFailuresBeforeEscalation must be at least 1.");
        }

        if (AuthorizedUserIds.Count == 0 && Enabled)
        {
            problems.Add(
                "No authorized users: every access will be denied. Disable the policy instead " +
                "if that is the intent.");
        }

        return problems;
    }
}
