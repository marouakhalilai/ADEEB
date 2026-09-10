using SecureAgent.Core.Domain;
using SecureAgent.Core.Policy;
using SecureAgent.Tests.Fakes;
using Xunit;

namespace SecureAgent.Tests.Policy;

/// <summary>
/// The policy engine is the component the product's correctness rests on, so its decision
/// surface is covered exhaustively rather than by sampling.
/// </summary>
[Trait("Category", "Portable")]
public sealed class PolicyEngineTests
{
    private static readonly Guid Adeeb = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid Someone = Guid.Parse("22222222-2222-2222-2222-222222222222");

    private readonly PolicyEngine _engine = new();
    private readonly TestClock _clock = new();
    private readonly InMemoryAuthSessionStore _sessions;

    public PolicyEngineTests() => _sessions = new InMemoryAuthSessionStore(_clock);

    private static ApplicationPolicy Policy(
        AppMatchKind kind = AppMatchKind.FileName,
        string value = "notepad.exe",
        AssuranceLevel assurance = AssuranceLevel.Biometric,
        ContinuousMode continuous = ContinuousMode.Off,
        bool enabled = true,
        Schedule? hours = null,
        params Guid[] users) => new()
        {
            Id = Guid.Parse("aaaaaaaa-0000-0000-0000-000000000001"),
            DisplayName = "Notepad",
            Match = new AppMatcher(kind, value),
            AuthorizedUserIds = users.Length == 0 ? [Adeeb] : users,
            MinimumAssurance = assurance,
            SessionTtl = TimeSpan.FromMinutes(5),
            AbsenceGrace = TimeSpan.FromSeconds(60),
            Continuous = continuous,
            Enabled = enabled,
            ActiveHours = hours,
        };

    private ActivationContext Activation(
        string fileName = "notepad.exe",
        string? path = @"C:\Windows\System32\notepad.exe",
        string? publisher = null,
        int windowsSession = 1) => new()
        {
            FileName = fileName,
            ExecutablePath = path,
            PublisherCn = publisher,
            WindowsSessionId = windowsSession,
            ProcessId = 4242,
            LocalTime = _clock.UtcNow,
            MonotonicTicks = _clock.Ticks,
        };

    private void OpenSession(
        ApplicationPolicy policy,
        Guid user,
        AssuranceLevel assurance = AssuranceLevel.Biometric,
        int windowsSession = 1) => _sessions.Open(new AuthSession
        {
            PolicyId = policy.Id,
            UserId = user,
            WindowsSessionId = windowsSession,
            Verifier = VerifierKind.WindowsHello,
            Assurance = assurance,
            OpenedAtTicks = _clock.Ticks,
            ExpiresAtTicks = _clock.Ticks + (long)policy.SessionTtl.TotalMilliseconds,
            LastPresenceTicks = _clock.Ticks,
        });

    // ---------------------------------------------------------------- matching

    [Fact]
    public void Unprotected_application_is_ignored_entirely()
    {
        var d = _engine.Evaluate(Activation("chrome.exe"), [Policy()], _sessions);

        Assert.Equal(DecisionKind.NotProtected, d.Kind);
        Assert.Null(d.Policy);
    }

    [Fact]
    public void Empty_policy_set_protects_nothing()
    {
        var d = _engine.Evaluate(Activation(), [], _sessions);

        Assert.Equal(DecisionKind.NotProtected, d.Kind);
    }

    [Fact]
    public void Disabled_policy_does_not_apply()
    {
        var d = _engine.Evaluate(Activation(), [Policy(enabled: false)], _sessions);

        Assert.Equal(DecisionKind.NotProtected, d.Kind);
    }

    [Fact]
    public void File_name_match_is_case_insensitive()
    {
        var d = _engine.Evaluate(Activation("NOTEPAD.EXE"), [Policy()], _sessions);

        Assert.Equal(DecisionKind.VerificationRequired, d.Kind);
    }

    [Fact]
    public void Publisher_match_wins_over_a_weaker_file_name_policy()
    {
        // A signed application must be recognised by publisher even when a file-name policy
        // also matches, so that telemetry reports the strong rule and the stronger policy's
        // settings apply.
        var byName = Policy(AppMatchKind.FileName, "notepad.exe") with
        {
            Id = Guid.Parse("aaaaaaaa-0000-0000-0000-00000000000a"),
        };
        var byPublisher = Policy(AppMatchKind.PublisherSignature, "Microsoft Windows") with
        {
            Id = Guid.Parse("aaaaaaaa-0000-0000-0000-00000000000b"),
        };

        var d = _engine.Evaluate(
            Activation(publisher: "Microsoft Windows"),
            [byName, byPublisher],
            _sessions);

        Assert.Equal(AppMatchKind.PublisherSignature, d.MatchedBy);
        Assert.Equal(byPublisher.Id, d.Policy!.Id);
    }

    [Fact]
    public void Full_path_match_wins_over_file_name()
    {
        var byName = Policy(AppMatchKind.FileName, "notepad.exe") with
        {
            Id = Guid.Parse("aaaaaaaa-0000-0000-0000-00000000000a"),
        };
        var byPath = Policy(AppMatchKind.FullPath, @"C:\Windows\System32\notepad.exe") with
        {
            Id = Guid.Parse("aaaaaaaa-0000-0000-0000-00000000000c"),
        };

        var d = _engine.Evaluate(Activation(), [byName, byPath], _sessions);

        Assert.Equal(AppMatchKind.FullPath, d.MatchedBy);
    }

    [Fact]
    public void Renamed_copy_does_not_match_a_full_path_policy()
    {
        // The attack a path policy is meant to resist: same file name, different location.
        var d = _engine.Evaluate(
            Activation(path: @"C:\Users\intruder\Downloads\notepad.exe"),
            [Policy(AppMatchKind.FullPath, @"C:\Windows\System32\notepad.exe")],
            _sessions);

        Assert.Equal(DecisionKind.NotProtected, d.Kind);
    }

    [Fact]
    public void Unsigned_binary_never_matches_a_publisher_policy()
    {
        var d = _engine.Evaluate(
            Activation(publisher: null),
            [Policy(AppMatchKind.PublisherSignature, "Microsoft Windows")],
            _sessions);

        Assert.Equal(DecisionKind.NotProtected, d.Kind);
    }

    // ---------------------------------------------------------------- schedule

    [Fact]
    public void Policy_outside_its_active_hours_does_not_apply()
    {
        _clock.SetWallClock(new DateTimeOffset(2026, 9, 10, 12, 0, 0, TimeSpan.Zero));

        // Active 22:00-06:00; noon is outside.
        var d = _engine.Evaluate(
            Activation(),
            [Policy(hours: new Schedule(22 * 60, 6 * 60))],
            _sessions);

        Assert.Equal(DecisionKind.NotProtected, d.Kind);
    }

    [Fact]
    public void Overnight_schedule_wraps_past_midnight()
    {
        _clock.SetWallClock(new DateTimeOffset(2026, 9, 10, 2, 30, 0, TimeSpan.Zero));

        var d = _engine.Evaluate(
            Activation(),
            [Policy(hours: new Schedule(22 * 60, 6 * 60))],
            _sessions);

        Assert.Equal(DecisionKind.VerificationRequired, d.Kind);
    }

    // ---------------------------------------------------------------- authorisation

    [Fact]
    public void Policy_with_no_authorized_users_denies_without_prompting()
    {
        var d = _engine.Evaluate(
            Activation(),
            [Policy(users: []) with { AuthorizedUserIds = [] }],
            _sessions);

        Assert.Equal(DecisionKind.DenyNoAuthorizedUsers, d.Kind);
        Assert.Empty(d.AuthorizedUserIds);
    }

    // ---------------------------------------------------------------- sessions

    [Fact]
    public void Valid_session_allows_without_reverification()
    {
        var p = Policy();
        OpenSession(p, Adeeb);

        var d = _engine.Evaluate(Activation(), [p], _sessions);

        Assert.Equal(DecisionKind.AllowFromSession, d.Kind);
    }

    [Fact]
    public void Expired_session_requires_reverification()
    {
        var p = Policy();
        OpenSession(p, Adeeb);
        _clock.Advance(TimeSpan.FromMinutes(6));

        var d = _engine.Evaluate(Activation(), [p], _sessions);

        Assert.Equal(DecisionKind.VerificationRequired, d.Kind);
    }

    [Fact]
    public void Winding_the_wall_clock_back_does_not_extend_a_session()
    {
        // The attack: a local user sets the system clock backwards hoping to keep an open
        // session alive. TTLs are monotonic, so only real elapsed time counts.
        var p = Policy();
        OpenSession(p, Adeeb);

        _clock.AdvanceTicksOnly(TimeSpan.FromMinutes(6));
        _clock.SetWallClock(_clock.UtcNow.AddHours(-3));

        var d = _engine.Evaluate(Activation(), [p], _sessions);

        Assert.Equal(DecisionKind.VerificationRequired, d.Kind);
    }

    [Fact]
    public void Session_does_not_carry_across_a_windows_session_switch()
    {
        var p = Policy();
        OpenSession(p, Adeeb, windowsSession: 1);

        var d = _engine.Evaluate(Activation(windowsSession: 2), [p], _sessions);

        Assert.Equal(DecisionKind.VerificationRequired, d.Kind);
    }

    [Fact]
    public void Revoking_a_user_invalidates_their_open_session_immediately()
    {
        var p = Policy();
        OpenSession(p, Adeeb);

        // Adeeb removed from the policy while their session is still within its TTL.
        var tightened = p with { AuthorizedUserIds = new[] { Someone } };

        var d = _engine.Evaluate(Activation(), [tightened], _sessions);

        Assert.Equal(DecisionKind.VerificationRequired, d.Kind);
    }

    [Fact]
    public void Session_opened_at_lower_assurance_cannot_satisfy_a_tightened_policy()
    {
        var p = Policy(assurance: AssuranceLevel.Any);
        OpenSession(p, Adeeb, assurance: AssuranceLevel.Any);

        var tightened = p with { MinimumAssurance = AssuranceLevel.HelloOrIr };

        var d = _engine.Evaluate(Activation(), [tightened], _sessions);

        Assert.Equal(DecisionKind.VerificationRequired, d.Kind);
    }

    [Fact]
    public void Higher_assurance_session_satisfies_a_lower_requirement()
    {
        var p = Policy(assurance: AssuranceLevel.Biometric);
        OpenSession(p, Adeeb, assurance: AssuranceLevel.HelloOrIr);

        var d = _engine.Evaluate(Activation(), [p], _sessions);

        Assert.Equal(DecisionKind.AllowFromSession, d.Kind);
    }

    // ---------------------------------------------------------------- continuous mode

    [Fact]
    public void Absence_beyond_grace_drops_a_continuous_session()
    {
        // The walk-away case: TTL has time left, but presence lapsed.
        var p = Policy(continuous: ContinuousMode.OnForeground);
        OpenSession(p, Adeeb);

        _clock.Advance(TimeSpan.FromSeconds(90));   // grace is 60s, TTL is 5 min

        var d = _engine.Evaluate(Activation(), [p], _sessions);

        Assert.Equal(DecisionKind.VerificationRequired, d.Kind);
    }

    [Fact]
    public void Absence_is_ignored_when_continuous_mode_is_off()
    {
        var p = Policy(continuous: ContinuousMode.Off);
        OpenSession(p, Adeeb);

        _clock.Advance(TimeSpan.FromSeconds(90));

        var d = _engine.Evaluate(Activation(), [p], _sessions);

        Assert.Equal(DecisionKind.AllowFromSession, d.Kind);
    }

    [Fact]
    public void Refreshed_presence_keeps_a_continuous_session_alive()
    {
        var p = Policy(continuous: ContinuousMode.OnForeground);
        OpenSession(p, Adeeb);

        _clock.Advance(TimeSpan.FromSeconds(45));
        _sessions.RefreshPresence(p.Id, 1, _clock.Ticks);
        _clock.Advance(TimeSpan.FromSeconds(45));

        var d = _engine.Evaluate(Activation(), [p], _sessions);

        Assert.Equal(DecisionKind.AllowFromSession, d.Kind);
    }

    // ---------------------------------------------------------------- session store

    [Fact]
    public void Closing_a_windows_session_drops_only_its_own_sessions()
    {
        var p = Policy();
        OpenSession(p, Adeeb, windowsSession: 1);
        OpenSession(p, Adeeb, windowsSession: 2);

        var dropped = _sessions.CloseAllForWindowsSession(1);

        Assert.Equal(1, dropped);
        Assert.Null(_sessions.Find(p.Id, 1));
        Assert.NotNull(_sessions.Find(p.Id, 2));
    }

    // ---------------------------------------------------------------- validation

    [Fact]
    public void High_assurance_policy_cannot_rest_on_a_file_name_match()
    {
        // Otherwise the assurance level is a lie: renaming any binary defeats it.
        var problems = Policy(AppMatchKind.FileName, assurance: AssuranceLevel.HelloOrIr).Validate();

        Assert.Contains(problems, p => p.Contains("FileName match", StringComparison.Ordinal));
    }

    [Fact]
    public void Sound_policy_validates_clean()
    {
        Assert.Empty(Policy().Validate());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Non_positive_session_ttl_is_rejected(int minutes)
    {
        var problems = (Policy() with { SessionTtl = TimeSpan.FromMinutes(minutes) }).Validate();

        Assert.Contains(problems, p => p.Contains("SessionTtl", StringComparison.Ordinal));
    }

    [Fact]
    public void Enabled_policy_with_no_users_is_flagged()
    {
        var problems = (Policy() with { AuthorizedUserIds = [] }).Validate();

        Assert.Contains(problems, p => p.Contains("No authorized users", StringComparison.Ordinal));
    }
}
