using SecureAgent.Core.Abstractions;
using SecureAgent.Core.Domain;

namespace SecureAgent.Core.Policy;

/// <summary>
/// A successful verification, valid for a bounded time.
/// </summary>
/// <remarks>
/// Expiry is expressed in monotonic ticks, never wall-clock time. A local user who can
/// change the system clock must not be able to extend an open session by winding it
/// backwards (CLAUDE.md rule 22).
/// </remarks>
public sealed record AuthSession
{
    /// <summary>The policy this session satisfies.</summary>
    public required Guid PolicyId { get; init; }

    /// <summary>The identity that was verified.</summary>
    public required Guid UserId { get; init; }

    /// <summary>
    /// The Windows terminal session it was established in. Sessions never carry across a
    /// fast-user-switch or an RDP reconnect: a different Windows session is a different
    /// person until proven otherwise.
    /// </summary>
    public required int WindowsSessionId { get; init; }

    /// <summary>Which rung of the ladder established it.</summary>
    public required VerifierKind Verifier { get; init; }

    /// <summary>The assurance actually achieved, which may exceed what the policy required.</summary>
    public required AssuranceLevel Assurance { get; init; }

    /// <summary>Monotonic tick when the session was opened.</summary>
    public required long OpenedAtTicks { get; init; }

    /// <summary>Monotonic tick after which the session is no longer valid.</summary>
    public required long ExpiresAtTicks { get; init; }

    /// <summary>
    /// Monotonic tick of the last confirmed presence. Distinct from
    /// <see cref="OpenedAtTicks"/> so a continuous-mode policy can drop a session on
    /// absence well before its TTL runs out.
    /// </summary>
    public required long LastPresenceTicks { get; init; }

    /// <summary>Whether the session is still within its TTL at the given tick.</summary>
    public bool IsValidAt(long nowTicks) => nowTicks < ExpiresAtTicks;

    /// <summary>Whether presence has lapsed beyond the policy's grace period.</summary>
    public bool IsAbsentAt(long nowTicks, TimeSpan grace) =>
        nowTicks - LastPresenceTicks > (long)grace.TotalMilliseconds;
}

/// <summary>Holds the open authentication sessions for this machine.</summary>
public interface IAuthSessionStore
{
    /// <summary>Returns the session covering this policy and Windows session, if any.</summary>
    AuthSession? Find(Guid policyId, int windowsSessionId);

    /// <summary>Records a new session, replacing any existing one for the same key.</summary>
    void Open(AuthSession session);

    /// <summary>Extends the presence timestamp after a successful continuous check.</summary>
    void RefreshPresence(Guid policyId, int windowsSessionId, long nowTicks);

    /// <summary>Drops one session, for example on a failed presence check.</summary>
    void Close(Guid policyId, int windowsSessionId);

    /// <summary>
    /// Drops every session belonging to a Windows terminal session. Called on lock,
    /// logoff, disconnect and fast user switch.
    /// </summary>
    int CloseAllForWindowsSession(int windowsSessionId);

    /// <summary>Drops every session on the machine, for example after a clock anomaly.</summary>
    int CloseAll();
}

/// <summary>
/// In-memory session store.
/// </summary>
/// <remarks>
/// Deliberately not persisted. A session surviving a service restart would mean a crash —
/// or a deliberate kill — silently extends access, which is the opposite of what a restart
/// should mean for a security agent. Losing sessions on restart costs one extra prompt.
/// </remarks>
public sealed class InMemoryAuthSessionStore : IAuthSessionStore
{
    private readonly Dictionary<(Guid PolicyId, int WindowsSessionId), AuthSession> _sessions = [];
    private readonly Lock _gate = new();
    private readonly ISystemClock _clock;
    private long _lastObservedTicks;

    /// <summary>Creates the store.</summary>
    public InMemoryAuthSessionStore(ISystemClock clock)
    {
        _clock = clock;
        _lastObservedTicks = clock.Ticks;
    }

    /// <inheritdoc />
    public AuthSession? Find(Guid policyId, int windowsSessionId)
    {
        lock (_gate)
        {
            DetectMonotonicRegression();
            return _sessions.GetValueOrDefault((policyId, windowsSessionId));
        }
    }

    /// <inheritdoc />
    public void Open(AuthSession session)
    {
        ArgumentNullException.ThrowIfNull(session);
        lock (_gate)
        {
            _sessions[(session.PolicyId, session.WindowsSessionId)] = session;
        }
    }

    /// <inheritdoc />
    public void RefreshPresence(Guid policyId, int windowsSessionId, long nowTicks)
    {
        lock (_gate)
        {
            if (_sessions.TryGetValue((policyId, windowsSessionId), out var existing))
            {
                _sessions[(policyId, windowsSessionId)] =
                    existing with { LastPresenceTicks = nowTicks };
            }
        }
    }

    /// <inheritdoc />
    public void Close(Guid policyId, int windowsSessionId)
    {
        lock (_gate)
        {
            _sessions.Remove((policyId, windowsSessionId));
        }
    }

    /// <inheritdoc />
    public int CloseAllForWindowsSession(int windowsSessionId)
    {
        lock (_gate)
        {
            var doomed = _sessions.Keys.Where(k => k.WindowsSessionId == windowsSessionId).ToList();
            foreach (var key in doomed)
            {
                _sessions.Remove(key);
            }

            return doomed.Count;
        }
    }

    /// <inheritdoc />
    public int CloseAll()
    {
        lock (_gate)
        {
            var count = _sessions.Count;
            _sessions.Clear();
            return count;
        }
    }

    /// <summary>
    /// Drops all sessions if the monotonic clock ever appears to move backwards.
    /// </summary>
    /// <remarks>
    /// <see cref="Environment.TickCount64"/> should never regress. If it does, the
    /// assumption underpinning every TTL comparison has failed, and the safe response is
    /// to invalidate everything and re-verify rather than to reason about how far off it
    /// might be.
    /// </remarks>
    private void DetectMonotonicRegression()
    {
        var now = _clock.Ticks;
        if (now < _lastObservedTicks)
        {
            _sessions.Clear();
        }

        _lastObservedTicks = now;
    }
}
