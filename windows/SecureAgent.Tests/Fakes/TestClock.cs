using SecureAgent.Core.Abstractions;

namespace SecureAgent.Tests.Fakes;

/// <summary>
/// A controllable clock for tests.
/// </summary>
/// <remarks>
/// Keeps the two clocks independently movable on purpose. The attack this models is a
/// local user winding the system clock backwards to extend an authentication session: in
/// that scenario <see cref="UtcNow"/> jumps around while <see cref="Ticks"/> keeps
/// advancing. Any policy test that only ever moves them together will pass while the
/// production code is wrong.
/// </remarks>
public sealed class TestClock : ISystemClock
{
    /// <summary>Creates a clock at a fixed, arbitrary starting point.</summary>
    public TestClock(DateTimeOffset? start = null, long startTicks = 1_000_000)
    {
        UtcNow = start ?? new DateTimeOffset(2026, 9, 9, 12, 0, 0, TimeSpan.Zero);
        Ticks = startTicks;
    }

    /// <inheritdoc />
    public DateTimeOffset UtcNow { get; private set; }

    /// <inheritdoc />
    public long Ticks { get; private set; }

    /// <summary>Advances both clocks, as normal time passing does.</summary>
    public void Advance(TimeSpan by)
    {
        UtcNow = UtcNow.Add(by);
        Ticks += (long)by.TotalMilliseconds;
    }

    /// <summary>
    /// Advances the monotonic clock only, leaving wall time untouched. Models an NTP
    /// correction that holds wall time still.
    /// </summary>
    public void AdvanceTicksOnly(TimeSpan by) => Ticks += (long)by.TotalMilliseconds;

    /// <summary>
    /// Moves wall-clock time without touching the monotonic clock. Models a user tampering
    /// with the system clock — the case that must not extend a session.
    /// </summary>
    public void SetWallClock(DateTimeOffset to) => UtcNow = to;
}
