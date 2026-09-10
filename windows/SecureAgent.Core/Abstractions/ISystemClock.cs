namespace SecureAgent.Core.Abstractions;

/// <summary>
/// The only source of time in the security path.
/// </summary>
/// <remarks>
/// <para>
/// Two clocks, deliberately separated (CLAUDE.md rule 22):
/// </para>
/// <para>
/// <see cref="UtcNow"/> is wall-clock time. It is for display, correlation and audit
/// records. It can move backwards — NTP correction, a user changing the system clock,
/// a VM resuming from a snapshot — and an attacker with local access can move it
/// deliberately.
/// </para>
/// <para>
/// <see cref="Ticks"/> is a monotonic counter that only ever increases while the machine
/// is running. <em>All</em> authentication-session lifetime arithmetic uses this. Using
/// wall-clock time for a TTL means winding the clock back extends every open session,
/// which turns a five-minute grace window into an indefinite one.
/// </para>
/// </remarks>
public interface ISystemClock
{
    /// <summary>Wall-clock time in UTC. For audit records and display only.</summary>
    DateTimeOffset UtcNow { get; }

    /// <summary>
    /// Milliseconds since an arbitrary fixed origin, monotonically non-decreasing for the
    /// lifetime of the process host. Use for every duration and expiry comparison.
    /// </summary>
    long Ticks { get; }
}

/// <summary>Production clock. <see cref="Environment.TickCount64"/> is monotonic and cheap.</summary>
public sealed class SystemClock : ISystemClock
{
    /// <inheritdoc />
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;

    /// <inheritdoc />
    public long Ticks => Environment.TickCount64;
}
