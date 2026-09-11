using SecureAgent.Core.Domain;

namespace SecureAgent.Core.Policy;

/// <summary>A verification that has been requested and not yet answered.</summary>
/// <param name="CorrelationId">Ties the request, the result and the audit records together.</param>
/// <param name="PolicyId">The policy being satisfied.</param>
/// <param name="WindowsSessionId">The terminal session it belongs to.</param>
/// <param name="App">The application that triggered it.</param>
/// <param name="StartedAtTicks">Monotonic tick the request was issued.</param>
public sealed record PendingVerification(
    string CorrelationId,
    Guid PolicyId,
    int WindowsSessionId,
    AppRef App,
    long StartedAtTicks);

/// <summary>Tracks verifications that are in flight.</summary>
public interface IVerificationTracker
{
    /// <summary>
    /// Registers a new verification unless one is already outstanding for the same policy
    /// and terminal session.
    /// </summary>
    /// <returns>True when the caller should issue a verification request; false to suppress it.</returns>
    bool TryBegin(PendingVerification pending, long nowTicks);

    /// <summary>Completes a verification and returns what it was for, or null if unknown.</summary>
    PendingVerification? Complete(string correlationId);

    /// <summary>Drops everything outstanding for a terminal session, on lock or logoff.</summary>
    int AbandonSession(int windowsSessionId);

    /// <summary>Number of verifications currently outstanding.</summary>
    int OutstandingCount { get; }
}

/// <summary>
/// In-memory tracker that suppresses duplicate verification prompts.
/// </summary>
/// <remarks>
/// <para>
/// Exists because of a bug seen in a live run: opening one protected application produced
/// three <c>VerificationRequired</c> decisions in seven seconds. The Windows Hello prompt is
/// itself a window, so dismissing it hands focus back to the protected application, which
/// raises a fresh foreground event. No session exists yet — the first verification is still
/// in flight — so the policy engine quite correctly asks for verification again, and the
/// user is prompted on top of the prompt they are already answering.
/// </para>
/// <para>
/// This is not a hole. Every stacked prompt still has to pass, and the service validates each
/// claim independently. It is a usability defect, and on a security product usability defects
/// are how you end up uninstalled.
/// </para>
/// <para>
/// <b>The expiry is the part that matters.</b> Suppressing duplicates means a stuck entry
/// blocks all future verification for that policy. If the broker is killed while a prompt is
/// open, nothing would ever call <see cref="Complete"/>, and the application would be
/// permanently unverifiable — silently allowed forever under a fail-open policy, or
/// permanently blocked under a fail-closed one. Both are worse than the duplicate prompts
/// this fixes. So entries expire on the monotonic clock, and the expiry deliberately exceeds
/// the verifier's own timeout so a slow-but-alive verification is never cut off early.
/// </para>
/// </remarks>
public sealed class VerificationTracker : IVerificationTracker
{
    /// <summary>
    /// How long an outstanding verification is honoured before it is treated as abandoned.
    /// </summary>
    /// <remarks>
    /// Comfortably longer than the 30-second verifier timeout the service issues. The margin
    /// is one-sided on purpose: expiring too early reintroduces the duplicate prompt, while
    /// expiring a little late costs at most one extra prompt after a broker crash.
    /// </remarks>
    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromSeconds(45);

    private readonly Dictionary<string, PendingVerification> _byCorrelation = [];
    private readonly Dictionary<(Guid PolicyId, int WindowsSessionId), string> _byPolicy = [];
    private readonly TimeSpan _lifetime;
    private readonly Lock _gate = new();

    /// <summary>Creates the tracker.</summary>
    /// <param name="lifetime">Override the abandonment threshold; defaults to <see cref="DefaultLifetime"/>.</param>
    public VerificationTracker(TimeSpan? lifetime = null) =>
        _lifetime = lifetime ?? DefaultLifetime;

    /// <inheritdoc />
    public int OutstandingCount
    {
        get
        {
            lock (_gate)
            {
                return _byCorrelation.Count;
            }
        }
    }

    /// <inheritdoc />
    public bool TryBegin(PendingVerification pending, long nowTicks)
    {
        ArgumentNullException.ThrowIfNull(pending);

        lock (_gate)
        {
            var key = (pending.PolicyId, pending.WindowsSessionId);

            if (_byPolicy.TryGetValue(key, out var existingId)
                && _byCorrelation.TryGetValue(existingId, out var existing))
            {
                if (!IsExpired(existing, nowTicks))
                {
                    // A prompt is already on screen for this application. Suppress.
                    return false;
                }

                // The previous attempt was abandoned — most likely the broker died while a
                // prompt was open. Drop it and let this one through, rather than leaving the
                // application unverifiable forever.
                _byCorrelation.Remove(existingId);
                _byPolicy.Remove(key);
            }

            _byCorrelation[pending.CorrelationId] = pending;
            _byPolicy[key] = pending.CorrelationId;
            return true;
        }
    }

    /// <inheritdoc />
    public PendingVerification? Complete(string correlationId)
    {
        lock (_gate)
        {
            if (!_byCorrelation.Remove(correlationId, out var pending))
            {
                return null;
            }

            _byPolicy.Remove((pending.PolicyId, pending.WindowsSessionId));
            return pending;
        }
    }

    /// <inheritdoc />
    public int AbandonSession(int windowsSessionId)
    {
        lock (_gate)
        {
            var doomed = _byCorrelation
                .Where(kv => kv.Value.WindowsSessionId == windowsSessionId)
                .Select(kv => kv.Key)
                .ToList();

            foreach (var id in doomed)
            {
                if (_byCorrelation.Remove(id, out var pending))
                {
                    _byPolicy.Remove((pending.PolicyId, pending.WindowsSessionId));
                }
            }

            return doomed.Count;
        }
    }

    private bool IsExpired(PendingVerification pending, long nowTicks) =>
        nowTicks - pending.StartedAtTicks > (long)_lifetime.TotalMilliseconds;
}
