using SecureAgent.Core.Domain;
using SecureAgent.Core.Policy;
using Xunit;

namespace SecureAgent.Tests.Policy;

/// <summary>
/// Covers the duplicate-prompt suppression and, more importantly, the expiry that keeps it
/// from turning into a permanent block.
/// </summary>
[Trait("Category", "Portable")]
public sealed class VerificationTrackerTests
{
    private static readonly Guid PolicyA = Guid.Parse("aaaaaaaa-0000-0000-0000-000000000001");
    private static readonly Guid PolicyB = Guid.Parse("bbbbbbbb-0000-0000-0000-000000000002");

    private static readonly AppRef App =
        AppRef.FromUntrusted(AppMatchKind.FileName, "notepad.exe");

    private static PendingVerification Pending(
        string correlationId,
        Guid policyId,
        int session = 1,
        long startedAt = 1000) =>
        new(correlationId, policyId, session, App, startedAt);

    [Fact]
    public void First_verification_is_admitted()
    {
        var tracker = new VerificationTracker();

        Assert.True(tracker.TryBegin(Pending("c1", PolicyA), nowTicks: 1000));
        Assert.Equal(1, tracker.OutstandingCount);
    }

    [Fact]
    public void Second_verification_for_the_same_app_is_suppressed()
    {
        // The actual bug: dismissing the Hello prompt returns focus to the protected app,
        // raising another foreground event while the first verification is still in flight.
        var tracker = new VerificationTracker();
        tracker.TryBegin(Pending("c1", PolicyA), nowTicks: 1000);

        Assert.False(tracker.TryBegin(Pending("c2", PolicyA), nowTicks: 1200));
        Assert.Equal(1, tracker.OutstandingCount);
    }

    [Fact]
    public void Different_applications_do_not_suppress_each_other()
    {
        var tracker = new VerificationTracker();
        tracker.TryBegin(Pending("c1", PolicyA), nowTicks: 1000);

        Assert.True(tracker.TryBegin(Pending("c2", PolicyB), nowTicks: 1000));
        Assert.Equal(2, tracker.OutstandingCount);
    }

    [Fact]
    public void Same_policy_in_a_different_windows_session_is_not_suppressed()
    {
        // Two users switched between sessions are two people, each owed their own prompt.
        var tracker = new VerificationTracker();
        tracker.TryBegin(Pending("c1", PolicyA, session: 1), nowTicks: 1000);

        Assert.True(tracker.TryBegin(Pending("c2", PolicyA, session: 2), nowTicks: 1000));
    }

    [Fact]
    public void Completing_releases_the_suppression()
    {
        var tracker = new VerificationTracker();
        tracker.TryBegin(Pending("c1", PolicyA), nowTicks: 1000);

        var completed = tracker.Complete("c1");

        Assert.NotNull(completed);
        Assert.Equal(PolicyA, completed!.PolicyId);
        Assert.Equal(0, tracker.OutstandingCount);
        Assert.True(tracker.TryBegin(Pending("c2", PolicyA), nowTicks: 1500));
    }

    [Fact]
    public void Completing_an_unknown_correlation_id_returns_null()
    {
        // A stale reply after a restart, or a broker inventing traffic. Acting on it would
        // mean opening a session on an unsolicited claim.
        var tracker = new VerificationTracker();

        Assert.Null(tracker.Complete("never-issued"));
    }

    [Fact]
    public void Abandoned_verification_expires_rather_than_blocking_forever()
    {
        // The failure mode that makes suppression dangerous: if the broker is killed while a
        // prompt is open, nothing ever completes the entry. Without expiry the application
        // becomes permanently unverifiable — silently allowed forever under a fail-open
        // policy, or permanently blocked under a fail-closed one.
        var tracker = new VerificationTracker(lifetime: TimeSpan.FromSeconds(45));
        tracker.TryBegin(Pending("c1", PolicyA, startedAt: 1000), nowTicks: 1000);

        // Still inside the lifetime: suppressed.
        Assert.False(tracker.TryBegin(Pending("c2", PolicyA), nowTicks: 1000 + 44_000));

        // Past it: admitted again.
        Assert.True(tracker.TryBegin(Pending("c3", PolicyA), nowTicks: 1000 + 46_000));
    }

    [Fact]
    public void Expiry_replaces_the_stale_entry_rather_than_accumulating()
    {
        var tracker = new VerificationTracker(lifetime: TimeSpan.FromSeconds(45));
        tracker.TryBegin(Pending("c1", PolicyA, startedAt: 1000), nowTicks: 1000);
        tracker.TryBegin(Pending("c2", PolicyA, startedAt: 100_000), nowTicks: 100_000);

        Assert.Equal(1, tracker.OutstandingCount);

        // The superseded entry is gone, so a late answer to it is correctly unrecognised.
        Assert.Null(tracker.Complete("c1"));
        Assert.NotNull(tracker.Complete("c2"));
    }

    [Fact]
    public void Expiry_is_longer_than_the_verifier_timeout()
    {
        // Expiring before the verifier gives up would reintroduce the duplicate prompt on
        // every slow-but-legitimate authentication.
        Assert.True(VerificationTracker.DefaultLifetime > TimeSpan.FromSeconds(30));
    }

    [Fact]
    public void Session_change_abandons_that_sessions_verifications_only()
    {
        // A prompt in flight when the desktop locks is asking about someone who may no
        // longer be there; a late answer must not open a session.
        var tracker = new VerificationTracker();
        tracker.TryBegin(Pending("c1", PolicyA, session: 1), nowTicks: 1000);
        tracker.TryBegin(Pending("c2", PolicyB, session: 1), nowTicks: 1000);
        tracker.TryBegin(Pending("c3", PolicyA, session: 2), nowTicks: 1000);

        var abandoned = tracker.AbandonSession(1);

        Assert.Equal(2, abandoned);
        Assert.Equal(1, tracker.OutstandingCount);
        Assert.Null(tracker.Complete("c1"));
        Assert.NotNull(tracker.Complete("c3"));
    }

    [Fact]
    public void Abandoning_frees_the_slot_for_a_new_verification()
    {
        var tracker = new VerificationTracker();
        tracker.TryBegin(Pending("c1", PolicyA, session: 1), nowTicks: 1000);
        tracker.AbandonSession(1);

        Assert.True(tracker.TryBegin(Pending("c2", PolicyA, session: 1), nowTicks: 1100));
    }

    [Fact]
    public void Concurrent_begins_admit_exactly_one()
    {
        // Foreground events arrive on the hook thread while results arrive on IPC threads,
        // so the check and the insert have to be atomic together.
        var tracker = new VerificationTracker();
        var admitted = 0;

        Parallel.For(0, 200, i =>
        {
            if (tracker.TryBegin(Pending($"c{i}", PolicyA), nowTicks: 1000))
            {
                Interlocked.Increment(ref admitted);
            }
        });

        Assert.Equal(1, admitted);
        Assert.Equal(1, tracker.OutstandingCount);
    }
}
