using SecureAgent.Core.Audit;
using SecureAgent.Core.Domain;
using Xunit;

namespace SecureAgent.Tests.Audit;

/// <summary>
/// Phase 1 exit criterion: a broken chain is detected by test (plan §13).
/// </summary>
[Trait("Category", "Portable")]
public sealed class AuditChainTests
{
    private static SecurityEvent Event(string id, EventKind kind = EventKind.AppActivated) => new()
    {
        Id = id,
        Timestamp = new DateTimeOffset(2026, 9, 9, 14, 30, 0, TimeSpan.Zero),
        WindowsSessionId = 1,
        Kind = kind,
        Severity = Severity.Info,
        Outcome = Outcome.NotApplicable,
        App = AppRef.FromUntrusted(AppMatchKind.FileName, "notepad.exe"),
    };

    private static List<SecurityEvent> Chain(params string[] ids)
    {
        var result = new List<SecurityEvent>(ids.Length);
        string? prev = null;
        foreach (var id in ids)
        {
            var sealedEvent = EventHasher.Seal(Event(id), prev);
            result.Add(sealedEvent);
            prev = sealedEvent.Hash;
        }

        return result;
    }

    [Fact]
    public void Sealed_record_is_self_consistent()
    {
        var e = EventHasher.Seal(Event("01J000000000000000000000A1"), null);

        Assert.True(EventHasher.IsSelfConsistent(e));
        Assert.Equal(EventHasher.GenesisPrevHash, e.PrevHash);
        Assert.Equal(64, e.Hash.Length);
    }

    [Fact]
    public void Intact_chain_verifies_and_returns_head()
    {
        var chain = Chain("01J000000000000000000000A1", "01J000000000000000000000A2", "01J000000000000000000000A3");

        var result = AuditChain.Verify(chain);

        Assert.True(result.IsIntact);
        Assert.Equal(chain[^1].Hash, result.Head);
    }

    [Fact]
    public void Deleting_a_record_breaks_the_link()
    {
        var chain = Chain("01J000000000000000000000A1", "01J000000000000000000000A2", "01J000000000000000000000A3");

        // The classic attack: quietly remove the record of your own failed verification.
        chain.RemoveAt(1);

        var result = AuditChain.Verify(chain);

        Assert.Equal(ChainFault.BrokenLink, result.Fault);
        Assert.Equal(1, result.FailedAtIndex);
        Assert.Equal("01J000000000000000000000A3", result.FailedAtId);
    }

    [Fact]
    public void Editing_a_record_is_detected()
    {
        var chain = Chain("01J000000000000000000000A1", "01J000000000000000000000A2");

        // Rewrite a denial as an allow, keeping the stored hash.
        chain[1] = chain[1] with { Outcome = Outcome.Allowed };

        var result = AuditChain.Verify(chain);

        Assert.Equal(ChainFault.RecordAltered, result.Fault);
        Assert.Equal(1, result.FailedAtIndex);
    }

    [Fact]
    public void Reordering_records_is_detected()
    {
        var chain = Chain("01J000000000000000000000A1", "01J000000000000000000000A2", "01J000000000000000000000A3");
        (chain[1], chain[2]) = (chain[2], chain[1]);

        var result = AuditChain.Verify(chain);

        Assert.Equal(ChainFault.BrokenLink, result.Fault);
    }

    [Fact]
    public void Chain_that_does_not_continue_from_the_known_head_is_rejected()
    {
        var chain = Chain("01J000000000000000000000A1", "01J000000000000000000000A2");

        // Startup reconciliation: the control plane's last-known-good head disagrees, which
        // means records were dropped while the service was not running (plan §06).
        var result = AuditChain.Verify(chain, expectedPrevHash: new string('b', 64));

        Assert.Equal(ChainFault.UnexpectedOrigin, result.Fault);
        Assert.Equal(0, result.FailedAtIndex);
    }

    [Fact]
    public void Continuation_from_a_known_head_verifies()
    {
        var first = Chain("01J000000000000000000000A1", "01J000000000000000000000A2");

        var continuation = new List<SecurityEvent>();
        var prev = first[^1].Hash;
        foreach (var id in new[] { "01J000000000000000000000B1", "01J000000000000000000000B2" })
        {
            var e = EventHasher.Seal(Event(id), prev);
            continuation.Add(e);
            prev = e.Hash;
        }

        var result = AuditChain.Verify(continuation, expectedPrevHash: first[^1].Hash);

        Assert.True(result.IsIntact);
    }

    [Fact]
    public void Empty_batch_is_intact_and_preserves_the_head()
    {
        var result = AuditChain.Verify([], expectedPrevHash: new string('c', 64));

        Assert.True(result.IsIntact);
        Assert.Equal(new string('c', 64), result.Head);
    }

    [Fact]
    public void Unsealed_record_is_not_self_consistent()
    {
        Assert.False(EventHasher.IsSelfConsistent(Event("01J000000000000000000000A1")));
    }
}
