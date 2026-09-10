using SecureAgent.Core.Audit;
using SecureAgent.Core.Domain;
using Xunit;

namespace SecureAgent.Tests.Audit;

/// <summary>
/// The canonical form is an on-disk format. These tests pin the properties that a future
/// refactor could silently break, invalidating every chain already in the field.
/// </summary>
[Trait("Category", "Portable")]
public sealed class EventHasherTests
{
    private static SecurityEvent Base() => new()
    {
        Id = "01J000000000000000000000A1",
        Timestamp = new DateTimeOffset(2026, 9, 9, 14, 30, 0, TimeSpan.Zero),
        WindowsSessionId = 1,
        Kind = EventKind.VerificationFailed,
        Severity = Severity.High,
        Outcome = Outcome.Denied,
        App = AppRef.FromUntrusted(AppMatchKind.FileName, "chrome.exe"),
        Verifier = VerifierKind.LocalFace,
        Confidence = ConfidenceBucket.Low,
    };

    [Fact]
    public void Hash_is_stable_across_calls()
    {
        var e = EventHasher.Seal(Base(), null);

        Assert.Equal(e.Hash, EventHasher.ComputeHash(e));
    }

    [Theory]
    [InlineData("outcome")]
    [InlineData("severity")]
    [InlineData("verifier")]
    [InlineData("confidence")]
    [InlineData("timestamp")]
    [InlineData("session")]
    [InlineData("app")]
    public void Every_security_relevant_field_changes_the_hash(string field)
    {
        var original = EventHasher.Seal(Base(), null);

        SecurityEvent mutated = field switch
        {
            "outcome" => original with { Outcome = Outcome.Allowed },
            "severity" => original with { Severity = Severity.Info },
            "verifier" => original with { Verifier = VerifierKind.RecoveryCode },
            "confidence" => original with { Confidence = ConfidenceBucket.High },
            "timestamp" => original with { Timestamp = original.Timestamp.AddSeconds(1) },
            "session" => original with { WindowsSessionId = 2 },
            "app" => original with { App = AppRef.FromUntrusted(AppMatchKind.FileName, "notepad.exe") },
            _ => throw new ArgumentOutOfRangeException(nameof(field)),
        };

        Assert.NotEqual(original.Hash, EventHasher.ComputeHash(mutated));
    }

    [Fact]
    public void Timestamp_offset_does_not_change_the_hash()
    {
        // The same instant expressed in two zones must hash identically, or a device that
        // changes time zone appears to have a corrupt chain.
        var utc = Base();
        var shifted = utc with { Timestamp = utc.Timestamp.ToOffset(TimeSpan.FromHours(5)) };

        Assert.Equal(EventHasher.ComputeHash(utc), EventHasher.ComputeHash(shifted));
    }

    [Fact]
    public void Null_and_empty_fields_do_not_collide()
    {
        // Without a distinct null marker, an attacker could clear a field — say, blank a
        // publisher name — without disturbing the hash.
        var withNull = Base() with { App = new AppRef(AppMatchKind.FullPath, "chrome.exe", PublisherCn: null) };
        var withEmpty = Base() with { App = new AppRef(AppMatchKind.FullPath, "chrome.exe", PublisherCn: string.Empty) };

        Assert.NotEqual(EventHasher.ComputeHash(withNull), EventHasher.ComputeHash(withEmpty));
    }

    [Fact]
    public void Field_boundaries_cannot_be_shifted()
    {
        // Moving content across a field boundary must not produce the same canonical
        // string, or two different events would share a hash.
        var a = Base() with { App = AppRef.FromUntrusted(AppMatchKind.FullPath, "ab", publisherCn: "c") };
        var b = Base() with { App = AppRef.FromUntrusted(AppMatchKind.FullPath, "a", publisherCn: "bc") };

        Assert.NotEqual(EventHasher.ComputeHash(a), EventHasher.ComputeHash(b));
    }

    [Fact]
    public void Separator_inside_an_attacker_controlled_field_cannot_shift_boundaries()
    {
        // A window title is whatever a process chose to name its window — including a
        // literal copy of the canonical form's own field separator. With a bare separator
        // and no length prefix, these two genuinely different events collided, which is
        // precisely the forgery the chain exists to prevent.
        //
        // Written as (char)0x1F rather than an escape so no control character ever appears
        // literally in a source file.
        var sep = ((char)0x1F).ToString();

        var split = Base() with
        {
            App = new AppRef(AppMatchKind.FullPath, "x.exe", PublisherCn: "p", PathHash: "q"),
        };
        var merged = Base() with
        {
            App = new AppRef(AppMatchKind.FullPath, "x.exe", PublisherCn: $"p{sep}q", PathHash: null),
        };

        Assert.NotEqual(EventHasher.ComputeHash(split), EventHasher.ComputeHash(merged));
    }

    [Fact]
    public void Length_prefix_survives_a_title_that_mimics_the_encoding()
    {
        // The same idea one level up: a title that looks like a length-prefixed field.
        var a = Base() with { App = new AppRef(AppMatchKind.FileName, "x.exe", WindowTitle: "5:hello") };
        var b = Base() with { App = new AppRef(AppMatchKind.FileName, "x.exe", WindowTitle: "hello") };

        Assert.NotEqual(EventHasher.ComputeHash(a), EventHasher.ComputeHash(b));
    }

    [Fact]
    public void Meta_ordering_does_not_affect_the_hash()
    {
        var forward = Base() with
        {
            Meta = new Dictionary<string, string> { ["alpha"] = "1", ["beta"] = "2" },
        };
        var reverse = Base() with
        {
            Meta = new Dictionary<string, string> { ["beta"] = "2", ["alpha"] = "1" },
        };

        Assert.Equal(EventHasher.ComputeHash(forward), EventHasher.ComputeHash(reverse));
    }

    [Fact]
    public void Meta_content_still_affects_the_hash()
    {
        var one = Base() with { Meta = new Dictionary<string, string> { ["attempts"] = "1" } };
        var two = Base() with { Meta = new Dictionary<string, string> { ["attempts"] = "2" } };

        Assert.NotEqual(EventHasher.ComputeHash(one), EventHasher.ComputeHash(two));
    }

    [Fact]
    public void Sealing_with_a_different_predecessor_changes_the_hash()
    {
        var first = EventHasher.Seal(Base(), null);
        var second = EventHasher.Seal(Base(), new string('a', 64));

        Assert.NotEqual(first.Hash, second.Hash);
    }
}
