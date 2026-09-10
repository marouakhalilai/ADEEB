using SecureAgent.Core.Domain;
using Xunit;

namespace SecureAgent.Tests.Domain;

/// <summary>
/// ULIDs are the audit chain's primary key and the cloud's idempotency key, so the
/// properties the rest of the system relies on are asserted rather than assumed.
/// </summary>
[Trait("Category", "Portable")]
public sealed class UlidTests
{
    [Fact]
    public void Has_the_documented_length_and_alphabet()
    {
        var id = Ulid.NewUlid();

        Assert.Equal(Ulid.Length, id.Length);
        Assert.True(Ulid.IsValid(id));
    }

    [Fact]
    public void Excludes_the_ambiguous_letters()
    {
        // Crockford Base32 drops I, L, O and U so ids survive being read aloud or retyped
        // from a support ticket.
        for (var i = 0; i < 200; i++)
        {
            var id = Ulid.NewUlid();
            Assert.False(id.Contains('I', StringComparison.Ordinal), $"'I' in {id}");
            Assert.False(id.Contains('L', StringComparison.Ordinal), $"'L' in {id}");
            Assert.False(id.Contains('O', StringComparison.Ordinal), $"'O' in {id}");
            Assert.False(id.Contains('U', StringComparison.Ordinal), $"'U' in {id}");
        }
    }

    [Fact]
    public void Later_timestamps_sort_after_earlier_ones()
    {
        // The property the audit index depends on: key order equals chain order.
        var t0 = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        var a = Ulid.NewUlid(t0);
        var b = Ulid.NewUlid(t0.AddMilliseconds(1));
        var c = Ulid.NewUlid(t0.AddYears(1));

        Assert.True(string.CompareOrdinal(a, b) < 0);
        Assert.True(string.CompareOrdinal(b, c) < 0);
    }

    [Fact]
    public void Same_millisecond_ids_are_still_distinct()
    {
        var t = DateTimeOffset.UtcNow;
        var ids = new HashSet<string>(StringComparer.Ordinal);

        for (var i = 0; i < 1000; i++)
        {
            Assert.True(ids.Add(Ulid.NewUlid(t)), "duplicate ULID within one millisecond");
        }
    }

    [Fact]
    public void Bulk_generation_produces_no_collisions()
    {
        var ids = new HashSet<string>(StringComparer.Ordinal);

        for (var i = 0; i < 20_000; i++)
        {
            Assert.True(ids.Add(Ulid.NewUlid()));
        }
    }

    [Fact]
    public void Timestamp_prefix_is_stable_for_the_same_instant()
    {
        // First 10 characters encode the 48-bit timestamp; two ids from the same
        // millisecond must share them, or time-ordering breaks.
        var t = new DateTimeOffset(2026, 9, 10, 12, 0, 0, TimeSpan.Zero);

        Assert.Equal(Ulid.NewUlid(t)[..10], Ulid.NewUlid(t)[..10]);
    }

    [Fact]
    public void Rejects_timestamps_before_the_epoch()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => Ulid.NewUlid(new DateTimeOffset(1960, 1, 1, 0, 0, 0, TimeSpan.Zero)));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("too-short")]
    [InlineData("0123456789012345678901234I")]   // contains an excluded letter
    [InlineData("012345678901234567890123456")]  // one too long
    public void Invalid_forms_are_rejected(string? value)
    {
        Assert.False(Ulid.IsValid(value));
    }

    [Fact]
    public void Matches_the_pattern_the_event_schema_declares()
    {
        // schema/security-event.schema.json pins ^[0-9A-HJKMNP-TV-Z]{26}$; drift here would
        // mean the device writes ids the control plane rejects.
        var pattern = new System.Text.RegularExpressions.Regex("^[0-9A-HJKMNP-TV-Z]{26}$");

        for (var i = 0; i < 500; i++)
        {
            Assert.Matches(pattern, Ulid.NewUlid());
        }
    }
}
