using System.Security.Cryptography;

namespace SecureAgent.Core.Domain;

/// <summary>
/// Generates ULIDs: 128-bit identifiers that sort by creation time.
/// </summary>
/// <remarks>
/// <para>
/// Used as the primary key for audit records, for two reasons that a GUID would not serve.
/// They sort lexicographically in creation order, which keeps the audit table's index dense
/// and makes chain order and key order agree; and they are generated client-side, which is
/// what makes cloud ingest idempotent — a retried batch carries the same ids and dedupes
/// naturally, with no server round-trip to allocate keys.
/// </para>
/// <para>
/// Format is 48 bits of millisecond timestamp followed by 80 bits of randomness, rendered
/// in Crockford Base32 as 26 characters. The randomness comes from a cryptographic RNG:
/// audit-record ids should not be guessable, and a predictable id is a small but free hint
/// to anyone probing the log.
/// </para>
/// </remarks>
public static class Ulid
{
    // Crockford Base32: no I, L, O or U, so the alphabet resists transcription errors and
    // cannot accidentally spell words.
    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    /// <summary>Length of the rendered form.</summary>
    public const int Length = 26;

    /// <summary>Creates a new ULID for the current instant.</summary>
    public static string NewUlid() => NewUlid(DateTimeOffset.UtcNow);

    /// <summary>Creates a new ULID for a given instant.</summary>
    public static string NewUlid(DateTimeOffset timestamp)
    {
        Span<byte> bytes = stackalloc byte[16];

        var ms = timestamp.ToUnixTimeMilliseconds();
        if (ms < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(timestamp), "ULID timestamps must be at or after the Unix epoch.");
        }

        // 48-bit big-endian timestamp, most significant byte first, so lexicographic order
        // matches chronological order.
        bytes[0] = (byte)(ms >> 40);
        bytes[1] = (byte)(ms >> 32);
        bytes[2] = (byte)(ms >> 24);
        bytes[3] = (byte)(ms >> 16);
        bytes[4] = (byte)(ms >> 8);
        bytes[5] = (byte)ms;

        RandomNumberGenerator.Fill(bytes[6..]);

        return Encode(bytes);
    }

    /// <summary>Whether a string is a well-formed ULID.</summary>
    public static bool IsValid(string? value)
    {
        if (value is not { Length: Length })
        {
            return false;
        }

        foreach (var c in value)
        {
            if (!Alphabet.Contains(c, StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Renders 16 bytes as 26 Base32 characters.
    /// </summary>
    /// <remarks>
    /// 26 characters carry 130 bits, so the first character encodes only the top 2 bits of
    /// the 128 and can never exceed '7'. Walking the bit stream rather than special-casing
    /// that keeps the encoder obviously correct.
    /// </remarks>
    private static string Encode(ReadOnlySpan<byte> bytes)
    {
        Span<char> output = stackalloc char[Length];

        var bitBuffer = 0;
        var bitCount = 0;
        var index = Length;

        // Encode from the least significant end so the leftover high bits land in the first
        // character rather than the last.
        for (var i = bytes.Length - 1; i >= 0; i--)
        {
            bitBuffer |= bytes[i] << bitCount;
            bitCount += 8;

            while (bitCount >= 5)
            {
                output[--index] = Alphabet[bitBuffer & 0x1F];
                bitBuffer >>= 5;
                bitCount -= 5;
            }
        }

        if (bitCount > 0)
        {
            output[--index] = Alphabet[bitBuffer & 0x1F];
        }

        while (index > 0)
        {
            output[--index] = Alphabet[0];
        }

        return new string(output);
    }
}
