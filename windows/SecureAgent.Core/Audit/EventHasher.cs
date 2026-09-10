using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using SecureAgent.Core.Domain;

namespace SecureAgent.Core.Audit;

/// <summary>
/// Computes the tamper-evidence hash for an audit record.
/// </summary>
/// <remarks>
/// <para>
/// The property that matters: given a sequence of records, any deletion, reordering or
/// field edit changes at least one <see cref="SecurityEvent.Hash"/> and therefore breaks
/// continuity with the following record's <see cref="SecurityEvent.PrevHash"/>. The
/// control plane re-verifies the chain on ingest, so tampering that happens on the device
/// is visible from the server (plan §06).
/// </para>
/// <para>
/// This does not make the log unforgeable — an attacker who owns the machine and the
/// signing key can rebuild a consistent chain from any point. What it does is remove the
/// cheap attack: quietly deleting the row that recorded your own failed verification.
/// Server-side chain-head pinning is what closes the rest of that gap.
/// </para>
/// <para>
/// Canonical form is deliberately hand-rolled rather than JSON-serialized. A serializer's
/// property order, culture handling or null treatment can change under a library upgrade,
/// which would silently invalidate every historical chain in the field.
/// </para>
/// </remarks>
public static class EventHasher
{
    /// <summary>
    /// Current canonical-form version. Part of the hashed content, so a format change
    /// announces itself rather than silently producing different digests for old records.
    /// </summary>
    private const string FormatVersion = "v1";

    /// <summary>
    /// Field terminator. Written as an escape, never as a literal control character in
    /// source: a literal U+001F would be at the mercy of editor encoding, git filters and
    /// line-ending conversion, and changing it invalidates every chain in the field.
    /// </summary>
    private const char FieldSeparator = '\u001F';

    /// <summary>Marks an absent field, so null and empty string cannot collide.</summary>
    private const char NullMarker = '-';

    /// <summary>The hash recorded for a record that has no predecessor.</summary>
    public const string GenesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000";

    /// <summary>
    /// Returns <paramref name="e"/> with <see cref="SecurityEvent.PrevHash"/> set to
    /// <paramref name="prevHash"/> and <see cref="SecurityEvent.Hash"/> computed over it.
    /// </summary>
    /// <param name="e">The record to seal. Its existing hash fields are ignored.</param>
    /// <param name="prevHash">
    /// The previous record's hash, or null for the first record in a chain.
    /// </param>
    public static SecurityEvent Seal(SecurityEvent e, string? prevHash)
    {
        ArgumentNullException.ThrowIfNull(e);

        var linked = e with { PrevHash = prevHash ?? GenesisPrevHash };
        return linked with { Hash = ComputeHash(linked) };
    }

    /// <summary>
    /// Computes the SHA-256 of a record's canonical form. Ignores any value already in
    /// <see cref="SecurityEvent.Hash"/> so that the result is recomputable for verification.
    /// </summary>
    public static string ComputeHash(SecurityEvent e)
    {
        ArgumentNullException.ThrowIfNull(e);

        var canonical = Canonicalize(e);
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Convert.ToHexStringLower(digest);
    }

    /// <summary>
    /// Verifies that a record's stored hash matches its content.
    /// </summary>
    public static bool IsSelfConsistent(SecurityEvent e)
    {
        ArgumentNullException.ThrowIfNull(e);
        if (string.IsNullOrEmpty(e.Hash))
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(e.Hash),
            Encoding.ASCII.GetBytes(ComputeHash(e)));
    }

    /// <summary>
    /// Renders the stable, order-fixed form that is hashed.
    /// </summary>
    /// <remarks>
    /// Field order here is part of the on-disk format. Appending a new field at the end is
    /// safe for records sealed afterwards but invalidates verification of records sealed
    /// before it, so any change needs a <see cref="FormatVersion"/> bump and a migration.
    /// </remarks>
    private static string Canonicalize(SecurityEvent e)
    {
        var sb = new StringBuilder(512);

        Append(sb, FormatVersion);
        Append(sb, e.Id);
        Append(sb, e.Timestamp.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        Append(sb, e.WindowsSessionId.ToString(CultureInfo.InvariantCulture));
        Append(sb, e.Kind.ToString());
        Append(sb, e.Severity.ToString());
        Append(sb, e.Outcome.ToString());
        Append(sb, e.PolicyId?.ToString("D", CultureInfo.InvariantCulture));
        Append(sb, e.UserId?.ToString("D", CultureInfo.InvariantCulture));
        Append(sb, e.App?.MatchKind.ToString());
        Append(sb, e.App?.FileName);
        Append(sb, e.App?.PublisherCn);
        Append(sb, e.App?.PathHash);
        Append(sb, e.App?.WindowTitle);
        Append(sb, e.Verifier.ToString());
        Append(sb, e.Confidence.ToString());
        Append(sb, e.LivenessPassed?.ToString());
        Append(sb, e.ElapsedMs?.ToString(CultureInfo.InvariantCulture));
        Append(sb, e.Action.ToString());
        Append(sb, e.PrevHash);

        // Meta is unordered by type, so it is sorted to keep the canonical form stable.
        if (e.Meta is { Count: > 0 })
        {
            foreach (var kv in e.Meta.OrderBy(static k => k.Key, StringComparer.Ordinal))
            {
                Append(sb, kv.Key);
                Append(sb, kv.Value);
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Appends one length-prefixed field.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The length prefix is a security control, not a formatting choice. Some of the fields
    /// hashed here are attacker-controlled — <see cref="AppRef.WindowTitle"/> is whatever a
    /// process chose to name its window. With a bare separator, a title containing a literal
    /// <see cref="FieldSeparator"/> could shift the boundary between fields and make two
    /// genuinely different events produce the same canonical string, which is exactly the
    /// collision the chain is supposed to prevent.
    /// </para>
    /// <para>
    /// Length-prefixing makes the encoding injective regardless of field content: distinct
    /// field tuples always render to distinct strings.
    /// </para>
    /// </remarks>
    private static void Append(StringBuilder sb, string? value)
    {
        if (value is null)
        {
            // A null field and an empty field must not collide, or an attacker could clear
            // a field — blanking a publisher name, say — without disturbing the hash.
            sb.Append(NullMarker);
        }
        else
        {
            sb.Append(value.Length.ToString(CultureInfo.InvariantCulture));
            sb.Append(':');
            sb.Append(value);
        }

        sb.Append(FieldSeparator);
    }
}
