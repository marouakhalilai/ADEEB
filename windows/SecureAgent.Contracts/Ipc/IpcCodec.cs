using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecureAgent.Contracts.Ipc;

/// <summary>
/// Frames <see cref="IpcMessage"/> values onto a stream and reads them back.
/// </summary>
/// <remarks>
/// <para>
/// Wire format is a 4-byte big-endian length prefix followed by that many bytes of UTF-8
/// JSON. Deliberately boring: the pipe is reachable by the interactive user, so the parser
/// is a place where a hostile peer gets to feed us bytes.
/// </para>
/// <para>
/// The length is validated <em>before</em> any buffer is allocated. Without that check, a
/// peer sends a 2 GB length prefix and the security service dies to an out-of-memory
/// exception — a denial of service against the thing that is supposed to be protecting the
/// machine, achievable by any local user with four bytes.
/// </para>
/// </remarks>
public static class IpcCodec
{
    /// <summary>
    /// Largest accepted frame. Generous for the messages we actually send — the biggest is
    /// an embedding of a few kilobytes — and small enough that a hostile length prefix
    /// cannot exhaust memory.
    /// </summary>
    public const int MaxFrameBytes = 64 * 1024;

    private static readonly JsonSerializerOptions Options = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        // No indentation: this is a wire format, not a document.
        WriteIndented = false,
    };

    /// <summary>Writes one framed message.</summary>
    public static async Task WriteAsync(Stream stream, IpcMessage message, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(message);

        var payload = JsonSerializer.SerializeToUtf8Bytes(message, Options);
        if (payload.Length > MaxFrameBytes)
        {
            throw new InvalidOperationException(
                $"Refusing to send a {payload.Length}-byte frame; the limit is {MaxFrameBytes}.");
        }

        var header = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(header, payload.Length);

        await stream.WriteAsync(header, ct);
        await stream.WriteAsync(payload, ct);
        await stream.FlushAsync(ct);
    }

    /// <summary>
    /// Reads one framed message, or null when the peer closed the connection cleanly.
    /// </summary>
    /// <exception cref="InvalidDataException">
    /// The peer sent a malformed frame. The caller must treat this as a hostile or broken
    /// peer and drop the connection rather than attempt to resynchronise: once framing is
    /// lost there is no way to find the next message boundary.
    /// </exception>
    public static async Task<IpcMessage?> ReadAsync(Stream stream, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var header = new byte[4];
        if (!await ReadExactlyAsync(stream, header, ct))
        {
            return null;
        }

        var length = BinaryPrimitives.ReadInt32BigEndian(header);

        // Validate before allocating. This is the whole point of the check.
        if (length <= 0 || length > MaxFrameBytes)
        {
            throw new InvalidDataException(
                $"Frame length {length} is outside the accepted range (1..{MaxFrameBytes}).");
        }

        var payload = new byte[length];
        if (!await ReadExactlyAsync(stream, payload, ct))
        {
            throw new InvalidDataException("Peer closed the connection mid-frame.");
        }

        try
        {
            return JsonSerializer.Deserialize<IpcMessage>(payload, Options)
                ?? throw new InvalidDataException("Frame deserialized to null.");
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("Frame is not a valid IPC message.", ex);
        }
    }

    /// <summary>
    /// Fills the buffer completely, or returns false if the stream ended first.
    /// </summary>
    /// <remarks>
    /// A pipe read can return fewer bytes than asked for. Treating a short read as a
    /// complete message is the classic framing bug, and here it would mean parsing a
    /// truncated frame as if it were whole.
    /// </remarks>
    private static async Task<bool> ReadExactlyAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken ct)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var got = await stream.ReadAsync(buffer[read..], ct);
            if (got == 0)
            {
                return false;
            }

            read += got;
        }

        return true;
    }
}
