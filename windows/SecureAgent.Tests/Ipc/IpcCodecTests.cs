using System.Buffers.Binary;
using SecureAgent.Contracts.Ipc;
using SecureAgent.Core.Domain;
using Xunit;

namespace SecureAgent.Tests.Ipc;

/// <summary>
/// The pipe is reachable by the interactive user, so the codec is an attack surface: these
/// cover the hostile-peer cases, not just the happy path.
/// </summary>
[Trait("Category", "Portable")]
public sealed class IpcCodecTests
{
    private static async Task<IpcMessage?> RoundTrip(IpcMessage message)
    {
        using var stream = new MemoryStream();
        await IpcCodec.WriteAsync(stream, message, CancellationToken.None);
        stream.Position = 0;
        return await IpcCodec.ReadAsync(stream, CancellationToken.None);
    }

    [Fact]
    public async Task App_activated_round_trips()
    {
        var sent = new AppActivatedMessage
        {
            CorrelationId = "c1",
            App = AppRef.FromUntrusted(AppMatchKind.FileName, "notepad.exe"),
            WindowsSessionId = 1,
            ProcessId = 4242,
        };

        var got = Assert.IsType<AppActivatedMessage>(await RoundTrip(sent));

        Assert.Equal("c1", got.CorrelationId);
        Assert.Equal("notepad.exe", got.App.FileName);
        Assert.Equal(4242, got.ProcessId);
    }

    [Fact]
    public async Task Decision_round_trips_with_its_enum_values()
    {
        var sent = new DecisionMessage
        {
            CorrelationId = "c2",
            Outcome = Outcome.Denied,
            Action = EnforcementAction.Overlay,
            UserFacingReason = "Not recognised",
        };

        var got = Assert.IsType<DecisionMessage>(await RoundTrip(sent));

        Assert.Equal(Outcome.Denied, got.Outcome);
        Assert.Equal(EnforcementAction.Overlay, got.Action);
    }

    [Fact]
    public async Task Polymorphic_dispatch_preserves_the_concrete_type()
    {
        // Without the discriminator the reader would get a base IpcMessage and the service
        // would silently ignore messages it should act on.
        var sent = new VerifyRequestMessage
        {
            CorrelationId = "c3",
            MinimumAssurance = AssuranceLevel.HelloOrIr,
            TimeoutMs = 5000,
            Interactive = true,
        };

        Assert.IsType<VerifyRequestMessage>(await RoundTrip(sent));
    }

    [Fact]
    public async Task Clean_close_reads_as_null_not_an_error()
    {
        using var empty = new MemoryStream();

        Assert.Null(await IpcCodec.ReadAsync(empty, CancellationToken.None));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    [InlineData(IpcCodec.MaxFrameBytes + 1)]
    [InlineData(int.MaxValue)]
    public async Task Hostile_length_prefix_is_rejected_before_allocating(int declaredLength)
    {
        // The denial-of-service a local user could otherwise mount with four bytes: declare
        // a 2 GB frame and let the security service die allocating it.
        var header = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(header, declaredLength);
        using var stream = new MemoryStream(header);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => IpcCodec.ReadAsync(stream, CancellationToken.None));
    }

    [Fact]
    public async Task Truncated_frame_is_rejected_rather_than_parsed()
    {
        // A short read must not be mistaken for a complete message.
        var header = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(header, 128);
        using var stream = new MemoryStream([.. header, .. new byte[10]]);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => IpcCodec.ReadAsync(stream, CancellationToken.None));
    }

    [Fact]
    public async Task Garbage_payload_is_rejected()
    {
        var payload = "this is not json"u8.ToArray();
        var header = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(header, payload.Length);
        using var stream = new MemoryStream([.. header, .. payload]);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => IpcCodec.ReadAsync(stream, CancellationToken.None));
    }

    [Fact]
    public async Task Unknown_discriminator_is_rejected()
    {
        var payload = """{"$kind":"attacker-invented","CorrelationId":"x"}"""u8.ToArray();
        var header = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(header, payload.Length);
        using var stream = new MemoryStream([.. header, .. payload]);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => IpcCodec.ReadAsync(stream, CancellationToken.None));
    }

    [Fact]
    public async Task Two_messages_on_one_stream_stay_framed()
    {
        using var stream = new MemoryStream();
        var ct = CancellationToken.None;

        await IpcCodec.WriteAsync(stream, new PresencePingMessage
        {
            CorrelationId = "a",
            PolicyId = Guid.Empty,
            WindowsSessionId = 1,
            Present = true,
        }, ct);
        await IpcCodec.WriteAsync(stream, new PresencePingMessage
        {
            CorrelationId = "b",
            PolicyId = Guid.Empty,
            WindowsSessionId = 1,
            Present = false,
        }, ct);

        stream.Position = 0;

        var first = Assert.IsType<PresencePingMessage>(await IpcCodec.ReadAsync(stream, ct));
        var second = Assert.IsType<PresencePingMessage>(await IpcCodec.ReadAsync(stream, ct));

        Assert.Equal("a", first.CorrelationId);
        Assert.True(first.Present);
        Assert.Equal("b", second.CorrelationId);
        Assert.False(second.Present);
    }

    [Fact]
    public async Task Oversized_outbound_message_is_refused_at_the_sender()
    {
        // Catch our own bug before it becomes the peer's problem.
        var huge = new DecisionMessage
        {
            CorrelationId = "c",
            Outcome = Outcome.Denied,
            Action = EnforcementAction.Overlay,
            UserFacingReason = new string('x', IpcCodec.MaxFrameBytes),
        };

        using var stream = new MemoryStream();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => IpcCodec.WriteAsync(stream, huge, CancellationToken.None));
    }
}
