namespace SecureAgent.Core.Domain;

/// <summary>
/// Everything the policy engine is told about an application coming to the foreground.
/// </summary>
/// <remarks>
/// <para>
/// Assembled by the broker and sent across the IPC boundary. Every string here originates
/// on the device and is untrusted (CLAUDE.md rule 23): the broker runs as the interactive
/// user, who may be the adversary, so nothing on this type is a security assertion — it is
/// a claim the service evaluates.
/// </para>
/// <para>
/// This is why the broker performs no policy evaluation of its own. It reports; the service
/// decides.
/// </para>
/// </remarks>
public sealed record ActivationContext
{
    /// <summary>Executable file name, lower-cased, e.g. <c>notepad.exe</c>.</summary>
    public required string FileName { get; init; }

    /// <summary>Full path when it could be resolved. Null when the process vanished first.</summary>
    public string? ExecutablePath { get; init; }

    /// <summary>
    /// Authenticode publisher common name when the binary is signed and the signature
    /// verified. Null for unsigned binaries or when verification failed — the two are not
    /// distinguished here because neither may be treated as a valid publisher.
    /// </summary>
    public string? PublisherCn { get; init; }

    /// <summary>Windows terminal session the activation happened in.</summary>
    public required int WindowsSessionId { get; init; }

    /// <summary>Process id at the moment of resolution; may already be dead.</summary>
    public int ProcessId { get; init; }

    /// <summary>Window title, untrusted and opt-in. Never used in matching decisions.</summary>
    public string? WindowTitle { get; init; }

    /// <summary>Wall-clock time of the activation, used only for schedule evaluation.</summary>
    public required DateTimeOffset LocalTime { get; init; }

    /// <summary>Monotonic timestamp, used for every TTL comparison (rule 22).</summary>
    public required long MonotonicTicks { get; init; }

    /// <summary>Projects the untrusted fields into the redacted form stored in audit records.</summary>
    public AppRef ToAppRef(AppMatchKind resolvedBy) => AppRef.FromUntrusted(
        resolvedBy,
        FileName,
        PublisherCn,
        pathHash: null,
        windowTitle: WindowTitle);
}
