namespace SecureAgent.Core.Domain;

/// <summary>
/// A reference to the application involved in an event, in the redacted form that is safe
/// to persist and sync.
/// </summary>
/// <remarks>
/// Every string on this type originates on the device and is therefore untrusted input
/// (CLAUDE.md rule 23). <see cref="WindowTitle"/> in particular is set by whatever is
/// running on the machine: a browser tab can be named anything at all, including a
/// prompt-injection payload aimed at the analyst layer. It is opt-in, truncated, and must
/// be delimited as evidence — never as instruction — before it reaches a model.
/// </remarks>
/// <param name="MatchKind">Which rule resolved this application to a policy.</param>
/// <param name="FileName">Executable file name, e.g. <c>notepad.exe</c>.</param>
/// <param name="PublisherCn">Authenticode publisher common name, when the binary is signed.</param>
/// <param name="PathHash">
/// SHA-256 of the full executable path. The path itself is never synced because it
/// routinely contains the user's name.
/// </param>
/// <param name="WindowTitle">Untrusted, opt-in, truncated to <see cref="MaxWindowTitleLength"/>.</param>
public sealed record AppRef(
    AppMatchKind MatchKind,
    string FileName,
    string? PublisherCn = null,
    string? PathHash = null,
    string? WindowTitle = null)
{
    /// <summary>Window titles are truncated to this many characters before storage.</summary>
    public const int MaxWindowTitleLength = 64;

    /// <summary>An application that could not be resolved to a name at all.</summary>
    public static AppRef Unresolved { get; } = new(AppMatchKind.Unresolved, string.Empty);

    /// <summary>
    /// Builds an <see cref="AppRef"/> with the untrusted fields normalised: the file name
    /// lower-cased and length-capped, the window title truncated. Prefer this over the
    /// constructor at every trust boundary.
    /// </summary>
    public static AppRef FromUntrusted(
        AppMatchKind matchKind,
        string? fileName,
        string? publisherCn = null,
        string? pathHash = null,
        string? windowTitle = null)
    {
        var name = (fileName ?? string.Empty).Trim();
        if (name.Length > 260)
        {
            name = name[..260];
        }

        var title = windowTitle?.Trim();
        if (title is { Length: > MaxWindowTitleLength })
        {
            title = title[..MaxWindowTitleLength];
        }

        var publisher = publisherCn?.Trim();
        if (publisher is { Length: > 256 })
        {
            publisher = publisher[..256];
        }

        return new AppRef(
            matchKind,
            name.ToLowerInvariant(),
            string.IsNullOrEmpty(publisher) ? null : publisher,
            string.IsNullOrEmpty(pathHash) ? null : pathHash,
            string.IsNullOrEmpty(title) ? null : title);
    }
}
