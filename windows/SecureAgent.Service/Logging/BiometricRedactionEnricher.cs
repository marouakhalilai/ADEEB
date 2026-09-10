using Serilog.Core;
using Serilog.Events;

namespace SecureAgent.Service.Logging;

/// <summary>
/// Strips biometric material from log events before they reach any sink.
/// </summary>
/// <remarks>
/// <para>
/// CLAUDE.md rule 25 says to log confidence buckets, never scores, embeddings or images.
/// A rule that lives only in a document decays; this makes it mechanical. It is the last
/// line rather than the first — the property is that no future contributor can leak an
/// embedding through a log statement even by accident.
/// </para>
/// <para>
/// Why a raw similarity score matters as much as the vector itself: the score is a
/// biometric proxy. Enough logged scores for known probe images narrows an enrolled
/// template far more than it looks like it should, and unlike a password it cannot be
/// rotated.
/// </para>
/// </remarks>
public sealed class BiometricRedactionEnricher : ILogEventEnricher
{
    /// <summary>The value substituted for a forbidden property.</summary>
    public const string Redacted = "[redacted:biometric]";

    private static readonly string[] ForbiddenProperties =
    [
        "Embedding",
        "Embeddings",
        "Vector",
        "Template",
        "FaceTemplate",
        "Similarity",
        "SimilarityScore",
        "Score",
        "CosineDistance",
        "Distance",
        "Frame",
        "Image",
        "Bitmap",
        "Pixels",
    ];

    /// <inheritdoc />
    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        ArgumentNullException.ThrowIfNull(logEvent);
        ArgumentNullException.ThrowIfNull(propertyFactory);

        foreach (var name in ForbiddenProperties)
        {
            if (logEvent.Properties.ContainsKey(name))
            {
                logEvent.AddOrUpdateProperty(propertyFactory.CreateProperty(name, Redacted));
            }
        }
    }

    /// <summary>
    /// Whether a property name is one this enricher redacts. Exposed so tests can assert
    /// the list rather than restating it.
    /// </summary>
    public static bool IsForbidden(string propertyName) =>
        ForbiddenProperties.Contains(propertyName, StringComparer.Ordinal);
}
