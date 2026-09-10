using System.Text.Json;
using SecureAgent.Core.Domain;
using Xunit;

namespace SecureAgent.Tests.Domain;

/// <summary>
/// <c>schema/security-event.schema.json</c> is declared to be the single source of truth
/// across C#, TypeScript and the database (plan §02). A declaration is worthless without
/// something that fails when it drifts — this is that something.
/// </summary>
/// <remarks>
/// Runs against the real schema file, copied to the output directory by the csproj rather
/// than duplicated in-tree. Adding an enum member on either side without the other breaks
/// the build, which is the whole point.
/// </remarks>
[Trait("Category", "Portable")]
public sealed class SchemaParityTests
{
    private static readonly JsonElement Schema = LoadSchema();

    private static JsonElement LoadSchema()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "schema", "security-event.schema.json");
        Assert.True(File.Exists(path), $"Schema not found at {path}. Check the csproj None/Link item.");

        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        return doc.RootElement.Clone();
    }

    private static string[] EnumValues(string definitionName)
    {
        return Schema.GetProperty("$defs")
            .GetProperty(definitionName)
            .GetProperty("enum")
            .EnumerateArray()
            .Where(static v => v.ValueKind == JsonValueKind.String)
            .Select(static v => v.GetString()!)
            .ToArray();
    }

    private static void AssertParity<TEnum>(string definitionName)
        where TEnum : struct, Enum
    {
        var schemaValues = EnumValues(definitionName).Order(StringComparer.Ordinal).ToArray();
        var clrValues = Enum.GetNames<TEnum>().Order(StringComparer.Ordinal).ToArray();

        var missingInClr = schemaValues.Except(clrValues, StringComparer.Ordinal).ToArray();
        var missingInSchema = clrValues.Except(schemaValues, StringComparer.Ordinal).ToArray();

        Assert.True(
            missingInClr.Length == 0,
            $"{definitionName}: in schema but not in {typeof(TEnum).Name}: {string.Join(", ", missingInClr)}");
        Assert.True(
            missingInSchema.Length == 0,
            $"{definitionName}: in {typeof(TEnum).Name} but not in schema: {string.Join(", ", missingInSchema)}");
    }

    [Fact]
    public void EventKind_matches_schema() => AssertParity<EventKind>("eventKind");

    [Fact]
    public void Severity_matches_schema() => AssertParity<Severity>("severity");

    [Fact]
    public void Outcome_matches_schema() => AssertParity<Outcome>("outcome");

    [Fact]
    public void AppMatchKind_matches_schema()
    {
        var schemaValues = Schema
            .GetProperty("$defs").GetProperty("appRef")
            .GetProperty("properties").GetProperty("matchKind")
            .GetProperty("enum")
            .EnumerateArray()
            .Select(static v => v.GetString()!)
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(Enum.GetNames<AppMatchKind>().Order(StringComparer.Ordinal), schemaValues);
    }

    [Fact]
    public void Window_title_cap_matches_schema()
    {
        // If the schema relaxes this and the CLR truncation does not follow, oversized
        // attacker-controlled text reaches the analyst prompt.
        var max = Schema
            .GetProperty("$defs").GetProperty("appRef")
            .GetProperty("properties").GetProperty("windowTitle")
            .GetProperty("maxLength")
            .GetInt32();

        Assert.Equal(AppRef.MaxWindowTitleLength, max);
    }

    [Fact]
    public void Nullable_enums_in_schema_carry_a_null_member()
    {
        // verifierKind and confidenceBucket are nullable on the wire. The CLR side models
        // "absent" as a None member instead, so the schema must allow both shapes.
        foreach (var name in new[] { "verifierKind", "confidenceBucket" })
        {
            var def = Schema.GetProperty("$defs").GetProperty(name).GetProperty("enum");
            Assert.Contains(def.EnumerateArray(), static v => v.ValueKind == JsonValueKind.Null);
            Assert.Contains(def.EnumerateArray(), static v => v.ValueKind == JsonValueKind.String && v.GetString() == "None");
        }
    }
}
