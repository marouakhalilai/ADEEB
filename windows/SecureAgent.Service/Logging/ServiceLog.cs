using Microsoft.Extensions.Logging;

namespace SecureAgent.Service.Logging;

/// <summary>
/// Source-generated log methods for the core service.
/// </summary>
/// <remarks>
/// <para>
/// House style: every log statement in the service and broker goes through a generated
/// method here rather than a <c>logger.LogInformation(...)</c> call site. Three reasons,
/// in order of importance for this product:
/// </para>
/// <list type="number">
/// <item>
/// <b>Stable event ids.</b> Operational alerting keys off ids, not message text. A rule
/// that greps for a log string breaks the first time someone rewords it; a rule on
/// <c>EventId 1300</c> does not.
/// </item>
/// <item>
/// <b>No argument evaluation when the level is disabled.</b> The generator emits the
/// <c>IsEnabled</c> guard, which matters on a service that logs on every foreground change.
/// </item>
/// <item>
/// <b>A fixed message template.</b> The set of properties a message can carry is declared
/// in one place, which is what makes the redaction rules in
/// <see cref="BiometricRedactionEnricher"/> auditable rather than aspirational.
/// </item>
/// </list>
/// <para>
/// Id ranges: 1000-1099 lifecycle, 1100-1199 IPC, 1200-1299 policy, 1300-1399 verification,
/// 1400-1499 enforcement, 1500-1599 vault and keys, 1900-1999 faults and tamper.
/// </para>
/// </remarks>
internal static partial class ServiceLog
{
    [LoggerMessage(
        EventId = 1000,
        Level = LogLevel.Information,
        Message = "SecureAgent core service ready at {StartedAt} (monotonic origin {MonotonicTicks})")]
    public static partial void ServiceReady(ILogger logger, DateTimeOffset startedAt, long monotonicTicks);

    [LoggerMessage(
        EventId = 1001,
        Level = LogLevel.Information,
        Message = "SecureAgent core service stopping")]
    public static partial void ServiceStopping(ILogger logger);
}
