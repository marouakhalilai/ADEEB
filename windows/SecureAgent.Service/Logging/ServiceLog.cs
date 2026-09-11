using Microsoft.Extensions.Logging;
using SecureAgent.Core.Audit;
using SecureAgent.Core.Domain;
using SecureAgent.Core.Policy;
using SecureAgent.Contracts.Ipc;

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

    [LoggerMessage(
        EventId = 1002,
        Level = LogLevel.Information,
        Message = "Local store ready at {DatabasePath}")]
    public static partial void DatabaseReady(ILogger logger, string databasePath);

    [LoggerMessage(
        EventId = 1900,
        Level = LogLevel.Critical,
        Message = "Audit chain verification FAILED: {Fault} at index {Index} (event {EventId}). " +
                  "This indicates tampering or storage corruption.")]
    public static partial void ChainVerificationFailed(
        ILogger logger, ChainFault fault, int index, string? eventId);

    [LoggerMessage(
        EventId = 1003,
        Level = LogLevel.Information,
        Message = "Audit chain verified intact ({Count} records)")]
    public static partial void ChainVerified(ILogger logger, int count);

    // ---- IPC, 1100-1199 ----

    [LoggerMessage(
        EventId = 1100,
        Level = LogLevel.Information,
        Message = "IPC listening on pipe {PipeName}")]
    public static partial void IpcListening(ILogger logger, string pipeName);

    [LoggerMessage(
        EventId = 1101,
        Level = LogLevel.Debug,
        Message = "Broker connected")]
    public static partial void BrokerConnected(ILogger logger);

    [LoggerMessage(
        EventId = 1102,
        Level = LogLevel.Debug,
        Message = "Broker disconnected: {Reason}")]
    public static partial void BrokerDisconnected(ILogger logger, string reason);

    [LoggerMessage(
        EventId = 1103,
        Level = LogLevel.Warning,
        Message = "Broker sent a malformed frame; dropping the connection")]
    public static partial void BrokerProtocolViolation(ILogger logger, Exception ex);

    [LoggerMessage(
        EventId = 1104,
        Level = LogLevel.Error,
        Message = "Failed to accept an IPC connection")]
    public static partial void IpcAcceptFailed(ILogger logger, Exception ex);

    // ---- Policy and decisions, 1200-1399 ----

    [LoggerMessage(
        EventId = 1200,
        Level = LogLevel.Information,
        Message = "Loaded {Count} polic(ies)")]
    public static partial void PoliciesLoaded(ILogger logger, int count);

    [LoggerMessage(
        EventId = 1300,
        Level = LogLevel.Information,
        Message = "{App} activated: {Decision} (policy {PolicyName}, matched by {MatchedBy})")]
    public static partial void ActivationDecided(
        ILogger logger, string app, DecisionKind decision, string policyName, AppMatchKind matchedBy);

    // Logged at Debug, not Information: suppression is the normal case whenever a prompt is
    // on screen, and at Information it would be noise on every single verification.
    [LoggerMessage(
        EventId = 1302,
        Level = LogLevel.Debug,
        Message = "Suppressed a duplicate verification for {App} ({PolicyName}); one is already in flight")]
    public static partial void VerificationSuppressed(ILogger logger, string app, string policyName);

    [LoggerMessage(
        EventId = 1301,
        Level = LogLevel.Information,
        Message = "Verification {Result} for {App} via {Verifier} in {ElapsedMs}ms")]
    public static partial void VerificationCompleted(
        ILogger logger, VerificationOutcomeDto result, string app, VerifierKind verifier, int elapsedMs);

    [LoggerMessage(
        EventId = 1400,
        Level = LogLevel.Warning,
        Message = "Enforcing {Action} on {App}: {Reason}")]
    public static partial void EnforcementApplied(
        ILogger logger, EnforcementAction action, string app, string reason);
}
