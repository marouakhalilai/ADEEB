using Microsoft.Extensions.Logging;
using SecureAgent.Core.Domain;

namespace SecureAgent.Broker.Logging;

/// <summary>
/// Source-generated log methods for the session broker.
/// </summary>
/// <remarks>
/// Same house style and id conventions as the service's log class, in a separate range so
/// the two processes' events never collide in an aggregated view: 2000-2099 lifecycle,
/// 2100-2199 IPC, 2200-2299 window hook, 2300-2399 capture and verification,
/// 2400-2499 overlay, 2900-2999 faults.
/// </remarks>
internal static partial class BrokerLog
{
    [LoggerMessage(
        EventId = 2000,
        Level = LogLevel.Information,
        Message = "SecureAgent broker ready (pid {ProcessId}, Windows session {WindowsSessionId})")]
    public static partial void BrokerReady(ILogger logger, int processId, int windowsSessionId);

    [LoggerMessage(
        EventId = 2001,
        Level = LogLevel.Information,
        Message = "SecureAgent broker stopping")]
    public static partial void BrokerStopping(ILogger logger);

    // ---- IPC, 2100-2199 ----

    [LoggerMessage(
        EventId = 2100,
        Level = LogLevel.Information,
        Message = "Connected to the SecureAgent service")]
    public static partial void ConnectedToService(ILogger logger);

    [LoggerMessage(
        EventId = 2101,
        Level = LogLevel.Warning,
        Message = "SecureAgent service unreachable; retrying in {BackoffSeconds}s. Protection is degraded.")]
    public static partial void ServiceUnreachable(ILogger logger, int backoffSeconds);

    [LoggerMessage(
        EventId = 2102,
        Level = LogLevel.Warning,
        Message = "Lost the connection to the SecureAgent service: {Reason}")]
    public static partial void ServiceConnectionLost(ILogger logger, string reason);

    // ---- window hook, 2200-2299 ----

    [LoggerMessage(
        EventId = 2200,
        Level = LogLevel.Information,
        Message = "Foreground monitoring active")]
    public static partial void WatcherStarted(ILogger logger);

    [LoggerMessage(
        EventId = 2201,
        Level = LogLevel.Debug,
        Message = "Foreground: {FileName} (pid {ProcessId})")]
    public static partial void ForegroundChanged(ILogger logger, string fileName, uint processId);

    [LoggerMessage(
        EventId = 2202,
        Level = LogLevel.Error,
        Message = "Foreground monitoring fault")]
    public static partial void WatcherFault(ILogger logger, Exception ex);

    // ---- verification, 2300-2399 ----

    // Takes a count and the strongest rung rather than a joined list: composing that string
    // costs real work on every verification, and CA1873 is right to object to paying it
    // before knowing the level is even enabled.
    [LoggerMessage(
        EventId = 2300,
        Level = LogLevel.Information,
        Message = "Verifier ladder: {Count} rung(s), strongest {Strongest}")]
    public static partial void VerifiersAvailable(ILogger logger, int count, VerifierKind strongest);

    // Enums are passed through as-is rather than pre-formatted with ToString(): the
    // generator formats them only when the level is enabled, and the structured sink keeps
    // them as typed values rather than opaque strings.
    [LoggerMessage(
        EventId = 2301,
        Level = LogLevel.Information,
        Message = "Verification requested for assurance {Assurance}; using {Verifier}")]
    public static partial void VerificationStarting(
        ILogger logger, AssuranceLevel assurance, VerifierKind verifier);

    [LoggerMessage(
        EventId = 2302,
        Level = LogLevel.Warning,
        Message = "No verifier available at assurance {Assurance}")]
    public static partial void NoVerifierAvailable(ILogger logger, AssuranceLevel assurance);

    // ---- overlay, 2400-2499 ----

    [LoggerMessage(
        EventId = 2400,
        Level = LogLevel.Information,
        Message = "Showing security overlay: {Reason}")]
    public static partial void OverlayShown(ILogger logger, string reason);

    [LoggerMessage(
        EventId = 2401,
        Level = LogLevel.Information,
        Message = "Overlay dismissed")]
    public static partial void OverlayDismissed(ILogger logger);
}
