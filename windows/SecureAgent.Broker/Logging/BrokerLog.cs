using Microsoft.Extensions.Logging;

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
}
