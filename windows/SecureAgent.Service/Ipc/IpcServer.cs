using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using SecureAgent.Contracts.Ipc;
using SecureAgent.Service.Logging;

namespace SecureAgent.Service.Ipc;

/// <summary>Handles one message from a connected broker and optionally replies.</summary>
/// <param name="message">The message received.</param>
/// <param name="ct">Cancellation for the connection.</param>
/// <returns>A reply to send back, or null to send nothing.</returns>
public delegate Task<IpcMessage?> IpcHandler(IpcMessage message, CancellationToken ct);

/// <summary>
/// The service side of the broker channel.
/// </summary>
/// <remarks>
/// <para>
/// This is the most security-sensitive interface in the product. The service runs as
/// LocalSystem; the broker runs as the interactive user, who may be the adversary. Every
/// byte arriving here is untrusted, and the pipe itself must be reachable by exactly the
/// right principals and no others.
/// </para>
/// <para>
/// Three properties the DACL below is responsible for:
/// </para>
/// <list type="bullet">
/// <item>
/// The interactive user can connect, because the broker must. Without an explicit grant the
/// default DACL on a LocalSystem-created pipe would exclude them entirely.
/// </item>
/// <item>
/// Remote users cannot. Named pipes are reachable over SMB through the IPC$ share, so a
/// pipe with a careless DACL is a network-facing service. The explicit deny for the NETWORK
/// principal closes that, and deny entries are evaluated before allows.
/// </item>
/// <item>
/// Nobody can take ownership or rewrite the DACL to grant themselves more, because neither
/// <c>TakeOwnership</c> nor <c>ChangePermissions</c> is granted to anyone but SYSTEM.
/// </item>
/// </list>
/// </remarks>
public sealed class IpcServer : IAsyncDisposable
{
    private readonly string _pipeName;
    private readonly ILogger<IpcServer> _logger;
    private readonly IpcHandler _handler;
    private readonly CancellationTokenSource _stopping = new();
    private Task? _acceptLoop;

    /// <summary>Creates the server.</summary>
    public IpcServer(string pipeName, IpcHandler handler, ILogger<IpcServer> logger)
    {
        _pipeName = pipeName;
        _handler = handler;
        _logger = logger;
    }

    /// <summary>Starts accepting broker connections in the background.</summary>
    public void Start() => _acceptLoop = Task.Run(() => AcceptLoopAsync(_stopping.Token));

    /// <summary>
    /// Builds the pipe's access control list.
    /// </summary>
    /// <remarks>
    /// Exposed so a test can assert the rules rather than trusting that the intent in the
    /// comments matches the code. An ACL that silently drifts open is not the kind of bug
    /// that announces itself.
    /// </remarks>
    public static PipeSecurity BuildPipeSecurity()
    {
        var security = new PipeSecurity();

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);
        var network = new SecurityIdentifier(WellKnownSidType.NetworkSid, null);

        // Deny first. Windows evaluates deny entries ahead of allows, so this holds even
        // though INTERACTIVE is granted below.
        security.AddAccessRule(new PipeAccessRule(
            network, PipeAccessRights.FullControl, AccessControlType.Deny));

        security.AddAccessRule(new PipeAccessRule(
            system, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            admins, PipeAccessRights.FullControl, AccessControlType.Allow));

        // The account the service itself runs under needs FullControl, and this is not
        // redundant with the SYSTEM grant above.
        //
        // Creating each additional instance of an existing named pipe requires WRITE_DAC on
        // the ones already open. In production the service is LocalSystem and the SYSTEM
        // rule covers it, but when it runs under an ordinary account — which is exactly how
        // it runs during development — the DACL would otherwise grant that account only
        // ReadWrite and lock the service out of its own pipe. The first broker connects,
        // and every connection after it fails with UnauthorizedAccessException.
        using var current = WindowsIdentity.GetCurrent();
        if (current.User is { } self && self != system)
        {
            security.AddAccessRule(new PipeAccessRule(
                self, PipeAccessRights.FullControl, AccessControlType.Allow));
        }

        // The broker needs to read, write and wait — and nothing more. Notably absent:
        // ChangePermissions and TakeOwnership.
        security.AddAccessRule(new PipeAccessRule(
            interactive,
            PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize,
            AccessControlType.Allow));

        return security;
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = NamedPipeServerStreamAcl.Create(
                    _pipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.WriteThrough,
                    inBufferSize: IpcCodec.MaxFrameBytes,
                    outBufferSize: IpcCodec.MaxFrameBytes,
                    BuildPipeSecurity());

                await pipe.WaitForConnectionAsync(ct);

                // Each connection is served on its own task so one broker cannot block
                // another session's broker from connecting.
                var connection = pipe;
                pipe = null;
                _ = Task.Run(() => ServeAsync(connection, ct), ct);
            }
            catch (OperationCanceledException)
            {
                pipe?.Dispose();
                return;
            }
            catch (Exception ex)
            {
                pipe?.Dispose();
                ServiceLog.IpcAcceptFailed(_logger, ex);

                // Back off rather than spinning: if pipe creation is failing, retrying at
                // full speed turns a fault into a CPU burn on a security service.
                await Task.Delay(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
            }
        }
    }

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        try
        {
            ServiceLog.BrokerConnected(_logger);

            while (pipe.IsConnected && !ct.IsCancellationRequested)
            {
                var message = await IpcCodec.ReadAsync(pipe, ct);
                if (message is null)
                {
                    break;
                }

                var reply = await _handler(message, ct);
                if (reply is not null)
                {
                    await IpcCodec.WriteAsync(pipe, reply, ct);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Shutting down.
        }
        catch (InvalidDataException ex)
        {
            // Framing is lost; there is no safe way to find the next message boundary, so
            // the connection is dropped rather than resynchronised. A broker sending
            // malformed frames is either broken or hostile, and both warrant a record.
            ServiceLog.BrokerProtocolViolation(_logger, ex);
        }
        catch (IOException ex)
        {
            ServiceLog.BrokerDisconnected(_logger, ex.Message);
        }
        finally
        {
            await pipe.DisposeAsync();
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await _stopping.CancelAsync();

        if (_acceptLoop is not null)
        {
            try
            {
                await _acceptLoop;
            }
            catch (OperationCanceledException)
            {
                // Expected on shutdown.
            }
        }

        _stopping.Dispose();
    }
}
