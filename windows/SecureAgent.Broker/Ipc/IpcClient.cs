using System.IO.Pipes;
using Microsoft.Extensions.Logging;
using SecureAgent.Broker.Logging;
using SecureAgent.Contracts.Ipc;

namespace SecureAgent.Broker.Ipc;

/// <summary>
/// The broker side of the service channel.
/// </summary>
/// <remarks>
/// <para>
/// Reconnects on its own. The service can restart, be upgraded, or be stopped by an
/// administrator; when that happens the broker must keep trying rather than silently give
/// up, because a broker that has quietly stopped talking to the service looks exactly like
/// a machine that is protected when it is not.
/// </para>
/// <para>
/// Connection loss is surfaced through <see cref="Connected"/> so the tray UI can tell the
/// user that protection is degraded. Failing loudly is the whole point (plan §05).
/// </para>
/// </remarks>
public sealed class IpcClient : IAsyncDisposable
{
    private readonly string _pipeName;
    private readonly ILogger<IpcClient> _logger;
    private readonly Func<IpcMessage, CancellationToken, Task<IpcMessage?>> _onServerMessage;
    private readonly SemaphoreSlim _writeGate = new(1, 1);

    private NamedPipeClientStream? _pipe;
    private bool _disposed;

    /// <summary>Creates the client.</summary>
    /// <param name="pipeName">Pipe to connect to.</param>
    /// <param name="onServerMessage">Handles a message pushed by the service.</param>
    /// <param name="logger">Logger.</param>
    public IpcClient(
        string pipeName,
        Func<IpcMessage, CancellationToken, Task<IpcMessage?>> onServerMessage,
        ILogger<IpcClient> logger)
    {
        _pipeName = pipeName;
        _onServerMessage = onServerMessage;
        _logger = logger;
    }

    /// <summary>Whether a live connection to the service exists right now.</summary>
    public bool Connected => _pipe?.IsConnected == true;

    /// <summary>
    /// Runs the connect/serve/reconnect loop until cancelled.
    /// </summary>
    public async Task RunAsync(CancellationToken ct)
    {
        var backoff = TimeSpan.FromSeconds(1);
        var maxBackoff = TimeSpan.FromSeconds(30);

        while (!ct.IsCancellationRequested)
        {
            try
            {
                var pipe = new NamedPipeClientStream(
                    ".",
                    _pipeName,
                    PipeDirection.InOut,
                    PipeOptions.Asynchronous);

                await pipe.ConnectAsync((int)TimeSpan.FromSeconds(5).TotalMilliseconds, ct);
                _pipe = pipe;
                backoff = TimeSpan.FromSeconds(1);

                BrokerLog.ConnectedToService(_logger);
                await ServeAsync(pipe, ct);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (TimeoutException)
            {
                BrokerLog.ServiceUnreachable(_logger, (int)backoff.TotalSeconds);
            }
            catch (IOException ex)
            {
                BrokerLog.ServiceConnectionLost(_logger, ex.Message);
            }
            finally
            {
                if (_pipe is not null)
                {
                    await _pipe.DisposeAsync();
                    _pipe = null;
                }
            }

            try
            {
                await Task.Delay(backoff, ct);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            // Exponential backoff, capped. A tight reconnect loop against a stopped service
            // would spin a core for as long as the service stays down.
            backoff = TimeSpan.FromSeconds(Math.Min(backoff.TotalSeconds * 2, maxBackoff.TotalSeconds));
        }
    }

    private async Task ServeAsync(NamedPipeClientStream pipe, CancellationToken ct)
    {
        while (pipe.IsConnected && !ct.IsCancellationRequested)
        {
            var message = await IpcCodec.ReadAsync(pipe, ct);
            if (message is null)
            {
                return;
            }

            var reply = await _onServerMessage(message, ct);
            if (reply is not null)
            {
                await SendAsync(reply, ct);
            }
        }
    }

    /// <summary>
    /// Sends a message to the service.
    /// </summary>
    /// <returns>False when there is no connection, so callers can degrade rather than throw.</returns>
    public async Task<bool> SendAsync(IpcMessage message, CancellationToken ct)
    {
        var pipe = _pipe;
        if (pipe is null || !pipe.IsConnected)
        {
            return false;
        }

        // One writer at a time: two concurrent writes would interleave their frames on the
        // stream and destroy the framing for everything that follows.
        await _writeGate.WaitAsync(ct);
        try
        {
            await IpcCodec.WriteAsync(pipe, message, ct);
            return true;
        }
        catch (IOException)
        {
            return false;
        }
        finally
        {
            _writeGate.Release();
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        if (_pipe is not null)
        {
            await _pipe.DisposeAsync();
            _pipe = null;
        }

        _writeGate.Dispose();
    }
}
