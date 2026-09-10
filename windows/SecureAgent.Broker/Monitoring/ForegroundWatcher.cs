using System.Diagnostics;
using SecureAgent.Broker.Win32;

namespace SecureAgent.Broker.Monitoring;

/// <summary>A window belonging to another process came to the foreground.</summary>
/// <param name="FileName">Executable file name, lower-cased.</param>
/// <param name="ExecutablePath">Full path, or null if the process vanished first.</param>
/// <param name="ProcessId">Owning process id.</param>
/// <param name="WindowTitle">Untrusted window title, or null.</param>
public readonly record struct ForegroundChange(
    string FileName,
    string? ExecutablePath,
    uint ProcessId,
    string? WindowTitle);

/// <summary>
/// Watches for foreground window changes.
/// </summary>
/// <remarks>
/// <para>
/// Event-driven via <c>SetWinEventHook</c> rather than polling. Polling
/// <c>GetForegroundWindow</c> on a timer is the obvious implementation and the wrong one:
/// it burns CPU continuously on a background agent, and it still misses an application that
/// is opened and closed between two ticks — which is exactly the access an attacker would
/// like to go unrecorded.
/// </para>
/// <para>
/// The hook must be installed on a thread that pumps messages, so this owns a dedicated
/// thread running a classic Win32 message loop. That is also why this lives in the broker:
/// a Session 0 service has no access to the interactive desktop's window events at all.
/// </para>
/// </remarks>
public sealed class ForegroundWatcher : IDisposable
{
    private readonly Action<ForegroundChange> _onChange;
    private readonly Action<Exception> _onError;
    private readonly int _ownProcessId = Environment.ProcessId;

    private Thread? _pumpThread;
    private uint _pumpThreadId;
    private nint _hook;
    private bool _disposed;

    // Held in a field for the lifetime of the hook. If this delegate were only a local, the
    // GC would collect it while Windows still holds the function pointer, and the process
    // would die at the next foreground change — a crash that only appears under load and
    // looks entirely unrelated to this code.
    private NativeMethods.WinEventProc? _callback;

    /// <summary>Creates the watcher.</summary>
    /// <param name="onChange">Invoked for each foreground change, on the pump thread.</param>
    /// <param name="onError">Invoked when a change could not be resolved.</param>
    public ForegroundWatcher(Action<ForegroundChange> onChange, Action<Exception> onError)
    {
        _onChange = onChange;
        _onError = onError;
    }

    /// <summary>Starts watching. Returns once the hook is installed.</summary>
    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var ready = new ManualResetEventSlim(false);

        _pumpThread = new Thread(() => PumpAsync(ready))
        {
            IsBackground = true,
            Name = "SecureAgent.ForegroundWatcher",
        };

        // The message loop requires an STA thread.
        _pumpThread.SetApartmentState(ApartmentState.STA);
        _pumpThread.Start();

        ready.Wait(TimeSpan.FromSeconds(5));
    }

    private void PumpAsync(ManualResetEventSlim ready)
    {
        try
        {
            _pumpThreadId = NativeMethods.GetCurrentThreadId();
            _callback = OnWinEvent;

            _hook = NativeMethods.SetWinEventHook(
                NativeMethods.EVENT_SYSTEM_FOREGROUND,
                NativeMethods.EVENT_SYSTEM_FOREGROUND,
                nint.Zero,
                _callback,
                idProcess: 0,
                idThread: 0,
                NativeMethods.WINEVENT_OUTOFCONTEXT | NativeMethods.WINEVENT_SKIPOWNPROCESS);

            if (_hook == nint.Zero)
            {
                _onError(new InvalidOperationException(
                    "SetWinEventHook failed; foreground monitoring is unavailable."));
                return;
            }
        }
        finally
        {
            ready.Set();
        }

        while (NativeMethods.GetMessage(out var msg, nint.Zero, 0, 0) > 0)
        {
            NativeMethods.TranslateMessage(ref msg);
            NativeMethods.DispatchMessage(ref msg);
        }
    }

    private void OnWinEvent(
        nint hWinEventHook,
        uint eventType,
        nint hwnd,
        int idObject,
        int idChild,
        uint dwEventThread,
        uint dwmsEventTime)
    {
        // idObject != OBJID_WINDOW (0) means the event is about a child element, not the
        // window itself. Acting on those produces duplicate activations for one app switch.
        if (eventType != NativeMethods.EVENT_SYSTEM_FOREGROUND || hwnd == nint.Zero || idObject != 0)
        {
            return;
        }

        try
        {
            NativeMethods.GetWindowThreadProcessId(hwnd, out var pid);
            if (pid == 0 || pid == _ownProcessId)
            {
                return;
            }

            var path = NativeMethods.TryGetProcessPath(pid);

            // The process may have exited between the event and this lookup. That is an
            // ordinary race, not a fault: report what we have rather than dropping the
            // activation entirely, because the file name alone may still match a policy.
            var fileName = path is not null
                ? Path.GetFileName(path)
                : SafeProcessName(pid);

            if (string.IsNullOrEmpty(fileName))
            {
                return;
            }

            _onChange(new ForegroundChange(
                fileName.ToLowerInvariant(),
                path,
                pid,
                NativeMethods.GetWindowTitle(hwnd)));
        }
        catch (Exception ex)
        {
            // A callback that throws crosses back into unmanaged code and takes the process
            // with it. Nothing may escape here.
            _onError(ex);
        }
    }

    private static string? SafeProcessName(uint pid)
    {
        try
        {
            using var process = Process.GetProcessById((int)pid);
            return process.ProcessName + ".exe";
        }
        catch (ArgumentException)
        {
            return null;   // Already gone.
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>Reports the currently focused application, for the initial state at startup.</summary>
    public ForegroundChange? Current()
    {
        var hwnd = NativeMethods.GetForegroundWindow();
        if (hwnd == nint.Zero)
        {
            return null;
        }

        NativeMethods.GetWindowThreadProcessId(hwnd, out var pid);
        if (pid == 0 || pid == _ownProcessId)
        {
            return null;
        }

        var path = NativeMethods.TryGetProcessPath(pid);
        var fileName = path is not null ? Path.GetFileName(path) : SafeProcessName(pid);

        return string.IsNullOrEmpty(fileName)
            ? null
            : new ForegroundChange(
                fileName.ToLowerInvariant(),
                path,
                pid,
                NativeMethods.GetWindowTitle(hwnd));
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        if (_hook != nint.Zero)
        {
            NativeMethods.UnhookWinEvent(_hook);
            _hook = nint.Zero;
        }

        if (_pumpThreadId != 0)
        {
            NativeMethods.PostThreadMessageW(_pumpThreadId, NativeMethods.WM_QUIT, 0, 0);
        }

        _pumpThread?.Join(TimeSpan.FromSeconds(2));
        _callback = null;
    }
}
