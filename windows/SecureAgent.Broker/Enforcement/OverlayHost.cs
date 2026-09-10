using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Windows.Forms;

namespace SecureAgent.Broker.Enforcement;

/// <summary>
/// Owns the UI thread the overlay lives on.
/// </summary>
/// <remarks>
/// <para>
/// WinForms requires every window to be created and touched from a single STA thread that
/// pumps messages. The broker is a background worker with no UI thread of its own, so this
/// creates one and marshals every overlay operation onto it.
/// </para>
/// <para>
/// Deliberately separate from the foreground watcher's pump thread. Sharing them would mean
/// a modal Windows Hello prompt blocks the message loop that delivers foreground events, so
/// the agent would go blind for exactly as long as the user takes to authenticate.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class OverlayHost : IDisposable
{
    private readonly ManualResetEventSlim _ready = new(false);
    private Thread? _uiThread;
    private SecurityOverlay? _overlay;
    private ApplicationContext? _context;
    private bool _disposed;

    /// <summary>Starts the UI thread. Returns once it is pumping.</summary>
    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_uiThread is not null)
        {
            return;
        }

        _uiThread = new Thread(Pump)
        {
            IsBackground = true,
            Name = "SecureAgent.Overlay",
        };
        _uiThread.SetApartmentState(ApartmentState.STA);
        _uiThread.Start();

        _ready.Wait(TimeSpan.FromSeconds(5));
    }

    private void Pump()
    {
        _overlay = new SecurityOverlay();
        _context = new ApplicationContext();

        // A never-shown pump window gives Invoke a target before any overlay form exists.
        using var anchor = new Form
        {
            ShowInTaskbar = false,
            FormBorderStyle = FormBorderStyle.None,
            Opacity = 0,
        };

        // Touching Handle forces the underlying window to be created. Waiting for the Load
        // event instead would deadlock: Load fires only when a form is shown, and this one
        // never is, so the handle would never exist and every BeginInvoke would be silently
        // dropped.
        _ = anchor.Handle;

        _anchor = anchor;
        _ready.Set();

        Application.Run(_context);
    }

    private Form? _anchor;

    /// <summary>Shows the overlay. Safe to call from any thread.</summary>
    public void Show(string appName, string reason)
    {
        var anchor = _anchor;
        if (anchor is null || _overlay is null)
        {
            return;
        }

        anchor.BeginInvoke(() => _overlay.Show(appName, reason));
    }

    /// <summary>Hides the overlay. Safe to call from any thread.</summary>
    public void Hide()
    {
        var anchor = _anchor;
        if (anchor is null || _overlay is null)
        {
            return;
        }

        anchor.BeginInvoke(() => _overlay.Hide());
    }

    /// <summary>Stops the UI thread.</summary>
    public void Stop()
    {
        var anchor = _anchor;
        if (anchor is not null && _context is not null)
        {
            anchor.BeginInvoke(() =>
            {
                _overlay?.Hide();
                _context.ExitThread();
            });
        }

        _uiThread?.Join(TimeSpan.FromSeconds(2));
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        Stop();
        _overlay?.Dispose();
        _context?.Dispose();
        _ready.Dispose();
        _disposed = true;
    }
}

/// <summary>Session-level actions that have no managed equivalent.</summary>
[SupportedOSPlatform("windows")]
internal static partial class NativeSession
{
    /// <summary>
    /// Locks the workstation.
    /// </summary>
    /// <remarks>
    /// The strongest action the product takes, and the honest one: it hands enforcement to
    /// Windows rather than pretending an overlay is a boundary.
    /// </remarks>
    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool LockWorkStation();
}
