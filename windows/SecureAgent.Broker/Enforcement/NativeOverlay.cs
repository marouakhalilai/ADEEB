using System.Runtime.InteropServices;

namespace SecureAgent.Broker.Enforcement;

/// <summary>
/// Window-style adjustments the managed <c>Form</c> API cannot express.
/// </summary>
/// <remarks>
/// WinForms has no property for "show on top without taking focus". Setting
/// <c>TopMost</c> alone activates the window, which steals keystrokes from whatever the
/// user was typing into — a security prompt that eats input is a data-loss bug.
/// </remarks>
internal static partial class NativeOverlay
{
    private const int GWL_EXSTYLE = -20;
    private const int WS_EX_NOACTIVATE = 0x08000000;
    private const int WS_EX_TOOLWINDOW = 0x00000080;

    private const uint SWP_NOSIZE = 0x0001;
    private const uint SWP_NOMOVE = 0x0002;
    private const uint SWP_NOACTIVATE = 0x0010;
    private const uint SWP_SHOWWINDOW = 0x0040;

    private static readonly nint HWND_TOPMOST = new(-1);

    [LibraryImport("user32.dll", EntryPoint = "GetWindowLongPtrW", SetLastError = true)]
    private static partial nint GetWindowLongPtr(nint hWnd, int nIndex);

    [LibraryImport("user32.dll", EntryPoint = "SetWindowLongPtrW", SetLastError = true)]
    private static partial nint SetWindowLongPtr(nint hWnd, int nIndex, nint dwNewLong);

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetWindowPos(
        nint hWnd, nint hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);

    /// <summary>
    /// Marks a window as topmost and non-activating, then shows it.
    /// </summary>
    /// <remarks>
    /// <c>WS_EX_NOACTIVATE</c> keeps focus where it is; <c>WS_EX_TOOLWINDOW</c> keeps the
    /// overlay out of Alt-Tab, where it would otherwise appear as a switchable window and
    /// invite the user to tab past it.
    /// </remarks>
    internal static void ShowNoActivate(nint hWnd)
    {
        var style = GetWindowLongPtr(hWnd, GWL_EXSTYLE);
        SetWindowLongPtr(hWnd, GWL_EXSTYLE, style | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW);

        SetWindowPos(
            hWnd,
            HWND_TOPMOST,
            0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
    }
}
