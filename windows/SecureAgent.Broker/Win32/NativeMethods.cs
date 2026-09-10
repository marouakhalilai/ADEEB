using System.Runtime.InteropServices;
using System.Text;

namespace SecureAgent.Broker.Win32;

/// <summary>
/// P/Invoke declarations for the broker.
/// </summary>
/// <remarks>
/// Everything here is Win32 because the corresponding managed API either does not exist or
/// does not work from a background process. Kept in one place so the unmanaged surface of
/// the product is auditable at a glance.
/// </remarks>
internal static partial class NativeMethods
{
    internal const uint EVENT_SYSTEM_FOREGROUND = 0x0003;
    internal const uint WINEVENT_OUTOFCONTEXT = 0x0000;
    internal const uint WINEVENT_SKIPOWNPROCESS = 0x0002;

    internal const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    /// <summary>Callback invoked when a watched window event fires.</summary>
    internal delegate void WinEventProc(
        nint hWinEventHook,
        uint eventType,
        nint hwnd,
        int idObject,
        int idChild,
        uint dwEventThread,
        uint dwmsEventTime);

    /// <summary>
    /// Installs an out-of-context event hook.
    /// </summary>
    /// <remarks>
    /// Out-of-context means the callback runs in our process rather than being injected into
    /// the target — essential here, because injecting a security agent into every
    /// application it watches would be both a stability and a trust disaster. The trade-off
    /// is that the installing thread must pump messages, which is why the watcher owns a
    /// dedicated thread with a message loop.
    /// </remarks>
    [LibraryImport("user32.dll", SetLastError = true)]
    internal static partial nint SetWinEventHook(
        uint eventMin,
        uint eventMax,
        nint hmodWinEventProc,
        WinEventProc lpfnWinEventProc,
        uint idProcess,
        uint idThread,
        uint dwFlags);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool UnhookWinEvent(nint hWinEventHook);

    [LibraryImport("user32.dll")]
    internal static partial nint GetForegroundWindow();

    [LibraryImport("user32.dll", SetLastError = true)]
    internal static partial uint GetWindowThreadProcessId(nint hWnd, out uint lpdwProcessId);

    // Buffer-filling calls take a raw pointer: the source generator cannot marshal an
    // [Out] char[] without runtime marshalling disabled assembly-wide, which is a far more
    // invasive change than confining the pointer to a wrapper below.
    [LibraryImport("user32.dll", EntryPoint = "GetWindowTextW", SetLastError = true)]
    internal static unsafe partial int GetWindowText(nint hWnd, char* lpString, int nMaxCount);

    [LibraryImport("user32.dll", EntryPoint = "GetWindowTextLengthW", SetLastError = true)]
    internal static partial int GetWindowTextLength(nint hWnd);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial nint OpenProcess(
        uint dwDesiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
        uint dwProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseHandle(nint hObject);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static unsafe partial bool QueryFullProcessImageName(
        nint hProcess,
        uint dwFlags,
        char* lpExeName,
        ref uint lpdwSize);

    // ---- message loop ----

    [StructLayout(LayoutKind.Sequential)]
    internal struct MSG
    {
        internal nint hwnd;
        internal uint message;
        internal nint wParam;
        internal nint lParam;
        internal uint time;
        internal int ptX;
        internal int ptY;
    }

    [LibraryImport("user32.dll", EntryPoint = "GetMessageW")]
    internal static partial int GetMessage(out MSG lpMsg, nint hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

    [LibraryImport("user32.dll", EntryPoint = "TranslateMessage")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool TranslateMessage(ref MSG lpMsg);

    [LibraryImport("user32.dll", EntryPoint = "DispatchMessageW")]
    internal static partial nint DispatchMessage(ref MSG lpMsg);

    [LibraryImport("user32.dll")]
    internal static partial void PostQuitMessage(int nExitCode);

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool PostThreadMessageW(uint idThread, uint Msg, nint wParam, nint lParam);

    internal const uint WM_QUIT = 0x0012;

    [LibraryImport("kernel32.dll")]
    internal static partial uint GetCurrentThreadId();

    // ---- idle detection, for continuous-mode pacing ----

    [StructLayout(LayoutKind.Sequential)]
    internal struct LASTINPUTINFO
    {
        internal uint cbSize;
        internal uint dwTime;
    }

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetLastInputInfo(ref LASTINPUTINFO plii);

    /// <summary>Milliseconds since the last keyboard or mouse input, machine-wide.</summary>
    internal static uint GetIdleMilliseconds()
    {
        var info = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
        return GetLastInputInfo(ref info)
            ? unchecked((uint)Environment.TickCount - info.dwTime)
            : 0;
    }

    /// <summary>Reads a window's title, capped at the length the audit schema accepts.</summary>
    internal static string? GetWindowTitle(nint hWnd)
    {
        var length = GetWindowTextLength(hWnd);
        if (length <= 0)
        {
            return null;
        }

        // Cap the buffer. A window can declare a title of essentially any length, and this
        // string is attacker-controlled input on its way to an audit record.
        var capacity = Math.Min(length, 512) + 1;
        var buffer = new char[capacity];

        int copied;
        unsafe
        {
            fixed (char* p = buffer)
            {
                copied = GetWindowText(hWnd, p, capacity);
            }
        }

        return copied > 0 ? new string(buffer, 0, copied) : null;
    }

    /// <summary>
    /// Resolves a process id to its full executable path.
    /// </summary>
    /// <remarks>
    /// Uses <c>PROCESS_QUERY_LIMITED_INFORMATION</c>, which is the least privilege that
    /// answers the question and, unlike the fuller access rights, succeeds against elevated
    /// processes without the broker itself being elevated.
    /// </remarks>
    internal static string? TryGetProcessPath(uint processId)
    {
        var handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
        if (handle == nint.Zero)
        {
            // The process exited between the event firing and this call. Normal, not an error.
            return null;
        }

        try
        {
            var capacity = 1024u;
            var buffer = new char[capacity];

            unsafe
            {
                fixed (char* p = buffer)
                {
                    // On success the API writes the used length back into capacity.
                    return QueryFullProcessImageName(handle, 0, p, ref capacity)
                        ? new string(buffer, 0, (int)capacity)
                        : null;
                }
            }
        }
        finally
        {
            CloseHandle(handle);
        }
    }
}
