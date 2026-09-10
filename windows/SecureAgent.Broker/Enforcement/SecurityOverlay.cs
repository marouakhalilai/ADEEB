using System.Drawing;
using System.Runtime.Versioning;
using System.Windows.Forms;

namespace SecureAgent.Broker.Enforcement;

/// <summary>
/// The full-screen barrier shown when access is denied.
/// </summary>
/// <remarks>
/// <para>
/// This is the MVP's entire enforcement mechanism, deliberately. It is fully reversible,
/// destroys no work, and cannot lose a document — unlike terminating the process, which the
/// product does not do by default and which would generate support load out of all
/// proportion to the benefit.
/// </para>
/// <para>
/// Two behaviours matter more than they look:
/// </para>
/// <list type="bullet">
/// <item>
/// It never steals keyboard focus. An overlay that grabs focus would swallow keystrokes the
/// user is mid-way through typing into whatever was in front, which turns a security prompt
/// into data loss.
/// </item>
/// <item>
/// It covers every monitor. Covering only the primary display leaves the protected window
/// perfectly usable on a second screen, which is not a partial defence but no defence.
/// </item>
/// </list>
/// <para>
/// An overlay is a barrier, not a boundary. Someone with local administrator rights can
/// close it — that limit is stated in the threat model rather than papered over here.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class SecurityOverlay : IDisposable
{
    private readonly List<Form> _screens = [];
    private bool _disposed;

    /// <summary>Raised when the user asks to verify. Runs on the UI thread.</summary>
    public event EventHandler? VerifyRequested;

    /// <summary>Whether the overlay is currently on screen.</summary>
    public bool IsVisible => _screens.Count > 0;

    /// <summary>
    /// Shows the overlay across every display.
    /// </summary>
    /// <param name="appName">The application being protected.</param>
    /// <param name="reason">Short, non-technical explanation drawn from a fixed set.</param>
    public void Show(string appName, string reason)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (IsVisible)
        {
            return;
        }

        foreach (var screen in Screen.AllScreens)
        {
            var form = BuildForm(screen, appName, reason);
            _screens.Add(form);

            // Show without activating, so focus stays where the user left it.
            NativeOverlay.ShowNoActivate(form.Handle);
            form.Visible = true;
        }
    }

    private Form BuildForm(Screen screen, string appName, string reason)
    {
        var form = new Form
        {
            FormBorderStyle = FormBorderStyle.None,
            StartPosition = FormStartPosition.Manual,
            Bounds = screen.Bounds,
            TopMost = true,
            ShowInTaskbar = false,
            BackColor = Color.FromArgb(16, 15, 22),
            Opacity = 0.94,
            // Do not steal focus from whatever the user was typing into.
            KeyPreview = false,
        };

        var title = new Label
        {
            Text = "Locked by SecureAgent",
            ForeColor = Color.FromArgb(237, 236, 242),
            Font = new Font("Segoe UI", 28F, FontStyle.Bold),
            AutoSize = true,
        };

        var detail = new Label
        {
            Text = $"{appName} is protected.{Environment.NewLine}{reason}",
            ForeColor = Color.FromArgb(181, 178, 192),
            Font = new Font("Segoe UI", 13F),
            AutoSize = true,
            TextAlign = ContentAlignment.MiddleCenter,
        };

        var verify = new Button
        {
            Text = "Verify to continue",
            Font = new Font("Segoe UI", 12F),
            Size = new Size(220, 44),
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(168, 31, 50),
            ForeColor = Color.White,
        };
        verify.FlatAppearance.BorderSize = 0;
        verify.Click += (_, _) => VerifyRequested?.Invoke(this, EventArgs.Empty);

        // Only the primary display carries the controls; the others are plain covers, so a
        // multi-monitor setup does not show three competing buttons.
        if (screen.Primary)
        {
            form.Controls.Add(title);
            form.Controls.Add(detail);
            form.Controls.Add(verify);

            void Layout()
            {
                var cx = form.ClientSize.Width / 2;
                var cy = form.ClientSize.Height / 2;
                title.Location = new Point(cx - (title.Width / 2), cy - 120);
                detail.Location = new Point(cx - (detail.Width / 2), cy - 40);
                verify.Location = new Point(cx - (verify.Width / 2), cy + 60);
            }

            form.Shown += (_, _) => Layout();
            form.Resize += (_, _) => Layout();
        }

        return form;
    }

    /// <summary>Removes the overlay from every display.</summary>
    public void Hide()
    {
        foreach (var form in _screens)
        {
            form.Close();
            form.Dispose();
        }

        _screens.Clear();
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        Hide();
        _disposed = true;
    }
}
