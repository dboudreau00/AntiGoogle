// Anti-Google — removes Google telemetry from Windows, and tells you what that breaks first.
// Copyright (C) 2026 The Anti-Google contributors
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Shell;
using System.Windows.Threading;
using AntiGoogle.App.ViewModels;

namespace AntiGoogle.App;

public partial class MainWindow : Window
{
    private HwndSource? _source;
    private bool _snapHoverActive;
    private IInputElement? _focusBeforeOverlay;

    public MainWindow()
    {
        InitializeComponent();

        var vm = new MainViewModel();
        // Subscribe BEFORE assigning DataContext so this runs before the IsEnabled bindings react
        // and disable whatever currently has focus.
        vm.PropertyChanged += OnViewModelPropertyChanged;
        DataContext = vm;
    }

    // =========================================================================
    // Focus and screen-reader announcements
    //
    // Disabling the content behind a modal keeps Tab OUT, but nothing was moving focus IN. The
    // sequence was: click Apply -> IsBusy -> ContentArea disabled -> the focused button is now
    // disabled -> WPF falls back to Keyboard.Focus(null) -> focus lands on the Window and the
    // keyboard is completely dead for the duration of a machine-wide apply.
    // =========================================================================

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (DataContext is not MainViewModel vm) return;

        switch (e.PropertyName)
        {
            // WPF does NOT raise LiveRegionChanged when a bound Text changes; it has to be raised
            // by hand or the live region announces nothing at all.
            case nameof(MainViewModel.BusyMessage):
                RaiseLiveRegionChanged(BusyMessageText);
                return;

            case nameof(MainViewModel.LastResult):
                RaiseLiveRegionChanged(ResultBannerText);
                return;

            case nameof(MainViewModel.IsOverlayOpen):
                MoveFocusForOverlay(vm);
                return;
        }
    }

    private void MoveFocusForOverlay(MainViewModel vm)
    {
        if (vm.IsOverlayOpen)
        {
            _focusBeforeOverlay ??= Keyboard.FocusedElement;

            // Queued at Input priority so the Visibility and IsEnabled bindings have settled —
            // focusing a still-collapsed element silently does nothing.
            Dispatcher.BeginInvoke(DispatcherPriority.Input, new Action(() =>
            {
                var host = vm.ShowConsent ? ConsentOverlay
                         : vm.ShowConfirm ? ConfirmOverlay
                         : (FrameworkElement)BusyOverlay;

                if (!host.MoveFocus(new TraversalRequest(FocusNavigationDirection.First)))
                    Keyboard.Focus(host);   // the busy overlay has no focusable children
            }));
        }
        else
        {
            var restore = _focusBeforeOverlay;
            _focusBeforeOverlay = null;

            Dispatcher.BeginInvoke(DispatcherPriority.Input, new Action(() =>
            {
                if (restore is UIElement { IsEnabled: true, IsVisible: true, Focusable: true })
                    Keyboard.Focus(restore);
            }));
        }
    }

    private static void RaiseLiveRegionChanged(UIElement? element)
    {
        if (element is null) return;
        if (!AutomationPeer.ListenerExists(AutomationEvents.LiveRegionChanged)) return;

        // FromElement returns null until a UIA client has forced peer creation, hence the fallback.
        var peer = UIElementAutomationPeer.FromElement(element)
                ?? UIElementAutomationPeer.CreatePeerForElement(element);
        peer?.RaiseAutomationEvent(AutomationEvents.LiveRegionChanged);
    }

    // =========================================================================
    // Caption buttons
    //
    // Deliberately in code-behind. Minimise/maximise/close are window chrome, not application
    // state — routing them through MainViewModel would hand the view model a Window reference
    // and buy nothing.
    // =========================================================================

    private void MinimizeButton_Click(object sender, RoutedEventArgs e)
        => SystemCommands.MinimizeWindow(this);

    private void MaximizeButton_Click(object sender, RoutedEventArgs e)
        => ToggleMaximize();

    private void CloseButton_Click(object sender, RoutedEventArgs e)
        => SystemCommands.CloseWindow(this);

    private void ToggleMaximize()
    {
        if (WindowState == WindowState.Maximized) SystemCommands.RestoreWindow(this);
        else SystemCommands.MaximizeWindow(this);
    }

    // =========================================================================
    // Message hook
    // =========================================================================

    protected override void OnSourceInitialized(EventArgs e)
    {
        // base first: this raises SourceInitialized, which is when WindowChromeWorker attaches
        // its own hook. HwndSource invokes hooks in REVERSE registration order, so adding ours
        // afterwards means ours runs first and can short-circuit WindowChrome's hit-testing for
        // the snap-layout region.
        base.OnSourceInitialized(e);

        _source = (HwndSource?)PresentationSource.FromVisual(this);
        _source?.AddHook(WndProc);

        UpdateMaximizedPadding();
    }

    /// <summary>
    /// WPF raises this once WindowState has actually settled. The WM_WINDOWPOSCHANGED hook sees a
    /// stale WindowState and, on maximise, no further WM_WINDOWPOSCHANGED follows — so without
    /// this second, settled pass the margin compensation could miss the transition entirely.
    /// </summary>
    protected override void OnStateChanged(EventArgs e)
    {
        base.OnStateChanged(e);
        UpdateMaximizedPadding();
    }

    protected override void OnClosed(EventArgs e)
    {
        // The hook is torn down with the source anyway, but removing it explicitly keeps the
        // window out of the message path during teardown.
        _source?.RemoveHook(WndProc);
        _source = null;

        if (DataContext is MainViewModel vm) vm.PropertyChanged -= OnViewModelPropertyChanged;

        base.OnClosed(e);
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        switch (msg)
        {
            case WM_GETMINMAXINFO:
                WmGetMinMaxInfo(hwnd, lParam);
                handled = true;
                break;

            case WM_WINDOWPOSCHANGED:
                // Covers maximise, restore, monitor changes, and WM_DPICHANGED (which
                // repositions the window and therefore raises this afterwards).
                UpdateMaximizedPadding();
                break;

            // ---- Windows 11 Snap Layouts ----
            case WM_NCHITTEST:
                if (IsOverMaximizeButton(lParam))
                {
                    handled = true;
                    return new IntPtr(HTMAXBUTTON);
                }
                break;

            case WM_NCMOUSEMOVE:
                // Also clears the highlight when the cursor slides off the button onto the rest
                // of the caption, where wParam becomes HTCAPTION.
                SetSnapHover(wParam.ToInt32() == HTMAXBUTTON, hwnd);
                break;

            case WM_NCMOUSELEAVE:
                SetSnapHover(false, hwnd);
                break;

            case WM_NCLBUTTONDOWN:
                if (wParam.ToInt32() == HTMAXBUTTON)
                {
                    SetMaximizeButtonHover("CaptionPressed");
                    handled = true;
                }
                break;

            case WM_NCLBUTTONUP:
                if (wParam.ToInt32() == HTMAXBUTTON)
                {
                    _snapHoverActive = false;
                    ClearMaximizeButtonHover();
                    ToggleMaximize();
                    handled = true;
                }
                break;

            case WM_NCLBUTTONDBLCLK:
                // A fast double-click on the maximise button sends DOWN, UP, DBLCLK, UP. Without
                // this the DBLCLK reaches DefWindowProc, which starts a nested modal loop for a
                // caption button we own — the second click is lost and the button can stick.
                if (wParam.ToInt32() == HTMAXBUTTON)
                {
                    handled = true;
                }
                break;

            case WM_ACTIVATE:
                // Losing activation mid-press leaves no further NC mouse messages, so clear the
                // hand-driven hover rather than leaving the button lit.
                if ((wParam.ToInt32() & 0xFFFF) == WA_INACTIVE)
                {
                    _snapHoverActive = false;
                    ClearMaximizeButtonHover();
                }
                break;
        }

        return IntPtr.Zero;
    }

    // =========================================================================
    // Constrain maximise to the monitor WORK AREA.
    //
    // Honest status: on .NET 9 this appears to change nothing — WPF's WindowChromeWorker already
    // clamps maximise to the work area by itself, and enabling or disabling this handler produces
    // an identical maximised rect. It is NOT inert though (deliberately halving ptMaxSize does
    // resize the window), so it is kept as defence-in-depth for configurations that could not be
    // tested here — second monitor, side or top taskbar, auto-hide taskbar, mixed DPI — and
    // because it is the only thing setting ptMinTrackSize once handled = true.
    //
    // It does NOT fix the maximised client overhang. See UpdateMaximizedPadding for that.
    // =========================================================================

    private void WmGetMinMaxInfo(IntPtr hwnd, IntPtr lParam)
    {
        var mmi = Marshal.PtrToStructure<MINMAXINFO>(lParam);

        var monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
        if (monitor != IntPtr.Zero)
        {
            var mi = new MONITORINFO { cbSize = Marshal.SizeOf<MONITORINFO>() };
            if (GetMonitorInfo(monitor, ref mi))
            {
                // ptMaxPosition is relative to the MONITOR's own top-left, not the desktop
                // origin. Using desktop coordinates is the classic multi-monitor bug: correct on
                // the primary display, wildly offset on every other one.
                mmi.ptMaxPosition.X = mi.rcWork.Left - mi.rcMonitor.Left;
                mmi.ptMaxPosition.Y = mi.rcWork.Top - mi.rcMonitor.Top;
                mmi.ptMaxSize.X = mi.rcWork.Right - mi.rcWork.Left;
                mmi.ptMaxSize.Y = mi.rcWork.Bottom - mi.rcWork.Top;
            }
        }

        // handled = true suppresses WPF's own WM_GETMINMAXINFO processing, which is what normally
        // enforces Window.MinWidth / MinHeight. Re-apply it here. MINMAXINFO is in PHYSICAL
        // pixels; MinWidth/MinHeight are in DIPs.
        var dpi = GetDpiForWindow(hwnd);
        var scale = dpi > 0 ? dpi / 96.0 : 1.0;

        if (MinWidth > 0 && !double.IsInfinity(MinWidth))
            mmi.ptMinTrackSize.X = (int)Math.Ceiling(MinWidth * scale);

        if (MinHeight > 0 && !double.IsInfinity(MinHeight))
            mmi.ptMinTrackSize.Y = (int)Math.Ceiling(MinHeight * scale);

        // ptMaxTrackSize is left alone on purpose. It arrives as the virtual-screen bounds;
        // clamping it to one monitor's work area would stop the user dragging the window larger
        // than a single display.

        Marshal.StructureToPtr(mmi, lParam, false);
    }

    // =========================================================================
    // THE ONE THAT ACTUALLY MATTERS.
    //
    // WindowChrome zeroes the non-client area via WM_NCCALCSIZE, so the resize frame that a
    // normal maximised window hides off-screen becomes OUR client area. Without compensation the
    // maximised window sits at (-8,-8): the title bar loses 8 of its 40px and the close button's
    // corner is literally off the screen, which breaks the throw-to-corner gesture everyone uses.
    //
    // The margin is DIFFERENCED from the actual window rect against the monitor work area rather
    // than computed from SM_CXSIZEFRAME + SM_CXPADDEDBORDER, so it is automatically correct at
    // any DPI, on any monitor, with the taskbar on any edge, and collapses to zero when there is
    // no overhang.
    // =========================================================================

    private void UpdateMaximizedPadding()
    {
        if (_source is null || Root is null) return;

        var hwnd = _source.Handle;
        if (hwnd == IntPtr.Zero) return;

        // Window.WindowState is ONE TRANSITION STALE in here. This hook runs BEFORE DefWindowProc,
        // and it is DefWindowProc's handling of WM_WINDOWPOSCHANGED that emits the WM_SIZE from
        // which WPF updates the DP. Measured on .NET 9: at the maximise the hook reads
        // WindowState == Normal while IsZoomed() is already true, takes the early-exit branch and
        // zeroes the margin — and no further WM_WINDOWPOSCHANGED arrives, so the compensation
        // never ran at all. It only self-corrected after a minimise/restore round trip, which is
        // exactly why manual testing looked fine. Ask Win32, not WPF.
        //
        // IsIconic matters too: a minimised window's rect is (-32000,-32000), which would
        // otherwise produce a ~32000-DIP nonsense margin.
        if (!IsZoomed(hwnd) || IsIconic(hwnd))
        {
            Root.Margin = default;
            return;
        }

        if (!GetWindowRect(hwnd, out var win)) return;

        var monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
        if (monitor == IntPtr.Zero) return;

        var mi = new MONITORINFO { cbSize = Marshal.SizeOf<MONITORINFO>() };
        if (!GetMonitorInfo(monitor, ref mi)) return;

        // CompositionTarget is null once the source is being disposed, and the hook is still live
        // at that point — a maximised window closing would otherwise NRE here.
        var target = _source.CompositionTarget;
        if (target is null) return;

        // Device pixels -> DIPs. M11/M22 are 1/dpiScaleX and 1/dpiScaleY.
        var toDip = target.TransformFromDevice;

        Root.Margin = new Thickness(
            Math.Max(0, (mi.rcWork.Left - win.Left) * toDip.M11),
            Math.Max(0, (mi.rcWork.Top - win.Top) * toDip.M22),
            Math.Max(0, (win.Right - mi.rcWork.Right) * toDip.M11),
            Math.Max(0, (win.Bottom - mi.rcWork.Bottom) * toDip.M22));
    }

    // =========================================================================
    // Windows 11 Snap Layouts
    //
    // Returning HTMAXBUTTON from WM_NCHITTEST is what makes the OS offer the hover-to-snap
    // flyout. The cost is that the button becomes non-client as far as Windows is concerned: WPF
    // never sees the mouse over it, so IsMouseOver stays false and Click never fires. Hover,
    // press and invoke are all hand-driven below.
    // =========================================================================

    private bool IsOverMaximizeButton(IntPtr lParam)
    {
        if (MaximizeButton is null || !MaximizeButton.IsVisible) return false;
        if (MaximizeButton.ActualWidth <= 0 || MaximizeButton.ActualHeight <= 0) return false;

        // GET_X_LPARAM / GET_Y_LPARAM must SIGN-EXTEND. The common `lParam & 0xFFFF` idiom treats
        // the coordinate as unsigned and breaks on any monitor placed left of or above the
        // primary, where screen coordinates are legitimately negative.
        var packed = lParam.ToInt64();
        var x = (short)(packed & 0xFFFF);
        var y = (short)((packed >> 16) & 0xFFFF);

        try
        {
            // PointFromScreen takes PHYSICAL device pixels and returns element-local DIPs, so it
            // handles the DPI conversion for us.
            var local = MaximizeButton.PointFromScreen(new Point(x, y));
            return new Rect(0, 0, MaximizeButton.ActualWidth, MaximizeButton.ActualHeight).Contains(local);
        }
        catch (InvalidOperationException)
        {
            // WM_NCHITTEST can arrive before the visual is connected to a PresentationSource.
            // Not an error, just too early to answer.
            return false;
        }
    }

    private void SetSnapHover(bool on, IntPtr hwnd)
    {
        if (on == _snapHoverActive) return;
        _snapHoverActive = on;

        if (!on)
        {
            ClearMaximizeButtonHover();
            return;
        }

        SetMaximizeButtonHover("CaptionHover");

        // Without TME_NONCLIENT the system never sends WM_NCMOUSELEAVE and the highlight stays
        // lit permanently after the cursor leaves the button.
        var tme = new TRACKMOUSEEVENT
        {
            cbSize = Marshal.SizeOf<TRACKMOUSEEVENT>(),
            dwFlags = TME_LEAVE | TME_NONCLIENT,
            hwndTrack = hwnd,
            dwHoverTime = 0
        };

        TrackMouseEvent(ref tme);
    }

    /// <summary>
    /// Sets LOCAL Background and Foreground on the button. Local values outrank the Style setters,
    /// and the template's IsMouseOver trigger can never be active here (WPF does not see the mouse
    /// at all while we own the hit test), so the two cannot fight. ClearValue restores the Style.
    ///
    /// Foreground matters as much as Background: the template's hover trigger brightens the glyph
    /// to Text, and driving only the background made the maximise button hover visibly differently
    /// from Minimize and Close sitting right beside it.
    /// </summary>
    private void SetMaximizeButtonHover(string backgroundKey)
    {
        if (TryFindResource(backgroundKey) is Brush background) MaximizeButton.Background = background;
        if (TryFindResource("Text") is Brush foreground) MaximizeButton.Foreground = foreground;
    }

    private void ClearMaximizeButtonHover()
    {
        MaximizeButton.ClearValue(BackgroundProperty);
        MaximizeButton.ClearValue(ForegroundProperty);
    }

    // =========================================================================
    // Win32
    //
    // DllImport rather than LibraryImport on purpose: the LibraryImport source generator emits
    // pointer-based marshalling stubs and therefore needs AllowUnsafeBlocks across the whole
    // project. Not worth enabling unsafe code app-wide for five interop calls.
    // =========================================================================

    private const int WM_GETMINMAXINFO = 0x0024;
    private const int WM_WINDOWPOSCHANGED = 0x0047;
    private const int WM_NCHITTEST = 0x0084;
    private const int WM_NCMOUSEMOVE = 0x00A0;
    private const int WM_NCLBUTTONDOWN = 0x00A1;
    private const int WM_NCLBUTTONUP = 0x00A2;
    private const int WM_NCLBUTTONDBLCLK = 0x00A3;
    private const int WM_NCMOUSELEAVE = 0x02A2;
    private const int WM_ACTIVATE = 0x0006;

    private const int WA_INACTIVE = 0;
    private const int HTMAXBUTTON = 9;

    private const uint MONITOR_DEFAULTTONEAREST = 0x00000002;
    private const uint TME_LEAVE = 0x00000002;
    private const uint TME_NONCLIENT = 0x00000010;

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT { public int X; public int Y; }

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT { public int Left; public int Top; public int Right; public int Bottom; }

    /// <summary>Five POINTs, 40 bytes on x64. Field ORDER is load-bearing.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct MINMAXINFO
    {
        public POINT ptReserved;
        public POINT ptMaxSize;
        public POINT ptMaxPosition;
        public POINT ptMinTrackSize;
        public POINT ptMaxTrackSize;
    }

    /// <summary>cbSize MUST be set before EVERY GetMonitorInfo call or it fails silently.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct MONITORINFO
    {
        public int cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;
    }

    /// <summary>
    /// 24 bytes on x64 — hwndTrack is pointer-sized, so Sequential layout inserts 4 bytes of
    /// padding after dwFlags. Do not add Pack = 1; that would break it.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct TRACKMOUSEEVENT
    {
        public int cbSize;
        public uint dwFlags;
        public IntPtr hwndTrack;
        public uint dwHoverTime;
    }

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint dwFlags);

    // Explicit W entry point: GetMonitorInfo is a macro in the headers with no unsuffixed export.
    [DllImport("user32.dll", EntryPoint = "GetMonitorInfoW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetMonitorInfo(IntPtr hMonitor, ref MONITORINFO lpmi);

    // Windows 10 1607+. Returns 0 for an invalid hwnd, hence the guard at the call site. Correct
    // here only because app.manifest declares PerMonitorV2 dpiAwareness.
    [DllImport("user32.dll")]
    private static extern uint GetDpiForWindow(IntPtr hwnd);

    [DllImport("user32.dll", EntryPoint = "TrackMouseEvent")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TrackMouseEvent(ref TRACKMOUSEEVENT lpEventTrack);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    // The authoritative window state. Window.WindowState lags by one transition inside the hook.
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsZoomed(IntPtr hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsIconic(IntPtr hWnd);
}
