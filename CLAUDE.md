# CLAUDE.md — Anti-Google project brief

Orientation for Claude Code working in this repo. Read fully before changing anything. The
**hard rules** are non-negotiable.

---

## 0) What this is

A Windows desktop app (C# / **.NET 9** / **WPF**, MVVM via CommunityToolkit.Mvvm) that removes
Google telemetry from a Windows machine across four layers — hosts file, Windows Firewall,
services & scheduled tasks, Chrome/Edge registry policy — and **states the cost of every rule in
plain language before applying it**. Ships armed on the Aggressive profile. Every change is
journalled and reversible.

Note: **.NET 9, not 8.** TFM is `net9.0-windows` throughout.

---

## 1) HARD RULES

1. **Every rule must declare its breakage.** A `BlockRule` that is `DefaultEnabled` with an empty
   `Breaks` list is a test failure, not an oversight. This is the entire product thesis: the user
   is told the cost before paying it. If you add a rule, write its `Breakage` entries honestly —
   including when the cost is a **security** loss, not a convenience loss.
2. **Journal the reverse BEFORE mutating.** Every engine writes its `JournalEntry` first, then
   changes the OS. Killing the process mid-apply must still leave a complete way back. Never
   reorder this.
3. **Revert must be exact, not best-effort.** Record the *previous* value, including the
   "this value did not exist" case (`PreviousValue == null` → delete on revert). Never restore a
   guessed default.
4. **Never restore the hosts file from the backup on revert.** Strip the managed block from the
   *current* file instead. Restoring a stale backup silently destroys user edits made after apply.
   There is a test (`RevertKeepsUserEntriesAddedAfterApply`) — do not "fix" it away.
5. **Sinkhole IPv4 AND IPv6.** Every hosts domain gets both `0.0.0.0` and `::`. A v4-only blocklist
   is routinely defeated by AAAA fallback.
6. **Never fetch Google's IP ranges at runtime.** A privacy tool that phones `gstatic.com` to ask
   which addresses to block is self-defeating and makes behaviour depend on a file Google controls.
   `GoogleIpRanges` is static by design.
7. **The app manifest stays `asInvoker`.** It must boot, scan and preview with no admin. Only Apply
   and Restore check elevation. Do not switch to `requireAdministrator` for convenience.
8. **Consent-gated rules are never armed by a profile switch.** `RequiresExplicitConsent` rules
   demand a typed `ARM` and must stay off in `ApplyProfile`. Enforced by a test.
9. **Do not weaken the preflight refusals.** In particular, blocking Google Public DNS when 8.8.8.8
   *is* the machine's resolver takes the whole internet down. That is a `Blocker`, not a warning.
10. **Honesty over polish.** If something cannot be verified, say so — and say precisely what was
    and was not checked. Direct pushback beats reassurance in this codebase.

---

## 2) Architecture

### `AntiGoogle.Core` (class library, no UI deps)
- `Model/` — `BlockRule` (declarative: what to remove + what it costs), `Breakage`
  (What / Severity / Detail), `RegistryPolicy`, `PlannedChange` / `ChangePlan` / `ApplyReport`.
- `Catalog/` — `GoogleEndpoints` (domain groups), `GoogleIpRanges` (Core / PublicDns /
  CloudPlatform, deliberately split), `RuleCatalog` (~23 rules, the editorial heart of the app).
- `Engines/` — `HostsFileEngine`, `FirewallEngine`, `ServiceEngine`, `ScheduledTaskEngine`,
  `RegistryPolicyEngine`. Each implements `IRevertEngine.RevertAsync` and must be **idempotent**.
- `Journal/` — `ChangeJournal` (atomic write: temp + flush-to-disk + `File.Replace`),
  `JournalEntry` (one reversible fact).
- `Safety/Preflight` — elevation, Google-DNS-as-resolver, hosts writability, pre-existing Chrome
  policy, domain join, firewall service state. Returns `Blocker` findings that mark rules
  `Refused` rather than attempting them.
- `Discovery/GoogleAppScanner` — finds Google/Chromium/Electron binaries. The Electron tell is a
  sibling `icudtl.dat` / `resources.pak`.
- `ProtectionService` — orchestrates plan → confirm → apply → journal → revert.

### `AntiGoogle.App` (WPF)
- `Theme.xaml` — cold dark palette + the single type/radius scale; severity colours are the
  loudest thing on screen by design. Every interactive control carries hover, **pressed** and
  **keyboard-focus** states — the default WPF focus adorner is invisible on `#0E1013`.
- `Logo.xaml` — the ONE definition of the logo (see §7). Merged into `App.xaml`.
- `MainWindow.xaml` — custom title bar + nav rail + six pages + three overlays. **Pages are plain
  elements with `Visibility` bound through `IndexToVisibility` — NOT a `TabControl`.** See §4.
- `MainWindow.xaml.cs` — `WindowChrome` custom chrome, caption buttons, maximised-overhang
  compensation, Windows 11 Snap Layouts. See §6.
- `ViewModels/MainViewModel` — rules, live degradation recompute, confirm overlay, typed-consent
  overlay, containment, journal, `IsOverlayOpen` gating.

### `tools/AntiGoogle.IconGen` (console, not in the app build path)
Renders `Logo.xaml` to `src/AntiGoogle.App/Assets/AntiGoogle.ico` + PNGs. Run by hand after any
logo change: `dotnet run --project tools/AntiGoogle.IconGen`.

### Data locations
`%ProgramData%\AntiGoogle\` → `journal.json`, `settings.json`, `backups\`, `logs\`.
ProgramData not AppData: the changes are machine-wide, so a per-user journal would be invisible to
another admin trying to undo them.

---

## 3) Build / run / verify

```bash
dotnet build AntiGoogle.sln
dotnet run --project src/AntiGoogle.App
dotnet run --project tests/AntiGoogle.Verify
```

### Two test runners, one set of assertions
`dotnet test` works (39 checks) — but only where **Smart App Control** is not enforced. When it is,
it blocks Microsoft-signed `testhost.exe` from loading unsigned test assemblies (`0x800711C7`) and
vstest then discovers zero tests in *any* project on the machine, reporting success as loudly as a
real pass. Check `HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy` →
`VerifiedAndReputablePolicyState` before debugging a suite that has gone quiet.

`tests/AntiGoogle.Verify` is a console runner that `<Compile Include>`-links the *same* source files
from `AntiGoogle.Core.Tests` and executes `[Fact]`/`[Theory]` by reflection. It exists because SAC
can be re-enabled at any time, and it needs no signed test host. One copy of every assertion, two
ways to run it — **keep them in sync**; Core has `InternalsVisibleTo` for *both* assembly names, so
update both if you rename either. If SAC is ever switched back on, `dotnet test` silently reports
zero tests again and `AntiGoogle.Verify` is the fallback.

### Verifying the UI actually works
`dotnet build` succeeding proves nothing about XAML. Launch it and drive it with **UI Automation**
(`System.Windows.Automation`) — synthetic mouse clicks do not reliably reach the window, and
`PrintWindow(hwnd, hdc, 2)` captures the window content even when another window overlaps it.

**`PrintWindow` CANNOT reveal off-screen clipping.** It captures the window's own bitmap including
any part hanging off the monitor, so a maximised window whose close button is 8px past the screen
edge looks perfectly flush in the capture. That is exactly how the maximised-overhang bug in §6
survived a visual check. For anything about on-screen position, measure
`AutomationElement.Current.BoundingRectangle` against `Screen.PrimaryScreen.WorkingArea`.

**The harness kills detached processes when a command ends.** Launch, drive, and screenshot in a
*single* PowerShell invocation, or the app will appear to have crashed when it simply got cleaned up.

---

## 4) Debugging history — do not relearn these

- **`TabControl` with a stripped template destroys the automation tree.** The original layout used
  `<TabControl>` with a `ControlTemplate` that was just a `ContentPresenter`. It looked correct and
  built clean, but **no control on any page was exposed to accessibility tools** — a screen reader
  user could not operate an app that makes destructive system changes. Replaced with plain elements
  whose `Visibility` binds through `IndexToVisibility`. Collapsed elements are correctly excluded
  from the automation tree. Do not reintroduce the TabControl.
- **`.GetAwaiter().GetResult()` on the UI thread froze the window.** `HostsFileEngine` flushed the
  DNS cache synchronously during Apply, blocking the UI for up to 15s. `Apply` is now `ApplyAsync`
  and the flush is awaited.
- **`Disable-ScheduledTask -TaskName "\Full\Path"` silently matches nothing.** The cmdlets take
  `-TaskPath` and `-TaskName` as separate parameters. `SplitTaskPath` handles it; pipe from
  `Get-ScheduledTask`.
- **Google's updater services carry a version suffix** (`GoogleUpdaterService152.0.7933.0`) that
  changes with every Chrome release. Match by prefix (`GoogleUpdaterService*`) via registry
  enumeration under `HKLM\SYSTEM\CurrentControlSet\Services` — exact names are useless.
- **Literal NUL bytes written into a `.cs` file** produce `Split('')`, which is a parse error that
  the Edit tool then cannot match. Use a named `const char` initialised to `'\u0000'` (see `RegistryPolicyEngine.MultiStringSeparator`).
- **Duplicate `RegistryPolicy` entries in one rule** make revert correctness depend on journal
  replay order. Keep the list deduplicated.
- **Containment has no catalog rule**, so its degradation would never reach the impact report.
  `ContainmentWarningRule` synthesises one. If you add another runtime-generated change type, give
  it a synthetic warning too — silence there breaks hard rule #1.
- **The overlays used to live inside the content column**, so the nav rail stayed live during an
  Apply. You could change pages mid-confirmation and — much worse — click "Restart as
  Administrator", which calls `Application.Shutdown()`, while a destructive operation was running.
  They are now children of the ROOT grid at row 1 spanning both columns, and the rail and content
  bind `IsEnabled` to `!IsOverlayOpen` (a scrim alone never stopped Tab). They deliberately do NOT
  cover the title bar — close must stay reachable during a long apply.
- **`MaxHeight` on the confirm card made it unusable at the window's own minimum size.** With
  `MinHeight="640"` and a `MaxHeight="680"` centred card, the DockPanel arranged the accept
  checkbox and the Apply/Cancel buttons off-screen with no way to scroll to them — the gate on the
  destructive action simply could not be reached. Use `Margin` and let the inner `ScrollViewer`
  absorb overflow. Never put a fixed `MaxHeight` on a modal taller than `MinHeight`.
- **`TextWrapping` is inert inside a horizontal `StackPanel`** (it measures at infinite width), so
  the longest and most important breakage headlines were being silently clipped. Severity-label +
  text pairs are `Grid`s with `Auto`/`*` columns.
- **`x:Name="Content"` on a child of a `Window` shadows `ContentControl.Content`** (CS0108). Named
  `ContentArea`.
- **A `.ico` referenced by `Window.Icon` must ALSO be a `<Resource>` in the csproj.**
  `<ApplicationIcon>` only sets the *file* icon; `Window.Icon` resolves its URI against assembly
  resources. Missing, it throws `TypeConverterMarkupExtension` at window construction — which
  reports a line number in `MainWindow.xaml` and says nothing about the icon. Also note the WPF
  build uses a `_wpftmp` shadow project: after a csproj change affecting XAML, a suspiciously fast
  incremental build may not have picked it up. Rebuild before concluding the fix failed.
- **`System.IO` is NOT in the implicit usings for a `UseWPF` project**, and `System.Windows.Shapes.Path`
  collides with `System.IO.Path`. `IconGen` imports `System.IO` explicitly and aliases `IOPath`.
- **XML comments cannot contain `--`**, so a csproj comment containing `dotnet run --project`
  is an MSB4025 parse error.
- **Exception messages from XAML load are useless without the inner chain.** `App.OnUnhandledException`
  now walks `InnerException` up to 8 deep; the outer `TypeConverterMarkupExtension` text names
  neither the resource nor the reason.
- **An implicit `<Style TargetType="TextBlock">` must NOT set `Foreground` or `FontSize`.** It applies
  inside control templates too — including the TextBlock a `ContentPresenter` generates for string
  Content — and a style setter outranks property inheritance, so it silently overrides every
  control's own values. Measured before the fix: `DangerButton`'s `#120706` label rendered
  `#E6E9EF` (**2.53:1** on the accent — the app's primary destructive action failing AA),
  GhostButton and unselected NavItem lost `TextMuted`, and ToolTip text rendered `#E6E9EF` on
  WPF's default `#F1F2F7` popup background at **1.09:1**, i.e. invisible. Set them on the Window
  and let them inherit. `FontFamily` is safe to keep because CaptionButton overrides it locally.
  Note popups do NOT inherit from the Window, so `ToolTip` needs its own style.
- **`Window.WindowState` is one transition STALE inside a `WM_WINDOWPOSCHANGED` hook.** The hook
  runs before `DefWindowProc`, and it is `DefWindowProc` that emits the `WM_SIZE` WPF updates the
  DP from. At the maximise the hook read `Normal` while `IsZoomed()` was already true, took the
  early-exit and zeroed the margin — so the overhang compensation never ran at all. It self-corrected
  after a minimise/restore round trip, which is why it looked fine by hand. Use `IsZoomed()` /
  `IsIconic()`, and add an `OnStateChanged` pass for the settled state.
- **`Border` and `Panel` (Grid, StackPanel, Canvas) have NO automation peer.** `AutomationProperties.*`
  on them is silently dead code — a live region on a `Border` announces nothing. Put it on a
  `TextBlock`. And WPF does **not** raise `LiveRegionChanged` when a bound `Text` changes; it must
  be raised by hand (see `MainWindow.RaiseLiveRegionChanged`).
- **`ToolTipService.ShowOnDisabled` defaults to false**, so a tooltip explaining *why* a button is
  disabled can never be seen. The four elevation-gated buttons no longer bind `IsEnabled`; the view
  model already guards both paths and now reports the reason through the result banner.
- **`DockPanel` puts its fill child LAST in markup**, so a docked-bottom accept checkbox is read
  BEFORE the list it refers to. The confirm and consent overlays use a 3-row `Grid` so markup order
  matches visual order.
- **Hosts revert normalises trailing whitespace to a single CRLF.** Byte-identity round-trip tests
  must use a fixture that already ends in exactly one CRLF, or they fail for a non-bug.

---

## 5) Editorial policy for `Breaks`

This is the product. Write like you are warning a friend, not filing a ticket.

- Name the **user-visible capability**, not the mechanism. "Paid streaming in Chrome", not
  "Widevine CDM component update failure".
- Say what they will actually observe, including that it may be **silent** ("notifications simply
  never arrive").
- Flag **security** losses as loudly as convenience ones. Disabling Chrome updates is `Severe`.
- Give the workaround where one exists.
- Where a rule is a genuine **trade** rather than a win (the DoH rule), say that explicitly.
- A severe breakage with a stub `Detail` under 40 characters fails a test.

---

## 6) The custom title bar

`WindowChrome`, with **`WindowStyle` left at its default `SingleBorderWindow`**. Do not set
`WindowStyle="None"` — keeping the real window styles is what gives drag, double-click-to-maximise,
Aero Snap, the Alt+Space menu, the native drop shadow and Windows 11 rounded corners for free.
`ResizeMode` must stay `CanResize` or Snap Layouts will not appear.

Two mechanisms, and it matters which one is load-bearing:

- **`UpdateMaximizedPadding` is the one that matters.** WindowChrome zeroes the non-client area via
  `WM_NCCALCSIZE`, so the resize frame a normal maximised window hides off-screen becomes *our*
  client area: maximised, the window sits at `(-8,-8)`, the title bar loses 8 of its 40px and the
  close button's corner is off the screen. The margin is *differenced* from the real window rect
  against the monitor work area, so it is correct at any DPI, on any monitor, with the taskbar on
  any edge, and collapses to zero when there is no overhang.
- **`WM_GETMINMAXINFO` is defence-in-depth only.** On .NET 9 WPF's `WindowChromeWorker` already
  clamps maximise to the work area — the handler measurably changes nothing on a single-monitor
  bottom-taskbar setup. It is kept because it is the only thing setting `ptMinTrackSize` once
  `handled = true` suppresses WPF's own Min/Max enforcement, and for the multi-monitor / side
  taskbar / mixed-DPI cases that could not be tested here. If you delete one, delete this one.

Snap Layouts works by returning `HTMAXBUTTON` from `WM_NCHITTEST`. The cost: the OS now owns that
button's input, so WPF never fires `MouseEnter`/`Click` on it and hover/press/invoke are hand-driven
from `WM_NCMOUSEMOVE` / `WM_NCLBUTTONDOWN` / `WM_NCLBUTTONUP`. `TrackMouseEvent` with
**`TME_NONCLIENT`** is the easily-missed piece — without it `WM_NCMOUSELEAVE` never arrives and the
highlight stays lit forever.

Caption glyphs are Segoe Fluent Icons `E921` / `E922` / `E923` / `E8BB`, verified present on this
machine. The maximise glyph is set in `CaptionMaximizeButton`'s **Style**, never inline — a locally
set `Content` outranks a Style trigger and would freeze the glyph.

---

## 7) The logo

"Null Route": an outbound arrow arrested by a solid slab it never reaches. Defined once, in
`src/AntiGoogle.App/Logo.xaml`, as three `Geometry` resources on a 64×64 viewbox — canonical, a
small-size frame with a wider gap for the 16/32 ICO entries, and a full-bleed-slab variant for
large display. `IconGen` reads that same file, so the window mark and the taskbar icon cannot drift.

Ink bounds are exactly `(4,4,56,56)` and every axis-aligned edge is divisible by 4, so at 16px they
land on whole pixels with no antialiasing on any straight edge.

**Do not**: mirror it (the arrow then enters from the right and reads as *inbound*), place it in a
badge/ring/tile/rounded-square (that is Google's app-icon grammar regardless of the glyph, and it
would eat the padding the geometry carries), stroke it, rotate it, or use more than two tonal
values. Accent `#FF5A4E` on dark; ink on light — `#FF5A4E` on white is ~3:1 and fails at icon scale.

Known tradeoff, scored 4/10 on originality by the judging pass: at small sizes it has a family
resemblance to the media "skip to end" glyph. The differentiators are the slab's height advantage
over the arrowhead and the 16-unit shaft (media glyphs use a bare triangle and a bar of equal or
lesser height). Do not shorten the shaft or equalise the heights to "balance" it.

---

## 8) Open gaps / roadmap

1. **Elevated end-to-end pass still outstanding — but much narrower now.**
   `ProtectionService.ApplyAsync` / `RevertAllAsync` ARE covered unelevated by
   `tests/AntiGoogle.Core.Tests/ProtectionServiceTests.cs`: full BuildPlan → Apply → RevertAll round
   trip asserted byte-identical for the hosts file and exact for HKCU registry values, journal
   emptied, preflight refusal proven to leave the target untouched, apply proven to continue past a
   failing engine, containment's synthetic warning proven to reach `plan.Degradations`, and hard
   rule #2 proven from BOTH sides (a failed write still leaves a durable reverse; an unwritable
   journal prevents the write entirely).

   What that suite **cannot** reach, because the OS refuses it without admin — all measured, not assumed:
   - `ServiceEngine` / `ScheduledTaskEngine` / `FirewallEngine` mutate+revert (`sc.exe` error 5,
     `Disable-ScheduledTask` access denied, `New-NetFirewallRule` error 5)
   - the real hosts file's ACL path (`File.Replace` on a SYSTEM-owned file, and the `File.Copy` fallback)
   - HKLM writes under `SOFTWARE\Policies` via `RegistryView.Registry64`
   - the real `Preflight` findings, above all the Google-DNS-as-resolver Blocker (hard rule #9)

   Manual pass required, ideally on a throwaway VM: elevated Apply → verify hosts + firewall group +
   service start types + task states → Restore → verify byte-identical and journal empty.

   **`FirewallEngine` takes its rule group as a constructor parameter and tests MUST pass a distinct
   one.** `RevertAllAsync` sweeps the entire group; a suite run from an elevated shell against the
   default group would delete the user's real Anti-Google firewall rules.
2. Per-rule revert exists in `ProtectionService.RevertRuleAsync` but is not wired to the UI.
3. Scheduled re-apply / drift detection (settings say what you *want*; journal says what *is*) —
   the comparison is not surfaced anywhere yet.
4. No signed build. Signing would make the suite immune to Smart App Control being re-enabled.
5. Snap Layouts' hover flyout is still eyeball-only — it needs a real dwelling cursor, and synthetic
   input does not reliably reach the window. The hit-test path is exercised and cannot crash.
