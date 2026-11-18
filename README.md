<div align="center">

<img src="src/AntiGoogle.App/Assets/logo-128.png" width="88" alt="Anti-Google" />

# Anti-Google

**Strips Google telemetry out of Windows — and tells you, in plain language, exactly what that costs you before it does anything.**

[![CI](https://github.com/dboudreau00/AntiGoogle/actions/workflows/ci.yml/badge.svg)](https://github.com/dboudreau00/AntiGoogle/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/dboudreau00/AntiGoogle?include_prereleases)](https://github.com/dboudreau00/AntiGoogle/releases)
[![Licence: GPL v3](https://img.shields.io/badge/licence-GPLv3-blue.svg)](LICENSE)
[![.NET 9](https://img.shields.io/badge/.NET-9.0-512BD4)](https://dotnet.microsoft.com/)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D4)](#)

</div>

---

<div align="center">
<img src="docs/screenshots/01-dashboard.png" width="880" alt="Anti-Google dashboard" />
<br /><sub>Every screenshot in this file is the real window, captured in a disposable Windows 11 VM. The sample files its scanner finds were planted there for the purpose.</sub>
</div>

---

## The point

Most "block Google" tools hand you a list of domains and wish you luck. When your bank's login page
stops working three weeks later, nothing connects that to the hosts file you edited.

Anti-Google inverts that. Every rule declares what it breaks, at what severity, in words you can act
on. The **Impact report** is the primary screen, not a footnote — you cannot apply anything without
first seeing the full degradation list.

> **Severe — Widevine DRM: paid streaming in Chrome**
> Widevine ships as a Chrome component from this CDN. If it is missing or expires, Netflix, Spotify
> Web, Amazon Prime and Disney+ stop playing in Chrome. This is the single most common surprise from
> aggressive Google blocking.

That is a real entry from the catalog. All 36 rules read like that.

<div align="center">
<img src="docs/screenshots/04-impact.png" width="880" alt="The Impact report, listing what will stop working" />
<br /><em>The Impact report opens with a verdict, then everything that breaks, worst first, each citing the rule that causes it.</em>
</div>

---

## Install

Grab the latest build from [**Releases**](https://github.com/dboudreau00/AntiGoogle/releases). It is a
single self-contained `.exe` — no .NET runtime needed, no installer, nothing written outside
`%ProgramData%\AntiGoogle`.

**It is unsigned.** SmartScreen will warn on first run, and Smart App Control may block it outright.
Verify the SHA-256 against `SHA256SUMS.txt` in the release, or build it yourself — the whole point of
a tool like this is that you do not have to take anyone's word for it.

---

## Four enforcement layers

Each is independent and separately reversible.

| Layer | What it does | Blind spot |
|---|---|---|
| **Hosts file** | Sinkholes domains to `0.0.0.0` **and** `::` | No wildcards; DoH walks straight past it |
| **Windows Firewall** | Outbound blocks by IP range and by program | Blunt — cannot tell telemetry from anything else |
| **Services & tasks** | Disables Google updater services and scheduled tasks | Records prior start type; restores exactly |
| **Registry policy** | Chrome/Edge enterprise policy values | Shows as "managed by your organization" in Chrome |

**On hosts semantics:** a hosts entry matches one exact name. Listing `googleapis.com` does *not*
block `fcm.googleapis.com`. Every subdomain that matters is enumerated by hand in
[`GoogleEndpoints.cs`](src/AntiGoogle.Core/Catalog/GoogleEndpoints.cs) — that is why those lists are
long and boring instead of clever.

**On DNS-over-HTTPS:** the `reg.chrome.doh` rule is load-bearing. Without it Chrome resolves names
through its own encrypted DNS and ignores every hosts entry this app writes. It is also an honest
*trade*, not a pure win: your DNS queries go back to plaintext, so your ISP can see them again. The
rule says so on its own card.

<div align="center">
<img src="docs/screenshots/02-rules.png" width="880" alt="The rules list" />
<br /><em>Every rule shows its layer, its risk tier, and how many degradations it causes.</em>
</div>

<div align="center">
<img src="docs/screenshots/03-rules-expanded.png" width="880" alt="A rule expanded to show its breakage detail" />
<br /><em>Expanded, a rule spells out each consequence and how bad it is.</em>
</div>

---

## The default profile is Aggressive

This build ships **armed**. 25 rules are enabled out of the box, blackholing `googleapis.com` and
`gstatic.com`. That breaks Google Fonts, some reCAPTCHA flows, Firebase push notifications,
Chromecast, and Android tooling. Nothing is written to your machine until you press **Apply** and
tick the confirmation, but the intent ships pre-loaded.

Two categories deliberately stay **off** even at Aggressive:

- **Content blocks** — Google Search, YouTube, Google sign-in. Removing telemetry is a different
  thing from removing your ability to use the web.
- **Safe Browsing** — disabling phishing and malware warnings is a security regression. You should
  opt into that deliberately, not inherit it from a profile.

Both, plus the IP-range sledgehammers, are gated behind a typed `ARM` confirmation.

<div align="center">
<img src="docs/screenshots/10-consent-overlay.png" width="880" alt="The typed-consent overlay" />
<br /><em>A rule that can lock you out of your network cannot be armed by a single click.</em>
</div>

---

## Getting back

The feature that matters most is the one that undoes everything.

Before any change is written, its **reverse** is recorded to a journal in
`%ProgramData%\AntiGoogle\journal.json` — the previous service start type, the previous registry
value (including "this value did not exist"), the firewall rules created, a timestamped hosts backup.
The journal is flushed to disk *before* the change is made, so killing the app mid-apply still leaves
a complete way back.

**Restore everything** replays it newest-first, then sweeps the `Anti-Google` firewall group as a
backstop in case the journal itself was lost.

Hosts revert **strips the managed block** rather than restoring the backup — restoring a stale backup
would silently discard hosts edits you made in the meantime. There is a test for that.

The journal lives in `ProgramData`, not your user profile, so another administrator can undo these
changes even if your account is gone.

<div align="center">
<img src="docs/screenshots/08-history.png" width="880" alt="History and restore, listing every recorded change" />
<br /><em>Every change, newest first, with the state it replaced. This list includes four quarantined items and the firewall rules that hold a program to this machine.</em>
</div>

<div align="center">
<img src="docs/screenshots/24-restore-dialog.png" width="423" alt="The restore confirmation dialog" />
<br /><em>Restore everything asks first, and says how many recorded changes it will reverse.</em>
</div>

<div align="center">
<img src="docs/screenshots/25-restored.png" width="880" alt="History after a restore, with nothing left to undo" />
<br /><em>Afterwards the journal is empty. In the test VM the hosts file is byte-identical to before, and every quarantined file is back byte for byte.</em>
</div>

---

## Preview before you commit

Nothing reaches the OS that has not first appeared in a plan you have seen. **Preview** runs the
whole pipeline — preflight safety checks, rule resolution, change planning — and touches nothing.

<div align="center">
<img src="docs/screenshots/05-impact-preview.png" width="880" alt="A dry-run preview showing safety findings and planned changes" />
<br /><em>A dry run: preflight confirmed the machine's DNS resolvers are not Google's, then the plan lists every change it would make. Nothing has been written.</em>
</div>

<div align="center">
<img src="docs/screenshots/18-preview-planned-changes.png" width="880" alt="The planned quarantines further down the preview, each with its path" />
<br /><em>Further down the same plan, each quarantine is listed with the exact path it would move, ahead of the list of what will stop working.</em>
</div>

Preflight refuses rather than warns where a rule would be catastrophic on *this* machine. The clearest
case: if `8.8.8.8` is your actual resolver, blocking Google's IP ranges takes away name resolution for
everything — so that rule is refused outright, not merely flagged.

---

## Apply

**Apply** plans again and opens the confirmation: the full list of what will stop working, and every
change that will be made. Nothing is written until you tick the box.

<div align="center">
<img src="docs/screenshots/19-confirm-apply.png" width="880" alt="The apply confirmation, listing what will stop working" />
<br /><em>The confirmation repeats the cost before it asks.</em>
</div>

<div align="center">
<img src="docs/screenshots/20-dashboard-applied.png" width="880" alt="The dashboard after an apply" />
<br /><em>Afterwards the dashboard counts what changed: names sinkholed, names looped to this machine, firewall rules, policy values, a program held to local-only, and items in quarantine.</em>
</div>

---

## App containment

Scans for binaries that inherit Google's networking stack:

- **Google first-party** — Chrome, Drive, Earth, the updater
- **Chromium browsers** — Edge, Brave, Vivaldi, Opera
- **Embedded Chromium** — Electron and CEF apps that ship a whole Chromium inside and phone home
  under *their vendor's* name, not Google's

That third category is the interesting one. The tell is an `icudtl.dat` or `resources.pak` sitting
next to the executable — hard to fake, hard to miss. On a normal machine this turns up things like
OBS's browser plugin, Logitech's Options+ helper, and Razer's app engine.

Containing one writes a firewall rule scoped to that single executable. The rest of the machine is
untouched. Marking one **local-only** instead confines it to this machine (see below).

<div align="center">
<img src="docs/screenshots/06-containment-empty.png" width="880" alt="The containment page before a scan" />
<br /><em>Nothing is scanned until you ask, and the scan changes nothing.</em>
</div>

<div align="center">
<img src="docs/screenshots/07-containment-scanned.png" width="880" alt="The containment scanner listing Chromium-derived binaries" />
<br /><em>Each hit shows the evidence it was flagged on, and its signing publisher. Every program has two switches: Contain, which blocks it, and Local-only, which keeps it running on this machine.</em>
</div>

---

## Local-only mode

Some Google software is worth keeping running and not worth letting talk. Local-only mode keeps a
service, a scheduled task, an app or a group of names alive, and lets it reach this machine and
nothing else.

- **Services, tasks and apps** keep running and keep their start type. Two firewall rules confine the
  program, or the service when it lives inside `svchost.exe`: one outbound, one inbound, each blocking
  every address except `127.0.0.0/8` and `::1`.
- **Names** in a local-only hosts group resolve to `127.0.0.1` and `::1` instead of `0.0.0.0` and `::`,
  so a connection attempt loops back to this machine. Nothing is started to answer it. If something on
  the machine is already listening on port 80 or 443, those names are sinkholed instead and the preview
  says so, because loopback would deliver Google-bound requests to it.
- A program under the Windows directory, or one that cannot be identified, is refused rather than
  confined.
- **Verify local-only** reads each rule back from Windows and checks the live socket table for any
  confined program connected off the machine. It reports what it cannot see: UDP is connectionless,
  and a service inside `svchost.exe` has no process of its own to audit.

It has its own cost, shown like any other. Keeping the updater running but cut off does not patch
Chrome, and nothing reports that updates are off.

What it cannot confine: a lookup for a name the hosts file does not list is made by Windows on the
program's behalf, so a per-program firewall rule stops the connection that follows, not the lookup.

<div align="center">
<img src="docs/screenshots/13-rules-local-only.png" width="880" alt="Rules with the Keep running, local-only switch turned on" />
<br /><em>A rule that can be kept running has a <strong>Keep running, local-only</strong> switch. Turned on, the card says LOCAL-ONLY. Here the updater services and the update CDN names are set to it.</em>
</div>

<div align="center">
<img src="docs/screenshots/14-impact-local-only.png" width="880" alt="The Impact report stating the cost of local-only mode" />
<br /><em>The Impact report states the cost of local-only mode in place of the cost of blocking. Names that loop to this machine are refused at once, and some programs retry a refusal faster than they retry a failed lookup.</em>
</div>

<div align="center">
<img src="docs/screenshots/27-impact-local-only-apps.png" width="880" alt="The Impact report saying that local-only apps cannot reach the internet" />
<br /><em>Local-only has a cost of its own, stated plainly: the program keeps running, and everything that needs the web fails, not only Google's part of it.</em>
</div>

<div align="center">
<img src="docs/screenshots/21-containment-verified.png" width="880" alt="Verify local-only passing for a running, confined program" />
<br /><em><strong>Verify local-only</strong> after an apply. Edge is running here under a local-only jail. The rules are read back from Windows, the live sockets of the running process are checked, and the looped names are resolved.</em>
</div>

<div align="center">
<img src="docs/screenshots/26-harness-local-only.png" width="880" alt="The test harness measuring a jailed program from outside" />
<br /><em>The same behavior measured by the test harness in the VM, not by the app: a jailed program still reaches loopback on IPv4, IPv6 and by name, and an address on another machine is refused by the firewall.</em>
</div>

---

## Markers

A marker is something that marks a machine as a vendor's.

- **Network markers** are names, handled by the hosts engine like any other: extended Google tracking
  and measurement hosts, Mandiant's marketing trackers (on by default), and Mandiant's portal and API,
  VirusTotal and Google SecOps (off by default, because they are services a security practitioner may
  use).
- **Host markers** are found by a read-only scan: crash dumps, the Software Reporter Tool, the Android
  and Cloud CLI usage IDs, Google Update's install records, Chrome's launch beacon, and the files of
  FireEye, Trellix and Mandiant software. Each states how sure the catalog is of its location.

Identifiers, leftovers and optional components can be **quarantined**: moved to
`%ProgramData%\AntiGoogle\quarantine` with a manifest and a SHA-256 for every file, and restored byte
for byte. It never deletes. Restore never overwrites a file the program has recreated since: the old
copy is placed beside it. Software and security agents are reported and never moved, and the Mandiant
services rule is refused while an endpoint security agent is installed.

<div align="center">
<img src="docs/screenshots/15-markers-network.png" width="880" alt="The network marker rules" />
<br /><em>Network markers are ordinary rules with declared costs. The ones aimed at services a security practitioner may use stay off until you turn them on.</em>
</div>

<div align="center">
<img src="docs/screenshots/16-markers-found.png" width="880" alt="What the marker scan found, with its class and confidence" />
<br /><em>The scan lists what it found with a class and a confidence for each. Identifiers and leftovers offer a Quarantine switch. A security agent is reported and never offered one.</em>
</div>

<div align="center">
<img src="docs/screenshots/17-markers-quarantine-chosen.png" width="880" alt="Four markers chosen for quarantine" />
<br /><em>Four items chosen for quarantine. They are moved on the next Apply and listed in the plan first.</em>
</div>

---

## Reports

**Report** reads the machine back and writes one self-contained HTML file (no script, nothing loaded
from anywhere) and the same data as JSON. It says how each layer works on this machine, what is armed
and what it costs, what was changed in the hosts file, firewall, services, tasks and registry, what is
confined and the evidence, what was quarantined, what was found and left alone, the safety checks, and
what none of it covers. Your home folder appears as `%USERPROFILE%`.

```bash
AntiGoogle.exe --report C:\path\to\folder
```

writes the same report without opening a window. Every apply, undo, quarantine and restore is also
appended to `%ProgramData%\AntiGoogle\audit.jsonl`, so the history survives the journal forgetting it.

<div align="center">
<img src="docs/screenshots/22-report-empty.png" width="880" alt="The Report page before any report exists" />
<br /><em>Nothing is written until you ask for a report.</em>
</div>

<div align="center">
<img src="docs/screenshots/23-report-page.png" width="880" alt="The Report page after generating a report" />
<br /><em>Generate report builds one and opens it. The summary line says whether the verification passed.</em>
</div>

The report itself, section by section. It is one HTML file, readable with no network and no script.

<div align="center">
<img src="docs/screenshots/30-report-glance.png" width="880" alt="The top of a report: counts, verification and how the layers work" />
<br /><em>The counts, the verdict of the verification, and how each layer works on this machine.</em>
</div>

<div align="center">
<img src="docs/screenshots/31-report-armed.png" width="880" alt="The armed rules and what each costs" />
<br /><em>Every armed rule, in the mode it was armed in, with the worst thing it costs. Each cost expands.</em>
</div>

<div align="center">
<img src="docs/screenshots/32-report-changed.png" width="880" alt="What was changed on the machine, read back" />
<br /><em>What was changed, read back from the machine: hosts groups and their mode, the firewall rules, services, tasks, and each registry value with what it was before.</em>
</div>

<div align="center">
<img src="docs/screenshots/33-report-evidence.png" width="880" alt="The evidence for local-only, the quarantine and the markers found" />
<br /><em>The evidence that a program is confined, what went into quarantine and where it is held, and what the scan found and left alone.</em>
</div>

<div align="center">
<img src="docs/screenshots/34-report-checks-activity.png" width="880" alt="Safety checks and recent activity" />
<br /><em>The safety checks, then the activity log: every apply, undo, quarantine and restore.</em>
</div>

<div align="center">
<img src="docs/screenshots/35-report-limits.png" width="880" alt="The report's closing section, on what it does not cover" />
<br /><em>It ends by saying what none of this covers.</em>
</div>

---

## It does not demand administrator rights to be looked at

The app runs **as-invoker**. It boots, scans and previews with no elevation at all; only Apply and
Restore need it, and there is an explicit button for that. A privacy tool that requires admin just to
be examined is asking for more trust than it has earned.

<div align="center">
<img src="docs/screenshots/11-needs-admin.png" width="880" alt="The app explaining it needs administrator rights" />
<br /><em>Started without elevation, the app says so and offers to restart as administrator. Browsing, scanning and previewing still work.</em>
</div>

---

## Build from source

```bash
dotnet build AntiGoogle.sln
```

```bash
dotnet run --project src/AntiGoogle.App
```

Produce the self-contained release binary:

```bash
./publish-windows.ps1
```

### Tests

```bash
dotnet test
```

226 checks, covering the catalog's own invariants, the journal, the plan and undo logic, local-only
mode, markers and quarantine, the report, and a full `BuildPlan → Apply → RevertAll` round trip
asserted **byte-identical** for the hosts file and exact for registry values, plus proof that a
reverse is journalled *before* each mutation, from both directions.

What those cannot reach (services, scheduled tasks, firewall rules, HKLM, the real hosts file) is
covered by an end-to-end harness for a disposable VM:

```bash
dotnet publish tests/AntiGoogle.Elevated -c Release -r win-x64 --self-contained true
```

See [docs/ELEVATED-TESTING.md](docs/ELEVATED-TESTING.md). The same VM also runs
`tests/AntiGoogle.Elevated/ui-test.ps1`, which drives the real window with UI Automation: every page, a
local-only rule, a quarantine, an Apply and a Restore through the real buttons, and a generated report.

There is a second runner:

```bash
dotnet run --project tests/AntiGoogle.Verify
```

It **links the same test source files** and executes the same `[Fact]`/`[Theory]` methods by
reflection. It exists because when **Smart App Control is enforced**, Windows blocks Microsoft-signed
`testhost.exe` from loading unsigned test assemblies (`0x800711C7`) and `dotnet test` silently
reports zero tests in every project. One copy of every assertion, two ways to run it.

---

## The mark

<img src="docs/screenshots/logo-strip.png" width="420" alt="The Null Route logo at 16, 20, 24, 32, 48 and 64 pixels" />

**"Null Route"** — an outbound data arrow driven hard to the right and arrested by a solid slab it
never reaches. The arrow is the telemetry beacon leaving your machine; the slab is the sink: the hosts
entry, the firewall rule, the disabled service. The gap between them is the actual subject. The packet
does not bounce and it does not pass. It stops, and nothing is drawn on the far side.

It deliberately refuses metaphor. It does not draw *protection* the way a shield or a padlock does —
it draws a flow and a hard stop, which is literally what all four layers do. For an app whose whole
pitch is that it will not overclaim, a mark that claims only "this specific thing was stopped" is the
honest one.

Defined once in [`Logo.xaml`](src/AntiGoogle.App/Logo.xaml) as vector geometry on a 64×64 viewbox,
pixel-hinted so every straight edge lands on a whole pixel at 16px. Regenerate the icon after any
change:

```bash
dotnet run --project tools/AntiGoogle.IconGen
```

That reads the same `Logo.xaml` the window uses, so the title-bar mark and the taskbar icon cannot
drift apart. Each size is rendered from the vector at its native resolution — downscaling one 256px
render to 16px turns crisp edges into grey mush, exactly where the icon works hardest.

---

## Layout

```
src/AntiGoogle.Core/          class library, no UI dependencies
  Model/                      BlockRule, Breakage, PlannedChange
  Catalog/                    the curated endpoint + rule data
  Engines/                    hosts, firewall, service, task, registry
  Journal/                    the undo log
  Safety/                     preflight checks
  Discovery/                  Chromium-derived binary scanner
  Markers/                    marker catalog, scanner, quarantine vault
  Verification/               local-only verifier
  Reporting/                  audit log, report builder and renderer
  Platform/                   process runner, elevation, socket tables
src/AntiGoogle.App/           WPF UI
tools/AntiGoogle.IconGen/     renders Logo.xaml to the multi-resolution .ico
tests/AntiGoogle.Core.Tests/  xunit suite
tests/AntiGoogle.Verify/      console runner over the same sources
tests/AntiGoogle.Elevated/    end-to-end harness for a disposable VM
docs/SPEC.md                  what the software is, what was verified, what is required
docs/ELEVATED-TESTING.md      how to run the harness
```

---

## Honest limits

- **The elevated Apply and Restore round trip has been run on a Windows 11 virtual machine, and on
  nothing else.** `tests/AntiGoogle.Elevated` does it, and it found and fixed three ways a restore was
  not exact. The same VM also ran the real window end to end with UI Automation. Nothing has been run
  on a domain-joined machine, on Windows 10, or against a real Chrome, Drive or Mandiant installation.
  Use a disposable VM for your first run.
- This reduces Google's reach. It does not make you anonymous, and it is no substitute for using a
  browser that does not report to Google in the first place.
- Software that ships its own DNS resolver bypasses the hosts layer. Only firewall IP rules catch it,
  and those are blunt enough to be off by default.
- The IP ranges are static. They are long-lived AS15169 allocations, but they are deliberately **not**
  fetched from `gstatic.com/ipranges/goog.json` at runtime — a privacy tool that phones Google to ask
  which addresses to block is self-defeating, and it would make behaviour depend on a file Google
  controls.
- On a domain-joined machine, Group Policy may fight or reapply these values, and your IT department
  may reasonably treat the changes as tampering. Preflight warns you; believe it.
- Disabling the Google updater means **Chrome stops getting security patches**. That is a real risk,
  not a footnote. Update it by hand or accept the exposure knowingly.
- Not audited. Reviewed adversarially, with an automated suite, but that is not the same thing.

<div align="center">
<img src="docs/screenshots/09-about.png" width="880" alt="The About page, with the limits and the licence" />
<br /><em>The About page says the same: what it does, its limits, the default profile and the licence.</em>
</div>

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version: **every rule must declare what it breaks**,
and a rule armed by default with an empty breakage list is a test failure.

## Security

See [SECURITY.md](SECURITY.md). Report privately. The bugs that matter most are the ones that leave a
machine in a state the user did not choose and cannot get out of.

## Licence

[GNU General Public License v3.0 or later](LICENSE).

Anti-Google is free software. You may redistribute and modify it under the GPL, and if you distribute
a modified version you must pass the same freedoms — and the source — on to whoever receives it. It
comes with absolutely no warranty.
