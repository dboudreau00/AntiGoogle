# Changelog

All notable changes to Anti-Google are recorded here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.2.0] - 2026-11-18

### Added

- **Local-only mode.** A service, scheduled task, app or hosts group can be kept running but confined
  to this machine instead of being blocked. Programs get an outbound and an inbound firewall rule
  blocking every address except loopback (a service inside `svchost.exe` is confined by name). Local-only
  hosts names resolve to `127.0.0.1` and `::1`. Programs under the Windows directory are refused, and if
  something local listens on port 80 or 443 the names are sinkholed instead. Every rule that offers it
  declares its own cost. **Verify local-only** reads the rules back and checks live sockets.
- **Markers.** Network rules for extended Google tracking and measurement hosts, Mandiant marketing
  trackers (armed by default), and Mandiant's portal and API, VirusTotal and Google SecOps (off by
  default). A read-only scan for host markers (crash dumps, the Software Reporter Tool, usage IDs, Google
  Update records, FireEye, Trellix and Mandiant software), each with a stated confidence.
- **Quarantine.** Identifiers, leftovers and optional components can be moved into
  `%ProgramData%\AntiGoogle\quarantine` with a manifest and a SHA-256 per file, and restored byte for
  byte. Nothing is deleted, nothing is overwritten on restore, links are never followed, and security
  agents are never touched. The Mandiant services rule is refused while an endpoint agent is installed.
- **Reports.** One self-contained HTML file and a JSON file describing what is armed, changed,
  confined and quarantined, with the evidence. `AntiGoogle.exe --report` writes one without a window.
  An append-only audit log, `audit.jsonl`, records every apply, undo, quarantine and restore.
- **Plans make the machine match the armed set.** A rule that was applied and is no longer armed, or
  that moved between blocking and local-only, is undone by the next apply, and the preview lists those
  undo changes first.
- `tests/AntiGoogle.Elevated`, an end-to-end harness for a disposable virtual machine with a UI
  Automation script for the real window, and `docs/SPEC.md`.
- README screenshots of every page and flow, captured from this build in a test VM, including local-only
  mode, markers, quarantine, the generated report, Apply and Restore.

### Fixed

Found by running the real engines on a Windows 11 virtual machine:

- Restoring a service turned "Automatic (Delayed Start)" into plain Automatic.
- The preflight warned that "something else" was managing Chrome after Anti-Google had set the policy
  itself. It now counts only values the journal does not record as its own.
- Restoring left an empty `HKLM\SOFTWARE\Policies\Google` behind when Anti-Google had created it.
- Applying and restoring changed the hosts file's owner and access list. It is now overwritten in
  place.

---

## [0.1.0] — 2026-08-06

First public release. Everything below is new.

### The point of it

Every rule declares, in plain language, what it breaks — at what severity, with the consequence
spelled out — and the **Impact report** is the hero screen rather than a footnote. You cannot apply
anything without first seeing the full degradation list and ticking a box that says you read it.

### Added — enforcement

- **Hosts-file sinkholing** with a delimited managed block. Every domain gets **both** an IPv4
  (`0.0.0.0`) and an IPv6 (`::`) entry — an IPv4-only blocklist is routinely defeated by an app
  falling back to the AAAA record.
- **Windows Firewall** outbound blocks by IP range and by program path, all tagged with a rule group
  so cleanup is one sweep even if the journal is lost.
- **Service and scheduled-task control.** Google's updater services carry a version suffix that
  changes with every Chrome release, so matching is by registry prefix, not exact name. Tasks are
  disabled, never deleted — a deleted task cannot be restored.
- **Chrome and Edge enterprise policy** values, including `DnsOverHttpsMode=off`, which is
  load-bearing: without it Chrome resolves names through its own encrypted DNS and walks straight
  past every hosts entry.
- **23 curated rules** across telemetry, crash reporting, updates, ads/analytics, APIs/CDN,
  sign-in/captcha, push, media, sync, search and DNS.

### Added — safety

- **Journalled undo.** Every change records its reverse *before* the change is made, so killing the
  app mid-apply still leaves a complete way back. The journal lives in `%ProgramData%`, not a user
  profile, so another administrator can undo the changes even if your account is gone.
- **Preflight refusals.** Blocking Google Public DNS when `8.8.8.8` *is* the machine's resolver
  takes the whole internet down, so that is a hard refusal rather than a warning. Also checks
  elevation, hosts-file writability, pre-existing Chrome policy, domain join, and the firewall
  service.
- **Typed consent** (`ARM`) for the rules that can lock you out of accounts or the network. A
  profile switch can never arm one.
- **Safe Browsing stays off by default**, even on the Aggressive profile. Disabling phishing and
  malware warnings is a security regression you should opt into deliberately.
- Hosts revert **strips the managed block** rather than restoring the backup, so hosts edits made
  after an apply are not silently destroyed.

### Added — application

- Custom `WindowChrome` title bar with Windows 11 Snap Layouts, keeping native drag, Aero Snap,
  Alt+Space and rounded corners.
- "Null Route" logo, defined once as vector geometry and rendered to a multi-resolution `.ico` by
  `tools/AntiGoogle.IconGen`, so the window mark and taskbar icon cannot drift apart.
- **Chromium-derived binary scanner.** Finds Google's own apps, Chromium browsers, and Electron/CEF
  apps that embed a whole Chromium and phone home under their vendor's name — detected by
  `icudtl.dat` / `resources.pak` sitting beside the executable.
- Runs **as-invoker**. It boots, scans and previews with no administrator rights; only Apply and
  Restore need elevation.

### Added — accessibility

- Keyboard focus visuals on every interactive control, and pressed states throughout.
- Accessible names on the rule and containment toggles, which previously announced only
  "checkbox, unchecked" with no indication of which system-wide rule was being armed.
- Severity and preflight level conveyed as **words** as well as colour.
- Focus moves into modal overlays and is restored on close; live regions announce the busy message
  and the result banner.
- Palette contrast raised to meet WCAG AA on every surface it is used against.

### Known limitations

- The elevated Apply → Restore round trip has **not** been exercised against a real machine.
  Service, scheduled-task and firewall mutation, HKLM writes, and the real hosts file's ACL path all
  need administrator rights, so the automated suite cannot reach them.
- Snap Layouts' hover flyout is verified by eye only — it needs a real dwelling cursor.
- Per-rule revert exists in the core but is not wired to the UI.
- IP ranges are static by design and are not fetched at runtime.

[Unreleased]: https://github.com/dboudreau00/AntiGoogle/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/dboudreau00/AntiGoogle/releases/tag/v0.2.0
[0.1.0]: https://github.com/dboudreau00/AntiGoogle/releases/tag/0.1.0
