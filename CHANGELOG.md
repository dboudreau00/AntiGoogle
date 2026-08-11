# Changelog

All notable changes to Anti-Google are recorded here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/dboudreau00/AntiGoogle/releases/tag/0.1.0
