# Anti-Google v0.1.0

**Strips Google telemetry out of Windows — and tells you, in plain language, exactly what that costs
you before it does anything.**

First public release.

---

## What it does

Four independent, separately reversible layers:

| Layer | What it does |
|---|---|
| **Hosts file** | Sinkholes Google telemetry domains to `0.0.0.0` **and** `::` |
| **Windows Firewall** | Outbound blocks by IP range and by program path |
| **Services & tasks** | Disables the Google updater services and scheduled tasks |
| **Registry policy** | Chrome and Edge enterprise policy values |

23 curated rules. Every one declares what it breaks, at what severity, with the consequence spelled
out — and the **Impact report** is the hero screen, not a footnote. You cannot apply anything without
first seeing the full degradation list and ticking a box saying you read it.

## What makes it different

Most "block Google" tools hand you a list of domains and wish you luck. When your bank's login page
stops working three weeks later, nothing connects that to the hosts file you edited.

> **Severe — Widevine DRM: paid streaming in Chrome**
> Widevine ships as a Chrome component from this CDN. If it is missing or expires, Netflix, Spotify
> Web, Amazon Prime and Disney+ stop playing in Chrome. This is the single most common surprise from
> aggressive Google blocking.

That is a real catalog entry. They all read like that.

## Getting back out

Every change records its **reverse before the change is made**, to a journal in
`%ProgramData%\AntiGoogle`. Killing the app mid-apply still leaves a complete way back. "Restore
everything" replays it newest-first, then sweeps the firewall group as a backstop in case the journal
itself was lost. The journal lives in ProgramData rather than a user profile, so another
administrator can undo the changes even if your account is gone.

## Safety behaviour worth knowing

- **Preflight refuses, it does not merely warn.** If `8.8.8.8` is your actual resolver, blocking
  Google's IP ranges would take away name resolution for the entire machine — so that rule is refused
  outright.
- **Typed consent** (`ARM`) for anything that can lock you out of accounts or your network. A profile
  switch can never arm one.
- **Safe Browsing stays off by default**, even on the Aggressive profile. Turning off phishing and
  malware warnings is a security regression you should choose deliberately.
- **Runs as-invoker.** Boots, scans and previews with no administrator rights at all.

## The default profile is Aggressive

This build ships armed — `googleapis.com` and `gstatic.com` blackholed. That breaks Google Fonts,
some reCAPTCHA flows, Firebase push notifications, Chromecast and Android tooling. Content blocks
(Search, YouTube, Google sign-in) and the IP-range sledgehammers stay off until you consent to each
one individually.

---

## Install

Download `AntiGoogle-v0.1.0-win-x64.zip` or the bare `AntiGoogle.exe`. Self-contained — no .NET
runtime required, no installer, nothing written outside `%ProgramData%\AntiGoogle`.

**The binary is unsigned.** SmartScreen will warn on first run and Smart App Control may block it
outright. Verify against `SHA256SUMS.txt`:

```powershell
Get-FileHash .\AntiGoogle.exe -Algorithm SHA256
```

Or build it yourself — the point of a tool like this is that you do not have to take anyone's word
for it.

**Requires:** Windows 10 or 11, x64.

---

## Read this before you run it

**The elevated Apply → Restore round trip has not been exercised against a real machine.** The
automated suite covers the full plan → apply → revert cycle unelevated, asserting the hosts file
returns byte-identical and registry values return exactly — but service, scheduled-task and firewall
mutation, HKLM writes, and the real hosts file's ACL path all require administrator rights and cannot
be reached by any test that does not have them.

**Use a disposable VM for your first run.** Not because it is expected to fail, but because that
claim has not been earned yet, and this app edits your hosts file, your firewall and your services.

Other known gaps:

- Snap Layouts' hover flyout is verified by eye only.
- Per-rule revert exists in the core but is not wired to the UI.
- Not audited. Reviewed adversarially, with an automated suite, but that is not the same thing.

---

## Licence

[GPLv3 or later](https://www.gnu.org/licenses/gpl-3.0.html). Free software, no warranty; if you
distribute a modified version you must pass the same freedoms — and the source — on with it.

**Full changelog:** [CHANGELOG.md](https://github.com/<OWNER>/AntiGoogle/blob/main/CHANGELOG.md)
