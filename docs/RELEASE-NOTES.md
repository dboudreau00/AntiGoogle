# Anti-Google v0.2.0

**Keep some Google services running but confined to this machine. Block Google and Mandiant markers.
See what was changed, removed and quarantined.**

Second public release. It also fixes four defects found by running Apply and Restore on a real
Windows 11 virtual machine for the first time.

---

## What is new

**Local-only mode.** A service, scheduled task, program or hosts group can be kept running but
confined to this machine instead of being blocked. Programs and services get an outbound and an
inbound firewall rule that blocks every address except loopback; a service inside `svchost.exe` is
confined by name. Local-only hosts names resolve to `127.0.0.1` and `::1`, and are sinkholed instead
when something on the machine listens on port 80 or 443. Programs under the Windows directory are
refused. Every rule that offers it states its own cost, because keeping something running but cut off
breaks different things from blocking it, and it still breaks the web parts of whatever you confine.
**Verify local-only** reads the rules back from Windows and checks the live sockets for a connection
that leaves the machine.

**Markers.** Network rules for extended Google tracking and measurement hosts and for Mandiant
marketing trackers (armed by default), and for Mandiant's portal and API, VirusTotal and Google SecOps
(off by default, because a security practitioner may use them). A read-only scan for host markers:
crash dumps, the Software Reporter Tool, usage IDs, Google Update records, and FireEye, Trellix and
Mandiant software, each with a stated confidence.

**Quarantine.** Identifiers, leftovers and optional components can be moved into
`%ProgramData%\AntiGoogle\quarantine` with a manifest and a SHA-256 per file, and restored byte for
byte. Nothing is deleted, nothing is overwritten on restore, links are never followed, and security
agents are never touched. The Mandiant services rule is refused while an endpoint agent is installed.

**Reports.** One self-contained HTML file and a JSON file describing what is armed, changed, confined
and quarantined, with the evidence behind each line. Generate it from the **Report** page, or run
`AntiGoogle.exe --report` for one without a window. An append-only audit log, `audit.jsonl`, records
every apply, undo, quarantine and restore.

**Plans make the machine match the armed set.** A rule that was applied and is no longer armed, or
that moved between blocking and local-only, is undone by the next apply, and the preview lists those
undo changes first.

## Fixed

Found by running the real engines on a Windows 11 virtual machine:

- Restoring a service turned "Automatic (Delayed Start)" into plain Automatic.
- The preflight warned that "something else" was managing Chrome after Anti-Google had set the policy
  itself.
- Restoring left an empty `HKLM\SOFTWARE\Policies\Google` behind when Anti-Google had created it.
- Applying and restoring changed the hosts file's owner and access list. It is now overwritten in
  place.

---

## Install

Download `AntiGoogle-v0.2.0-win-x64.zip` or the bare `AntiGoogle.exe`. Self-contained, no .NET runtime
required, no installer, nothing written outside `%ProgramData%\AntiGoogle`.

**The binary is unsigned.** SmartScreen will warn on first run and Smart App Control may block it
outright. Verify against `SHA256SUMS.txt`:

```powershell
Get-FileHash .\AntiGoogle.exe -Algorithm SHA256
```

Or build it yourself. The point of a tool like this is that you do not have to take anyone's word for
it.

**Requires:** Windows 10 or 11, x64.

---

## Read this before you run it

The elevated Apply and Restore round trip now has an end-to-end test, and it passes on a Windows 11
virtual machine: 161 checks, plus 56 more that drive the real window. That VM is the only machine it
has run on. Nothing has been run on Windows 10, on a domain-joined machine, or against a real Chrome,
Drive or Mandiant installation.

**Use a disposable VM for your first run.** This app edits your hosts file, your firewall and your
services.

Other known gaps:

- Inbound blocking is checked by reading the rule back from Windows, not from a second machine.
- A blocked UDP send is silent, so confinement of UDP traffic is not proven.
- Local-only confines the connection, not the name lookup. A name the hosts file does not list can
  still be looked up.
- Local-only names resolve to loopback and nothing answers them, by design. There is no TLS listener
  and no certificate authority.
- The Mandiant hostnames come from third-party integration documentation, not from Mandiant.
- Snap Layouts' hover flyout is verified by eye only.
- Not audited. Reviewed adversarially, with an automated suite, but that is not the same thing.

---

## Licence

[GPLv3 or later](https://www.gnu.org/licenses/gpl-3.0.html). Free software, no warranty; if you
distribute a modified version you must pass the same freedoms, and the source, on with it.

**Full changelog:** [CHANGELOG.md](https://github.com/dboudreau00/AntiGoogle/blob/main/CHANGELOG.md)
