# Elevated testing

The unit suite cannot reach the parts of Anti-Google that need administrator rights: services and
scheduled tasks, Windows Firewall, HKLM, and the real hosts file. `tests/AntiGoogle.Elevated` drives
the real engines against a real machine, reads the result back with tools that share no code with the
engines, reverts, and compares the machine with a snapshot taken before.

It modifies the machine it runs on. **Run it in a disposable virtual machine.**

## What stops it from running somewhere it should not

It refuses to start unless all of these hold:

- it is elevated;
- the machine reports itself as a virtual machine (BIOS manufacturer or product), unless
  `--allow-physical` is passed;
- `--yes-modify-this-machine` is passed;
- no Anti-Google state is already present (a journal with entries, or a managed hosts block), unless
  `--force-dirty` is passed.

## Running it

On the build machine:

```bash
dotnet publish tests/AntiGoogle.Elevated -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true
```

Copy `AntiGoogle.Elevated.exe` into the VM and run it from an administrator prompt:

```bash
AntiGoogle.Elevated.exe --yes-modify-this-machine
```

| Option | Meaning |
|---|---|
| `--scenario <name>` | Run one scenario. Default `all`. |
| `--off-box-peer <ip>` | An address on **another machine** that is on-link and has nothing listening. Enables the live traffic check (below). |
| `--out <folder>` | Where `results.json` and reports go. Default `%ProgramData%\AntiGoogleElevatedTest\out`. |

Exit code 0 means every check passed.

The harness builds its own fixtures: Google-named services (a 20-line .NET Framework `ServiceBase`,
compiled with the `csc.exe` that ships in Windows), scheduled tasks, files in the places the marker
catalog looks, and a socket probe. Nothing is downloaded. It removes them at the end, and recovers
through the journal if a scenario crashes.

## Scenarios

| Scenario | What it proves |
|---|---|
| `preflight` | A healthy elevated machine produces no Blocker. |
| `roundtrip-clean`, `roundtrip-preexisting-policy` | The default profile applies, reads back correctly with `sc`, `reg`, `Export-ScheduledTask` and the resolver, and restores to a snapshot-identical machine (hosts content and ACL, services including the delayed-start flag, tasks, policy keys). |
| `idempotent-reapply` | A second apply changes nothing and leaves one managed block. |
| `containment-roundtrip` | Per-app containment writes the rule it should and removes it. |
| `localonly-services-and-tasks` | Local-only keeps services and tasks running and unchanged, confines their programs with exactly the expected inbound and outbound rules, refuses anything under the Windows directory, and restores exactly. |
| `localonly-live-traffic` | With `--off-box-peer`: a jailed program still reaches IPv4 loopback, IPv6 loopback and `localhost`, and is **denied** (`AccessDenied`, 10013) reaching the peer. A positive control before the jail and a check after restore show that the denial is the jail's doing. |
| `localonly-hosts` | A local-only name resolves to `127.0.0.1` and `::1`, a blocked name resolves to nothing, and with a listener on port 443 the loopback mapping is refused in favour of the sinkhole. |
| `mode-switch-and-unarm` | Switching a rule between blocking and local-only, and un-arming it, undoes the previous mode exactly. |
| `quarantine-real-paths` | Markers at their real locations are moved into the vault with hashes, a file in use fails safely, a report-only marker is refused, and everything comes back byte for byte. |
| `security-agent-guard` | With a FireEye folder present, the Mandiant services rule is refused and the agent's files cannot be quarantined. |
| `report-end-to-end` | A report built from the live machine passes its own verification, is self-contained, and carries no home-folder path. |

## UI automation

`ui-test.ps1` drives the real window with UI Automation in the same disposable VM. Publish the app the
way a release is built, copy `AntiGoogle.exe` and `ui-test.ps1` into one folder in the VM, and run it
from an elevated PowerShell inside an interactive desktop session (UI Automation and screenshots need
one):

```bash
dotnet publish src/AntiGoogle.App -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true
```

```bash
powershell -ExecutionPolicy Bypass -File ui-test.ps1 -YesModifyThisMachine -AppFolder C:\agtest
```

It has the same refusals as the harness: not elevated, not a virtual machine, Anti-Google state already
present. The exit code is the number of failed checks. Results go to `ui-results.txt`, screenshots to
`shots\` and the report it generates to `gui-report.html`, all in the app folder.

It checks that:

- the navigation rail lists the eight pages in order, and each page renders and is exposed to
  accessibility tools;
- the Rules page offers a local-only switch on a hosts rule and on a service rule and none on a registry
  policy rule, and the Impact report states the local-only cost;
- **Verify local-only** says nothing is confined before an apply, and confirms the looped names after it;
- the Markers scan finds an identifier planted where the catalog looks, and it can be chosen for
  quarantine;
- Apply works through the real confirmation overlay, and the hosts file, journal and vault read back
  correctly;
- Generate report writes an HTML file and a JSON file that name the quarantined item, pass their own
  verification, and do not blame another tool for the Chrome policy Anti-Google itself set;
- Restore everything works through the real dialog and leaves the hosts file byte-identical, the
  identifier back byte for byte, and the journal, vault and firewall group empty;
- `AntiGoogle.exe --report` writes a report without a window and exits 0.

The window is 1180 by 820 and a small lab screen is not, so the script moves it into view.

## Platform facts it relies on

Measured on Windows 11 22H2, see the specification (section 8):

- Windows Firewall does not filter loopback traffic, and does not filter traffic to the machine's own
  network addresses either. A jail therefore never needs to carve loopback out, and "own address" is
  not a way to test it.
- A blocked outbound connect fails immediately with `WSAEACCES` (10013). A blocked UDP send does not
  fail, so UDP cannot be proven by a send error.
- A hosts entry of `0.0.0.0` and `::` makes the resolver return "no data" without ever connecting.

## Limits

- The off-box peer must be a second machine. A VM's own address is local, and Windows treats
  connections to it as loopback.
- Inbound blocking is read back and verified by rule, but not exercised with an off-box client.
- No real Chrome, Drive or Mandiant agent is installed, so marker locations are checked against
  synthetic files at the catalog's own paths.
- The Restore confirmation is a native message box that UI Automation did not list in the lab image, so
  `ui-test.ps1` finds and answers it through its window handle.
