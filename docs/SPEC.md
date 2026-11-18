# Anti-Google specification

This describes what the software is, what was verified about it on a real Windows machine, and what
the local-only, marker and reporting features require and how they are built. Where this document and
the code disagree, the code ships and this file is the bug.

1 Purpose · 2 The system · 3 What was verified · 4 Requirements · 5 Design · 6 Safety rules ·
7 Test plan · 8 Platform facts measured · 9 Interpretations · 10 Out of scope

---

## 1. Purpose

Anti-Google removes Google's telemetry from a Windows machine and says, in plain language, what each
removal costs before it does anything. Every change is journalled first and reversible exactly.

Three things were added to the original product:

1. **Local-only mode.** Keep selected Google services and apps running, but let them talk only to this
   machine. Names that would have gone to Google resolve to loopback, and a firewall rule stops
   everything else. Web functions break, by design. The program does not.
2. **Markers.** A catalog of what marks a machine as Google's, Mandiant's or another Google-owned
   security vendor's. Network indicators are blocked. On-disk identifiers and leftovers are found,
   reported and, where safe and asked for, quarantined with a way back.
3. **Reporting.** An append-only audit log and a self-contained report that explains how the protection
   works on this machine and lists what was changed, blocked, looped back and quarantined, with the
   evidence that it holds.

It also closes the gap the README admitted to. The elevated Apply and Restore round trip had never been
run on a real machine. It has now (section 3).

### Non-goals

- Anonymity. This reduces Google's reach. It does not hide the machine.
- Defeating a security product. Anti-Google never stops, patches, unloads or deletes an endpoint
  security agent and has no tamper-protection bypass. Security-agent markers are detect-and-report only.
- A local TLS endpoint. Nothing installs a certificate authority or terminates TLS for Google names
  (section 5.3).

---

## 2. The system

C# on .NET 9 with WPF and MVVM. Two main assemblies and four enforcement layers.

| Layer | Engine | What it writes | How it is undone |
|---|---|---|---|
| Hosts file | `HostsFileEngine` | one delimited block, `0.0.0.0` and `::` (or loopback) per name | strip the block from the current file |
| Windows Firewall | `FirewallEngine` | block rules in the group `Anti-Google` | remove by name, then sweep the group |
| Services and tasks | `ServiceEngine`, `ScheduledTaskEngine` | start type to Disabled, task to Disabled | restore the recorded start type, delay flag and state |
| Registry policy | `RegistryPolicyEngine` | Chrome, Edge and Google Update policy values | restore the recorded value, or delete it, then remove keys it created |
| Quarantine | `QuarantineEngine` | moves a marker into the vault | move it back after checking its hash |

`ProtectionService` orchestrates plan, confirm, apply, journal and revert. `Preflight` refuses rules that
would be catastrophic on this machine. `GoogleAppScanner` finds Google and Chromium-derived binaries.
State lives in `%ProgramData%\AntiGoogle\`: `journal.json`, `settings.json`, `audit.jsonl`, `backups\`,
`quarantine\`, `reports\`, `logs\`.

### Invariants

Every new feature keeps these. They are enforced by tests and by review.

1. Every rule declares its breakage. One armed by default with none is a test failure.
2. The reverse is journalled before anything is mutated.
3. Revert is exact: the previous value, including "did not exist", never a guessed default.
4. The hosts file is never restored from its backup. The managed block is stripped from the current file.
5. IPv4 and IPv6 are always handled together.
6. Google's IP ranges are never fetched at run time.
7. The manifest stays `asInvoker`. Only Apply and Restore need elevation.
8. Consent-gated rules are never armed by a profile switch.
9. Preflight refusals are not weakened.
10. Honesty over polish.

---

## 3. What was verified

### 3.1 Method

`tests/AntiGoogle.Elevated` drove the real engines inside a disposable Windows 11 virtual machine (22H2,
build 22621, VMware, host-only network) with synthetic Google-named services and scheduled tasks, and
read every result back with tools that share no code with the engines: `sc.exe`, `reg.exe`,
`Export-ScheduledTask`, `Get-NetFirewallRule`, the system resolver, and a snapshot of the services' whole
registry keys, the policy trees and the hosts file's content and security descriptor.

### 3.2 The baseline, before any change to the engines

68 of 70 checks passed. Everything the product is for worked:

- 116 names sinkholed on IPv4 and IPv6, the user's own hosts lines kept, and the Windows resolver
  refused a sinkholed name.
- Google-named services disabled and stopped, a decoy service untouched, tasks disabled, registry
  policy set (read with `reg.exe`), a pre-existing policy value restored to exactly what it was.
- A second apply changed nothing and left one managed block. Per-app containment wrote the right rule.

It also found three ways a restore was **not** exact, each a breach of invariant 3:

| # | Defect | Measured |
|---|---|---|
| 1 | Restoring a service lost its delay flag. `sc config start= auto` clears `DelayedAutostart`. | `gupdate` went from `AUTO_START (DELAYED)` to `AUTO_START` |
| 2 | Restoring left an empty `HKLM\SOFTWARE\Policies\Google` when Anti-Google had created it. | key absent before, present after |
| 3 | Writing the hosts file with `File.Replace` swapped in a new file with its creator's owner and a default ACL. | owner `SYSTEM` became `Administrators`, plus an extra explicit ACE |

All three are fixed (section 5.6) and covered by unit tests. The same harness then passed 70 of 70.

### 3.3 The new features

The harness grew from 6 scenarios to 12, and every scenario ends by comparing the machine snapshot with
the one taken before it started. The last run on the final code passed all 161 checks.

| Scenario | What it shows | Checks |
|---|---|---|
| `preflight`, `roundtrip-clean`, `roundtrip-preexisting-policy`, `idempotent-reapply`, `containment-roundtrip` | The baseline, re-run after the fixes and the rewrite of the plan and apply path | 72 |
| `localonly-services-and-tasks` | Five Google-named services and the task that runs a Google app are confined on their own program and not disabled. Tasks that run `cmd.exe` are refused as inside the Windows directory. No service or task changed state. | 15 |
| `localonly-live-traffic` | A real process under the jail: IPv4 and IPv6 loopback and the name `localhost` work, an address off this machine is refused with 10013, and after restore it is not. | 12 |
| `localonly-hosts` | Looped names resolve to loopback on both families and blocked names resolve to nothing. With a listener on port 443 the plan falls back to sinkholing and says why. | 14 |
| `mode-switch-and-unarm` | Blocked to local-only and back, and un-arming, each leave exactly the intended state and an empty journal. | 10 |
| `quarantine-real-paths` | The scanner finds four markers on real paths. A file another program holds open fails safely and the rest still move. Restore is byte for byte and the vault is under `ProgramData`. | 17 |
| `security-agent-guard` | With a FireEye agent installed, the preflight raises a Blocker, the Mandiant services rule is refused and the agent's files cannot be quarantined. | 8 |
| `report-end-to-end` | A mixed apply produces a report that passes its own verification, has no script, and never contains the home folder. | 13 |

`ui-test.ps1` then drove the real window of the release-style single-file build on a fresh VM, through
every page, a local-only rule, a planted identifier chosen for quarantine, Apply, a generated report,
Restore everything and the headless `--report`, and read the machine back with tools that share no code
with the app. All 56 checks passed. Restore left the hosts file byte-identical, the identifier back byte
for byte, and the journal, vault and firewall group empty.

Running the window found two faults in the new pages and one older one, all fixed. The verification
verdict claimed a confined program when only hosts names had been checked. A report that had saved
correctly showed a red error on a machine with no browser. And the preflight blamed "something else" for
Chrome policy that Anti-Google had just set, which every report after an apply repeated.

The unit suites ran 226 checks through both `dotnet test` and the standalone runner.

---

## 4. Requirements

IDs are stable. "Must" blocks a release. "Should" does not.

### 4.1 Local-only mode

| ID | Requirement |
|---|---|
| LO-1 | A rule that targets a Google service, scheduled task or hosts group can be armed in local-only mode instead of being blocked. Must. |
| LO-2 | In local-only mode a service or task is not disabled. It keeps running and its start type and state do not change. Must. |
| LO-3 | A local-only service, task or application has outbound and inbound traffic confined to loopback by firewall rules: Block, remote address "everything except 127.0.0.0/8 and ::1", scoped to the program, or to the service name when the host is `svchost.exe`. Must. |
| LO-4 | Names in a local-only group resolve to `127.0.0.1` and `::1` instead of `0.0.0.0` and `::`. IPv4 and IPv6 both. Must. |
| LO-5 | If something on this machine listens on port 80 or 443, a loopback mapping would deliver Google-bound requests to it. Planning must detect that, fall back to the sinkhole for the affected names and say so. Must. |
| LO-6 | Local-only refuses any program under the Windows directory and any program that does not exist or cannot be identified. Must. |
| LO-7 | Local-only has its own declared breakage (`LocalOnlyBreaks`), shown in the Impact report in place of the blocking cost. Must. |
| LO-8 | Local-only can be chosen per rule and per application, and the choice persists. Must. |
| LO-9 | A verify action reads each rule back and audits the live socket table for every confined program, reporting any connection that is not loopback. It states what it cannot see. Must. |
| LO-10 | Switching a rule between blocking and local-only undoes the previous mode before applying the new one. Must. |
| LO-11 | Everything above is reverted exactly by Restore. Must. |

### 4.2 Markers

| ID | Requirement |
|---|---|
| MK-1 | Network markers exist for extended Google tracking and measurement hosts, Mandiant marketing trackers, Mandiant services, VirusTotal and Google SecOps. Each is a normal rule with declared breakage. Must. |
| MK-2 | Mandiant marketing trackers and the extended Google tracking hosts are armed by the Aggressive profile. Mandiant services, VirusTotal and SecOps are off by default: they are services a security practitioner may use, not telemetry. Must. |
| MK-3 | Host markers (files, directories, registry keys, services) are classified `Identifier`, `Leftover`, `OptionalComponent`, `Component` or `SecurityAgent`, and each states its source and confidence. Must. |
| MK-4 | A scan finds host markers without elevation. It reads names, sizes and dates, never the contents of a file. Must. |
| MK-5 | Only `Identifier`, `Leftover` and `OptionalComponent` markers of Medium or High confidence can be quarantined. Software and security agents are report-only, and tests pin that. Must. |
| MK-6 | Quarantine moves a marker into the vault with a manifest (original path, SHA-256 per file, size, attributes, access list, time), journalled first. It never deletes. Must. |
| MK-7 | Restore puts the item back byte for byte. If the original path has been recreated, the recreated file is kept and the restored copy is placed beside it. Must. |
| MK-8 | Quarantine refuses links, paths that are not one of the marker's catalog locations, anything under the Windows directory, and anything over a size cap. A file in use fails safely and leaves no journal entry. Must. |
| MK-9 | A marker the user did not ask for is never moved, and quarantine is never armed by a profile. Must. |
| MK-10 | While a Mandiant, FireEye or Trellix endpoint agent is installed, the Mandiant services rule is refused. Must. |

### 4.3 Reporting

| ID | Requirement |
|---|---|
| RP-1 | An append-only audit log records every apply, undo, quarantine and restore with time, rule, layer, target and outcome, and never a secret. Must. |
| RP-2 | A report is one self-contained HTML file (no script, no external resource) plus the same data as JSON. Must. |
| RP-3 | The report explains how each layer works on this machine and what is armed in which mode. Must. |
| RP-4 | The report lists what was changed, read back from the live machine as well as from the journal. Must. |
| RP-5 | The report lists what was quarantined, what was found and left alone, and the evidence for local-only. Must. |
| RP-6 | The report says plainly what it does not cover. Must. |
| RP-7 | The user's home folder is shown as `%USERPROFILE%`. Must. |
| RP-8 | A report can be generated from the UI and, headless, with `AntiGoogle.exe --report`. Should. |

---

## 5. Design

### 5.1 Data model

- `EngineKind` gains `LocalOnly` and `Quarantine`. Existing values are never renumbered.
- `ReverseKind` gains `RestoreQuarantine`. Local-only jails reuse `RemoveFirewallRule`.
- `BlockRule` gains `SupportsLocalOnly`, `LocalOnlyBreaks` and `Vendor`.
- `JournalEntry` gains `Target`, `QuarantineId`, `PreviousDelayedAutostart` and `RegistryCreatedRoot`.
- `AppSettings` gains `LocalOnlyRuleIds`, `LocalOnlyApps`, `QuarantineMarkerIds` and
  `AcknowledgedMarkerIds`. A settings file without them loads with empty lists.
- `PlanRequest` carries everything the user chose. The old `BuildPlanAsync(ids, apps)` still works.

### 5.2 Planning: the machine matches the armed set

Apply used to only add. A rule that was armed, applied and then un-armed kept its effect until Restore.
Local-only mode makes that unacceptable, because switching mode has to undo the old mode. Planning now
compares the journal with the armed set and adds **undo** changes for every entry nothing claims any
more. They appear in the preview like any other change and run first. An entry is stale when its rule
is not armed, when its mode differs, when its app is no longer chosen, or when no hosts rule remains
armed (the hosts block is then removed, not left behind).

### 5.3 Local-only, concretely

Per confined target, two rules in the `Anti-Google` group:

```
Anti-Google: local-only <label> (out)   Outbound  Block  Program|Service  RemoteAddress = NonLoopback
Anti-Google: local-only <label> (in)    Inbound   Block  Program|Service  RemoteAddress = NonLoopback
NonLoopback = 0.0.0.0-126.255.255.255, 128.0.0.0-255.255.255.255, ::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
```

The label is the program's name plus a hash of its full path, so two copies of one program never share a
rule. Several services that run one program share one confinement. Each rule is journalled before it is
created and read back afterwards, and a rule that comes back different is an error, not a pass.

Why explicit ranges rather than "Any": Windows Firewall does not filter loopback at all (section 8), so
both behave the same today. The ranges keep the rule's meaning true if that ever changed, and make it
self-explanatory to anyone who opens it. Block rules beat Allow rules in Windows Firewall, so a vendor's
own allow rule does not defeat it.

Hosts: `127.0.0.1 name` and `::1 name`. No listener is started. A listener answering as Google would need
a certificate for Google's names, which means installing a certificate authority, which is a far larger
risk than the problem it solves. With nothing listening, a connection to loopback is refused at once,
which Google's clients treat as "offline". When two armed rules list the same name and only one is
local-only, the name is sinkholed: the stricter rule decides.

What cannot be confined: a lookup for a name that is not in the hosts file is made by the DNS Client
service on the program's behalf, not by the program, so a per-program rule stops the connection that
follows and not the lookup. Only names in the hosts file are guaranteed not to leave the machine. The
report says so.

### 5.4 Markers and quarantine

`MarkerDefinition` carries id, vendor, title, a plain-language reason, kind, class, locations with
environment tokens, action, confidence, breakage and source. One function expands tokens and refuses
anything that climbs out of its root. `MarkerScanner` never follows a reparse point and never opens a
file's contents. `QuarantineEngine` writes the manifest, journals the reverse, then moves, so a kill at
any point leaves either nothing moved or a manifest and a journal entry that put it back. Restore checks
every file against its recorded hash before it moves anything.

### 5.5 Reporting

`AuditLog` (JSON Lines, appended under a lock, a torn line costs one line) feeds `ReportBuilder`, which
reads the hosts file, Windows Firewall, service start types, task states and policy values back from the
machine and takes from the journal only what it alone knows: the value a change replaced, and when.
`ReportRenderer` writes HTML with every value encoded and no script, and JSON from the same data. A
`ProtectionService` built from an options object writes no audit log unless one is passed, so tests never
touch the real machine.

### 5.6 Fixes to the base engines

| Defect | Fix |
|---|---|
| Delay flag lost | Journal `DelayedAutostart`. Restore with `sc config start= delayed-auto` when it was set. Boot and system start types get their own words. |
| Created parent key left behind | Journal the shallowest key the change created. Revert removes empty keys from the leaf up to it and stops at any key that holds someone else's value. |
| Hosts owner and ACL changed | Stage the content in a temp file to prove the disk has room, then overwrite the hosts file in place. Fall back to replacing it only if the in-place write is refused. |

---

## 6. Safety rules for the new features

1. **Fail closed.** Unknown destination, unknown classification, unknown tenant: deny. A loopback mapping
   that cannot be proven safe becomes a sinkhole. A path that cannot be shown to be a vendor program is
   not confined. A file that cannot be shown to be at one of the catalog's locations is not moved.
2. **Never touch a security agent.** Security-agent markers cannot be quarantined and cannot be stopped.
   The Mandiant services rule is refused while one is installed.
3. **No new network code.** The app fetches no marker list, range or anything else at run time.
4. **No secrets.** Reports, logs and the audit log never contain credentials, tokens or the contents of
   an identifier file. Credential stores, browser profile files and token files are not markers, and a
   test fails if one is added.
5. **Test targets are throwaway.** Engines take their paths and group as parameters. The elevated harness
   refuses to run outside a virtual machine.

---

## 7. Test plan

| Level | Where | Covers |
|---|---|---|
| Unit | `tests/AntiGoogle.Core.Tests`, run by `dotnet test` and `AntiGoogle.Verify` | catalog invariants; hosts loopback and exact revert; the three base-engine fixes; firewall command construction, escaping and read-back parsing; marker catalog guards; scanner and quarantine against temp directories; plan, undo and reconcile with fake engines; socket tables; verifier; report building, escaping and redaction; audit log |
| Elevated | `tests/AntiGoogle.Elevated` in a VM | the real default profile applied and restored with snapshot equality; local-only with a live jailed process; hosts loopback and the listener fallback; mode switching; quarantine on real paths; the security-agent guard; the report |
| UI | `tests/AntiGoogle.Elevated/ui-test.ps1`, UI Automation against the real app in the VM | every page renders and is reachable; the new controls are exposed to accessibility tools; a quarantine, a report, and a full Apply and Restore through the real buttons and dialogs |

Acceptance: both unit runners green, the elevated harness green on a fresh VM, and the machine snapshot
equal before apply and after restore for every scenario.

---

## 8. Platform facts measured

Windows 11 22H2 (22621), in a VM with a host-only network. These are measurements, not documentation.

| Fact | Evidence |
|---|---|
| Windows Firewall does not filter loopback. A program-scoped Block rule with remote address Any left IPv4 loopback, IPv6 loopback and UDP loopback working. | TCP and UDP probes with and without the rule |
| It also does not filter traffic to the machine's own network address. A block rule did not stop a connection to the VM's own IPv4 address. A test that connects to its own address proves nothing about the rule. | same |
| A blocked outbound TCP connect to an off-box address fails at once with `WSAEACCES` (10013). Without the rule the same attempt times out. | peer on the host-only network |
| A blocked UDP send does not fail, so a UDP block cannot be proven by a send error. | `UDP-SENT` in both cases |
| `New-NetFirewallRule` accepts remote address ranges for IPv4 and IPv6 and stores them as written. The `-Service` parameter accepts the same ranges. | read back with `Get-NetFirewallAddressFilter` |
| A route lookup comes before the firewall: an off-link address with no route fails with `NetworkUnreachable` whether or not a rule exists. | probe to a documentation-range address |
| A hosts entry of `0.0.0.0` and `::` makes the resolver return "no data" with no connection attempt. `127.0.0.1` and `::1` resolve, IPv6 first, and a connection goes to loopback. | `Dns.GetHostAddresses` and a connect |
| `sc config start= auto` clears `DelayedAutostart`. | service registry key before and after |
| `File.Replace` on the hosts file changes its owner and adds an explicit ACE. | SDDL before and after |
| Inbound blocking could not be exercised from outside: the host's own firewall refuses connections to the VM. The inbound rule is verified by read-back only. | refused with `WSAEACCES` from the host |

---

## 9. Interpretations and open questions

- **"Markers."** Read as indicators: network indicators (names) and host indicators (the files, keys and
  services that identify a machine or an install to a vendor). Request headers, cookies and URL
  parameters are not covered. If that was meant, it needs its own specification.
- **"Mandiant markers."** Mandiant is part of Google Cloud. Public tracker lists flag two Mandiant
  marketing hosts. The intelligence portal and API are real services a practitioner may rely on. They are
  split accordingly: trackers on, services off. On disk, FireEye, Trellix and Mandiant agents are detected
  and reported and never touched. Mandiant's own hostnames come from third-party integration
  documentation, because no Mandiant network requirements page could be found.
- **Vendor artifact locations** that could not be confirmed against an official source or a live
  installation are marked Medium or Low confidence in the catalog. Low is report-only.
- **VirusTotal** is Google-owned and is in the catalog, off by default, because blocking it breaks malware
  analysis workflows.

## 10. Out of scope

- Registry-value quarantine. Registry identifiers are reported, not modified.
- Per-rule revert in the UI. The engine call exists.
- Scheduled re-apply and drift alerts.
- A local stub that answers on loopback.
- Signed builds.
- Windows 10, domain-joined machines, and real Chrome, Drive or Mandiant installations: unverified.
