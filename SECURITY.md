# Security policy

## Reporting a vulnerability

Please report security issues **privately** through GitHub's
[private vulnerability reporting](https://github.com/sYYn/AntiGoogle/security/advisories/new)
rather than opening a public issue.

Include the version, your Windows build, what you expected, what happened, and — if the bug touches
apply or revert — the contents of `%ProgramData%\AntiGoogle\journal.json` and the relevant log from
`%ProgramData%\AntiGoogle\logs`. Redact anything you consider sensitive; the app is written not to
put secrets in either, but check before you send.

## What counts as a security issue here

This app modifies system-wide configuration. The bugs that matter most are the ones that leave a
machine in a state the user did not choose and cannot get out of:

- **Any path where a change is applied without its reverse being journalled first.** This is the
  invariant the entire undo guarantee rests on.
- **Any path where revert does not restore the original state exactly** — a value restored to a
  guessed default rather than the recorded one, or a hosts file that loses user entries.
- **Any way to arm a consent-gated rule without the typed confirmation**, particularly the
  Google Public DNS firewall rule, which can take a machine offline entirely.
- **Preflight refusals being bypassed**, so a change that was supposed to be impossible is attempted.
- Privilege issues: anything that lets a non-administrator cause a privileged change, or that
  widens the surface of the elevated path.
- Command injection through a rule payload into the PowerShell or `sc.exe` invocations.

## What does not count

- The app breaking Google services. That is the entire point, and every rule documents it.
- Chrome no longer auto-updating when the updater rules are armed. Documented, marked Severe, and
  chosen deliberately by the user.
- Requiring administrator rights to change machine-wide settings.

## Scope and honesty

Anti-Google is not audited software. It has been reviewed adversarially and has an automated suite,
but the elevated Apply → Restore round trip has never been exercised against a real machine — see
the limitations section of the README. Treat it accordingly and prefer a disposable VM for your
first run.

## Supported versions

Only the latest release. This is a young project; there are no backports.
