# Contributing to Anti-Google

## The one rule that matters

**Every rule must declare what it breaks.** A `BlockRule` that is `DefaultEnabled` with an empty
`Breaks` list is a test failure, not an oversight — `CatalogTests` enforces it. This is the entire
product thesis: the user is told the cost before paying it.

If you add a rule, write its `Breakage` entries honestly, **including when the cost is a security
loss rather than a convenience loss**. Disabling Chrome's updater is `Severe` because an unpatched
browser is a genuine risk, and the rule says so in those words.

## Writing a breakage

This is the part of the codebase where prose quality is a functional requirement. Write like you
are warning a friend, not filing a ticket.

- Name the **user-visible capability**, not the mechanism. "Paid streaming in Chrome", not
  "Widevine CDM component update failure".
- Say what they will actually observe, including when the failure is **silent** — "notifications
  simply never arrive" is more useful than "FCM unavailable".
- Give the workaround where one exists.
- Where a rule is a genuine **trade** rather than a win, say so. The DNS-over-HTTPS rule buys local
  control at the cost of transport secrecy, and its text says exactly that.
- A `Severe` breakage with a `Detail` under 40 characters fails a test. Stubs are not acceptable
  on the loudest warnings.

## Non-negotiables

These are enforced by tests, by review, or by both. `CLAUDE.md` has the full list and the reasoning.

1. **Journal the reverse BEFORE mutating.** Killing the process mid-apply must still leave a
   complete way back. Never reorder this.
2. **Revert must be exact, not best-effort.** Record the *previous* value, including the "this did
   not exist" case. Never restore a guessed default.
3. **Never restore the hosts file from its backup on revert** — strip the managed block from the
   current file. A stale backup silently destroys edits made in between.
4. **Sinkhole IPv4 and IPv6.** Both, always.
5. **Never fetch Google's IP ranges at runtime.** A privacy tool that phones Google to ask which
   addresses to block is self-defeating.
6. **The manifest stays `asInvoker`.** The app must boot, scan and preview with no admin.
7. **Consent-gated rules are never armed by a profile switch.**
8. **Do not weaken preflight refusals.**

## Building

```bash
dotnet build AntiGoogle.sln
dotnet run --project src/AntiGoogle.App
```

## Testing

```bash
dotnet test
```

There is a second runner over the **same source files**:

```bash
dotnet run --project tests/AntiGoogle.Verify
```

It exists because Smart App Control, when enforced, blocks Microsoft-signed `testhost.exe` from
loading unsigned test assemblies and `dotnet test` then reports zero tests in every project. If you
add a test, both runners pick it up automatically — but `AntiGoogle.Core`'s `InternalsVisibleTo`
names **both** assemblies, so update both if you rename either.

**Tests must never touch the real machine.** `HostsFileEngine` and `FirewallEngine` take their
target path and rule group as constructor parameters for exactly this reason. In particular:
`RevertAllAsync` sweeps the entire firewall group, so a suite run from an elevated shell against the
default group would delete the user's real rules. Always pass a per-test group.

## Changing the logo

`src/AntiGoogle.App/Logo.xaml` is the single definition. After editing it:

```bash
dotnet run --project tools/AntiGoogle.IconGen
```

Commit the regenerated `Assets/`. Read the "do not" list in `Logo.xaml` first — the geometry is
pixel-hinted and several of its properties are load-bearing.

## Style

Match the surrounding code. Comments explain **why**, not what — and in the engines they frequently
record a measured fact or a rejected alternative, which is the most valuable kind of comment in this
codebase. Do not delete one because it looks like noise; several encode bugs that took real work to
find.

## Licence

By contributing you agree your work is licensed under the **GPLv3**, the same terms as the project.
New source files should carry the standard header — copy it from any existing file.
