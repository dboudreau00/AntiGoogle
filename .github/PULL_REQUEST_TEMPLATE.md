## What this changes

<!-- One or two sentences. -->

## Why

<!-- What problem does it solve? If it fixes a bug, what was the failure mode? -->

---

## Checklist

- [ ] `dotnet test` passes
- [ ] `dotnet run --project tests/AntiGoogle.Verify` passes (same assertions, no signed test host)
- [ ] The app still **boots** — `dotnet build` succeeding proves nothing about XAML

### If you added or changed a rule

- [ ] It declares every degradation it causes, in plain language
- [ ] Security losses are marked as loudly as convenience losses
- [ ] `Severe` breakages have a real explanation, not a stub
- [ ] Anything that can lock a user out of accounts or the network is `RequiresExplicitConsent`
- [ ] New domains list every subdomain individually — hosts entries have no wildcards

### If you touched an engine

- [ ] The reverse is journalled **before** the change is made
- [ ] Revert restores the recorded previous state exactly, including the "did not exist" case
- [ ] `RevertAsync` is idempotent — reverting twice is not an error
- [ ] No test can reach the real hosts file, the real firewall group, or HKLM

### If you changed the UI

- [ ] Interactive controls have hover, pressed and **keyboard focus** states
- [ ] Anything conveyed by colour is also conveyed as text
- [ ] New controls have an `AutomationProperties.Name` if their purpose is not in their content
- [ ] Pages remain plain elements with `IndexToVisibility` — no `TabControl` (it destroys the
      automation tree; see `CLAUDE.md`)

### If you changed the logo

- [ ] Regenerated `Assets/` with `dotnet run --project tools/AntiGoogle.IconGen`
- [ ] Read the "do not" list in `Logo.xaml`

## Anything you could not verify

<!-- Be specific. "I could not test the elevated path" is a useful thing to say and will not be
     held against you — claiming it works when you did not check will be. -->
