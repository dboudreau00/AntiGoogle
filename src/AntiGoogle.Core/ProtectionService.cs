// Anti-Google — removes Google telemetry from Windows, and tells you what that breaks first.
// Copyright (C) 2026 The Anti-Google contributors
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

using AntiGoogle.Core.Catalog;
using AntiGoogle.Core.Engines;
using AntiGoogle.Core.Journal;
using AntiGoogle.Core.Model;
using AntiGoogle.Core.Platform;
using AntiGoogle.Core.Safety;

namespace AntiGoogle.Core;

/// <summary>Snapshot of what is actually applied to this machine right now.</summary>
public sealed record ProtectionStatus(
    bool AnyProtection,
    int SinkholedDomains,
    int FirewallRules,
    int DisabledServices,
    int RegistryValues,
    int JournalEntries,
    bool Elevated);

/// <summary>
/// Everything <see cref="ProtectionService"/> talks to, so a test can point it at throwaway
/// targets instead of the live machine. Every member is optional and falls back to the production
/// object, so <c>new ProtectionService()</c> behaves exactly as before.
///
/// This is a testability seam, not a plug-in point: the app itself always uses the defaults.
/// </summary>
public sealed record ProtectionServiceOptions
{
    /// <summary>Undo log. Default writes to <see cref="AppPaths.JournalFile"/> in ProgramData.</summary>
    public ChangeJournal? Journal { get; init; }

    /// <summary>Point at a temp hosts file (and temp backup dir) to keep tests off the real one.</summary>
    public HostsFileEngine? Hosts { get; init; }

    public ServiceEngine? Services { get; init; }
    public ScheduledTaskEngine? Tasks { get; init; }
    public RegistryPolicyEngine? Registry { get; init; }

    /// <summary>Construct with a distinct group in tests — revert sweeps the whole group.</summary>
    public FirewallEngine? Firewall { get; init; }

    /// <summary>The rule universe plans are built from. Defaults to <see cref="RuleCatalog.All"/>.</summary>
    public IReadOnlyList<BlockRule>? Catalog { get; init; }

    /// <summary>
    /// Preflight override. Defaults to <see cref="Safety.Preflight.RunAsync"/>. Tests need this
    /// because the real preflight blocks every rule when unelevated, so no plan would ever be
    /// actionable — and because refusal behaviour has to be driven deterministically.
    /// </summary>
    public Func<CancellationToken, Task<List<PreflightFinding>>>? Preflight { get; init; }

    /// <summary>Elevation gate for apply/revert. Defaults to <see cref="Elevation.IsElevated"/>.</summary>
    public Func<bool>? IsElevated { get; init; }

    /// <summary>
    /// Whether <see cref="ProtectionService.RevertAllAsync"/> ends with the belt-and-braces sweep of
    /// the whole firewall group. On by default. Tests turn it off only to avoid a PowerShell spawn
    /// per test; it cannot be exercised unelevated anyway.
    /// </summary>
    public bool SweepFirewallGroupOnRevert { get; init; } = true;
}

/// <summary>
/// Orchestrates plan → confirm → apply → journal → revert across every engine.
///
/// The invariant the whole design rests on: nothing reaches the OS that did not first appear in a
/// <see cref="ChangePlan"/> the user saw, and nothing is changed before its reverse is durably
/// journalled. Revert therefore works even if the app is killed mid-apply.
/// </summary>
public sealed class ProtectionService
{
    private readonly HostsFileEngine _hosts;
    private readonly ServiceEngine _services;
    private readonly ScheduledTaskEngine _tasks;
    private readonly RegistryPolicyEngine _registry;
    private readonly FirewallEngine _firewall;
    private readonly ChangeJournal _journal;

    private readonly IReadOnlyList<BlockRule> _catalog;
    private readonly Func<CancellationToken, Task<List<PreflightFinding>>> _preflight;
    private readonly Func<bool> _isElevated;
    private readonly bool _sweepFirewallGroupOnRevert;

    public ChangeJournal Journal => _journal;

    public ProtectionService() : this(null) { }

    public ProtectionService(ProtectionServiceOptions? options)
    {
        var o = options ?? new ProtectionServiceOptions();

        _hosts = o.Hosts ?? new HostsFileEngine();
        _services = o.Services ?? new ServiceEngine();
        _tasks = o.Tasks ?? new ScheduledTaskEngine();
        _registry = o.Registry ?? new RegistryPolicyEngine();
        _firewall = o.Firewall ?? new FirewallEngine();
        _journal = o.Journal ?? new ChangeJournal();

        _catalog = o.Catalog ?? RuleCatalog.All;
        _preflight = o.Preflight ?? Safety.Preflight.RunAsync;
        _isElevated = o.IsElevated ?? (() => Elevation.IsElevated);
        _sweepFirewallGroupOnRevert = o.SweepFirewallGroupOnRevert;

        try { _journal.Load(); }
        catch (Exception ex) { Log.Error("Journal could not be loaded at startup.", ex); throw; }
    }

    /// <summary>Rule lookup against the injected catalog rather than the static one.</summary>
    private BlockRule? ById(string id) =>
        _catalog.FirstOrDefault(r => string.Equals(r.Id, id, StringComparison.OrdinalIgnoreCase));

    // ------------------------------------------------------------------ status

    public async Task<ProtectionStatus> GetStatusAsync(CancellationToken ct = default)
    {
        var sinkholed = _hosts.CurrentlyBlocked().Count;

        var fwRules = 0;
        try { fwRules = (await _firewall.ExistingRulesAsync(ct).ConfigureAwait(false)).Count; }
        catch (Exception ex) { Log.Warn($"Firewall rule count unavailable: {ex.Message}"); }

        var svc = _journal.Entries.Count(e => e.Reverse == ReverseKind.RestoreServiceStartType);
        var reg = _journal.Entries.Count(e => e.Reverse == ReverseKind.RestoreRegistryValue);

        return new ProtectionStatus(
            AnyProtection: sinkholed > 0 || fwRules > 0 || _journal.HasChanges,
            SinkholedDomains: sinkholed,
            FirewallRules: fwRules,
            DisabledServices: svc,
            RegistryValues: reg,
            JournalEntries: _journal.Entries.Count,
            Elevated: _isElevated());
    }

    // ------------------------------------------------------------------ planning

    /// <summary>
    /// Works out exactly what applying these rules would do, without touching anything.
    /// Rules refused by a preflight blocker are marked <see cref="ChangeOutcome.Refused"/> and
    /// carry the reason, so the UI can explain rather than silently drop them.
    /// </summary>
    public async Task<ChangePlan> BuildPlanAsync(
        IEnumerable<string> enabledRuleIds,
        IEnumerable<string>? containedApps = null,
        CancellationToken ct = default)
    {
        var plan = new ChangePlan();
        var ids = enabledRuleIds.ToHashSet(StringComparer.OrdinalIgnoreCase);

        plan.Findings.AddRange(await _preflight(ct).ConfigureAwait(false));

        var refusals = plan.Findings
            .Where(f => f.Level == FindingLevel.Blocker)
            .SelectMany(f => f.BlockedRuleIds.Select(id => (id, f.Title)))
            .GroupBy(x => x.id, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().Title, StringComparer.OrdinalIgnoreCase);

        var rules = _catalog.Where(r => ids.Contains(r.Id)).ToList();
        plan.Rules.AddRange(rules);

        var hostsRules = new List<BlockRule>();

        foreach (var rule in rules)
        {
            ct.ThrowIfCancellationRequested();

            if (refusals.TryGetValue(rule.Id, out var why))
            {
                plan.Changes.Add(new PlannedChange
                {
                    RuleId = rule.Id,
                    Engine = rule.Engine,
                    Description = $"{rule.Title} — refused",
                    Target = rule.Id,
                    Outcome = ChangeOutcome.Refused,
                    RefusalReason = why
                });
                continue;
            }

            switch (rule.Engine)
            {
                case EngineKind.Hosts:
                    hostsRules.Add(rule);
                    break;

                case EngineKind.Service:
                    foreach (var (name, start) in _services.Resolve(rule.ServiceNamePatterns))
                    {
                        plan.Changes.Add(new PlannedChange
                        {
                            RuleId = rule.Id,
                            Engine = EngineKind.Service,
                            Description = $"Disable service {name}" + (start == 4 ? " (already disabled)" : ""),
                            Target = name,
                            Outcome = start == 4 ? ChangeOutcome.AlreadySatisfied : ChangeOutcome.Applied
                        });
                    }
                    break;

                case EngineKind.ScheduledTask:
                    foreach (var t in await _tasks.ResolveAsync(rule.ScheduledTaskPatterns, ct).ConfigureAwait(false))
                    {
                        plan.Changes.Add(new PlannedChange
                        {
                            RuleId = rule.Id,
                            Engine = EngineKind.ScheduledTask,
                            Description = $"Disable scheduled task {t.Path}" + (t.Enabled ? "" : " (already disabled)"),
                            Target = t.Path,
                            Outcome = t.Enabled ? ChangeOutcome.Applied : ChangeOutcome.AlreadySatisfied
                        });
                    }
                    break;

                case EngineKind.Registry:
                    foreach (var pol in rule.RegistryValues)
                    {
                        var satisfied = _registry.IsSatisfied(pol);
                        plan.Changes.Add(new PlannedChange
                        {
                            RuleId = rule.Id,
                            Engine = EngineKind.Registry,
                            Description = $"Set {pol.Display}" + (satisfied ? " (already set)" : ""),
                            Target = $"{pol.Key}\\{pol.Name}",
                            Outcome = satisfied ? ChangeOutcome.AlreadySatisfied : ChangeOutcome.Applied
                        });
                    }
                    break;

                case EngineKind.Firewall:
                    plan.Changes.Add(new PlannedChange
                    {
                        RuleId = rule.Id,
                        Engine = EngineKind.Firewall,
                        Description = $"Create outbound block '{FirewallEngine.RuleNameFor(rule.Id)}' " +
                                      $"covering {rule.IpRanges.Count} ranges",
                        Target = FirewallEngine.RuleNameFor(rule.Id)
                    });
                    break;
            }
        }

        if (hostsRules.Count > 0)
        {
            var domainCount = hostsRules.SelectMany(r => r.Domains)
                                        .Distinct(StringComparer.OrdinalIgnoreCase).Count();
            plan.Changes.Add(new PlannedChange
            {
                RuleId = string.Join(",", hostsRules.Select(r => r.Id)),
                Engine = EngineKind.Hosts,
                Description = $"Sinkhole {domainCount} domains in the hosts file " +
                              $"({domainCount * 2} lines, IPv4 + IPv6) from {hostsRules.Count} rules",
                Target = "hosts"
            });
        }

        var contained = (containedApps ?? []).ToList();
        foreach (var app in contained)
        {
            var exists = File.Exists(app);
            plan.Changes.Add(new PlannedChange
            {
                RuleId = ContainmentRuleId(app),
                Engine = EngineKind.AppContainment,
                Description = $"Contain {Path.GetFileName(app)} — block its access to Google ranges",
                Target = app,
                Outcome = exists ? ChangeOutcome.Applied : ChangeOutcome.NotPresent
            });
        }

        // Containment targets are chosen at runtime, so they have no catalog entry and would
        // otherwise contribute nothing to the impact report — silently breaking the app's core
        // promise that every armed change states its cost. Synthesise the warning instead.
        if (contained.Count > 0)
            plan.Rules.Add(ContainmentWarningRule(contained));

        Log.Info($"Plan built: {plan.Changes.Count} changes across {rules.Count} rules, " +
                 $"{plan.SevereCount} severe degradations.");
        return plan;
    }

    // ------------------------------------------------------------------ apply

    public async Task<ApplyReport> ApplyAsync(
        ChangePlan plan, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        if (!_isElevated())
            throw new UnauthorizedAccessException("Applying changes requires administrator rights.");

        AppPaths.EnsureCreated();
        Log.Info($"=== APPLY start: {plan.Changes.Count} planned changes ===");

        var hostsRules = plan.Rules.Where(r => r.Engine == EngineKind.Hosts).ToList();
        var refusedIds = plan.Changes.Where(c => c.Outcome == ChangeOutcome.Refused)
                                     .Select(c => c.RuleId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        hostsRules = hostsRules.Where(r => !refusedIds.Contains(r.Id)).ToList();

        foreach (var change in plan.Changes)
        {
            ct.ThrowIfCancellationRequested();

            if (change.Outcome is ChangeOutcome.Refused or ChangeOutcome.NotPresent or ChangeOutcome.AlreadySatisfied)
                continue;

            progress?.Report(change.Description);

            try
            {
                switch (change.Engine)
                {
                    case EngineKind.Hosts:
                        if (hostsRules.Count > 0)
                            await _hosts.ApplyAsync(hostsRules, _journal, ct).ConfigureAwait(false);
                        change.Outcome = ChangeOutcome.Applied;
                        break;

                    case EngineKind.Service:
                    {
                        var rule = ById(change.RuleId);
                        if (rule is null) { change.Outcome = ChangeOutcome.NotPresent; break; }
                        var match = _services.Resolve(rule.ServiceNamePatterns)
                            .FirstOrDefault(s => string.Equals(s.Name, change.Target, StringComparison.OrdinalIgnoreCase));
                        if (match.Name is null) { change.Outcome = ChangeOutcome.NotPresent; break; }
                        change.Outcome = await _services
                            .ApplyAsync(rule, match.Name, match.StartType, _journal, ct).ConfigureAwait(false);
                        break;
                    }

                    case EngineKind.ScheduledTask:
                    {
                        var rule = ById(change.RuleId);
                        if (rule is null) { change.Outcome = ChangeOutcome.NotPresent; break; }
                        change.Outcome = await _tasks
                            .ApplyAsync(rule, new ScheduledTaskEngine.TaskInfo(change.Target, true), _journal, ct)
                            .ConfigureAwait(false);
                        break;
                    }

                    case EngineKind.Registry:
                    {
                        var rule = ById(change.RuleId);
                        var pol = rule?.RegistryValues.FirstOrDefault(p => $"{p.Key}\\{p.Name}" == change.Target);
                        if (rule is null || pol is null) { change.Outcome = ChangeOutcome.NotPresent; break; }
                        change.Outcome = _registry.Apply(rule, pol, _journal);
                        break;
                    }

                    case EngineKind.Firewall:
                    {
                        var rule = ById(change.RuleId);
                        if (rule is null) { change.Outcome = ChangeOutcome.NotPresent; break; }
                        change.Outcome = await _firewall
                            .ApplyRangeBlockAsync(rule, _journal, ct).ConfigureAwait(false);
                        break;
                    }

                    case EngineKind.AppContainment:
                    {
                        change.Outcome = await _firewall.ApplyProgramBlockAsync(
                            ContainmentRuleId(change.Target),
                            $"Anti-Google: contain {Path.GetFileName(change.Target)}",
                            change.Target,
                            GoogleIpRanges.Core,
                            _journal, ct).ConfigureAwait(false);
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                // One engine failing must not abandon the rest — and the journal already holds the
                // reverse for everything that did land, so the user can still undo cleanly.
                change.Outcome = ChangeOutcome.Failed;
                change.Error = ex.Message;
                Log.Error($"Change failed: {change.Description}", ex);
            }
        }

        var report = new ApplyReport { Plan = plan };
        Log.Info($"=== APPLY done: {report.Applied} applied, {report.Skipped} skipped, " +
                 $"{report.Failed} failed, {report.Refused} refused ===");
        return report;
    }

    // ------------------------------------------------------------------ revert

    /// <summary>
    /// Undoes everything, newest change first. Individual failures are collected rather than
    /// thrown so one stuck item cannot block the rest of the restore.
    /// </summary>
    public async Task<IReadOnlyList<string>> RevertAllAsync(
        IProgress<string>? progress = null, CancellationToken ct = default)
    {
        if (!_isElevated())
            throw new UnauthorizedAccessException("Restoring changes requires administrator rights.");

        var errors = new List<string>();
        Log.Info($"=== REVERT start: {_journal.Entries.Count} entries ===");

        foreach (var entry in _journal.ReplayOrder())
        {
            ct.ThrowIfCancellationRequested();
            progress?.Report($"Undoing: {entry.Description}");

            try
            {
                await RevertEntryAsync(entry, ct).ConfigureAwait(false);
                _journal.Remove(entry);
            }
            catch (Exception ex)
            {
                // Leave the entry in place so a later attempt can retry it.
                errors.Add($"{entry.Description}: {ex.Message}");
                Log.Error($"Revert failed for {entry.Description}", ex);
            }
        }

        // Belt and braces: sweep any firewall rule in our group the journal did not know about.
        if (_sweepFirewallGroupOnRevert)
        {
            try { await _firewall.RemoveAllAsync(ct).ConfigureAwait(false); }
            catch (Exception ex) { errors.Add($"Firewall group sweep: {ex.Message}"); }
        }

        Log.Info($"=== REVERT done: {errors.Count} errors, {_journal.Entries.Count} entries remaining ===");
        return errors;
    }

    /// <summary>Undoes only the entries belonging to one rule.</summary>
    public async Task<IReadOnlyList<string>> RevertRuleAsync(string ruleId, CancellationToken ct = default)
    {
        if (!_isElevated())
            throw new UnauthorizedAccessException("Restoring changes requires administrator rights.");

        var errors = new List<string>();
        foreach (var entry in _journal.ReplayOrder()
                     .Where(e => e.RuleId.Split(',').Contains(ruleId, StringComparer.OrdinalIgnoreCase)))
        {
            try
            {
                await RevertEntryAsync(entry, ct).ConfigureAwait(false);
                _journal.Remove(entry);
            }
            catch (Exception ex) { errors.Add($"{entry.Description}: {ex.Message}"); }
        }
        return errors;
    }

    private Task RevertEntryAsync(JournalEntry entry, CancellationToken ct) => entry.Reverse switch
    {
        ReverseKind.RestoreHostsBackup => _hosts.RevertAsync(entry, ct),
        ReverseKind.RestoreServiceStartType => _services.RevertAsync(entry, ct),
        ReverseKind.RestoreScheduledTask => _tasks.RevertAsync(entry, ct),
        ReverseKind.RestoreRegistryValue => _registry.RevertAsync(entry, ct),
        ReverseKind.RemoveFirewallRule => _firewall.RevertAsync(entry, ct),
        _ => Task.CompletedTask
    };

    /// <summary>Stable per-executable rule id, so re-containing the same app is idempotent.</summary>
    public static string ContainmentRuleId(string exePath) =>
        "contain." + Path.GetFileNameWithoutExtension(exePath).ToLowerInvariant();

    /// <summary>
    /// A synthetic rule carrying the honest cost of per-app containment. Not part of the catalog
    /// because its targets are whatever the user picked on the containment screen.
    /// </summary>
    public static BlockRule ContainmentWarningRule(IReadOnlyList<string> apps)
    {
        var names = string.Join(", ", apps.Select(Path.GetFileName).Take(6));
        var more = apps.Count > 6 ? $" and {apps.Count - 6} more" : "";

        return new BlockRule
        {
            Id = "contain.summary",
            Title = $"Per-app containment ({apps.Count} executables)",
            Summary = $"Firewall rules scoped to: {names}{more}",
            Category = RuleCategory.Containment,
            Tier = RiskTier.Aggressive,
            Engine = EngineKind.AppContainment,
            Breaks =
            [
                Breakage.Severe("Contained apps lose their update and licensing checks",
                    $"Blocking {names}{more} from Google ranges also stops whatever else they use those ranges for — " +
                    "auto-update, crash upload, licence validation, and any Google-hosted CDN they depend on. " +
                    "An Electron app that cannot reach its update server may nag, fail to launch, or hang on a network timeout."),
                Breakage.Notable("Failures look like network problems, not blocks",
                    "The app sees a connection timeout rather than a refusal, so its error message will be vague. " +
                    "If a contained app starts misbehaving, un-contain it here first before debugging anything else.")
            ]
        };
    }
}
