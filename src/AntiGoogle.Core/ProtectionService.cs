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

using System.Security.Cryptography;
using System.Text;
using AntiGoogle.Core.Catalog;
using AntiGoogle.Core.Engines;
using AntiGoogle.Core.Journal;
using AntiGoogle.Core.Markers;
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
    bool Elevated,
    int LoopbackDomains = 0,
    int LocalOnlyJails = 0,
    int QuarantinedItems = 0);

/// <summary>Everything the user has chosen, in one place: what a plan is built from.</summary>
public sealed record PlanRequest
{
    public IReadOnlyCollection<string> EnabledRuleIds { get; init; } = [];

    /// <summary>Programs whose access to Google's ranges is blocked.</summary>
    public IReadOnlyCollection<string> ContainedApps { get; init; } = [];

    /// <summary>Armed rules that keep their target running, confined to this machine.</summary>
    public IReadOnlyCollection<string> LocalOnlyRuleIds { get; init; } = [];

    /// <summary>Programs kept running but confined to this machine. Supersedes <see cref="ContainedApps"/>.</summary>
    public IReadOnlyCollection<string> LocalOnlyApps { get; init; } = [];

    /// <summary>Markers to move into the quarantine vault.</summary>
    public IReadOnlyCollection<string> QuarantineMarkerIds { get; init; } = [];
}

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

    /// <summary>Construct with a distinct group in tests: revert sweeps the whole group.</summary>
    public FirewallEngine? Firewall { get; init; }

    /// <summary>Quarantine vault. Point it at a temp directory in tests.</summary>
    public QuarantineEngine? Quarantine { get; init; }

    /// <summary>Marker scanner. Point it at a temp environment in tests.</summary>
    public MarkerScanner? Markers { get; init; }

    public IReadOnlyList<MarkerDefinition>? MarkerCatalog { get; init; }

    /// <summary>
    /// TCP ports 80 and 443 something local listens on (null when unreadable). Defaults to
    /// <see cref="Safety.Preflight.LoopbackWebListeners"/>. Tests drive it to prove the fallback.
    /// </summary>
    public Func<IReadOnlyList<int>?>? WebListeners { get; init; }

    /// <summary>The rule universe plans are built from. Defaults to <see cref="RuleCatalog.All"/>.</summary>
    public IReadOnlyList<BlockRule>? Catalog { get; init; }

    /// <summary>
    /// Preflight override. Defaults to <see cref="Safety.Preflight.RunAsync"/>. Tests need this
    /// because the real preflight blocks every rule when unelevated, so no plan would ever be
    /// actionable, and because refusal behaviour has to be driven deterministically.
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
/// Orchestrates plan, confirm, apply, journal and revert across every engine.
///
/// The invariant the whole design rests on: nothing reaches the OS that did not first appear in a
/// <see cref="ChangePlan"/> the user saw, and nothing is changed before its reverse is durably
/// journalled. Revert therefore works even if the app is killed mid-apply.
///
/// A plan also makes the machine match the armed set: journal entries that no armed rule claims any
/// more (a rule switched off, or switched between blocking and local-only) become undo changes, listed
/// in the preview and executed before anything new is applied.
/// </summary>
public sealed class ProtectionService
{
    private readonly HostsFileEngine _hosts;
    private readonly ServiceEngine _services;
    private readonly ScheduledTaskEngine _tasks;
    private readonly RegistryPolicyEngine _registry;
    private readonly FirewallEngine _firewall;
    private readonly QuarantineEngine _quarantine;
    private readonly MarkerScanner _markers;
    private readonly IReadOnlyList<MarkerDefinition> _markerCatalog;
    private readonly Func<IReadOnlyList<int>?> _webListeners;
    private readonly ChangeJournal _journal;

    private readonly IReadOnlyList<BlockRule> _catalog;
    private readonly Func<CancellationToken, Task<List<PreflightFinding>>> _preflight;
    private readonly Func<bool> _isElevated;
    private readonly bool _sweepFirewallGroupOnRevert;

    public ChangeJournal Journal => _journal;
    public QuarantineEngine Quarantine => _quarantine;
    public FirewallEngine Firewall => _firewall;
    public HostsFileEngine Hosts => _hosts;

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
        _quarantine = o.Quarantine ?? new QuarantineEngine();
        _markers = o.Markers ?? new MarkerScanner(new SystemMarkerEnvironment(_services));
        _markerCatalog = o.MarkerCatalog ?? Markers.MarkerCatalog.All;
        _webListeners = o.WebListeners ?? Safety.Preflight.LoopbackWebListeners;

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
        var looped = _hosts.CurrentlyLooped().Count;

        var fwRules = 0;
        try { fwRules = (await _firewall.ExistingRulesAsync(ct).ConfigureAwait(false)).Count; }
        catch (Exception ex) { Log.Warn($"Firewall rule count unavailable: {ex.Message}"); }

        var svc = _journal.Entries.Count(e => e.Reverse == ReverseKind.RestoreServiceStartType);
        var reg = _journal.Entries.Count(e => e.Reverse == ReverseKind.RestoreRegistryValue);
        var jails = _journal.Entries.Count(e => e.Engine == EngineKind.LocalOnly &&
                                                e.FirewallRuleName?.EndsWith("(out)", StringComparison.Ordinal) == true);
        var held = _quarantine.List().Count;

        return new ProtectionStatus(
            AnyProtection: sinkholed > 0 || looped > 0 || fwRules > 0 || held > 0 || _journal.HasChanges,
            SinkholedDomains: sinkholed,
            FirewallRules: fwRules,
            DisabledServices: svc,
            RegistryValues: reg,
            JournalEntries: _journal.Entries.Count,
            Elevated: _isElevated(),
            LoopbackDomains: looped,
            LocalOnlyJails: jails,
            QuarantinedItems: held);
    }

    // ------------------------------------------------------------------ planning

    public Task<ChangePlan> BuildPlanAsync(
        IEnumerable<string> enabledRuleIds,
        IEnumerable<string>? containedApps = null,
        CancellationToken ct = default) =>
        BuildPlanAsync(new PlanRequest
        {
            EnabledRuleIds = enabledRuleIds.ToList(),
            ContainedApps = (containedApps ?? []).ToList()
        }, ct);

    /// <summary>
    /// Works out exactly what applying this request would do, without touching anything.
    /// Rules refused by a preflight blocker are marked <see cref="ChangeOutcome.Refused"/> and
    /// carry the reason, so the UI can explain rather than silently drop them.
    /// </summary>
    public async Task<ChangePlan> BuildPlanAsync(PlanRequest request, CancellationToken ct = default)
    {
        var plan = new ChangePlan();
        var ids = request.EnabledRuleIds.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var localOnlyIds = request.LocalOnlyRuleIds.ToHashSet(StringComparer.OrdinalIgnoreCase);

        plan.Findings.AddRange(await _preflight(ct).ConfigureAwait(false));

        var vendorRuleIds = RuleCatalog.AgentSensitiveRuleIds
            .Where(id => _catalog.Any(r => string.Equals(r.Id, id, StringComparison.OrdinalIgnoreCase))).ToList();
        if (vendorRuleIds.Any(ids.Contains))
        {
            var agents = _markers.Scan(_markerCatalog.Where(m => m.Class == MarkerClass.SecurityAgent), ct);
            var finding = Safety.Preflight.SecurityAgentFinding(agents, vendorRuleIds);
            if (finding is not null) plan.Findings.Add(finding);
        }

        var refusals = plan.Findings
            .Where(f => f.Level == FindingLevel.Blocker)
            .SelectMany(f => f.BlockedRuleIds.Select(id => (id, f.Title)))
            .GroupBy(x => x.id, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().Title, StringComparer.OrdinalIgnoreCase);

        var rules = _catalog.Where(r => ids.Contains(r.Id)).ToList();

        // Hosts names may resolve to this machine only if nothing local would answer for Google.
        var wantsLoopback = rules.Any(r => r.Engine == EngineKind.Hosts && r.SupportsLocalOnly && localOnlyIds.Contains(r.Id)
                                           && !refusals.ContainsKey(r.Id));
        var loopbackAllowed = true;
        if (wantsLoopback)
        {
            var listeners = _webListeners();
            if (listeners is null || listeners.Count > 0)
            {
                loopbackAllowed = false;
                plan.LoopbackDowngraded = true;
                plan.Findings.Add(PreflightFinding.Warn(
                    "Local-only names were sinkholed instead",
                    listeners is null
                        ? "The list of local listeners could not be read, so no name was mapped to this machine."
                        : $"Something on this machine is listening on port {string.Join(" and ", listeners)}. A name mapped to loopback would " +
                          "be delivered to it, along with whatever the client sends Google. Those names resolve to nowhere instead."));
            }
        }

        RuleMode ModeOf(BlockRule r) =>
            r.SupportsLocalOnly && localOnlyIds.Contains(r.Id) && (r.Engine != EngineKind.Hosts || loopbackAllowed)
                ? RuleMode.LocalOnly
                : RuleMode.Block;

        var hostsRules = new List<BlockRule>();
        var armedModes = new Dictionary<string, RuleMode>(StringComparer.OrdinalIgnoreCase);

        foreach (var rule in rules)
        {
            ct.ThrowIfCancellationRequested();
            var mode = ModeOf(rule);
            armedModes[rule.Id] = mode;
            plan.Rules.Add(rule.ForMode(mode));

            if (refusals.TryGetValue(rule.Id, out var why))
            {
                plan.Changes.Add(new PlannedChange
                {
                    RuleId = rule.Id,
                    Engine = rule.Engine,
                    Description = $"{rule.Title} (refused)",
                    Target = rule.Id,
                    Outcome = ChangeOutcome.Refused,
                    RefusalReason = why
                });
                continue;
            }

            switch (rule.Engine)
            {
                case EngineKind.Hosts:
                    hostsRules.Add(rule.ForMode(mode));
                    if (mode == RuleMode.LocalOnly) plan.LoopbackRuleIds.Add(rule.Id);
                    break;

                case EngineKind.Service when mode == RuleMode.LocalOnly:
                    foreach (var (name, _) in _services.Resolve(rule.ServiceNamePatterns))
                        plan.Changes.Add(ServiceJailChange(rule, name));
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

                case EngineKind.ScheduledTask when mode == RuleMode.LocalOnly:
                    foreach (var t in await _tasks.ResolveAsync(rule.ScheduledTaskPatterns, ct).ConfigureAwait(false))
                        plan.Changes.AddRange(await TaskJailChangesAsync(rule, t.Path, ct).ConfigureAwait(false));
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
            var modes = HostsFileEngine.EffectiveModes(hostsRules, plan.LoopbackRuleIds);
            var looped = modes.Count(kv => kv.Value);
            var domainCount = modes.Count;
            plan.Changes.Add(new PlannedChange
            {
                RuleId = string.Join(",", hostsRules.Select(r => r.Id)),
                Engine = EngineKind.Hosts,
                Description = looped == 0
                    ? $"Sinkhole {domainCount} domains in the hosts file " +
                      $"({domainCount * 2} lines, IPv4 + IPv6) from {hostsRules.Count} rules"
                    : $"Write {domainCount} domains to the hosts file ({domainCount - looped} sinkholed, " +
                      $"{looped} resolved to this machine; {domainCount * 2} lines, IPv4 + IPv6) from {hostsRules.Count} rules",
                Target = "hosts"
            });
        }

        // Local-only apps supersede plain containment of the same program: the jail is the stricter of the two.
        var localOnlyApps = request.LocalOnlyApps.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        foreach (var app in localOnlyApps)
            plan.Changes.Add(AppJailChange(app));
        if (localOnlyApps.Count > 0)
            plan.Rules.Add(LocalOnlyWarningRule(localOnlyApps));

        var contained = request.ContainedApps
            .Where(a => !localOnlyApps.Contains(a, StringComparer.OrdinalIgnoreCase)).ToList();
        foreach (var app in contained)
        {
            var exists = File.Exists(app);
            plan.Changes.Add(new PlannedChange
            {
                RuleId = ContainmentRuleId(app),
                Engine = EngineKind.AppContainment,
                Description = $"Contain {Path.GetFileName(app)} (block its access to Google ranges)",
                Target = app,
                Outcome = exists ? ChangeOutcome.Applied : ChangeOutcome.NotPresent
            });
        }

        // Containment targets are chosen at runtime, so they have no catalog entry and would
        // otherwise contribute nothing to the impact report, silently breaking the app's core
        // promise that every armed change states its cost. Synthesise the warning instead.
        if (contained.Count > 0)
            plan.Rules.Add(ContainmentWarningRule(contained));

        PlanQuarantine(plan, request.QuarantineMarkerIds, ct);

        // What an earlier apply did that nothing armed claims any more is taken back, first.
        var undo = StaleEntries(request, ids, armedModes, hostsRules.Count > 0)
            .Select(e => new PlannedChange
            {
                RuleId = e.RuleId,
                Engine = e.Engine,
                Description = $"Undo: {e.Description}",
                Target = e.Id,
                IsUndo = true,
                JournalEntryId = e.Id
            }).ToList();
        plan.Changes.InsertRange(0, undo);

        Log.Info($"Plan built: {plan.Changes.Count} changes ({undo.Count} undo) across {rules.Count} rules, " +
                 $"{plan.SevereCount} severe degradations.");
        return plan;
    }

    // ------------------------------------------------------------------ planning helpers: local-only

    private PlannedChange ServiceJailChange(BlockRule rule, string serviceName)
    {
        var image = _services.ResolveImage(serviceName);
        string? program = null, service = null, refusal = null;

        if (image.SharedHost) service = serviceName;
        else if (image.ExecutablePath is { } exe)
        {
            try { FirewallEngine.ValidateJailTarget(exe, null); program = exe; }
            catch (Exception ex) when (ex is ArgumentException or FileNotFoundException) { refusal = ex.Message; }
        }
        else refusal = "the program it runs could not be identified";

        return JailChange(rule.Id, serviceName, program, service, refusal,
            service is not null ? $"svc.{serviceName}" : program is not null ? JailLabel(program) : "",
            $"Keep service {serviceName} running, confined to this machine");
    }

    private async Task<IReadOnlyList<PlannedChange>> TaskJailChangesAsync(BlockRule rule, string taskPath, CancellationToken ct)
    {
        var exes = await _tasks.ResolveActionPathsAsync(taskPath, ct).ConfigureAwait(false);
        if (exes.Count == 0)
            return [JailChange(rule.Id, taskPath, null, null, "it runs no program that can be named", "",
                $"Keep scheduled task {taskPath} running, confined to this machine")];

        var changes = new List<PlannedChange>();
        foreach (var exe in exes)
        {
            string? program = null, refusal = null;
            try { FirewallEngine.ValidateJailTarget(exe, null); program = exe; }
            catch (Exception ex) when (ex is ArgumentException or FileNotFoundException) { refusal = ex.Message; }

            changes.Add(JailChange(rule.Id, $"{taskPath}|{exe}", program, null, refusal,
                program is not null ? JailLabel(program) : "",
                $"Keep scheduled task {taskPath} running, confined to this machine ({Path.GetFileName(exe)})"));
        }
        return changes;
    }

    private static PlannedChange AppJailChange(string app)
    {
        if (!File.Exists(app))
            return new PlannedChange
            {
                RuleId = LocalOnlyAppRuleId(app), Engine = EngineKind.LocalOnly, Target = app,
                Description = $"Keep {Path.GetFileName(app)} running, confined to this machine",
                Outcome = ChangeOutcome.NotPresent
            };

        string? program = null, refusal = null;
        try { FirewallEngine.ValidateJailTarget(app, null); program = app; }
        catch (Exception ex) when (ex is ArgumentException or FileNotFoundException) { refusal = ex.Message; }

        return JailChange(LocalOnlyAppRuleId(app), app, program, null, refusal,
            program is not null ? JailLabel(program) : "",
            $"Keep {Path.GetFileName(app)} running, confined to this machine");
    }

    private static PlannedChange JailChange(
        string ruleId, string target, string? program, string? service, string? refusal, string label, string description) =>
        new()
        {
            RuleId = ruleId,
            Engine = EngineKind.LocalOnly,
            Target = target,
            Description = refusal is null ? description : $"{description} (refused)",
            Outcome = refusal is null ? ChangeOutcome.Applied : ChangeOutcome.Refused,
            RefusalReason = refusal,
            JailProgram = program,
            JailService = service,
            JailLabel = label
        };

    /// <summary>Stable short label for a jailed program: its name plus a hash of its full path, so two copies never collide.</summary>
    internal static string JailLabel(string programPath)
    {
        var full = Path.GetFullPath(programPath).ToLowerInvariant();
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(full)))[..8].ToLowerInvariant();
        return $"{Path.GetFileNameWithoutExtension(full)}-{hash}";
    }

    public static string LocalOnlyAppRuleId(string exePath) => "localonly.app." + JailLabel(exePath);

    // ------------------------------------------------------------------ planning helpers: markers

    private void PlanQuarantine(ChangePlan plan, IReadOnlyCollection<string> markerIds, CancellationToken ct)
    {
        var chosen = new List<MarkerDefinition>();
        foreach (var id in markerIds.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var def = _markerCatalog.FirstOrDefault(m => string.Equals(m.Id, id, StringComparison.OrdinalIgnoreCase));
            if (def is null) continue;

            if (!QuarantineEngine.IsQuarantinable(def))
            {
                plan.Changes.Add(new PlannedChange
                {
                    RuleId = def.JournalRuleId, Engine = EngineKind.Quarantine, Target = def.Id,
                    Description = $"Quarantine {def.Title} (refused)", Outcome = ChangeOutcome.Refused,
                    RefusalReason = QuarantineEngine.WhyReportedOnly(def)
                });
                continue;
            }

            var present = _markers.Scan([def], ct).Where(f => f.Exists).ToList();
            if (present.Count == 0)
            {
                plan.Changes.Add(new PlannedChange
                {
                    RuleId = def.JournalRuleId, Engine = EngineKind.Quarantine, Target = def.Id,
                    Description = $"Quarantine {def.Title} (not on this machine)", Outcome = ChangeOutcome.NotPresent
                });
                continue;
            }

            chosen.Add(def);
            foreach (var f in present)
                plan.Changes.Add(new PlannedChange
                {
                    RuleId = def.JournalRuleId, Engine = EngineKind.Quarantine, Target = f.Location,
                    Description = $"Quarantine {def.Title}: {f.Location} ({f.SizeLabel})"
                });
        }

        if (chosen.Count > 0)
            plan.Rules.Add(MarkerWarningRule(chosen));
    }

    // ------------------------------------------------------------------ planning helpers: reconcile

    /// <summary>
    /// Journal entries that nothing armed claims any more. Hosts entries are aggregates that are
    /// regenerated wholesale, so they are stale only when no hosts rule remains armed.
    /// </summary>
    private IEnumerable<JournalEntry> StaleEntries(
        PlanRequest r, HashSet<string> armed, Dictionary<string, RuleMode> modes, bool anyHostsArmed)
    {
        bool Armed(string id) => armed.Contains(id) && modes.ContainsKey(id);
        bool LocalOnly(string id) => modes.TryGetValue(id, out var m) && m == RuleMode.LocalOnly;

        foreach (var e in _journal.Entries)
        {
            var ids = e.RuleId.Split(',', StringSplitOptions.RemoveEmptyEntries);
            var stale = e.Engine switch
            {
                EngineKind.Hosts => !anyHostsArmed,
                EngineKind.Service or EngineKind.ScheduledTask => ids.All(id => !Armed(id) || LocalOnly(id)),
                EngineKind.Registry or EngineKind.Firewall => ids.All(id => !Armed(id)),
                EngineKind.AppContainment =>
                    !r.ContainedApps.Any(a => ContainmentRuleId(a) == e.RuleId) ||
                    r.LocalOnlyApps.Any(a => ContainmentRuleId(a) == e.RuleId),
                EngineKind.LocalOnly when e.RuleId.StartsWith("localonly.app.", StringComparison.Ordinal) =>
                    !r.LocalOnlyApps.Any(a => LocalOnlyAppRuleId(a) == e.RuleId),
                EngineKind.LocalOnly => ids.All(id => !Armed(id) || !LocalOnly(id)),
                EngineKind.Quarantine => !r.QuarantineMarkerIds.Any(m => "marker." + m == e.RuleId),
                _ => false
            };
            if (stale) yield return e;
        }
    }

    // ------------------------------------------------------------------ apply

    public async Task<ApplyReport> ApplyAsync(
        ChangePlan plan, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        if (!_isElevated())
            throw new UnauthorizedAccessException("Applying changes requires administrator rights.");

        AppPaths.EnsureCreated();
        Log.Info($"=== APPLY start: {plan.Changes.Count} planned changes ===");

        var refusedIds = plan.Changes.Where(c => c.Outcome == ChangeOutcome.Refused)
                                     .Select(c => c.RuleId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var hostsRules = plan.Rules.Where(r => r.Engine == EngineKind.Hosts && !refusedIds.Contains(r.Id)).ToList();

        foreach (var change in plan.Changes)
        {
            ct.ThrowIfCancellationRequested();

            if (change.Outcome is ChangeOutcome.Refused or ChangeOutcome.NotPresent or ChangeOutcome.AlreadySatisfied)
                continue;

            progress?.Report(change.Description);

            try
            {
                if (change.IsUndo)
                {
                    await UndoAsync(change, ct).ConfigureAwait(false);
                }
                else
                {
                    await ApplyOneAsync(change, plan, hostsRules, ct).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                // One engine failing must not abandon the rest, and the journal already holds the
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

    private async Task ApplyOneAsync(PlannedChange change, ChangePlan plan, List<BlockRule> hostsRules, CancellationToken ct)
    {
        switch (change.Engine)
        {
            case EngineKind.Hosts:
                if (hostsRules.Count > 0)
                    await _hosts.ApplyAsync(hostsRules, _journal, ct, plan.LoopbackRuleIds).ConfigureAwait(false);
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
                change.Outcome = await _firewall.ApplyRangeBlockAsync(rule, _journal, ct).ConfigureAwait(false);
                break;
            }

            case EngineKind.AppContainment:
                change.Outcome = await _firewall.ApplyProgramBlockAsync(
                    ContainmentRuleId(change.Target),
                    $"Anti-Google: contain {Path.GetFileName(change.Target)}",
                    change.Target,
                    GoogleIpRanges.Core,
                    _journal, ct).ConfigureAwait(false);
                break;

            case EngineKind.LocalOnly:
                change.Outcome = await _firewall.ApplyLoopbackJailAsync(
                    change.RuleId, change.JailLabel!, change.JailProgram, change.JailService, _journal, ct)
                    .ConfigureAwait(false);
                break;

            case EngineKind.Quarantine:
            {
                var def = _markerCatalog.FirstOrDefault(m => m.JournalRuleId == change.RuleId);
                var finding = def is null ? null : _markers.Scan([def], ct)
                    .FirstOrDefault(f => f.Exists && string.Equals(f.Location, change.Target, StringComparison.OrdinalIgnoreCase));
                if (def is null || finding is null) { change.Outcome = ChangeOutcome.NotPresent; break; }

                var result = await _quarantine.QuarantineAsync(def, finding, _journal, ct).ConfigureAwait(false);
                change.Outcome = result.Outcome;
                if (result.Outcome == ChangeOutcome.Failed) change.Error = result.Message;
                if (result.Outcome == ChangeOutcome.Refused) change.RefusalReason = result.Message;
                break;
            }
        }
    }

    private async Task UndoAsync(PlannedChange change, CancellationToken ct)
    {
        var entry = _journal.Entries.FirstOrDefault(e => e.Id == change.JournalEntryId);
        if (entry is null) { change.Outcome = ChangeOutcome.AlreadySatisfied; return; }

        await RevertEntryAsync(entry, ct).ConfigureAwait(false);
        _journal.Remove(entry);
        change.Outcome = ChangeOutcome.Applied;
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
        ReverseKind.RestoreQuarantine => _quarantine.RevertAsync(entry, ct),
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
                    $"Blocking {names}{more} from Google ranges also stops whatever else they use those ranges for: " +
                    "auto-update, crash upload, licence validation, and any Google-hosted CDN they depend on. " +
                    "An Electron app that cannot reach its update server may nag, fail to launch, or hang on a network timeout."),
                Breakage.Notable("Failures look like network problems, not blocks",
                    "The app sees a connection timeout rather than a refusal, so its error message will be vague. " +
                    "If a contained app starts misbehaving, un-contain it here first before debugging anything else.")
            ]
        };
    }

    /// <summary>The cost of keeping programs running but confined to this machine.</summary>
    public static BlockRule LocalOnlyWarningRule(IReadOnlyList<string> apps)
    {
        var names = string.Join(", ", apps.Select(Path.GetFileName).Take(6));
        var more = apps.Count > 6 ? $" and {apps.Count - 6} more" : "";

        return new BlockRule
        {
            Id = "localonly.summary",
            Title = $"Local-only apps ({apps.Count} executables)",
            Summary = $"Kept running, confined to this machine: {names}{more}",
            Category = RuleCategory.Containment,
            Tier = RiskTier.Aggressive,
            Engine = EngineKind.LocalOnly,
            Breaks =
            [
                Breakage.Severe("Local-only apps cannot reach the internet at all",
                    $"{names}{more} keep running, but every connection to anything off this machine is blocked in both directions. " +
                    "Sign-in, sync, updates, licence checks and anything that needs the web will fail, not only Google's part of it."),
                Breakage.Notable("Failures look like refused connections",
                    "The app is denied rather than timed out, so its error messages are vague. " +
                    "If a local-only app misbehaves, take it out of local-only mode before debugging anything else."),
                Breakage.Minor("Names the hosts file does not list can still leave a lookup",
                    "A name lookup is made by Windows on the app's behalf, so the firewall rule cannot stop the lookup itself, only the connection that would follow.")
            ]
        };
    }

    /// <summary>The cost of the markers the user chose to quarantine, stated like any other rule's.</summary>
    public static BlockRule MarkerWarningRule(IReadOnlyList<MarkerDefinition> markers) => new()
    {
        Id = "marker.summary",
        Title = $"Quarantined markers ({markers.Count})",
        Summary = string.Join(", ", markers.Select(m => m.Title).Take(4)) + (markers.Count > 4 ? $" and {markers.Count - 4} more" : ""),
        Category = RuleCategory.Containment,
        Tier = RiskTier.Aggressive,
        Engine = EngineKind.Quarantine,
        Breaks = markers.SelectMany(m => m.Breaks)
                        .GroupBy(b => b.What, StringComparer.OrdinalIgnoreCase)
                        .Select(g => g.First())
                        .ToList()
    };
}
