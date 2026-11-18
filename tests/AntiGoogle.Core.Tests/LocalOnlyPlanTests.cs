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

using System.Text;
using AntiGoogle.Core.Catalog;
using AntiGoogle.Core.Engines;
using AntiGoogle.Core.Journal;
using AntiGoogle.Core.Markers;
using AntiGoogle.Core.Model;
using AntiGoogle.Core.Reporting;
using AntiGoogle.Core.Safety;
using Microsoft.Win32;
using Xunit;

namespace AntiGoogle.Core.Tests;

internal sealed class FakeServices : ServiceEngine
{
    public Dictionary<string, (int Start, ServiceImage Image)> Known { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> Disabled { get; } = [];
    public List<string> Reverted { get; } = [];

    private static bool Matches(string pattern, string name) => pattern.EndsWith('*')
        ? name.StartsWith(pattern[..^1], StringComparison.OrdinalIgnoreCase)
        : string.Equals(pattern, name, StringComparison.OrdinalIgnoreCase);

    public override IReadOnlyList<(string Name, int StartType)> Resolve(IReadOnlyList<string> patterns) =>
        Known.Where(k => patterns.Any(p => Matches(p, k.Key))).Select(k => (k.Key, k.Value.Start)).ToList();

    public override ServiceImage ResolveImage(string name) => Known[name].Image;

    public override bool? ReadDelayedAutostart(string name) => false;

    public override Task<ChangeOutcome> ApplyAsync(
        BlockRule rule, string serviceName, int previousStart, ChangeJournal journal, CancellationToken ct)
    {
        journal.Append(new JournalEntry
        {
            RuleId = rule.Id, Engine = EngineKind.Service, Description = $"Disabled service {serviceName}",
            Reverse = ReverseKind.RestoreServiceStartType, ServiceName = serviceName, PreviousStartType = previousStart
        });
        Disabled.Add(serviceName);
        return Task.FromResult(ChangeOutcome.Applied);
    }

    public override Task RevertAsync(JournalEntry entry, CancellationToken ct = default)
    {
        Disabled.Remove(entry.ServiceName!);
        Reverted.Add(entry.ServiceName!);
        return Task.CompletedTask;
    }
}

internal sealed class FakeTasks : ScheduledTaskEngine
{
    public List<TaskInfo> Known { get; } = [];
    public Dictionary<string, string[]> Actions { get; } = new(StringComparer.OrdinalIgnoreCase);

    public override Task<IReadOnlyList<TaskInfo>> ResolveAsync(IReadOnlyList<string> patterns, CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<TaskInfo>>(Known.Where(t => patterns.Any(p => p.EndsWith('*')
            ? Path.GetFileName(t.Path).StartsWith(p[..^1], StringComparison.OrdinalIgnoreCase)
            : Path.GetFileName(t.Path).Equals(p, StringComparison.OrdinalIgnoreCase))).ToList());

    public override Task<IReadOnlyList<string>> ResolveActionPathsAsync(string taskPath, CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<string>>(Actions.TryGetValue(taskPath, out var a) ? a : []);
}

internal sealed class FakeFirewall() : FirewallEngine("Anti-Google-Test-" + Guid.NewGuid().ToString("N"))
{
    public List<(string RuleId, string Label, string? Program, string? Service)> Jails { get; } = [];
    public List<(string RuleId, string Path)> Contained { get; } = [];
    public List<string> RemovedRules { get; } = [];

    public override Task<ChangeOutcome> ApplyLoopbackJailAsync(
        string ruleId, string label, string? programPath, string? serviceName, ChangeJournal journal, CancellationToken ct)
    {
        ValidateJailTarget(programPath, serviceName);
        if (Jails.Any(j => j.Label == label)) return Task.FromResult(ChangeOutcome.AlreadySatisfied);

        foreach (var direction in new[] { FirewallDirection.Outbound, FirewallDirection.Inbound })
            journal.Append(new JournalEntry
            {
                RuleId = ruleId, Engine = EngineKind.LocalOnly, Reverse = ReverseKind.RemoveFirewallRule,
                FirewallRuleName = JailRuleName(label, direction), Target = programPath ?? serviceName,
                Description = $"Confined {label} to this machine ({direction})"
            });

        Jails.Add((ruleId, label, programPath, serviceName));
        return Task.FromResult(ChangeOutcome.Applied);
    }

    public override Task<ChangeOutcome> ApplyProgramBlockAsync(
        string ruleId, string displayName, string programPath, IReadOnlyList<string> ranges, ChangeJournal journal, CancellationToken ct)
    {
        journal.Append(new JournalEntry
        {
            RuleId = ruleId, Engine = EngineKind.AppContainment, Reverse = ReverseKind.RemoveFirewallRule,
            FirewallRuleName = displayName, Target = programPath, Description = $"Contained {Path.GetFileName(programPath)}"
        });
        Contained.Add((ruleId, programPath));
        return Task.FromResult(ChangeOutcome.Applied);
    }

    public override Task RevertAsync(JournalEntry entry, CancellationToken ct = default)
    {
        RemovedRules.Add(entry.FirewallRuleName!);
        Jails.RemoveAll(j => entry.FirewallRuleName == JailRuleName(j.Label, FirewallDirection.Outbound) ||
                             entry.FirewallRuleName == JailRuleName(j.Label, FirewallDirection.Inbound));
        Contained.RemoveAll(c => entry.RuleId == c.RuleId);
        return Task.CompletedTask;
    }

    public Func<string, FirewallRuleState?, FirewallRuleState?>? ReadBackOverride { get; set; }

    private FirewallRuleState? StateFor(string displayName)
    {
        foreach (var j in Jails)
            foreach (var d in new[] { FirewallDirection.Outbound, FirewallDirection.Inbound })
            {
                var spec = JailSpecFor(j.Label, j.Program, j.Service, d);
                if (spec.DisplayName == displayName)
                    return new FirewallRuleState(spec.DisplayName, true, d.ToString(), "Block", Group,
                        spec.ProgramPath, spec.ServiceName, [.. spec.RemoteAddresses]);
            }
        return null;
    }

    public override Task<FirewallRuleState?> ReadBackAsync(string displayName, CancellationToken ct = default)
    {
        var state = StateFor(displayName);
        return Task.FromResult(ReadBackOverride is null ? state : ReadBackOverride(displayName, state));
    }

    public override Task<IReadOnlyList<FirewallRuleState>> ListRulesAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<FirewallRuleState>>(Jails
            .SelectMany(j => new[] { FirewallDirection.Outbound, FirewallDirection.Inbound }
                .Select(d => StateFor(JailRuleName(j.Label, d))!))
            .ToList());

    public override Task<IReadOnlyList<string>> ExistingRulesAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<string>>([]);

    public override Task RemoveAllAsync(CancellationToken ct = default) => Task.CompletedTask;
}

/// <summary>
/// Plans and applies that involve local-only mode, quarantine and the undo of what is no longer armed.
/// Everything runs against fakes and temp directories; the real engines are measured by the elevated
/// harness.
/// </summary>
public class LocalOnlyPlanTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "antigoogle-tests", Guid.NewGuid().ToString("N"));
    private readonly string _hostsPath;
    private readonly string _regKey = $@"Software\AntiGoogleTests\{Guid.NewGuid():N}";
    private readonly FakeServices _services = new();
    private readonly FakeTasks _tasks = new();
    private readonly FakeFirewall _firewall = new();
    private readonly TempMarkerEnvironment _markerEnv;
    private IReadOnlyList<int>? _listeners = [];
    private List<PreflightFinding> _findings = [];

    private const string UserHosts = "# mine\r\n127.0.0.1 localdev.test\r\n";

    public LocalOnlyPlanTests()
    {
        Directory.CreateDirectory(_root);
        _hostsPath = Path.Combine(_root, "hosts");
        File.WriteAllText(_hostsPath, UserHosts, new UTF8Encoding(false));
        _markerEnv = new TempMarkerEnvironment(_root);
    }

    public void Dispose()
    {
        try { Registry.CurrentUser.DeleteSubKeyTree(_regKey, throwOnMissingSubKey: false); } catch { }
        try { Directory.Delete(_root, recursive: true); } catch { }
        GC.SuppressFinalize(this);
    }

    private string Exe(string name = "updater.exe")
    {
        var path = Path.Combine(_root, "Vendor", name);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, [0x4D, 0x5A]);
        return path;
    }

    private ProtectionService Service(IReadOnlyList<BlockRule> catalog, IReadOnlyList<MarkerDefinition>? markers = null, bool audit = false)
    {
        var vault = Path.Combine(_root, "vault");
        return new ProtectionService(new ProtectionServiceOptions
        {
            Hosts = new HostsFileEngine(_hostsPath, Path.Combine(_root, "backups")),
            Services = _services,
            Tasks = _tasks,
            Registry = new RegistryPolicyEngine(),
            Firewall = _firewall,
            Quarantine = new QuarantineEngine(vault, _markerEnv),
            Markers = new MarkerScanner(_markerEnv),
            MarkerCatalog = markers ?? [],
            Journal = new ChangeJournal(Path.Combine(_root, "journal.json")),
            Audit = audit ? new AuditLog(Path.Combine(_root, "audit.jsonl")) : null,
            Catalog = catalog,
            Preflight = _ => Task.FromResult(_findings),
            IsElevated = () => true,
            SweepFirewallGroupOnRevert = false,
            WebListeners = () => _listeners
        });
    }

    private static BlockRule SvcRule() => new()
    {
        Id = "test.svc", Title = "Test updater service", Summary = "s", Category = RuleCategory.Updates,
        Tier = RiskTier.Balanced, Engine = EngineKind.Service, ServiceNamePatterns = ["FakeUpdater*"],
        Breaks = [Breakage.Severe("No Chrome updates", "Chrome will not update itself while this rule blocks the updater service.")],
        SupportsLocalOnly = true,
        LocalOnlyBreaks = [Breakage.Notable("The updater keeps retrying", "It runs and every attempt is refused, so expect log noise.")]
    };

    private static BlockRule TaskRule() => new()
    {
        Id = "test.task", Title = "Test updater task", Summary = "s", Category = RuleCategory.Updates,
        Tier = RiskTier.Balanced, Engine = EngineKind.ScheduledTask, ScheduledTaskPatterns = ["FakeTask*"],
        Breaks = [Breakage.Minor("Nothing real", "Test.")],
        SupportsLocalOnly = true,
        LocalOnlyBreaks = [Breakage.Notable("The task keeps failing", "Each run is attempted and refused, so the history shows failures.")]
    };

    private static BlockRule HostsRule(bool localOnly = true) => new()
    {
        Id = "test.hosts", Title = "Test hosts rule", Summary = "s", Category = RuleCategory.Telemetry,
        Tier = RiskTier.Balanced, Engine = EngineKind.Hosts, Domains = ["update.example.invalid", "api.example.invalid"],
        Breaks = [Breakage.Minor("Nothing real", "Test.")],
        SupportsLocalOnly = localOnly,
        LocalOnlyBreaks = localOnly ? [Breakage.Notable("Programs may retry faster", "Refused connections are retried faster than failed lookups.")] : []
    };

    private BlockRule RegRule() => new()
    {
        Id = "test.reg", Title = "Test policy", Summary = "s", Category = RuleCategory.Telemetry,
        Tier = RiskTier.Balanced, Engine = EngineKind.Registry,
        RegistryValues = [RegistryPolicy.Dword(_regKey, "Flag", 1, RegistryHive2.CurrentUser)],
        Breaks = [Breakage.Minor("Nothing real", "Test.")]
    };

    private static PlanRequest Request(IEnumerable<string> armed, IEnumerable<string>? localOnly = null,
        IEnumerable<string>? contained = null, IEnumerable<string>? localOnlyApps = null, IEnumerable<string>? quarantine = null) => new()
    {
        EnabledRuleIds = armed.ToList(),
        LocalOnlyRuleIds = (localOnly ?? []).ToList(),
        ContainedApps = (contained ?? []).ToList(),
        LocalOnlyApps = (localOnlyApps ?? []).ToList(),
        QuarantineMarkerIds = (quarantine ?? []).ToList()
    };

    // ------------------------------------------------------------------ services and tasks

    [Fact]
    public async Task ALocalOnlyServiceIsKeptRunningAndConfinedNotDisabled()
    {
        var exe = Exe();
        _services.Known["FakeUpdater1"] = (2, new ServiceEngine.ServiceImage(exe, false));
        var svc = Service([SvcRule()]);

        var plan = await svc.BuildPlanAsync(Request(["test.svc"], ["test.svc"]));

        var change = Assert.Single(plan.Changes);
        Assert.Equal(EngineKind.LocalOnly, change.Engine);
        Assert.Equal(exe, change.JailProgram);
        Assert.Null(change.JailService);
        Assert.Contains("Keep service FakeUpdater1 running", change.Description);

        var report = await svc.ApplyAsync(plan);

        Assert.Equal(0, report.Failed);
        Assert.Empty(_services.Disabled);                 // LO-2: not disabled
        var jail = Assert.Single(_firewall.Jails);
        Assert.Equal(exe, jail.Program);
        Assert.Equal(2, svc.Journal.Entries.Count(e => e.Engine == EngineKind.LocalOnly)); // outbound and inbound
    }

    [Fact]
    public async Task AServiceInASharedHostIsConfinedByNameNotByProgram()
    {
        // Jailing svchost.exe would cut off half of Windows.
        _services.Known["FakeUpdater1"] = (2, new ServiceEngine.ServiceImage(@"C:\Windows\System32\svchost.exe", true));
        var svc = Service([SvcRule()]);

        var change = Assert.Single((await svc.BuildPlanAsync(Request(["test.svc"], ["test.svc"]))).Changes);

        Assert.Equal("FakeUpdater1", change.JailService);
        Assert.Null(change.JailProgram);
        Assert.Equal(ChangeOutcome.Applied, change.Outcome);
    }

    [Fact]
    public async Task AProgramInsideTheWindowsDirectoryIsRefusedAndNothingIsConfined()
    {
        var cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        _services.Known["FakeUpdater1"] = (2, new ServiceEngine.ServiceImage(cmd, false));
        var svc = Service([SvcRule()]);

        var plan = await svc.BuildPlanAsync(Request(["test.svc"], ["test.svc"]));
        var change = Assert.Single(plan.Changes);

        Assert.Equal(ChangeOutcome.Refused, change.Outcome);
        Assert.Contains("Windows directory", change.RefusalReason);

        await svc.ApplyAsync(plan);
        Assert.Empty(_firewall.Jails);
    }

    [Fact]
    public async Task AServiceWhoseProgramCannotBeIdentifiedIsRefused()
    {
        _services.Known["FakeUpdater1"] = (2, new ServiceEngine.ServiceImage(null, false));
        var change = Assert.Single((await Service([SvcRule()]).BuildPlanAsync(Request(["test.svc"], ["test.svc"]))).Changes);

        Assert.Equal(ChangeOutcome.Refused, change.Outcome);
        Assert.Contains("could not be identified", change.RefusalReason);
    }

    [Fact]
    public async Task ATwoServicesSharingOneProgramShareOneJail()
    {
        var exe = Exe("updater.exe");
        _services.Known["FakeUpdater1"] = (2, new ServiceEngine.ServiceImage(exe, false));
        _services.Known["FakeUpdater2"] = (3, new ServiceEngine.ServiceImage(exe, false));
        var svc = Service([SvcRule()]);

        var report = await svc.ApplyAsync(await svc.BuildPlanAsync(Request(["test.svc"], ["test.svc"])));

        Assert.Equal(0, report.Failed);
        Assert.Single(_firewall.Jails);
        Assert.Equal(2, svc.Journal.Entries.Count);
    }

    [Fact]
    public async Task ALocalOnlyTaskConfinesTheProgramItRunsAndStaysEnabled()
    {
        var exe = Exe("GoogleUpdate.exe");
        _tasks.Known.Add(new ScheduledTaskEngine.TaskInfo(@"\FakeTaskCore", true));
        _tasks.Actions[@"\FakeTaskCore"] = [exe];
        var svc = Service([TaskRule()]);

        var plan = await svc.BuildPlanAsync(Request(["test.task"], ["test.task"]));
        var change = Assert.Single(plan.Changes);
        Assert.Equal(EngineKind.LocalOnly, change.Engine);
        Assert.Equal(exe, change.JailProgram);

        await svc.ApplyAsync(plan);
        Assert.Equal(exe, Assert.Single(_firewall.Jails).Program);
    }

    [Fact]
    public async Task ATaskThatRunsNothingNameableIsRefused()
    {
        _tasks.Known.Add(new ScheduledTaskEngine.TaskInfo(@"\FakeTaskCore", true));
        _tasks.Actions[@"\FakeTaskCore"] = [];
        var change = Assert.Single((await Service([TaskRule()]).BuildPlanAsync(Request(["test.task"], ["test.task"]))).Changes);

        Assert.Equal(ChangeOutcome.Refused, change.Outcome);
        Assert.Contains("no program that can be named", change.RefusalReason);
    }

    [Fact]
    public async Task ARuleThatDoesNotSupportLocalOnlyIgnoresTheRequest()
    {
        var exe = Exe();
        _services.Known["FakeUpdater1"] = (2, new ServiceEngine.ServiceImage(exe, false));
        var rule = SvcRule().WithLocalOnly([]);
        var notSupported = new BlockRule
        {
            Id = "test.svc", Title = "x", Summary = "x", Category = RuleCategory.Updates, Tier = RiskTier.Balanced,
            Engine = EngineKind.Service, ServiceNamePatterns = ["FakeUpdater*"], Breaks = rule.Breaks
        };

        var change = Assert.Single((await Service([notSupported]).BuildPlanAsync(Request(["test.svc"], ["test.svc"]))).Changes);
        Assert.Equal(EngineKind.Service, change.Engine); // blocked, as before
    }

    // ------------------------------------------------------------------ the machine matches the armed set

    [Fact]
    public async Task SwitchingARuleFromBlockToLocalOnlyUndoesTheDisableFirst()
    {
        var exe = Exe();
        _services.Known["FakeUpdater1"] = (2, new ServiceEngine.ServiceImage(exe, false));
        var svc = Service([SvcRule()]);

        await svc.ApplyAsync(await svc.BuildPlanAsync(Request(["test.svc"])));        // blocked: service disabled
        Assert.Equal(["FakeUpdater1"], _services.Disabled);

        var plan = await svc.BuildPlanAsync(Request(["test.svc"], ["test.svc"]));      // now local-only
        Assert.True(plan.Changes[0].IsUndo);
        Assert.Equal(EngineKind.Service, plan.Changes[0].Engine);
        Assert.Contains(plan.Changes, c => c.Engine == EngineKind.LocalOnly && !c.IsUndo);

        await svc.ApplyAsync(plan);

        Assert.Empty(_services.Disabled);                                             // enabled again
        Assert.Equal(["FakeUpdater1"], _services.Reverted);
        Assert.Single(_firewall.Jails);
        Assert.DoesNotContain(svc.Journal.Entries, e => e.Engine == EngineKind.Service);
    }

    [Fact]
    public async Task SwitchingBackFromLocalOnlyRemovesTheJailAndBlocksAgain()
    {
        var exe = Exe();
        _services.Known["FakeUpdater1"] = (2, new ServiceEngine.ServiceImage(exe, false));
        var svc = Service([SvcRule()]);

        await svc.ApplyAsync(await svc.BuildPlanAsync(Request(["test.svc"], ["test.svc"])));
        Assert.Single(_firewall.Jails);

        await svc.ApplyAsync(await svc.BuildPlanAsync(Request(["test.svc"])));

        Assert.Empty(_firewall.Jails);
        Assert.Equal(["FakeUpdater1"], _services.Disabled);
        Assert.DoesNotContain(svc.Journal.Entries, e => e.Engine == EngineKind.LocalOnly);
    }

    [Fact]
    public async Task UnarmingARuleUndoesItOnTheNextApply()
    {
        using (Registry.CurrentUser.CreateSubKey(_regKey)) { }
        var svc = Service([RegRule()]);

        await svc.ApplyAsync(await svc.BuildPlanAsync(Request(["test.reg"])));
        using (var k = Registry.CurrentUser.OpenSubKey(_regKey)) Assert.Equal(1, k!.GetValue("Flag"));

        var plan = await svc.BuildPlanAsync(Request([]));
        var undo = Assert.Single(plan.Changes);
        Assert.True(undo.IsUndo);
        Assert.StartsWith("Undo:", undo.Description);

        await svc.ApplyAsync(plan);

        using (var k = Registry.CurrentUser.OpenSubKey(_regKey)) Assert.Null(k!.GetValue("Flag"));
        Assert.Empty(svc.Journal.Entries);
    }

    [Fact]
    public async Task APreviewListsTheUndoWithoutPerformingIt()
    {
        using (Registry.CurrentUser.CreateSubKey(_regKey)) { }
        var svc = Service([RegRule()]);
        await svc.ApplyAsync(await svc.BuildPlanAsync(Request(["test.reg"])));

        await svc.BuildPlanAsync(Request([]));

        using var k = Registry.CurrentUser.OpenSubKey(_regKey);
        Assert.Equal(1, k!.GetValue("Flag")); // planning touched nothing
        Assert.Single(svc.Journal.Entries);
    }

    [Fact]
    public async Task TheHostsBlockIsRemovedWhenNoHostsRuleRemainsArmed()
    {
        var before = File.ReadAllBytes(_hostsPath);
        var svc = Service([HostsRule()]);

        await svc.ApplyAsync(await svc.BuildPlanAsync(Request(["test.hosts"])));
        Assert.NotEqual(before, File.ReadAllBytes(_hostsPath));

        var plan = await svc.BuildPlanAsync(Request([]));
        Assert.Contains(plan.Changes, c => c.IsUndo && c.Engine == EngineKind.Hosts);
        await svc.ApplyAsync(plan);

        Assert.Equal(before, File.ReadAllBytes(_hostsPath));
    }

    [Fact]
    public async Task AStillArmedHostsRuleIsNotUndoneJustBecauseItIsReapplied()
    {
        var svc = Service([HostsRule()]);
        await svc.ApplyAsync(await svc.BuildPlanAsync(Request(["test.hosts"])));

        var plan = await svc.BuildPlanAsync(Request(["test.hosts"]));

        Assert.DoesNotContain(plan.Changes, c => c.IsUndo);
    }

    // ------------------------------------------------------------------ hosts: loopback

    [Fact]
    public async Task ALocalOnlyHostsRuleResolvesToThisMachine()
    {
        var svc = Service([HostsRule()]);

        var plan = await svc.BuildPlanAsync(Request(["test.hosts"], ["test.hosts"]));
        await svc.ApplyAsync(plan);

        var text = File.ReadAllText(_hostsPath);
        Assert.Contains("127.0.0.1 update.example.invalid", text);
        Assert.Contains("::1 api.example.invalid", text);
        Assert.DoesNotContain("0.0.0.0 update.example.invalid", text);
        Assert.Contains("resolved to this machine", plan.Changes.Single(c => c.Engine == EngineKind.Hosts).Description);
    }

    [Fact]
    public async Task ALocalWebListenerTurnsLoopbackIntoASinkholeWithAWarning()
    {
        // LO-5: a name mapped to loopback is delivered to whatever listens there. Fail closed.
        _listeners = [443];
        var svc = Service([HostsRule()]);

        var plan = await svc.BuildPlanAsync(Request(["test.hosts"], ["test.hosts"]));
        await svc.ApplyAsync(plan);

        var text = File.ReadAllText(_hostsPath);
        Assert.Contains("0.0.0.0 update.example.invalid", text);
        Assert.DoesNotContain("127.0.0.1 update.example.invalid", text);
        Assert.True(plan.LoopbackDowngraded);
        Assert.Empty(plan.LoopbackRuleIds);
        var warning = Assert.Single(plan.Findings, f => f.Title.StartsWith("Local-only names were sinkholed"));
        Assert.Equal(FindingLevel.Warning, warning.Level);
        Assert.Contains("443", warning.Detail);

        // The cost shown is the BLOCK cost, because that is what is actually applied.
        Assert.DoesNotContain(plan.Degradations, d => d.Breakage.What == "Programs may retry faster");
    }

    [Fact]
    public async Task AnUnreadableListenerTableAlsoFailsClosed()
    {
        _listeners = null;
        var svc = Service([HostsRule()]);

        var plan = await svc.BuildPlanAsync(Request(["test.hosts"], ["test.hosts"]));

        Assert.True(plan.LoopbackDowngraded);
        await svc.ApplyAsync(plan);
        Assert.DoesNotContain("127.0.0.1 update.example.invalid", File.ReadAllText(_hostsPath));
    }

    [Fact]
    public async Task NoListenerCheckIsMadeWhenNothingAsksForLoopback()
    {
        var asked = false;
        _listeners = [443];
        var svc = new ProtectionService(new ProtectionServiceOptions
        {
            Hosts = new HostsFileEngine(_hostsPath, Path.Combine(_root, "backups")),
            Journal = new ChangeJournal(Path.Combine(_root, "journal.json")),
            Catalog = [HostsRule()], Preflight = _ => Task.FromResult(new List<PreflightFinding>()),
            IsElevated = () => true, SweepFirewallGroupOnRevert = false,
            WebListeners = () => { asked = true; return [443]; }
        });

        var plan = await svc.BuildPlanAsync(Request(["test.hosts"]));

        Assert.False(asked);
        Assert.False(plan.LoopbackDowngraded);
    }

    [Fact]
    public async Task TheImpactReportStatesTheLocalOnlyCostNotTheBlockCost()
    {
        _services.Known["FakeUpdater1"] = (2, new ServiceEngine.ServiceImage(Exe(), false));
        var svc = Service([SvcRule(), HostsRule()]);

        var plan = await svc.BuildPlanAsync(Request(["test.svc", "test.hosts"], ["test.svc"]));

        Assert.Contains(plan.Degradations, d => d.Breakage.What == "The updater keeps retrying");
        Assert.DoesNotContain(plan.Degradations, d => d.Breakage.What == "No Chrome updates");   // not blocked
        Assert.Contains(plan.Degradations, d => d.Breakage.What == "Nothing real");              // hosts rule stayed in block mode
    }

    // ------------------------------------------------------------------ local-only apps

    [Fact]
    public async Task ALocalOnlyAppIsConfinedAndSupersedesContainmentOfTheSameProgram()
    {
        var app = Exe("FakeApp.exe");
        var svc = Service([]);

        var plan = await svc.BuildPlanAsync(Request([], contained: [app], localOnlyApps: [app]));

        Assert.Single(plan.Changes);
        Assert.Equal(EngineKind.LocalOnly, plan.Changes[0].Engine);
        Assert.Equal(ProtectionService.LocalOnlyAppRuleId(app), plan.Changes[0].RuleId);
        Assert.Contains(plan.Rules, r => r.Id == "localonly.summary");
        Assert.DoesNotContain(plan.Rules, r => r.Id == "contain.summary");

        await svc.ApplyAsync(plan);
        Assert.Equal(app, Assert.Single(_firewall.Jails).Program);
        Assert.Empty(_firewall.Contained);
    }

    [Fact]
    public async Task MovingAnAppFromContainmentToLocalOnlyUndoesTheContainment()
    {
        var app = Exe("FakeApp.exe");
        var svc = Service([]);
        await svc.ApplyAsync(await svc.BuildPlanAsync(Request([], contained: [app])));
        Assert.Single(_firewall.Contained);

        var plan = await svc.BuildPlanAsync(Request([], contained: [app], localOnlyApps: [app]));
        Assert.Contains(plan.Changes, c => c.IsUndo && c.Engine == EngineKind.AppContainment);
        await svc.ApplyAsync(plan);

        Assert.Empty(_firewall.Contained);
        Assert.Single(_firewall.Jails);
    }

    [Fact]
    public async Task RemovingAnAppFromLocalOnlyTakesTheJailAway()
    {
        var app = Exe("FakeApp.exe");
        var svc = Service([]);
        await svc.ApplyAsync(await svc.BuildPlanAsync(Request([], localOnlyApps: [app])));
        Assert.Single(_firewall.Jails);

        await svc.ApplyAsync(await svc.BuildPlanAsync(Request([])));

        Assert.Empty(_firewall.Jails);
        Assert.Empty(svc.Journal.Entries);
    }

    [Fact]
    public async Task ALocalOnlyAppThatDoesNotExistIsNotPresentAndOneInTheWindowsDirectoryIsRefused()
    {
        var gone = Path.Combine(_root, "gone.exe");
        var cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        var plan = await Service([]).BuildPlanAsync(Request([], localOnlyApps: [gone, cmd]));

        Assert.Equal(ChangeOutcome.NotPresent, plan.Changes[0].Outcome);
        Assert.Equal(ChangeOutcome.Refused, plan.Changes[1].Outcome);
    }

    [Fact]
    public async Task TheLocalOnlyAppWarningStatesASevereCost()
    {
        var plan = await Service([]).BuildPlanAsync(Request([], localOnlyApps: [Exe("FakeApp.exe")]));

        Assert.Contains(plan.Degradations, d => d.Breakage.Severity == BreakageSeverity.Severe
                                                && d.Breakage.What.Contains("cannot reach the internet"));
    }

    // ------------------------------------------------------------------ markers

    private MarkerDefinition QuarantinableMarker() => new()
    {
        Id = "test.marker", Vendor = "Test", Title = "Test identifier", Why = "w", Kind = MarkerKind.File,
        Class = MarkerClass.Identifier, Locations = [@"%LOCALAPPDATA%\Vendor\id.dat"], Action = MarkerAction.Quarantine,
        Confidence = Confidence.High, Source = "test", Breaks = [Breakage.Minor("A new ID is made", "The vendor creates a new one.")]
    };

    private string MakeMarkerFile()
    {
        var path = Path.Combine(_markerEnv.ResolveToken("%LOCALAPPDATA%")!, "Vendor", "id.dat");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, "identifier");
        return path;
    }

    [Fact]
    public async Task ARequestedMarkerIsQuarantinedAndRestoredByRevertAll()
    {
        var path = MakeMarkerFile();
        var svc = Service([], [QuarantinableMarker()]);

        var plan = await svc.BuildPlanAsync(Request([], quarantine: ["test.marker"]));
        var change = Assert.Single(plan.Changes);
        Assert.Equal(EngineKind.Quarantine, change.Engine);
        Assert.Equal(path, change.Target);
        Assert.Contains(plan.Rules, r => r.Id == "marker.summary");
        Assert.True(File.Exists(path)); // planning moved nothing

        var report = await svc.ApplyAsync(plan);
        Assert.Equal(0, report.Failed);
        Assert.False(File.Exists(path));
        Assert.Equal(1, (await svc.GetStatusAsync()).QuarantinedItems);

        Assert.Empty(await svc.RevertAllAsync());
        Assert.Equal("identifier", File.ReadAllText(path));
        Assert.Empty(svc.Journal.Entries);
    }

    [Fact]
    public async Task UnmarkingAMarkerRestoresItOnTheNextApply()
    {
        var path = MakeMarkerFile();
        var svc = Service([], [QuarantinableMarker()]);
        await svc.ApplyAsync(await svc.BuildPlanAsync(Request([], quarantine: ["test.marker"])));
        Assert.False(File.Exists(path));

        var plan = await svc.BuildPlanAsync(Request([]));
        Assert.Contains(plan.Changes, c => c.IsUndo && c.Engine == EngineKind.Quarantine);
        await svc.ApplyAsync(plan);

        Assert.True(File.Exists(path));
    }

    [Fact]
    public async Task AMarkerThatIsReportOnlyIsRefusedInThePlan()
    {
        var agent = QuarantinableMarker() with { Id = "test.agent", Class = MarkerClass.SecurityAgent };
        var plan = await Service([], [agent]).BuildPlanAsync(Request([], quarantine: ["test.agent"]));

        var change = Assert.Single(plan.Changes);
        Assert.Equal(ChangeOutcome.Refused, change.Outcome);
        Assert.Contains("reported only", change.RefusalReason);
    }

    [Fact]
    public async Task AMarkerThatIsNotOnThisMachineIsPlannedAsNotPresent()
    {
        var plan = await Service([], [QuarantinableMarker()]).BuildPlanAsync(Request([], quarantine: ["test.marker"]));
        Assert.Equal(ChangeOutcome.NotPresent, Assert.Single(plan.Changes).Outcome);
    }

    // ------------------------------------------------------------------ the security agent guard

    private static BlockRule MandiantServicesRule() => new()
    {
        Id = RuleCatalog.AgentSensitiveRuleIds[0], Title = "Mandiant services", Summary = "s", Category = RuleCategory.GoogleOwned,
        Tier = RiskTier.Aggressive, Engine = EngineKind.Hosts, Domains = ["advantage.example.invalid"],
        Breaks = [Breakage.Notable("Portal", "The portal stops loading.")]
    };

    private MarkerDefinition AgentMarker() => new()
    {
        Id = "test.agent-dir", Vendor = MarkerCatalog.Mandiant, Title = "Test endpoint agent", Why = "w", Kind = MarkerKind.Directory,
        Class = MarkerClass.SecurityAgent, Locations = [@"%PROGRAMDATA%\FireEye"], Confidence = Confidence.High, Source = "test"
    };

    [Fact]
    public async Task TheMandiantServicesRuleIsRefusedWhileAnEndpointAgentIsInstalled()
    {
        Directory.CreateDirectory(Path.Combine(_markerEnv.ResolveToken("%PROGRAMDATA%")!, "FireEye", "xagt"));
        var svc = Service([MandiantServicesRule()], [AgentMarker()]);

        var plan = await svc.BuildPlanAsync(Request([MandiantServicesRule().Id]));

        var finding = Assert.Single(plan.Findings, f => f.Level == FindingLevel.Blocker);
        Assert.Contains("endpoint security agent", finding.Title);
        var change = Assert.Single(plan.Changes);
        Assert.Equal(ChangeOutcome.Refused, change.Outcome);

        await svc.ApplyAsync(plan);
        Assert.DoesNotContain("advantage.example.invalid", File.ReadAllText(_hostsPath));
    }

    [Fact]
    public async Task TheMandiantServicesRuleIsNotRefusedWhenNoAgentIsPresent()
    {
        var svc = Service([MandiantServicesRule()], [AgentMarker()]);

        var plan = await svc.BuildPlanAsync(Request([MandiantServicesRule().Id]));

        Assert.DoesNotContain(plan.Findings, f => f.Level == FindingLevel.Blocker);
        Assert.NotEqual(ChangeOutcome.Refused, plan.Changes.Single().Outcome);
    }

    // ------------------------------------------------------------------ restore and audit

    [Fact]
    public async Task RevertAllTakesBackJailsHostsAndQuarantineTogether()
    {
        var before = File.ReadAllBytes(_hostsPath);
        var path = MakeMarkerFile();
        var app = Exe("FakeApp.exe");
        _services.Known["FakeUpdater1"] = (2, new ServiceEngine.ServiceImage(Exe(), false));
        var svc = Service([SvcRule(), HostsRule()], [QuarantinableMarker()]);

        await svc.ApplyAsync(await svc.BuildPlanAsync(Request(
            ["test.svc", "test.hosts"], ["test.svc", "test.hosts"], localOnlyApps: [app], quarantine: ["test.marker"])));
        Assert.Equal(2, _firewall.Jails.Count);
        Assert.False(File.Exists(path));

        Assert.Empty(await svc.RevertAllAsync());

        Assert.Empty(_firewall.Jails);
        Assert.True(File.Exists(path));
        Assert.Equal(before, File.ReadAllBytes(_hostsPath));
        Assert.Empty(svc.Journal.Entries);
    }

    [Fact]
    public async Task EveryChangeAndUndoIsRecordedInTheAuditLog()
    {
        var app = Exe("FakeApp.exe");
        var svc = Service([], audit: true);

        await svc.ApplyAsync(await svc.BuildPlanAsync(Request([], localOnlyApps: [app])));
        await svc.RevertAllAsync();

        var events = svc.Audit.Tail(100);
        Assert.Contains(events, e => e.Kind == "apply.start");
        Assert.Contains(events, e => e.Kind == "change" && e.Engine == "LocalOnly" && e.Outcome == "Applied");
        Assert.Contains(events, e => e.Kind == "apply.done");
        Assert.Contains(events, e => e.Kind == "restore.start");
        Assert.Contains(events, e => e.Kind == "undo" && e.Outcome == "Applied");
        Assert.Contains(events, e => e.Kind == "restore.done");
    }

    [Fact]
    public async Task ASuppliedOptionsObjectNeverWritesToTheRealAuditLog()
    {
        var svc = Service([]); // audit: false -> options.Audit is null
        Assert.False(svc.Audit.IsEnabled);
        await svc.ApplyAsync(await svc.BuildPlanAsync(Request([])));
    }
}
