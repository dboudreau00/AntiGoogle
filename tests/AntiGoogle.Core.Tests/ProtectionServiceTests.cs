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
using AntiGoogle.Core;
using AntiGoogle.Core.Engines;
using AntiGoogle.Core.Journal;
using AntiGoogle.Core.Model;
using AntiGoogle.Core.Safety;
using Microsoft.Win32;
using Xunit;

namespace AntiGoogle.Core.Tests;

/// <summary>
/// End-to-end orchestration tests for <see cref="ProtectionService"/> — the plan → apply → journal →
/// revert cycle that every other test only covers a slice of.
///
/// All of this runs UNELEVATED, by pointing the service at throwaway targets through
/// <see cref="ProtectionServiceOptions"/>:
///   * hosts   → a temp file, with backups redirected to a temp directory
///   * registry→ HKCU (the engine code path is identical to the HKLM one the real rules use)
///   * journal → a temp json file, NOT the machine's ProgramData journal
///   * firewall→ a per-test rule group, so the revert sweep can never touch the user's real rules
///   * preflight → deterministic findings, because the real one blocks every rule when unelevated
///   * elevation → forced true, because the gate is what we are testing past, not testing
///
/// What is deliberately NOT here: anything that actually mutates services, scheduled tasks or the
/// firewall. Those need administrator rights and are listed as the remaining manual pass in
/// CLAUDE.md §8. See <see cref="ServiceResolveMatchesExactNamesAndPrefixes"/> for the part of the
/// service engine that IS reachable unelevated.
/// </summary>
public class ProtectionServiceTests : IDisposable
{
    private readonly string _dir;
    private readonly string _hostsPath;
    private readonly string _backupDir;
    private readonly string _journalPath;
    private readonly string _regKey;
    private readonly string _firewallGroup;

    /// <summary>
    /// Must end in exactly one CRLF with no trailing blank line. Revert rebuilds the file as
    /// <c>TrimEnd() + CRLF</c>, so any other trailing whitespace would make the byte-identity
    /// assertion fail for a reason that is not a bug — see
    /// <see cref="RevertNormalisesAHostsFileThatDidNotEndInANewline"/>.
    /// </summary>
    private const string UserHosts =
        "# my own entries\r\n" +
        "127.0.0.1 localdev.test\r\n" +
        "10.0.0.5 nas.lan\r\n";

    public ProtectionServiceTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "antigoogle-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);

        _hostsPath = Path.Combine(_dir, "hosts");
        _backupDir = Path.Combine(_dir, "backups");
        _journalPath = Path.Combine(_dir, "journal.json");
        _regKey = $@"Software\AntiGoogleTests\{Guid.NewGuid():N}";
        _firewallGroup = $"Anti-Google-Test-{Guid.NewGuid():N}";

        File.WriteAllText(_hostsPath, UserHosts, new UTF8Encoding(false));
    }

    public void Dispose()
    {
        try { Registry.CurrentUser.DeleteSubKeyTree(_regKey, throwOnMissingSubKey: false); } catch { }
        try { new FileInfo(_hostsPath).IsReadOnly = false; } catch { }
        try { Directory.Delete(_dir, recursive: true); } catch { }
        GC.SuppressFinalize(this);
    }

    // ------------------------------------------------------------------ fixtures

    private BlockRule HostsRule() => new()
    {
        Id = "test.hosts",
        Title = "Test hosts rule",
        Summary = "Sinkholes two domains that cannot resolve anyway (.invalid is reserved).",
        Category = RuleCategory.Telemetry,
        Tier = RiskTier.Balanced,
        Engine = EngineKind.Hosts,
        Domains = ["alpha.example.invalid", "beta.example.invalid"],
        Breaks = [Breakage.Minor("Nothing real", "This rule exists only inside the test suite.")]
    };

    /// <summary>A value that does NOT pre-exist — revert must DELETE it, not restore a guess.</summary>
    private BlockRule RegNewRule() => new()
    {
        Id = "test.reg.new",
        Title = "Test registry rule (new value)",
        Summary = "Writes a value that was not there before.",
        Category = RuleCategory.Telemetry,
        Tier = RiskTier.Balanced,
        Engine = EngineKind.Registry,
        RegistryValues = [RegistryPolicy.Dword(_regKey, "NewFlag", 1, RegistryHive2.CurrentUser)],
        Breaks = [Breakage.Minor("Nothing real", "This rule exists only inside the test suite.")]
    };

    /// <summary>A value that DOES pre-exist — revert must restore the exact previous number.</summary>
    private BlockRule RegExistingRule() => new()
    {
        Id = "test.reg.existing",
        Title = "Test registry rule (existing value)",
        Summary = "Overwrites a value that was already set.",
        Category = RuleCategory.Telemetry,
        Tier = RiskTier.Balanced,
        Engine = EngineKind.Registry,
        RegistryValues = [RegistryPolicy.Dword(_regKey, "ExistingFlag", 0, RegistryHive2.CurrentUser)],
        Breaks = [Breakage.Minor("Nothing real", "This rule exists only inside the test suite.")]
    };

    private static BlockRule SvcRule() => new()
    {
        Id = "test.svc",
        Title = "Test service rule",
        Summary = "Disables a service that only the fake engine knows about.",
        Category = RuleCategory.Updates,
        Tier = RiskTier.Balanced,
        Engine = EngineKind.Service,
        ServiceNamePatterns = ["FakeGoogleUpdaterService*"],
        Breaks = [Breakage.Minor("Nothing real", "This rule exists only inside the test suite.")]
    };

    private void SeedRegistry()
    {
        using var key = Registry.CurrentUser.CreateSubKey(_regKey);
        key!.SetValue("ExistingFlag", 7, RegistryValueKind.DWord);
    }

    private int BackupCount() =>
        Directory.Exists(_backupDir) ? Directory.GetFiles(_backupDir).Length : 0;

    /// <summary>Builds a ProtectionService wired entirely to this test's throwaway targets.</summary>
    private ProtectionService Service(
        IReadOnlyList<BlockRule> catalog,
        List<PreflightFinding>? findings = null,
        ServiceEngine? services = null,
        ScheduledTaskEngine? tasks = null,
        string? journalPath = null,
        bool elevated = true)
        => new(new ProtectionServiceOptions
        {
            Hosts = new HostsFileEngine(_hostsPath, _backupDir),
            Registry = new RegistryPolicyEngine(),
            Firewall = new FirewallEngine(_firewallGroup),
            Services = services ?? new ServiceEngine(),
            Tasks = tasks ?? new ScheduledTaskEngine(),
            Journal = new ChangeJournal(journalPath ?? _journalPath),
            Catalog = catalog,
            Preflight = _ => Task.FromResult(findings ?? new List<PreflightFinding>()),
            IsElevated = () => elevated,
            SweepFirewallGroupOnRevert = false
        });

    /// <summary>Resolves to a service the fake owns, then blows up exactly where sc.exe would.</summary>
    private sealed class ExplodingServiceEngine : ServiceEngine
    {
        public const string FakeName = "FakeGoogleUpdaterService999.0.0.0";

        public override IReadOnlyList<(string Name, int StartType)> Resolve(IReadOnlyList<string> patterns) =>
            [(FakeName, 2)];

        public override Task<ChangeOutcome> ApplyAsync(
            BlockRule rule, string serviceName, int previousStart, ChangeJournal journal, CancellationToken ct) =>
            throw new InvalidOperationException($"sc config {serviceName} failed (5): Access is denied.");
    }

    // ------------------------------------------------------------------ 1. the round trip

    /// <summary>
    /// The test the whole suite was missing: a real plan, applied through the real orchestrator,
    /// then fully reverted, with the machine asserted byte-for-byte back to where it started.
    /// </summary>
    [Fact]
    public async Task FullApplyRevertRoundTripLeavesTheMachineExactlyAsItWas()
    {
        SeedRegistry();
        var hostsBefore = File.ReadAllBytes(_hostsPath);

        var catalog = new[] { RegNewRule(), RegExistingRule(), HostsRule() };
        var svc = Service(catalog);

        var plan = await svc.BuildPlanAsync(catalog.Select(r => r.Id));
        Assert.DoesNotContain(plan.Changes, c => c.Outcome == ChangeOutcome.Refused);

        // --- apply
        var report = await svc.ApplyAsync(plan);
        Assert.Equal(0, report.Failed);
        Assert.Equal(3, report.Applied);          // two registry values + one aggregate hosts block

        // ...and it genuinely changed something.
        var applied = await File.ReadAllTextAsync(_hostsPath);
        Assert.Contains("0.0.0.0 alpha.example.invalid", applied);
        Assert.Contains(":: alpha.example.invalid", applied);       // hard rule #5: v4 AND v6
        Assert.Contains("0.0.0.0 beta.example.invalid", applied);
        Assert.Contains("127.0.0.1 localdev.test", applied);        // user's own lines survive

        using (var mid = Registry.CurrentUser.OpenSubKey(_regKey))
        {
            Assert.Equal(1, mid!.GetValue("NewFlag"));
            Assert.Equal(0, mid.GetValue("ExistingFlag"));
        }

        Assert.Equal(3, svc.Journal.Entries.Count);
        Assert.True(BackupCount() >= 1);

        // --- revert
        var errors = await svc.RevertAllAsync();
        Assert.Empty(errors);

        // The journal is the app's record of "the machine is modified". Empty == nothing outstanding.
        Assert.Empty(svc.Journal.Entries);

        // Byte-for-byte, not merely "looks right".
        Assert.Equal(hostsBefore, File.ReadAllBytes(_hostsPath));

        using (var after = Registry.CurrentUser.OpenSubKey(_regKey))
        {
            Assert.NotNull(after);
            Assert.Null(after!.GetValue("NewFlag"));                    // did not exist → deleted
            Assert.Equal(7, after.GetValue("ExistingFlag"));            // existed → exact restore
            Assert.Equal(new[] { "ExistingFlag" }, after.GetValueNames());
        }
    }

    [Fact]
    public async Task RevertAllIsIdempotent()
    {
        SeedRegistry();
        var hostsBefore = File.ReadAllBytes(_hostsPath);

        var catalog = new[] { RegNewRule(), HostsRule() };
        var svc = Service(catalog);

        await svc.ApplyAsync(await svc.BuildPlanAsync(catalog.Select(r => r.Id)));

        Assert.Empty(await svc.RevertAllAsync());
        Assert.Empty(await svc.RevertAllAsync());   // must not throw or mangle anything

        Assert.Empty(svc.Journal.Entries);
        Assert.Equal(hostsBefore, File.ReadAllBytes(_hostsPath));
    }

    // ------------------------------------------------------------------ 2. preflight refusal

    /// <summary>
    /// A refusal must be a genuine non-attempt, not a silent success. Hard rule #9 depends on this:
    /// the Google-DNS blocker is the difference between a warning and taking the machine offline.
    /// </summary>
    [Fact]
    public async Task PreflightRefusalLeavesTheTargetGenuinelyUntouched()
    {
        var hostsBefore = File.ReadAllBytes(_hostsPath);

        var catalog = new[] { HostsRule() };
        var blocker = PreflightFinding.Block(
            "Hosts file is read-only",
            "Simulated blocker so the refusal path is deterministic.",
            "test.hosts");

        var svc = Service(catalog, [blocker]);
        var plan = await svc.BuildPlanAsync(catalog.Select(r => r.Id));

        // Refused rules still appear in the plan — the UI explains them rather than dropping them.
        var change = Assert.Single(plan.Changes);
        Assert.Equal(ChangeOutcome.Refused, change.Outcome);
        Assert.Equal("Hosts file is read-only", change.RefusalReason);

        var report = await svc.ApplyAsync(plan);

        Assert.Equal(1, report.Refused);
        Assert.Equal(0, report.Applied);
        Assert.Equal(0, report.Failed);

        // The point of the test: the target was not touched, not merely reported as untouched.
        Assert.Equal(hostsBefore, File.ReadAllBytes(_hostsPath));
        Assert.Empty(svc.Journal.Entries);
        Assert.Equal(0, BackupCount());     // not even a backup was taken
    }

    /// <summary>
    /// A blocker naming one rule must not quietly suppress its neighbours — refusal is per-rule.
    /// </summary>
    [Fact]
    public async Task ARefusalDoesNotStopTheRulesItDoesNotName()
    {
        SeedRegistry();
        var catalog = new[] { RegNewRule(), HostsRule() };
        var blocker = PreflightFinding.Block("Hosts file is read-only", "Simulated.", "test.hosts");

        var svc = Service(catalog, [blocker]);
        var plan = await svc.BuildPlanAsync(catalog.Select(r => r.Id));
        var report = await svc.ApplyAsync(plan);

        Assert.Equal(1, report.Refused);
        Assert.Equal(1, report.Applied);

        using var key = Registry.CurrentUser.OpenSubKey(_regKey);
        Assert.Equal(1, key!.GetValue("NewFlag"));
        Assert.DoesNotContain("alpha.example.invalid", await File.ReadAllTextAsync(_hostsPath));
    }

    // ------------------------------------------------------------------ 3. failure isolation

    /// <summary>
    /// One engine throwing must not abandon the rest of the plan — the journal already holds the
    /// reverse for whatever landed, so a partial apply is still fully undoable.
    /// </summary>
    [Fact]
    public async Task ApplyContinuesPastAFailingEngineInsteadOfAbandoningTheRest()
    {
        SeedRegistry();

        // Catalog order decides plan order, so the failure is guaranteed to come FIRST.
        var catalog = new[] { SvcRule(), RegNewRule(), HostsRule() };
        var svc = Service(catalog, services: new ExplodingServiceEngine());

        var plan = await svc.BuildPlanAsync(catalog.Select(r => r.Id));
        var report = await svc.ApplyAsync(plan);

        var failed = Assert.Single(plan.Changes, c => c.Outcome == ChangeOutcome.Failed);
        Assert.Equal(EngineKind.Service, failed.Engine);
        Assert.Equal(ExplodingServiceEngine.FakeName, failed.Target);
        Assert.NotNull(failed.Error);
        Assert.Contains("Access is denied", failed.Error!);

        // The failure really was ordered before the survivors, so this is "continued past",
        // not "happened to run first".
        var failIndex = plan.Changes.IndexOf(failed);
        var regIndex = plan.Changes.FindIndex(c => c.Engine == EngineKind.Registry);
        var hostsIndex = plan.Changes.FindIndex(c => c.Engine == EngineKind.Hosts);
        Assert.True(failIndex < regIndex, "the registry change must be planned after the failing one");
        Assert.True(failIndex < hostsIndex, "the hosts change must be planned after the failing one");

        Assert.Equal(ChangeOutcome.Applied, plan.Changes[regIndex].Outcome);
        Assert.Equal(ChangeOutcome.Applied, plan.Changes[hostsIndex].Outcome);
        Assert.Equal(1, report.Failed);
        Assert.Equal(2, report.Applied);

        using var key = Registry.CurrentUser.OpenSubKey(_regKey);
        Assert.Equal(1, key!.GetValue("NewFlag"));
        Assert.Contains("0.0.0.0 alpha.example.invalid", await File.ReadAllTextAsync(_hostsPath));

        // And what did land is still fully reversible.
        Assert.Empty(await svc.RevertAllAsync());
        Assert.Empty(svc.Journal.Entries);
    }

    // ------------------------------------------------------------------ 4. journal-before-mutation

    /// <summary>
    /// Hard rule #2, proved from the outside: make the hosts write fail and check the reverse was
    /// ALREADY durable on disk. If the order were inverted, a crash here would strand the machine.
    /// </summary>
    [Fact]
    public async Task TheReverseIsJournalledBeforeTheHostsFileIsMutated()
    {
        var hostsBefore = File.ReadAllBytes(_hostsPath);
        var catalog = new[] { HostsRule() };
        var svc = Service(catalog);

        new FileInfo(_hostsPath).IsReadOnly = true;
        try
        {
            var plan = await svc.BuildPlanAsync(catalog.Select(r => r.Id));
            var report = await svc.ApplyAsync(plan);
            Assert.Equal(1, report.Failed);
        }
        finally
        {
            new FileInfo(_hostsPath).IsReadOnly = false;
        }

        // The write never happened...
        Assert.Equal(hostsBefore, File.ReadAllBytes(_hostsPath));

        // ...but the way back was already recorded, in memory AND flushed to disk.
        var entry = Assert.Single(svc.Journal.Entries);
        Assert.Equal(ReverseKind.RestoreHostsBackup, entry.Reverse);
        Assert.NotNull(entry.BackupPath);
        Assert.True(File.Exists(entry.BackupPath), "the pre-apply backup must exist");
        Assert.Equal(hostsBefore, File.ReadAllBytes(entry.BackupPath!));

        var reloaded = new ChangeJournal(_journalPath);
        reloaded.Load();
        Assert.Single(reloaded.Entries);
    }

    /// <summary>
    /// The same invariant from the other side: if the journal cannot be made durable, the mutation
    /// must not happen at all. A change we cannot undo is worse than a change we did not make.
    /// </summary>
    [Fact]
    public async Task NothingIsMutatedWhenTheJournalCannotBeWritten()
    {
        SeedRegistry();

        var unwritable = Path.Combine(_dir, "no-such-dir", "nested", "journal.json");
        var catalog = new[] { RegNewRule() };
        var svc = Service(catalog, journalPath: unwritable);

        var plan = await svc.BuildPlanAsync(catalog.Select(r => r.Id));
        var report = await svc.ApplyAsync(plan);

        Assert.Equal(1, report.Failed);

        using var key = Registry.CurrentUser.OpenSubKey(_regKey);
        Assert.Null(key!.GetValue("NewFlag"));
        Assert.Equal(7, key.GetValue("ExistingFlag"));
    }

    // ------------------------------------------------------------------ 5. containment warning

    /// <summary>
    /// Containment targets are picked at runtime and have no catalog entry, so without the
    /// synthesised rule they would contribute nothing to the impact report — arming a Severe change
    /// while showing the user no cost at all, which is hard rule #1 inverted.
    /// </summary>
    [Fact]
    public async Task ContainmentSynthesisesAWarningRuleInThePlan()
    {
        var exe = Path.Combine(_dir, "SomeElectronApp.exe");
        await File.WriteAllTextAsync(exe, "not really an executable");

        var svc = Service([HostsRule()]);
        var plan = await svc.BuildPlanAsync([], [exe]);

        var synth = Assert.Single(plan.Rules, r => r.Id == "contain.summary");
        Assert.Equal(EngineKind.AppContainment, synth.Engine);
        Assert.Equal(RuleCategory.Containment, synth.Category);
        Assert.NotEmpty(synth.Breaks);
        Assert.Equal(BreakageSeverity.Severe, synth.WorstBreakage);
        Assert.Contains("SomeElectronApp.exe", synth.Summary);

        // It must reach the impact screen, which reads Degradations — not just sit in Rules.
        Assert.Contains(plan.Degradations, d => d.Rule.Id == "contain.summary");
        Assert.True(plan.SevereCount >= 1);

        var change = Assert.Single(plan.Changes);
        Assert.Equal(EngineKind.AppContainment, change.Engine);
        Assert.Equal(exe, change.Target);
        Assert.Equal(ChangeOutcome.Applied, change.Outcome);
    }

    [Fact]
    public async Task AContainmentTargetThatDoesNotExistIsPlannedAsNotPresent()
    {
        var missing = Path.Combine(_dir, "NeverInstalled.exe");
        var svc = Service([HostsRule()]);

        var plan = await svc.BuildPlanAsync([], [missing]);

        Assert.Equal(ChangeOutcome.NotPresent, Assert.Single(plan.Changes).Outcome);
        // The warning is still synthesised — the user asked to contain it either way.
        Assert.Contains(plan.Rules, r => r.Id == "contain.summary");
    }

    [Fact]
    public async Task NoContainmentMeansNoSyntheticWarningRule()
    {
        var catalog = new[] { HostsRule() };
        var svc = Service(catalog);

        var plan = await svc.BuildPlanAsync(catalog.Select(r => r.Id));

        Assert.DoesNotContain(plan.Rules, r => r.Id == "contain.summary");
    }

    // ------------------------------------------------------------------ 6. the elevation gate

    [Fact]
    public async Task ApplyAndRevertRefuseToRunWithoutAdministratorRights()
    {
        var catalog = new[] { HostsRule() };
        var svc = Service(catalog, elevated: false);
        var hostsBefore = File.ReadAllBytes(_hostsPath);

        // Planning is deliberately allowed unelevated — the app must preview without asking for UAC.
        var plan = await svc.BuildPlanAsync(catalog.Select(r => r.Id));
        Assert.NotEmpty(plan.Changes);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => svc.ApplyAsync(plan));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => svc.RevertAllAsync());

        Assert.Equal(hostsBefore, File.ReadAllBytes(_hostsPath));
        Assert.Empty(svc.Journal.Entries);
    }

    // ------------------------------------------------------------------ 7. unelevated engine reads

    /// <summary>
    /// <see cref="ServiceEngine.Resolve"/> is a plain HKLM registry read, so it works with no
    /// elevation at all. Prefix matching is the part that matters: Google's updater services carry
    /// a version suffix that changes on every Chrome release, so exact names are useless.
    /// </summary>
    [Fact]
    public void ServiceResolveMatchesExactNamesAndPrefixes()
    {
        using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        Assert.NotNull(services);

        var sample = services!.GetSubKeyNames().FirstOrDefault(n =>
        {
            using var k = services.OpenSubKey(n);
            return k?.GetValue("Start") is int;
        });
        Assert.NotNull(sample);

        var engine = new ServiceEngine();

        Assert.Contains(engine.Resolve([sample!]),
            s => string.Equals(s.Name, sample, StringComparison.OrdinalIgnoreCase));

        var prefix = sample![..Math.Min(4, sample.Length)] + "*";
        Assert.Contains(engine.Resolve([prefix]),
            s => string.Equals(s.Name, sample, StringComparison.OrdinalIgnoreCase));

        Assert.Empty(engine.Resolve(["NoSuchService-AntiGoogleTest"]));
    }

    /// <summary>Duplicate matches across overlapping patterns must be collapsed, not journalled twice.</summary>
    [Fact]
    public void ServiceResolveDoesNotReturnTheSameServiceTwice()
    {
        using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        var sample = services!.GetSubKeyNames().FirstOrDefault(n =>
        {
            using var k = services.OpenSubKey(n);
            return k?.GetValue("Start") is int;
        });
        Assert.NotNull(sample);

        var engine = new ServiceEngine();
        var found = engine.Resolve([sample!, sample!, sample![..Math.Min(4, sample.Length)] + "*"]);

        Assert.Equal(found.Select(f => f.Name.ToLowerInvariant()).Distinct().Count(), found.Count);
    }

    // ------------------------------------------------------------------ 8. documented deviation

    /// <summary>
    /// The one way revert is NOT byte-exact, recorded honestly rather than left as a trap: stripping
    /// the managed block rebuilds the file as <c>TrimEnd() + CRLF</c>, so a hosts file that ended
    /// without a trailing newline gains one. Nothing is lost, but it is a real difference and any
    /// byte-comparison test has to use a fixture that already ends in CRLF.
    /// </summary>
    [Fact]
    public async Task RevertNormalisesAHostsFileThatDidNotEndInANewline()
    {
        var path = Path.Combine(_dir, "hosts-no-trailing-newline");
        await File.WriteAllTextAsync(path, "127.0.0.1 localdev.test", new UTF8Encoding(false));

        var engine = new HostsFileEngine(path, _backupDir);
        var journal = new ChangeJournal(Path.Combine(_dir, "j2.json"));

        await engine.ApplyAsync([HostsRule()], journal);
        await engine.RevertAsync(journal.Entries.Single());

        var after = await File.ReadAllTextAsync(path);
        Assert.Equal("127.0.0.1 localdev.test\r\n", after);   // content intact, newline added
    }

    /// <summary>
    /// Every test in this class must stay off the machine's real state. If this fails, a seam was
    /// dropped and the suite is quietly editing the developer's own hosts file or journal.
    /// </summary>
    [Fact]
    public async Task TheSuiteNeverTouchesTheRealHostsFileOrJournal()
    {
        var realHosts = File.Exists(AppPaths.HostsFile) ? File.ReadAllBytes(AppPaths.HostsFile) : null;
        var realJournalExisted = File.Exists(AppPaths.JournalFile);

        SeedRegistry();
        var catalog = new[] { RegNewRule(), HostsRule() };
        var svc = Service(catalog);

        await svc.ApplyAsync(await svc.BuildPlanAsync(catalog.Select(r => r.Id)));
        await svc.RevertAllAsync();

        if (realHosts is not null)
            Assert.Equal(realHosts, File.ReadAllBytes(AppPaths.HostsFile));
        Assert.Equal(realJournalExisted, File.Exists(AppPaths.JournalFile));

        // Backups landed in the temp directory, not ProgramData.
        Assert.True(BackupCount() >= 1);
    }
}
