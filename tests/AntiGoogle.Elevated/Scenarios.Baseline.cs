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

using System.Net.Sockets;
using System.Text;
using AntiGoogle.Core;
using AntiGoogle.Core.Catalog;
using AntiGoogle.Core.Model;
using AntiGoogle.Core.Safety;
using Microsoft.Win32;

namespace AntiGoogle.Elevated;

internal sealed record ScenarioContext(Checks Checks, FixtureSet Fixtures, Options Options);

/// <summary>
/// The scenarios the unit suite cannot reach: the real default profile applied to a real machine
/// and taken back out again, read back through tools that share no code with the engines.
/// </summary>
internal static partial class Scenarios
{
    private const string UserHostsMarker = "agtest-user.local";

    public static readonly IReadOnlyList<(string Name, Func<ScenarioContext, Task> Run)> Baseline =
    [
        ("preflight", Preflight_Elevated),
        ("roundtrip-clean", cx => DefaultProfileRoundTrip(cx, preexistingPolicy: false)),
        ("roundtrip-preexisting-policy", cx => DefaultProfileRoundTrip(cx, preexistingPolicy: true)),
        ("idempotent-reapply", IdempotentReapply),
        ("containment-roundtrip", ContainmentRoundTrip)
    ];

    // ---------------------------------------------------------------------------------------------

    private static async Task Preflight_Elevated(ScenarioContext cx)
    {
        var c = cx.Checks;
        var findings = await Preflight.RunAsync().ConfigureAwait(false);
        foreach (var f in findings) c.Info($"{f.Level,-8} {f.Title}");

        c.Check("preflight reports no Blocker on an elevated, healthy machine",
            findings.All(f => f.Level != FindingLevel.Blocker),
            string.Join("\n", findings.Where(f => f.Level == FindingLevel.Blocker).Select(f => $"{f.Title}: {f.Detail}")));
        c.Check("the hosts file is found and writable",
            findings.All(f => !f.Title.Contains("Hosts file", StringComparison.OrdinalIgnoreCase) || f.Level != FindingLevel.Blocker));
    }

    // ---------------------------------------------------------------------------------------------

    private static async Task DefaultProfileRoundTrip(ScenarioContext cx, bool preexistingPolicy)
    {
        var c = cx.Checks;
        var fx = cx.Fixtures;
        await using var seed = new RegistrySeed(preexistingPolicy);
        SeedUserHostsEntries();

        var before = await MachineSnapshot.CaptureAsync(fx.ServiceNames, fx.TaskNames).ConfigureAwait(false);

        var service = new ProtectionService();
        var plan = await service.BuildPlanAsync(RuleCatalog.DefaultEnabledIds).ConfigureAwait(false);
        c.Check("the default profile plans at least one change per engine we can see on this machine",
            plan.Changes.Select(x => x.Engine).Distinct().Count() >= 4,
            string.Join(", ", plan.Changes.Select(x => x.Engine).Distinct()));
        c.Check("no change is refused by preflight", plan.Changes.All(x => x.Outcome != ChangeOutcome.Refused),
            string.Join("\n", plan.Changes.Where(x => x.Outcome == ChangeOutcome.Refused).Select(x => $"{x.Description}: {x.RefusalReason}")));

        var report = await service.ApplyAsync(plan).ConfigureAwait(false);
        c.Check("apply reports no failed change", report.Failed == 0,
            string.Join("\n", plan.Changes.Where(x => x.Outcome == ChangeOutcome.Failed).Select(x => $"{x.Description}: {x.Error}")));
        c.Info($"applied={report.Applied} skipped={report.Skipped} failed={report.Failed} refused={report.Refused}");

        await VerifyAppliedStateAsync(cx, preexistingPolicy).ConfigureAwait(false);

        var errors = await service.RevertAllAsync().ConfigureAwait(false);
        c.Check("restore reports no errors", errors.Count == 0, string.Join("\n", errors));

        var after = await MachineSnapshot.CaptureAsync(fx.ServiceNames, fx.TaskNames).ConfigureAwait(false);
        var diff = MachineSnapshot.Diff(before, after);
        c.Check("after restore the machine is exactly as it was before apply", diff.Count == 0, string.Join("\n", diff));

        // A second revert against an empty journal must be a quiet no-op.
        var again = await new ProtectionService().RevertAllAsync().ConfigureAwait(false);
        c.Check("a second restore finds nothing to do and raises no error", again.Count == 0, string.Join("\n", again));
    }

    private static async Task VerifyAppliedStateAsync(ScenarioContext cx, bool preexistingPolicy)
    {
        var c = cx.Checks;
        var fx = cx.Fixtures;

        // ---- hosts ----
        var text = File.ReadAllText(AppPaths.HostsFile);
        var begin = text.IndexOf(AppPaths.HostsBeginMarker, StringComparison.Ordinal);
        var end = text.IndexOf(AppPaths.HostsEndMarker, StringComparison.Ordinal);
        c.Check("hosts file carries exactly one managed block",
            begin >= 0 && end > begin && text.IndexOf(AppPaths.HostsBeginMarker, begin + 1, StringComparison.Ordinal) < 0);
        c.Check("the user's own hosts entries survived apply", text.Contains(UserHostsMarker, StringComparison.Ordinal));

        var block = begin >= 0 && end > begin ? text[begin..end] : "";
        var expected = RuleCatalog.All.Where(r => r.DefaultEnabled && r.Engine == EngineKind.Hosts)
            .SelectMany(r => r.Domains).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var v4 = block.Split('\n').Count(l => l.StartsWith("0.0.0.0 ", StringComparison.Ordinal));
        var v6 = block.Split('\n').Count(l => l.StartsWith(":: ", StringComparison.Ordinal));
        c.Check($"every one of the {expected.Count} default domains is sinkholed on IPv4 and IPv6",
            expected.All(d => block.Contains($"0.0.0.0 {d}", StringComparison.Ordinal) && block.Contains($":: {d}", StringComparison.Ordinal)),
            $"v4 lines={v4}, v6 lines={v6}");

        // The resolver is the real judge: does Windows now refuse to resolve a sinkholed name?
        string resolved;
        try
        {
            var addrs = await System.Net.Dns.GetHostAddressesAsync("www.google-analytics.com").ConfigureAwait(false);
            resolved = string.Join(",", addrs.Select(a => a.ToString()));
        }
        catch (SocketException ex) { resolved = $"error:{ex.SocketErrorCode}"; }
        c.Check("Windows no longer resolves www.google-analytics.com to a routable address",
            resolved.StartsWith("error:", StringComparison.Ordinal) || resolved is "0.0.0.0" or "::" or "0.0.0.0,::" or "::,0.0.0.0",
            $"resolved to: {resolved}");

        // ---- services ----
        foreach (var s in FixtureSet.Services)
        {
            var qc = (await Tools.ScAsync("qc", s.Name).ConfigureAwait(false)).StdOut;
            var q = (await Tools.ScAsync("query", s.Name).ConfigureAwait(false)).StdOut;
            if (s.MatchesCatalog)
            {
                c.Check($"service {s.Name} is DISABLED", qc.Contains("DISABLED", StringComparison.Ordinal), Flat(qc));
                c.Check($"service {s.Name} is STOPPED", q.Contains("STOPPED", StringComparison.Ordinal), Flat(q));
            }
            else
            {
                c.Check($"decoy service {s.Name} was left alone (still AUTO_START and RUNNING)",
                    qc.Contains("AUTO_START", StringComparison.Ordinal) && q.Contains("RUNNING", StringComparison.Ordinal), Flat(qc) + " | " + Flat(q));
            }
        }

        // ---- scheduled tasks ----
        foreach (var (name, matches) in FixtureSet.Tasks)
        {
            var state = (await Tools.PsAsync($"(Get-ScheduledTask -TaskName '{name}').State").ConfigureAwait(false)).StdOut.Trim();
            c.Check(matches ? $"task {name} is Disabled" : $"decoy task {name} was left alone",
                matches ? state == "Disabled" : state != "Disabled", $"state={state}");
        }

        // ---- registry, read through reg.exe rather than Microsoft.Win32 ----
        var metrics = await Tools.RegAsync("query", @"HKLM\SOFTWARE\Policies\Google\Chrome", "/v", "MetricsReportingEnabled").ConfigureAwait(false);
        c.Check("Chrome MetricsReportingEnabled is 0 (read with reg.exe)", metrics.StdOut.Contains("0x0", StringComparison.Ordinal), metrics.Combined);
        var doh = await Tools.RegAsync("query", @"HKLM\SOFTWARE\Policies\Microsoft\Edge", "/v", "DnsOverHttpsMode").ConfigureAwait(false);
        c.Check("Edge DnsOverHttpsMode is 'off' (read with reg.exe)", doh.StdOut.Contains("off", StringComparison.Ordinal), doh.Combined);
        if (preexistingPolicy)
        {
            var other = await Tools.RegAsync("query", @"HKLM\SOFTWARE\Policies\Google\Chrome", "/v", RegistrySeed.UnrelatedName).ConfigureAwait(false);
            c.Check("an unrelated pre-existing Chrome policy value was not touched", other.StdOut.Contains("0x7", StringComparison.Ordinal), other.Combined);
        }
    }

    // ---------------------------------------------------------------------------------------------

    private static async Task IdempotentReapply(ScenarioContext cx)
    {
        var c = cx.Checks;
        var fx = cx.Fixtures;
        SeedUserHostsEntries();
        var before = await MachineSnapshot.CaptureAsync(fx.ServiceNames, fx.TaskNames).ConfigureAwait(false);

        var service = new ProtectionService();
        var first = await service.ApplyAsync(await service.BuildPlanAsync(RuleCatalog.DefaultEnabledIds).ConfigureAwait(false)).ConfigureAwait(false);
        c.Check("first apply succeeds", first.Failed == 0);

        var plan2 = await service.BuildPlanAsync(RuleCatalog.DefaultEnabledIds).ConfigureAwait(false);
        var second = await service.ApplyAsync(plan2).ConfigureAwait(false);
        c.Check("second apply succeeds", second.Failed == 0);
        c.Check("second apply re-writes no service, task or registry change (all already satisfied)",
            plan2.Changes.Where(x => x.Engine is EngineKind.Service or EngineKind.ScheduledTask or EngineKind.Registry)
                         .All(x => x.Outcome is ChangeOutcome.AlreadySatisfied or ChangeOutcome.NotPresent),
            string.Join("\n", plan2.Changes.Where(x => x.Engine is EngineKind.Service or EngineKind.ScheduledTask or EngineKind.Registry
                && x.Outcome is not (ChangeOutcome.AlreadySatisfied or ChangeOutcome.NotPresent)).Select(x => $"{x.Engine} {x.Description} -> {x.Outcome}")));

        var text = File.ReadAllText(AppPaths.HostsFile);
        c.Check("the hosts file still holds exactly one managed block after two applies",
            CountOccurrences(text, AppPaths.HostsBeginMarker) == 1 && CountOccurrences(text, AppPaths.HostsEndMarker) == 1);

        var errors = await new ProtectionService().RevertAllAsync().ConfigureAwait(false);
        c.Check("restore after a double apply reports no errors", errors.Count == 0, string.Join("\n", errors));
        var diff = MachineSnapshot.Diff(before, await MachineSnapshot.CaptureAsync(fx.ServiceNames, fx.TaskNames).ConfigureAwait(false));
        c.Check("the machine is exactly as it was after a double apply and one restore", diff.Count == 0, string.Join("\n", diff));
    }

    // ---------------------------------------------------------------------------------------------

    private static async Task ContainmentRoundTrip(ScenarioContext cx)
    {
        var c = cx.Checks;
        var fx = cx.Fixtures;
        var before = await MachineSnapshot.CaptureAsync(fx.ServiceNames, fx.TaskNames).ConfigureAwait(false);

        var service = new ProtectionService();
        var plan = await service.BuildPlanAsync([], [fx.AppExe]).ConfigureAwait(false);
        var report = await service.ApplyAsync(plan).ConfigureAwait(false);
        c.Check("containing the fake app applies without failure", report.Failed == 0,
            string.Join("\n", plan.Changes.Where(x => x.Outcome == ChangeOutcome.Failed).Select(x => x.Error)));

        var name = $"Anti-Google: contain {Path.GetFileName(fx.AppExe)}";
        var rule = (await Tools.PsAsync(
            $"$r = Get-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue; if (-not $r) {{ 'MISSING' }} else {{ " +
            "$app = ($r | Get-NetFirewallApplicationFilter).Program; $addr = @(($r | Get-NetFirewallAddressFilter).RemoteAddress).Count; " +
            "\"$($r.Enabled)|$($r.Direction)|$($r.Action)|$($r.Group)|$app|$addr\" }").ConfigureAwait(false)).StdOut.Trim();
        var parts = rule.Split('|');
        c.Check("a firewall rule for exactly this program exists", parts.Length == 6, rule);
        if (parts.Length == 6)
        {
            c.Check("the rule is enabled, outbound, Block and in the Anti-Google group",
                parts[0] == "True" && parts[1] == "Outbound" && parts[2] == "Block" && parts[3] == AppPaths.FirewallGroup, rule);
            c.Check("the rule is scoped to the fake app's path", string.Equals(parts[4], fx.AppExe, StringComparison.OrdinalIgnoreCase), rule);
            c.Check($"the rule carries all {GoogleIpRanges.Core.Length} Google ranges", parts[5] == GoogleIpRanges.Core.Length.ToString(), rule);
        }

        var errors = await service.RevertAllAsync().ConfigureAwait(false);
        c.Check("restore reports no errors", errors.Count == 0, string.Join("\n", errors));
        var diff = MachineSnapshot.Diff(before, await MachineSnapshot.CaptureAsync(fx.ServiceNames, fx.TaskNames).ConfigureAwait(false));
        c.Check("the machine is exactly as it was after containment and restore", diff.Count == 0, string.Join("\n", diff));
    }

    // ---------------------------------------------------------------------------------------------

    private static string Flat(string s) =>
        string.Join(" | ", s.Replace("\r", "").Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0));

    private static int CountOccurrences(string text, string needle)
    {
        var count = 0;
        for (var i = text.IndexOf(needle, StringComparison.Ordinal); i >= 0; i = text.IndexOf(needle, i + 1, StringComparison.Ordinal)) count++;
        return count;
    }

    /// <summary>
    /// Makes the hosts file canonical (one trailing CRLF, no blank tail) and adds user entries, so
    /// "byte-identical after restore" tests what the engine promises rather than whatever trailing
    /// whitespace the machine happened to have. The harness is not allowed to be the reason a
    /// restore looks wrong.
    /// </summary>
    internal static void SeedUserHostsEntries()
    {
        var path = AppPaths.HostsFile;
        var text = File.ReadAllText(path);
        if (text.Contains(UserHostsMarker, StringComparison.Ordinal)) return;
        var seeded = text.TrimEnd('\r', '\n') + "\r\n" +
                     $"127.0.0.1 {UserHostsMarker}\r\n" +
                     "10.9.8.7 agtest-nas.lan\r\n";
        File.WriteAllText(path, seeded, new UTF8Encoding(false));
    }

    /// <summary>Puts the hosts file back the way the machine had it before the first scenario.</summary>
    internal static void RemoveUserHostsEntries()
    {
        var path = AppPaths.HostsFile;
        var lines = File.ReadAllLines(path).Where(l => !l.Contains(UserHostsMarker) && !l.Contains("agtest-nas.lan")).ToList();
        File.WriteAllText(path, string.Join("\r\n", lines).TrimEnd('\r', '\n') + "\r\n", new UTF8Encoding(false));
    }
}

/// <summary>
/// Optionally pre-creates a Chrome policy value (so revert must restore a REAL previous value) and
/// guarantees the policy tree is put back as the machine had it.
/// </summary>
internal sealed class RegistrySeed : IAsyncDisposable
{
    public const string UnrelatedName = "AgTestUnrelated";
    private const string Chrome = @"SOFTWARE\Policies\Google\Chrome";
    private readonly bool _seeded;

    public RegistrySeed(bool preexisting)
    {
        _seeded = preexisting;
        if (!preexisting) return;
        using var key = Registry.LocalMachine.CreateSubKey(Chrome, writable: true);
        key!.SetValue("MetricsReportingEnabled", 1, RegistryValueKind.DWord);
        key.SetValue(UnrelatedName, 7, RegistryValueKind.DWord);
    }

    public ValueTask DisposeAsync()
    {
        if (_seeded)
        {
            try { Registry.LocalMachine.DeleteSubKeyTree(@"SOFTWARE\Policies\Google", throwOnMissingSubKey: false); } catch { }
        }
        return ValueTask.CompletedTask;
    }
}
