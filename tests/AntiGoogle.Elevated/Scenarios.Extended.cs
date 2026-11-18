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

using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AntiGoogle.Core;
using AntiGoogle.Core.Catalog;
using AntiGoogle.Core.Engines;
using AntiGoogle.Core.Markers;
using AntiGoogle.Core.Model;
using AntiGoogle.Core.Reporting;
using AntiGoogle.Core.Safety;
using AntiGoogle.Core.Verification;

namespace AntiGoogle.Elevated;

/// <summary>
/// Scenarios for local-only mode, quarantine, the security-agent guard, mode switching and the report,
/// run against real engines. The firewall is judged by traffic from a real jailed process, not by
/// reading the rule back and nodding.
/// </summary>
internal static partial class Scenarios
{
    private const int ProbePort = 7101;

    public static readonly IReadOnlyList<(string Name, Func<ScenarioContext, Task> Run)> Extended =
    [
        ("localonly-services-and-tasks", LocalOnlyServicesAndTasks),
        ("localonly-live-traffic", LocalOnlyLiveTraffic),
        ("localonly-hosts", LocalOnlyHosts),
        ("mode-switch-and-unarm", ModeSwitchAndUnarm),
        ("quarantine-real-paths", QuarantineRealPaths),
        ("security-agent-guard", SecurityAgentGuard),
        ("report-end-to-end", ReportEndToEnd)
    ];

    // ---------------------------------------------------------------------------------------------

    private static async Task LocalOnlyServicesAndTasks(ScenarioContext cx)
    {
        var c = cx.Checks;
        var fx = cx.Fixtures;
        string[] ids = ["svc.google-updater", "task.google-updater", "svc.chrome-elevation"];
        var before = await MachineSnapshot.CaptureAsync(fx.ServiceNames, fx.TaskNames).ConfigureAwait(false);

        var service = new ProtectionService();
        var plan = await service.BuildPlanAsync(new PlanRequest { EnabledRuleIds = ids, LocalOnlyRuleIds = ids }).ConfigureAwait(false);

        c.Check("a local-only plan disables no service and no task",
            plan.Changes.All(x => x.Engine is not (EngineKind.Service or EngineKind.ScheduledTask)));

        var jails = plan.Changes.Where(x => x.Engine == EngineKind.LocalOnly).ToList();
        c.Check("all five Google-named services are planned as confined on their own program",
            jails.Count(x => string.Equals(x.JailProgram, fx.ServiceExe, StringComparison.OrdinalIgnoreCase)) == 5,
            string.Join("\n", jails.Select(x => $"{x.Description} -> {x.JailProgram} [{x.Outcome}]")));

        var refused = jails.Where(x => x.Outcome == ChangeOutcome.Refused).ToList();
        c.Check("the three tasks that run cmd.exe are refused, because that is inside the Windows directory",
            refused.Count == 3 && refused.All(x => x.RefusalReason!.Contains("Windows directory", StringComparison.Ordinal)),
            string.Join("\n", refused.Select(x => $"{x.Target}: {x.RefusalReason}")));
        c.Check("the task that runs the fake Google app is planned",
            jails.Any(x => string.Equals(x.JailProgram, fx.AppExe, StringComparison.OrdinalIgnoreCase) && x.Outcome == ChangeOutcome.Applied));
        c.Check("the preview states the local-only cost, including the updater caveat",
            plan.Degradations.Any(d => d.Breakage.What == "Chrome security updates" && d.Breakage.Severity == BreakageSeverity.Severe)
            && plan.Degradations.Any(d => d.Breakage.What == "The updater keeps retrying"));

        var report = await service.ApplyAsync(plan).ConfigureAwait(false);
        c.Check("apply reports no failure", report.Failed == 0,
            string.Join("\n", plan.Changes.Where(x => x.Outcome == ChangeOutcome.Failed).Select(x => $"{x.Description}: {x.Error}")));

        // ---- the firewall, read with a different projection than the product uses ----
        var rules = await ReadGroupAsync().ConfigureAwait(false);
        c.Check("exactly four rules exist: an outbound and an inbound block for each of the two programs", rules.Count == 4,
            string.Join("\n", rules.Select(r => r.ToString())));

        foreach (var program in new[] { fx.ServiceExe, fx.AppExe })
        foreach (var direction in new[] { "Outbound", "Inbound" })
        {
            var rule = rules.FirstOrDefault(r => string.Equals(r.Program, program, StringComparison.OrdinalIgnoreCase) && r.Direction == direction);
            c.Check($"{Path.GetFileName(program)} has an enabled {direction} Block rule for every address except loopback",
                rule is not null && rule.Action == "Block" && rule.Enabled == "True"
                && rule.Remote.SetEquals(LoopbackRanges.NonLoopback.Select(x => x.ToLowerInvariant())),
                rule?.ToString() ?? "no such rule");
        }

        // ---- nothing was switched off: the whole point of keeping them running ----
        var during = await MachineSnapshot.CaptureAsync(fx.ServiceNames, fx.TaskNames).ConfigureAwait(false);
        var moved = MachineSnapshot.Diff(before, during).Where(d => d.StartsWith("svc.") || d.StartsWith("task.")).ToList();
        c.Check("no service or task changed state while confined (gupdate is still delayed-automatic and running)", moved.Count == 0, string.Join("\n", moved));

        // ---- the product's own verifier ----
        var verdict = await new LoopbackVerifier(service.Firewall, service.Hosts, service.Journal).VerifyAsync().ConfigureAwait(false);
        c.Check("the verifier passes for both programs", verdict.Passed && verdict.Targets.Count == 2,
            string.Join("\n", verdict.Targets.SelectMany(t => t.Checks.Where(k => !k.Passed).Select(k => $"{t.Label}: {k.Name}: {k.Detail}"))));

        var errors = await service.RevertAllAsync().ConfigureAwait(false);
        c.Check("restore reports no errors", errors.Count == 0, string.Join("\n", errors));
        var diff = MachineSnapshot.Diff(before, await MachineSnapshot.CaptureAsync(fx.ServiceNames, fx.TaskNames).ConfigureAwait(false));
        c.Check("the machine is exactly as it was after confinement and restore", diff.Count == 0, string.Join("\n", diff));
    }

    // ---------------------------------------------------------------------------------------------

    private static async Task LocalOnlyLiveTraffic(ScenarioContext cx)
    {
        var c = cx.Checks;
        var fx = cx.Fixtures;
        var peer = cx.Options.OffBoxPeer;
        if (peer is null)
        {
            c.Info("skipped: pass --off-box-peer <ip of another machine> to run traffic through a real jail");
            return;
        }

        var ownIp = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .SelectMany(n => n.GetIPProperties().UnicastAddresses).Select(a => a.Address)
            .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)?.ToString();

        // The listener is a DIFFERENT file from the jailed program, so no rule ever applies to it.
        using var listener = Process.Start(new ProcessStartInfo(fx.ProbeExe, $"listen {ProbePort} 240") { CreateNoWindow = true, UseShellExecute = false })!;
        await Task.Delay(1500).ConfigureAwait(false);
        var before = await MachineSnapshot.CaptureAsync(fx.ServiceNames, fx.TaskNames).ConfigureAwait(false);

        try
        {
            // Positive control: with no rule, Windows Firewall does not refuse the off-box attempt.
            var controlOff = await Connect(fx.AppExe, peer).ConfigureAwait(false);
            c.Check("control: before the jail, the off-box attempt is not refused by Windows Firewall", !controlOff.Contains("AccessDenied"), controlOff);
            c.Check("control: before the jail, loopback works", (await Connect(fx.AppExe, "127.0.0.1").ConfigureAwait(false)).Contains("ECHO-OK"));

            var service = new ProtectionService();
            var plan = await service.BuildPlanAsync(new PlanRequest { LocalOnlyApps = [fx.AppExe] }).ConfigureAwait(false);
            var report = await service.ApplyAsync(plan).ConfigureAwait(false);
            c.Check("the fake app is confined without failure", report.Failed == 0,
                string.Join("\n", plan.Changes.Where(x => x.Outcome == ChangeOutcome.Failed).Select(x => x.Error)));

            var v4 = await Connect(fx.AppExe, "127.0.0.1").ConfigureAwait(false);
            var v6 = await Connect(fx.AppExe, "::1").ConfigureAwait(false);
            var name = await Connect(fx.AppExe, "localhost").ConfigureAwait(false);
            var off = await Connect(fx.AppExe, peer).ConfigureAwait(false);

            c.Check("jailed: IPv4 loopback still works", v4.Contains("ECHO-OK"), v4);
            c.Check("jailed: IPv6 loopback still works", v6.Contains("ECHO-OK"), v6);
            c.Check("jailed: the name localhost still works", name.Contains("ECHO-OK"), name);
            c.Check("jailed: an address off this machine is refused by the firewall (AccessDenied, 10013)", off.Contains("AccessDenied"), off);
            if (ownIp is not null)
                c.Check("jailed: this machine's own network address is still reachable, because it never leaves the machine",
                    (await Connect(fx.AppExe, ownIp).ConfigureAwait(false)).Contains("ECHO-OK"));

            // The product's verifier must agree with what the traffic showed.
            var verdict = await new LoopbackVerifier(service.Firewall, service.Hosts, service.Journal).VerifyAsync().ConfigureAwait(false);
            c.Check("the verifier agrees with the traffic", verdict.Passed,
                string.Join("\n", verdict.Targets.SelectMany(t => t.Checks.Where(k => !k.Passed).Select(k => k.Detail))));

            var errors = await service.RevertAllAsync().ConfigureAwait(false);
            c.Check("restore reports no errors", errors.Count == 0, string.Join("\n", errors));

            var after = await Connect(fx.AppExe, peer).ConfigureAwait(false);
            c.Check("after restore the off-box attempt is no longer refused by the firewall", !after.Contains("AccessDenied"), after);
        }
        finally
        {
            try { listener.Kill(); } catch { }
        }

        var diff = MachineSnapshot.Diff(before, await MachineSnapshot.CaptureAsync(fx.ServiceNames, fx.TaskNames).ConfigureAwait(false));
        c.Check("the machine is exactly as it was", diff.Count == 0, string.Join("\n", diff));

        async Task<string> Connect(string exe, string host) => await RunAsync(exe, $"connect {host} {ProbePort} 2500", 20).ConfigureAwait(false);
    }

    // ---------------------------------------------------------------------------------------------

    private static async Task LocalOnlyHosts(ScenarioContext cx)
    {
        var c = cx.Checks;
        var fx = cx.Fixtures;
        SeedUserHostsEntries();
        var before = await MachineSnapshot.CaptureAsync(fx.ServiceNames, fx.TaskNames).ConfigureAwait(false);
        var existing = Preflight.LoopbackWebListeners();
        c.Info($"listeners on 80/443 before the scenario: {(existing is null ? "unreadable" : existing.Count == 0 ? "none" : string.Join(",", existing))}");

        var request = new PlanRequest
        {
            EnabledRuleIds = ["hosts.update-delivery", "hosts.chrome-telemetry"],
            LocalOnlyRuleIds = ["hosts.update-delivery"]
        };

        var service = new ProtectionService();
        var plan = await service.BuildPlanAsync(request).ConfigureAwait(false);

        if (existing is { Count: 0 })
        {
            c.Check("with nothing listening, the local-only rule resolves to this machine", plan.LoopbackRuleIds.Contains("hosts.update-delivery") && !plan.LoopbackDowngraded);
            await service.ApplyAsync(plan).ConfigureAwait(false);

            var text = File.ReadAllText(AppPaths.HostsFile);
            c.Check("the hosts block holds 127.0.0.1 and ::1 for a looped name",
                text.Contains("127.0.0.1 update.googleapis.com", StringComparison.Ordinal) && text.Contains("::1 update.googleapis.com", StringComparison.Ordinal));
            c.Check("a blocked name still gets 0.0.0.0 and ::",
                text.Contains("0.0.0.0 clientservices.googleapis.com", StringComparison.Ordinal) && text.Contains(":: clientservices.googleapis.com", StringComparison.Ordinal));

            var looped = await Resolve("update.googleapis.com").ConfigureAwait(false);
            c.Check("Windows resolves the looped name to loopback on both families",
                looped.Contains("127.0.0.1") && looped.Contains("::1"), looped);
            var blocked = await Resolve("clientservices.googleapis.com").ConfigureAwait(false);
            c.Check("Windows resolves the blocked name to nothing", blocked.StartsWith("error:"), blocked);

            var refused = await RunAsync(fx.ProbeExe, "connect update.googleapis.com 443 2500", 20).ConfigureAwait(false);
            c.Check("a connection to the looped name goes to this machine and is refused, because nothing listens",
                refused.Contains("CONNECT-FAIL") && (refused.Contains("ConnectionRefused") || refused.Contains("10061")), refused);

            var verdict = await new LoopbackVerifier(service.Firewall, service.Hosts, service.Journal).VerifyAsync().ConfigureAwait(false);
            c.Check("the verifier confirms every looped name has both address families", verdict.Hosts.Count == 1 && verdict.Hosts[0].Passed,
                string.Join("\n", verdict.Hosts.Select(h => h.Detail)));

            c.Check("restore reports no errors", (await service.RevertAllAsync().ConfigureAwait(false)).Count == 0);
        }
        else
        {
            c.Info("something already listens on 80 or 443 here, so the loopback-resolves checks are skipped (the fallback is exercised below)");
        }

        // ---- LO-5: something local answers on 443, so loopback must not be used ----
        using var listener = Process.Start(new ProcessStartInfo(fx.ProbeExe, "listen 443 120") { CreateNoWindow = true, UseShellExecute = false })!;
        try
        {
            await Task.Delay(1500).ConfigureAwait(false);
            var seen = Preflight.LoopbackWebListeners();
            c.Check("the preflight sees the listener on 443", seen is { } s && s.Contains(443), seen is null ? "unreadable" : string.Join(",", seen));

            var downgraded = await service.BuildPlanAsync(request).ConfigureAwait(false);
            c.Check("the plan falls back to the sinkhole and says why", downgraded.LoopbackDowngraded && downgraded.LoopbackRuleIds.Count == 0
                && downgraded.Findings.Any(f => f.Title.StartsWith("Local-only names were sinkholed", StringComparison.Ordinal)));

            await service.ApplyAsync(downgraded).ConfigureAwait(false);
            var text = File.ReadAllText(AppPaths.HostsFile);
            c.Check("the hosts block sinkholes the name instead of looping it",
                text.Contains("0.0.0.0 update.googleapis.com", StringComparison.Ordinal) && !text.Contains("127.0.0.1 update.googleapis.com", StringComparison.Ordinal));
            var resolved = await Resolve("update.googleapis.com").ConfigureAwait(false);
            c.Check("Windows resolves it to nothing, so Google-bound requests never reach the local listener", resolved.StartsWith("error:"), resolved);
        }
        finally
        {
            try { listener.Kill(); } catch { }
        }

        c.Check("restore reports no errors", (await service.RevertAllAsync().ConfigureAwait(false)).Count == 0);
        var diff = MachineSnapshot.Diff(before, await MachineSnapshot.CaptureAsync(fx.ServiceNames, fx.TaskNames).ConfigureAwait(false));
        c.Check("the machine is exactly as it was", diff.Count == 0, string.Join("\n", diff));

        static async Task<string> Resolve(string name)
        {
            try { return string.Join(",", (await Dns.GetHostAddressesAsync(name).ConfigureAwait(false)).Select(a => a.ToString())); }
            catch (SocketException ex) { return $"error:{ex.SocketErrorCode}"; }
        }
    }

    // ---------------------------------------------------------------------------------------------

    private static async Task ModeSwitchAndUnarm(ScenarioContext cx)
    {
        var c = cx.Checks;
        var fx = cx.Fixtures;
        var before = await MachineSnapshot.CaptureAsync(fx.ServiceNames, fx.TaskNames).ConfigureAwait(false);
        string[] ids = ["svc.google-updater"];
        var service = new ProtectionService();

        // 1. Blocked: the services are disabled and stopped.
        await service.ApplyAsync(await service.BuildPlanAsync(new PlanRequest { EnabledRuleIds = ids }).ConfigureAwait(false)).ConfigureAwait(false);
        var blocked = (await Tools.ScAsync("qc", "gupdate").ConfigureAwait(false)).StdOut;
        c.Check("blocked: gupdate is disabled", blocked.Contains("DISABLED", StringComparison.Ordinal), Flat(blocked));

        // 2. Switch to local-only: the disable is undone first, exactly, and the jail goes on.
        var toLocal = await service.BuildPlanAsync(new PlanRequest { EnabledRuleIds = ids, LocalOnlyRuleIds = ids }).ConfigureAwait(false);
        c.Check("the preview lists the undo ahead of the new changes", toLocal.Changes.Count > 0 && toLocal.Changes[0].IsUndo);
        var r2 = await service.ApplyAsync(toLocal).ConfigureAwait(false);
        c.Check("switching to local-only fails nothing", r2.Failed == 0, string.Join("\n", toLocal.Changes.Where(x => x.Outcome == ChangeOutcome.Failed).Select(x => x.Error)));

        var during = await MachineSnapshot.CaptureAsync(fx.ServiceNames, fx.TaskNames).ConfigureAwait(false);
        var moved = MachineSnapshot.Diff(before, during).Where(d => d.StartsWith("svc.")).ToList();
        c.Check("local-only: every service is back exactly as it was, including delayed-automatic and running", moved.Count == 0, string.Join("\n", moved));
        c.Check("local-only: the jail rules exist", (await ReadGroupAsync().ConfigureAwait(false)).Count == 2);

        // 3. Back to blocked: the jail comes off, the services are disabled again.
        var toBlock = await service.BuildPlanAsync(new PlanRequest { EnabledRuleIds = ids }).ConfigureAwait(false);
        await service.ApplyAsync(toBlock).ConfigureAwait(false);
        c.Check("blocked again: no jail rule remains", (await ReadGroupAsync().ConfigureAwait(false)).Count == 0);
        c.Check("blocked again: gupdate is disabled", (await Tools.ScAsync("qc", "gupdate").ConfigureAwait(false)).StdOut.Contains("DISABLED", StringComparison.Ordinal));

        // 4. Un-arm everything: the next apply takes it all back.
        var unarm = await service.BuildPlanAsync(new PlanRequest()).ConfigureAwait(false);
        c.Check("un-arming plans undo changes and nothing else", unarm.Changes.Count > 0 && unarm.Changes.All(x => x.IsUndo));
        await service.ApplyAsync(unarm).ConfigureAwait(false);

        var diff = MachineSnapshot.Diff(before, await MachineSnapshot.CaptureAsync(fx.ServiceNames, fx.TaskNames).ConfigureAwait(false));
        c.Check("after un-arming, the machine is exactly as it was", diff.Count == 0, string.Join("\n", diff));
        c.Check("the journal is empty", service.Journal.Entries.Count == 0);

        await service.RevertAllAsync().ConfigureAwait(false);
    }

    // ---------------------------------------------------------------------------------------------

    private static async Task QuarantineRealPaths(ScenarioContext cx)
    {
        var c = cx.Checks;
        var fx = cx.Fixtures;
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var created = new List<string>();
        void MakeTree(string root)
        {
            if (!Directory.Exists(root)) created.Add(root);
        }

        var crashRoot = Path.Combine(local, "Google");
        var androidRoot = Path.Combine(profile, ".android");
        var gcloudRoot = Path.Combine(roaming, "gcloud");
        MakeTree(crashRoot); MakeTree(androidRoot); MakeTree(gcloudRoot);

        var chrome = Path.Combine(local, "Google", "Chrome", "User Data");
        var files = new Dictionary<string, byte[]>
        {
            [Path.Combine(chrome, "Crashpad", "reports", "a.dmp")] = Encoding.UTF8.GetBytes("dump a"),
            [Path.Combine(chrome, "Crashpad", "reports", "sub", "b.dmp")] = Encoding.UTF8.GetBytes("dump b, deeper"),
            [Path.Combine(chrome, "SwReporter", "1.2.3", "software_reporter_tool.exe")] = File.ReadAllBytes(fx.ProbeExe),
            [Path.Combine(androidRoot, "analytics.settings")] = Encoding.UTF8.GetBytes("{\"userId\":\"00000000-0000-0000-0000-000000000000\"}"),
            [Path.Combine(gcloudRoot, ".metricsUUID")] = Encoding.UTF8.GetBytes("11111111-1111-1111-1111-111111111111")
        };
        foreach (var (path, bytes) in files)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllBytes(path, bytes);
        }
        var hashes = files.ToDictionary(kv => kv.Key, kv => Convert.ToHexString(SHA256.HashData(kv.Value)));

        try
        {
            string[] markerIds = ["google.crashpad-reports", "google.chrome-swreporter", "google.android-analytics-id", "google.gcloud-metrics-id"];
            var found = await new MarkerScanner().ScanAsync().ConfigureAwait(false);
            foreach (var id in markerIds)
                c.Check($"the scanner finds {id}", found.Any(f => f.Definition.Id == id && f.Exists));
            c.Check("the scanner does not invent Chrome, Google Update or a FireEye agent on a clean machine",
                !found.Any(f => f.Exists && f.Definition.Id is "google.chrome-install" or "google.update-install" or "mandiant.endpoint-agent-files"));

            var service = new ProtectionService();
            var before = await MachineSnapshot.CaptureAsync(fx.ServiceNames, fx.TaskNames).ConfigureAwait(false);

            // A program holds one identifier open: that item fails safely and the rest still go.
            var heldPath = Path.Combine(androidRoot, "analytics.settings");
            var request = new PlanRequest { QuarantineMarkerIds = [.. markerIds, "google.chrome-local-state"] };
            var plan = await service.BuildPlanAsync(request).ConfigureAwait(false);
            c.Check("a report-only marker asked for is refused in the plan, not skipped silently",
                plan.Changes.Any(x => x.Engine == EngineKind.Quarantine && x.Outcome == ChangeOutcome.Refused));
            c.Check("the plan names every file or folder it would move",
                plan.Changes.Count(x => x.Engine == EngineKind.Quarantine && x.Outcome == ChangeOutcome.Applied) == 4);

            ChangePlan locked;
            using (new FileStream(heldPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                locked = await service.BuildPlanAsync(request).ConfigureAwait(false);
                await service.ApplyAsync(locked).ConfigureAwait(false);
            }
            var held = locked.Changes.Single(x => x.Target.Equals(heldPath, StringComparison.OrdinalIgnoreCase));
            c.Check("a file another program holds open fails safely and stays where it is",
                held.Outcome == ChangeOutcome.Failed && File.Exists(heldPath) && hashes[heldPath] == Hash(heldPath), held.Error ?? held.Outcome.ToString());
            c.Check("no journal entry or vault folder is left for the item that failed",
                service.Journal.Entries.All(e => !string.Equals(e.Target, heldPath, StringComparison.OrdinalIgnoreCase)));

            c.Check("the other three markers moved", !Directory.Exists(Path.Combine(chrome, "Crashpad", "reports"))
                && !Directory.Exists(Path.Combine(chrome, "SwReporter")) && !File.Exists(Path.Combine(gcloudRoot, ".metricsUUID")));

            // Release the file and apply again: now the last one goes.
            var again = await service.BuildPlanAsync(request).ConfigureAwait(false);
            await service.ApplyAsync(again).ConfigureAwait(false);
            c.Check("with the file released, the last marker moves too", !File.Exists(heldPath));

            var vault = service.Quarantine.List();
            c.Check("the vault holds four items with a manifest each", vault.Count == 4 && vault.All(m => m.Files.All(f => f.Sha256.Length == 64)),
                string.Join(", ", vault.Select(m => m.DefinitionId)));
            c.Check("the vault lives under ProgramData, not under the user's profile",
                service.Quarantine.VaultDirectory.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), StringComparison.OrdinalIgnoreCase));

            var errors = await service.RevertAllAsync().ConfigureAwait(false);
            c.Check("restore reports no errors", errors.Count == 0, string.Join("\n", errors));

            var wrong = files.Keys.Where(p => !File.Exists(p) || Hash(p) != hashes[p]).ToList();
            c.Check("every file is back, byte for byte", wrong.Count == 0, string.Join("\n", wrong));
            c.Check("the vault is empty again", service.Quarantine.List().Count == 0);

            var diff = MachineSnapshot.Diff(before, await MachineSnapshot.CaptureAsync(fx.ServiceNames, fx.TaskNames).ConfigureAwait(false));
            c.Check("the rest of the machine is exactly as it was", diff.Count == 0, string.Join("\n", diff));
        }
        finally
        {
            foreach (var root in created)
                try { Directory.Delete(root, recursive: true); } catch { /* the fixtures are ours to remove */ }
            foreach (var p in files.Keys.Where(File.Exists))
                try { File.Delete(p); } catch { }
        }

        static string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
    }

    // ---------------------------------------------------------------------------------------------

    private static async Task SecurityAgentGuard(ScenarioContext cx)
    {
        var c = cx.Checks;
        var fx = cx.Fixtures;
        SeedUserHostsEntries();
        var before = await MachineSnapshot.CaptureAsync(fx.ServiceNames, fx.TaskNames).ConfigureAwait(false);
        var hostsBefore = File.ReadAllBytes(AppPaths.HostsFile);

        var agentDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireEye");
        var existed = Directory.Exists(agentDir);
        Directory.CreateDirectory(Path.Combine(agentDir, "xagt"));
        File.WriteAllText(Path.Combine(agentDir, "xagt", "agent.log"), "pretend endpoint agent");

        try
        {
            var service = new ProtectionService();
            var request = new PlanRequest { EnabledRuleIds = [.. RuleCatalog.AgentSensitiveRuleIds] };

            var plan = await service.BuildPlanAsync(request).ConfigureAwait(false);
            c.Check("with an agent installed, the preflight raises a Blocker that names it",
                plan.Findings.Any(f => f.Level == FindingLevel.Blocker && f.Title.Contains("endpoint security agent", StringComparison.Ordinal)));
            c.Check("and the Mandiant services rule is refused", plan.Changes.All(x => x.Outcome == ChangeOutcome.Refused));
            await service.ApplyAsync(plan).ConfigureAwait(false);
            c.Check("nothing was written to the hosts file", File.ReadAllBytes(AppPaths.HostsFile).SequenceEqual(hostsBefore));

            var removal = await service.BuildPlanAsync(new PlanRequest { QuarantineMarkerIds = ["mandiant.endpoint-agent-files"] }).ConfigureAwait(false);
            await service.ApplyAsync(removal).ConfigureAwait(false);
            c.Check("a security agent's files cannot be quarantined", removal.Changes.Single().Outcome == ChangeOutcome.Refused && Directory.Exists(Path.Combine(agentDir, "xagt")),
                removal.Changes.Single().RefusalReason ?? "");

            Directory.Delete(agentDir, recursive: true);
            var clear = await service.BuildPlanAsync(request).ConfigureAwait(false);
            c.Check("with no agent installed, the same rule is not refused", clear.Changes.All(x => x.Outcome != ChangeOutcome.Refused)
                && !clear.Findings.Any(f => f.Level == FindingLevel.Blocker));
            await service.ApplyAsync(clear).ConfigureAwait(false);
            c.Check("and it blocks advantage.mandiant.com", File.ReadAllText(AppPaths.HostsFile).Contains("0.0.0.0 advantage.mandiant.com", StringComparison.Ordinal));

            c.Check("restore reports no errors", (await service.RevertAllAsync().ConfigureAwait(false)).Count == 0);
        }
        finally
        {
            if (!existed) try { Directory.Delete(agentDir, recursive: true); } catch { }
        }

        var diff = MachineSnapshot.Diff(before, await MachineSnapshot.CaptureAsync(fx.ServiceNames, fx.TaskNames).ConfigureAwait(false));
        c.Check("the machine is exactly as it was", diff.Count == 0, string.Join("\n", diff));
    }

    // ---------------------------------------------------------------------------------------------

    private static async Task ReportEndToEnd(ScenarioContext cx)
    {
        var c = cx.Checks;
        var fx = cx.Fixtures;
        SeedUserHostsEntries();
        var before = await MachineSnapshot.CaptureAsync(fx.ServiceNames, fx.TaskNames).ConfigureAwait(false);

        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var gcloud = Path.Combine(roaming, "gcloud");
        var createdGcloud = !Directory.Exists(gcloud);
        Directory.CreateDirectory(gcloud);
        File.WriteAllText(Path.Combine(gcloud, ".metricsUUID"), "22222222-2222-2222-2222-222222222222");

        var settings = new AppSettings
        {
            EnabledRuleIds = ["hosts.update-delivery", "hosts.chrome-telemetry", "svc.google-updater", "reg.chrome.telemetry"],
            LocalOnlyRuleIds = ["hosts.update-delivery", "svc.google-updater"],
            LocalOnlyApps = [fx.AppExe],
            QuarantineMarkerIds = ["google.gcloud-metrics-id"]
        };

        var service = new ProtectionService();
        try
        {
            var plan = await service.BuildPlanAsync(new PlanRequest
            {
                EnabledRuleIds = settings.EnabledRuleIds, LocalOnlyRuleIds = settings.LocalOnlyRuleIds,
                LocalOnlyApps = settings.LocalOnlyApps, QuarantineMarkerIds = settings.QuarantineMarkerIds
            }).ConfigureAwait(false);
            var applied = await service.ApplyAsync(plan).ConfigureAwait(false);
            c.Check("a mixed apply (block, local-only, app jail, quarantine) fails nothing", applied.Failed == 0,
                string.Join("\n", plan.Changes.Where(x => x.Outcome == ChangeOutcome.Failed).Select(x => $"{x.Description}: {x.Error}")));

            var report = await new ReportBuilder(service, "harness").BuildAsync(settings).ConfigureAwait(false);
            var saved = ReportWriter.Save(report, Path.Combine(cx.Options.OutDir, "reports"));
            var html = File.ReadAllText(saved.HtmlPath);
            var json = JsonDocument.Parse(File.ReadAllText(saved.JsonPath)).RootElement;
            c.Info($"report written to {saved.HtmlPath}");

            c.Check("the report passes its own verification", report.VerificationPassed == true,
                string.Join("\n", report.Verification.SelectMany(t => t.Checks.Where(k => !k.Passed).Select(k => $"{t.Label}: {k.Detail}"))));
            c.Check("it counts the confined programs and the quarantined item", report.Counts.LocalOnlyJails >= 1 && report.Counts.QuarantinedItems == 1,
                $"jails={report.Counts.LocalOnlyJails} quarantined={report.Counts.QuarantinedItems}");
            c.Check("it reads sinkholed and looped names from the live hosts file", report.Counts.SinkholedDomains > 0 && report.Counts.LoopbackDomains > 0,
                $"sinkholed={report.Counts.SinkholedDomains} looped={report.Counts.LoopbackDomains}");
            c.Check("it lists the firewall rules and shows the loopback jail as 'everything except loopback'",
                report.FirewallRules.Count >= 4 && report.FirewallRules.Any(f => f.RemoteSummary == "everything except loopback"));
            c.Check("the quarantined identifier is listed with its vault folder",
                report.Quarantined.Any(q => q.Title.Contains("Cloud CLI", StringComparison.Ordinal)));
            c.Check("the disabled-then-kept service is not reported as disabled (it was only confined)", report.Counts.DisabledServices == 0);
            c.Check("the HTML has no script and loads nothing", !html.Contains("<script", StringComparison.OrdinalIgnoreCase)
                && !html.Contains("href=", StringComparison.OrdinalIgnoreCase) && !html.Contains("src=", StringComparison.OrdinalIgnoreCase));
            c.Check("the home folder never appears in the report", !html.Replace("<wbr>", "").Contains(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), StringComparison.OrdinalIgnoreCase));
            c.Check("the JSON agrees with the HTML on the sinkholed count",
                json.GetProperty("Counts").GetProperty("SinkholedDomains").GetInt32() == report.Counts.SinkholedDomains
                && html.Contains($">{report.Counts.SinkholedDomains}<", StringComparison.Ordinal));
            c.Check("the recent activity records this apply", report.Activity.Any(e => e.Kind == "apply.done"));

            c.Check("restore reports no errors", (await service.RevertAllAsync().ConfigureAwait(false)).Count == 0);
        }
        finally
        {
            try { if (createdGcloud) Directory.Delete(gcloud, recursive: true); else File.Delete(Path.Combine(gcloud, ".metricsUUID")); } catch { }
        }

        var diff = MachineSnapshot.Diff(before, await MachineSnapshot.CaptureAsync(fx.ServiceNames, fx.TaskNames).ConfigureAwait(false));
        c.Check("the machine is exactly as it was", diff.Count == 0, string.Join("\n", diff));
    }

    // ---------------------------------------------------------------------------------------------

    private sealed record FirewallRow(string Name, string Direction, string Action, string Enabled, string Program, HashSet<string> Remote)
    {
        public override string ToString() => $"{Name} | {Direction} | {Action} | enabled={Enabled} | {Program} | {string.Join(",", Remote)}";
    }

    /// <summary>The Anti-Google firewall group, projected independently of the product's own read-back.</summary>
    private static async Task<List<FirewallRow>> ReadGroupAsync()
    {
        var res = await Tools.PsAsync(
            $"Get-NetFirewallRule -Group '{AppPaths.FirewallGroup}' -ErrorAction SilentlyContinue | ForEach-Object {{ " +
            "$a = $_ | Get-NetFirewallAddressFilter; $p = $_ | Get-NetFirewallApplicationFilter; " +
            "($_.DisplayName, $_.Direction, $_.Action, $_.Enabled, $p.Program, (@($a.RemoteAddress) -join ',')) -join '|' }").ConfigureAwait(false);

        var rows = new List<FirewallRow>();
        foreach (var line in res.StdOut.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var p = line.Split('|');
            if (p.Length != 6) continue;
            rows.Add(new FirewallRow(p[0], p[1], p[2], p[3], p[4],
                p[5].Split(',', StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim().ToLowerInvariant()).ToHashSet()));
        }
        return rows;
    }

    private static async Task<string> RunAsync(string exe, string arguments, int timeoutSeconds)
    {
        var psi = new ProcessStartInfo(exe, arguments) { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true };
        using var p = Process.Start(psi)!;
        var read = p.StandardOutput.ReadToEndAsync();
        if (!p.WaitForExit(timeoutSeconds * 1000))
        {
            try { p.Kill(); } catch { }
            return "TIMEOUT-KILLED";
        }
        return (await read.ConfigureAwait(false)).Trim().Replace("\r\n", " | ").Replace("\n", " | ");
    }
}
