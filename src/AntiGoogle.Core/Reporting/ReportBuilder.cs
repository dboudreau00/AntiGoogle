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
using AntiGoogle.Core.Markers;
using AntiGoogle.Core.Model;
using AntiGoogle.Core.Safety;
using AntiGoogle.Core.Verification;
using Microsoft.Win32;

namespace AntiGoogle.Core.Reporting;

/// <summary>
/// Gathers the report. What is on the machine is read back from the machine (the hosts file, Windows
/// Firewall, the service and registry values themselves), not copied from the journal, so a report that
/// says a change is in place has looked. The journal supplies only what it alone knows: the value a
/// change replaced, and when.
/// </summary>
public sealed class ReportBuilder(
    ProtectionService service, string appVersion, MarkerScanner? scanner = null,
    Func<CancellationToken, Task<List<PreflightFinding>>>? preflight = null)
{
    private const int ActivityEvents = 60;

    public async Task<ProtectionReport> BuildAsync(
        AppSettings settings, bool verify = true, bool scanMarkers = true, CancellationToken ct = default)
    {
        var status = await service.GetStatusAsync(ct).ConfigureAwait(false);
        var report = new ProtectionReport
        {
            GeneratedAt = DateTimeOffset.Now,
            AppVersion = appVersion,
            OsVersion = Environment.OSVersion.VersionString,
            Elevated = status.Elevated,
            Profile = settings.Profile.ToString()
        };

        var audit = service.Hosts.Audit();
        var firewallRules = await ReadFirewallAsync(ct).ConfigureAwait(false);
        var held = service.Quarantine.List();

        ArmedRules(report, settings);
        report.LocalOnlyApps = settings.LocalOnlyApps.Select(Redact).ToList();
        report.ContainedApps = settings.ContainedApps.Where(a => !settings.LocalOnlyApps.Contains(a, StringComparer.OrdinalIgnoreCase))
                                                    .Select(Redact).ToList();

        report.Hosts = new ReportHosts
        {
            Groups = audit.Groups.Select(g => new ReportHostsGroup(g.RuleId, g.Title, g.LocalOnly ? "Local-only" : "Blocked", [.. g.Domains])).ToList(),
            IncompleteNames = [.. audit.Incomplete]
        };
        report.FirewallRules = firewallRules;
        await JournalSectionsAsync(report, ct).ConfigureAwait(false);

        report.Quarantined = held.Select(m => new ReportQuarantined(
            m.Title, m.Vendor, Redact(m.OriginalPath), m.Kind.ToString(), m.FileCount, m.TotalBytes,
            m.CreatedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm"), m.Id)).ToList();

        if (scanMarkers) await ScanMarkersAsync(report, ct).ConfigureAwait(false);

        if (verify)
        {
            var result = await new LoopbackVerifier(service.Firewall, service.Hosts, service.Journal).VerifyAsync(ct).ConfigureAwait(false);
            if (result.AnythingToVerify)
            {
                report.VerificationPassed = result.Passed;
                report.Verification = result.Targets.Select(t => new ReportTargetCheck(
                    t.Label, t.ProgramPath is not null ? Redact(t.ProgramPath) : $"service {t.ServiceName}",
                    t.Checks.Select(c => new ReportCheck(c.Name, c.Passed, c.Detail)).ToList(),
                    t.Connections.Select(Redact).ToList())).ToList();
                if (result.Hosts.Count > 0)
                    report.Verification.Add(new ReportTargetCheck("hosts file", "names resolved to this machine",
                        result.Hosts.Select(c => new ReportCheck(c.Name, c.Passed, c.Detail)).ToList(), []));
            }
        }

        try
        {
            var findings = await (preflight ?? Safety.Preflight.RunAsync)(ct).ConfigureAwait(false);
            report.Findings = findings.Select(f => new ReportFinding(f.Level.ToString(), f.Title, f.Detail)).ToList();
        }
        catch (Exception ex) { Log.Warn($"Report: preflight failed: {ex.Message}"); }

        report.Activity = service.Audit.Tail(ActivityEvents).Select(e => new ReportEvent(
            e.At.ToString("yyyy-MM-dd HH:mm:ss"), e.Kind, e.RuleId ?? "", e.Engine ?? "",
            Redact(e.Target ?? ""), e.Outcome ?? "", Redact(e.Detail ?? ""))).ToList();

        report.Counts = new ReportCounts
        {
            SinkholedDomains = audit.Sinkholed.Count,
            LoopbackDomains = audit.Looped.Count,
            FirewallRules = firewallRules.Count,
            LocalOnlyJails = status.LocalOnlyJails,
            DisabledServices = report.Services.Count(s => s.Now.StartsWith("Disabled", StringComparison.Ordinal)),
            DisabledTasks = report.Tasks.Count(t => t.Now == "Disabled"),
            RegistryValues = report.Registry.Count,
            QuarantinedItems = held.Count,
            UndoableChanges = service.Journal.Entries.Count
        };

        report.Limits = Limits(report, status.Elevated);
        return report;
    }

    // ------------------------------------------------------------------ pieces

    private void ArmedRules(ProtectionReport report, AppSettings settings)
    {
        var armed = settings.EnabledRuleIds.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var localOnly = settings.LocalOnlyRuleIds.ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var rule in RuleCatalog.All.Where(r => armed.Contains(r.Id)).OrderBy(r => r.Category).ThenBy(r => r.Id, StringComparer.Ordinal))
        {
            var mode = rule.SupportsLocalOnly && localOnly.Contains(rule.Id) ? RuleMode.LocalOnly : RuleMode.Block;
            var costs = rule.BreaksFor(mode);
            report.ArmedRules.Add(new ReportRule(
                rule.Id, rule.Title, rule.Vendor ?? "Google", mode == RuleMode.LocalOnly ? "Local-only" : "Blocked",
                Layer(rule.Engine), rule.Tier.ToString(),
                costs.Count == 0 ? "None" : costs.Max(b => b.Severity).ToString(),
                costs.OrderByDescending(b => b.Severity).Select(b => new ReportCost(b.What, b.Severity.ToString(), b.Detail)).ToList()));
        }
    }

    private static string Layer(EngineKind engine) => engine switch
    {
        EngineKind.Hosts => "Hosts file",
        EngineKind.Firewall => "Firewall",
        EngineKind.Service => "Service",
        EngineKind.ScheduledTask => "Scheduled task",
        EngineKind.Registry => "Registry policy",
        EngineKind.AppContainment => "Containment",
        EngineKind.LocalOnly => "Local-only",
        EngineKind.Quarantine => "Quarantine",
        _ => engine.ToString()
    };

    private async Task<List<ReportFirewallRule>> ReadFirewallAsync(CancellationToken ct)
    {
        try
        {
            var rules = await service.Firewall.ListRulesAsync(ct).ConfigureAwait(false);
            return rules.OrderBy(r => r.DisplayName, StringComparer.OrdinalIgnoreCase).Select(r => new ReportFirewallRule(
                r.DisplayName, r.Direction, r.Action, r.Enabled,
                r.Program is not null ? Redact(r.Program) : r.Service is not null ? $"service {r.Service}" : "any program",
                r.RemoteAddresses.Count, Summarise(r.RemoteAddresses))).ToList();
        }
        catch (Exception ex)
        {
            Log.Warn($"Report: firewall rules unreadable: {ex.Message}");
            return [];
        }
    }

    private static string Summarise(IReadOnlyList<string> ranges)
    {
        if (ranges.Count == 0) return "any";
        var set = ranges.Select(r => r.Trim()).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (set.SetEquals(LoopbackRanges.NonLoopback)) return "everything except loopback";
        return ranges.Count <= 3 ? string.Join(", ", ranges) : $"{ranges.Count} ranges";
    }

    private async Task JournalSectionsAsync(ProtectionReport report, CancellationToken ct)
    {
        var services = new ServiceEngine();
        foreach (var e in service.Journal.Entries.OrderBy(e => e.At))
        {
            switch (e.Reverse)
            {
                case ReverseKind.RestoreServiceStartType when e.ServiceName is not null:
                {
                    var now = services.Resolve([e.ServiceName]).Select(s => (int?)s.StartType).FirstOrDefault();
                    report.Services.Add(new ReportService(e.ServiceName,
                        StartName(e.PreviousStartType, e.PreviousDelayedAutostart) + (e.PreviousServiceRunning == true ? ", running" : ""),
                        now is null ? "no longer installed" : StartName(now, null), e.RuleId, e.At));
                    break;
                }
                case ReverseKind.RestoreScheduledTask when e.TaskPath is not null:
                    report.Tasks.Add(new ReportTask(e.TaskPath, e.TaskWasEnabled == true ? "Enabled" : "Disabled", await TaskNowAsync(e.TaskPath, ct).ConfigureAwait(false), e.RuleId, e.At));
                    break;
                case ReverseKind.RestoreRegistryValue when e.RegistryKey is not null && e.RegistryName is not null:
                    report.Registry.Add(new ReportRegistryValue(
                        $"{(e.RegistryHive == RegistryHive2.LocalMachine ? "HKLM" : "HKCU")}\\{e.RegistryKey}\\{e.RegistryName}",
                        e.PreviousValue is null ? "(did not exist)" : e.PreviousValue, RegistryNow(e), e.RuleId, e.At));
                    break;
            }
        }
    }

    private static string StartName(int? start, bool? delayed) => start switch
    {
        0 => "Boot", 1 => "System", 2 => delayed == true ? "Automatic (delayed)" : "Automatic",
        3 => "Manual", 4 => "Disabled", _ => "unknown"
    };

    private static async Task<string> TaskNowAsync(string path, CancellationToken ct)
    {
        // A read-only look; a task that cannot be read says so rather than claiming a state.
        try
        {
            var (folder, name) = (path[..(path.LastIndexOf('\\') + 1)], path[(path.LastIndexOf('\\') + 1)..]);
            var res = await Platform.ProcessRunner.PowerShellAsync(
                $"(Get-ScheduledTask -TaskPath '{folder.Replace("'", "''")}' -TaskName '{name.Replace("'", "''")}' -ErrorAction SilentlyContinue).State",
                30_000, ct).ConfigureAwait(false);
            var state = res.StdOut.Trim();
            return state.Length == 0 ? "no longer present" : state;
        }
        catch { return "unreadable"; }
    }

    private static string RegistryNow(JournalEntry e)
    {
        try
        {
            using var root = RegistryKey.OpenBaseKey(
                e.RegistryHive == RegistryHive2.LocalMachine ? RegistryHive.LocalMachine : RegistryHive.CurrentUser, RegistryView.Registry64);
            using var key = root.OpenSubKey(e.RegistryKey!);
            var value = key?.GetValue(e.RegistryName!);
            return value is null ? "(not set)" : value.ToString() ?? "";
        }
        catch { return "unreadable"; }
    }

    private async Task ScanMarkersAsync(ProtectionReport report, CancellationToken ct)
    {
        try
        {
            var findings = await (scanner ?? new MarkerScanner()).ScanAsync(null, ct).ConfigureAwait(false);
            foreach (var f in findings.Where(f => f.Exists))
                report.Markers.Add(new ReportMarker(
                    f.Definition.Id, f.Definition.Vendor, f.Definition.Title, f.Definition.Class.ToString(),
                    f.Definition.CanQuarantine ? "Can be quarantined" : "Reported only", f.Definition.Confidence.ToString(),
                    Redact(f.Location), f.SizeLabel, f.Note ?? "", f.Definition.Why));
            report.MarkersNotFound = findings.Count(f => !f.Exists);
        }
        catch (Exception ex) { Log.Warn($"Report: marker scan failed: {ex.Message}"); }
    }

    private static List<string> Limits(ProtectionReport report, bool elevated)
    {
        var limits = new List<string>
        {
            "This reduces Google's reach. It does not make the machine anonymous.",
            "The hosts file matches one exact name. A name it does not list is not covered, and software that carries its own DNS resolver ignores the hosts file.",
            "A name lookup is made by Windows on a program's behalf, so a per-program firewall rule cannot stop the lookup, only the connection that follows.",
            "Marker locations marked Medium or Low confidence were not confirmed against a live installation.",
            "Everything above was read back from this machine at the time shown. It says nothing about changes made after that."
        };
        if (!elevated)
            limits.Add("The app was not running as administrator, so this report describes the machine but could not have changed it.");
        if (report.VerificationPassed is null && report.LocalOnlyApps.Count + report.ArmedRules.Count(r => r.Mode == "Local-only") > 0)
            limits.Add("Local-only mode is armed but has not been applied, so there was nothing to verify.");
        return limits;
    }

    // ------------------------------------------------------------------ privacy

    /// <summary>Paths are shown with the user's profile folder replaced, so a shared report does not carry the account name.</summary>
    internal static string Redact(string text)
    {
        if (string.IsNullOrEmpty(text)) return text;
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return string.IsNullOrEmpty(profile) ? text : text.Replace(profile, "%USERPROFILE%", StringComparison.OrdinalIgnoreCase);
    }
}
