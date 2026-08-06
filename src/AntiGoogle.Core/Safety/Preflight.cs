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

using System.Net.NetworkInformation;
using AntiGoogle.Core.Catalog;
using AntiGoogle.Core.Model;
using AntiGoogle.Core.Platform;
using Microsoft.Win32;

namespace AntiGoogle.Core.Safety;

public enum FindingLevel
{
    Info,
    Warning,
    /// <summary>Hard stop for the rules it names — those changes will be refused, not attempted.</summary>
    Blocker
}

/// <param name="BlockedRuleIds">Rules this finding refuses. Empty means it is advisory only.</param>
public sealed record PreflightFinding(
    FindingLevel Level,
    string Title,
    string Detail,
    IReadOnlyList<string> BlockedRuleIds)
{
    public static PreflightFinding Info(string title, string detail) => new(FindingLevel.Info, title, detail, []);
    public static PreflightFinding Warn(string title, string detail) => new(FindingLevel.Warning, title, detail, []);
    public static PreflightFinding Block(string title, string detail, params string[] ruleIds) =>
        new(FindingLevel.Blocker, title, detail, ruleIds);
}

/// <summary>
/// Runs before any plan is executed. The job here is to catch the configurations where a rule
/// that is merely inconvenient on a normal machine would be catastrophic on THIS machine —
/// above all, blocking the resolver the machine actually depends on.
/// </summary>
public static class Preflight
{
    public static async Task<List<PreflightFinding>> RunAsync(CancellationToken ct = default)
    {
        var findings = new List<PreflightFinding>();

        CheckElevation(findings);
        CheckGoogleDnsResolvers(findings);
        CheckHostsFile(findings);
        CheckExistingPolicies(findings);
        CheckDomainJoin(findings);
        await CheckFirewallServiceAsync(findings, ct).ConfigureAwait(false);

        return findings;
    }

    private static void CheckElevation(List<PreflightFinding> findings)
    {
        if (!Elevation.IsElevated)
        {
            findings.Add(PreflightFinding.Block(
                "Administrator rights required",
                "Anti-Google is running unelevated. Scanning and previewing work fine, but writing to the " +
                "hosts file, services, scheduled tasks, the firewall and HKLM all need administrator rights. " +
                "Use 'Restart as Administrator' before applying.",
                RuleCatalog.All.Select(r => r.Id).ToArray()));
        }
    }

    /// <summary>
    /// The single most dangerous interaction in this app: if the machine resolves DNS through
    /// 8.8.8.8, blocking Google's ranges removes name resolution entirely and the user is offline
    /// with no obvious cause. Refuse rather than warn.
    /// </summary>
    private static void CheckGoogleDnsResolvers(List<PreflightFinding> findings)
    {
        var googleResolvers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"
        };

        var hits = new List<string>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                foreach (var dns in nic.GetIPProperties().DnsAddresses)
                {
                    var s = dns.ToString();
                    if (googleResolvers.Contains(s)) hits.Add($"{nic.Name} → {s}");
                }
            }
        }
        catch (Exception ex)
        {
            Log.Warn($"DNS resolver probe failed: {ex.Message}");
            findings.Add(PreflightFinding.Warn(
                "Could not read this machine's DNS servers",
                "Anti-Google normally refuses to block Google Public DNS when it is your resolver. " +
                "That check could not run, so verify manually before arming the DNS firewall rule."));
            return;
        }

        if (hits.Count > 0)
        {
            findings.Add(PreflightFinding.Block(
                "This machine resolves DNS through Google Public DNS",
                $"Found: {string.Join(", ", hits)}. Blocking 8.8.8.8/8.8.4.4 would take away name " +
                "resolution for the whole machine — every app, not just Google's. That rule is refused. " +
                "Point your adapter at a different resolver first if you want it.",
                "fw.google-dns", "fw.google-ranges"));
        }
        else
        {
            findings.Add(PreflightFinding.Info(
                "DNS resolvers are not Google",
                "Safe to block Google Public DNS. Note this check cannot see a resolver configured on " +
                "your router — if the router forwards to 8.8.8.8, blocking it can still hurt."));
        }
    }

    private static void CheckHostsFile(List<PreflightFinding> findings)
    {
        try
        {
            if (!File.Exists(AppPaths.HostsFile))
            {
                findings.Add(PreflightFinding.Block(
                    "Hosts file not found",
                    $"Expected at {AppPaths.HostsFile}. All hosts-based rules are refused.",
                    RuleCatalog.All.Where(r => r.Engine == EngineKind.Hosts).Select(r => r.Id).ToArray()));
                return;
            }

            var info = new FileInfo(AppPaths.HostsFile);
            if (info.IsReadOnly)
            {
                findings.Add(PreflightFinding.Block(
                    "Hosts file is read-only",
                    "Some security suites lock the hosts file to stop malware editing it. Clear the " +
                    "read-only attribute, or add an exclusion, before hosts rules can apply.",
                    RuleCatalog.All.Where(r => r.Engine == EngineKind.Hosts).Select(r => r.Id).ToArray()));
                return;
            }

            var text = File.ReadAllText(AppPaths.HostsFile);
            var lines = text.Split('\n').Count(l => !string.IsNullOrWhiteSpace(l) && !l.TrimStart().StartsWith('#'));

            if (text.Contains(AppPaths.HostsBeginMarker, StringComparison.Ordinal))
            {
                findings.Add(PreflightFinding.Info(
                    "An Anti-Google block already exists in the hosts file",
                    "It will be replaced wholesale, not appended to. Your own entries outside the markers are untouched."));
            }
            else if (lines > 0)
            {
                findings.Add(PreflightFinding.Info(
                    $"Hosts file already has {lines} active entries",
                    "Anti-Google only ever writes between its own markers and backs the file up first, " +
                    "so existing entries survive both apply and revert."));
            }
        }
        catch (Exception ex)
        {
            findings.Add(PreflightFinding.Warn("Could not inspect the hosts file", ex.Message));
        }
    }

    /// <summary>
    /// If a real employer already manages Chrome by policy, our writes would silently override
    /// theirs and revert would hand control back in a way IT did not expect. Warn loudly.
    /// </summary>
    private static void CheckExistingPolicies(List<PreflightFinding> findings)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Google\Chrome");
            if (key is null) return;

            var existing = key.GetValueNames().Length;
            if (existing > 0)
            {
                findings.Add(PreflightFinding.Warn(
                    $"Chrome already has {existing} policy values set",
                    "Something else — an employer's MDM, or a previous privacy tool — is already managing " +
                    "Chrome on this machine. Anti-Google records each original value before overwriting it, " +
                    "so revert restores them. But if this is a work machine, changing managed policy may " +
                    "violate your IT rules. Check before applying."));
            }
        }
        catch (Exception ex)
        {
            Log.Warn($"Policy probe failed: {ex.Message}");
        }
    }

    private static void CheckDomainJoin(List<PreflightFinding> findings)
    {
        try
        {
            var domain = IPGlobalProperties.GetIPGlobalProperties().DomainName;
            if (!string.IsNullOrWhiteSpace(domain))
            {
                findings.Add(PreflightFinding.Warn(
                    $"This machine appears to be on a domain ({domain})",
                    "Group Policy may reapply or fight the values Anti-Google writes, and your IT department " +
                    "may treat these changes as tampering. On a managed work machine, do not apply without approval."));
            }
        }
        catch { /* not fatal */ }
    }

    private static async Task CheckFirewallServiceAsync(List<PreflightFinding> findings, CancellationToken ct)
    {
        try
        {
            var res = await ProcessRunner.RunAsync("sc.exe", ["query", "MpsSvc"], 15_000, ct).ConfigureAwait(false);
            if (!res.StdOut.Contains("RUNNING", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(PreflightFinding.Block(
                    "Windows Firewall service is not running",
                    "The Windows Defender Firewall service (MpsSvc) is stopped, so firewall rules cannot be " +
                    "created. Firewall and per-app containment rules are refused.",
                    RuleCatalog.All
                        .Where(r => r.Engine is EngineKind.Firewall or EngineKind.AppContainment)
                        .Select(r => r.Id).ToArray()));
            }
        }
        catch (Exception ex)
        {
            findings.Add(PreflightFinding.Warn("Could not query the Windows Firewall service", ex.Message));
        }
    }
}
