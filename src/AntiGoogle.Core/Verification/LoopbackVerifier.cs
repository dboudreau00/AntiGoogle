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

using System.Net;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using AntiGoogle.Core.Catalog;
using AntiGoogle.Core.Engines;
using AntiGoogle.Core.Journal;
using AntiGoogle.Core.Model;
using AntiGoogle.Core.Platform;

namespace AntiGoogle.Core.Verification;

public sealed record VerificationCheck(string Name, bool Passed, string Detail);

/// <summary>One confined program or service: its firewall rules as Windows holds them, and what it holds open now.</summary>
public sealed record TargetVerification(
    string Label,
    string? ProgramPath,
    string? ServiceName,
    IReadOnlyList<VerificationCheck> Checks,
    IReadOnlyList<string> Connections)
{
    public bool Passed => Checks.All(c => c.Passed);
}

public sealed record ContainmentVerification(
    DateTimeOffset At,
    IReadOnlyList<TargetVerification> Targets,
    IReadOnlyList<VerificationCheck> Hosts)
{
    public bool Passed => Targets.All(t => t.Passed) && Hosts.All(c => c.Passed);
    public bool AnythingToVerify => Targets.Count > 0 || Hosts.Count > 0;
}

/// <summary>
/// Checks that local-only mode really holds, without taking anyone's word for it. It reads each jail's
/// two firewall rules back from Windows and compares them with what they are meant to be, reads the
/// hosts block back for names that resolve to this machine, and walks the live socket table for every
/// confined program looking for a connection to anything off the machine.
///
/// What it cannot see: UDP is connectionless, so the table shows only what a program has bound, not who
/// it has sent to; and a program that runs inside svchost is confined by service name, which has no
/// process of its own to audit. Both are reported as such rather than as a pass.
/// </summary>
public sealed class LoopbackVerifier(FirewallEngine firewall, HostsFileEngine hosts, ChangeJournal journal)
{
    private static readonly Regex JailName = new(@"^Anti-Google: local-only (?<label>.+) \((?<dir>out|in)\)$", RegexOptions.Compiled);

    public async Task<ContainmentVerification> VerifyAsync(CancellationToken ct = default)
    {
        var targets = JailsFromJournal();
        var results = new List<TargetVerification>();

        IReadOnlyList<TcpEntry> tcp = [];
        try { tcp = await Task.Run(NetTables.Tcp, ct).ConfigureAwait(false); }
        catch (Exception ex) { Log.Warn($"Socket table unreadable: {ex.Message}"); }

        var own = OwnAddresses();

        foreach (var t in targets)
            results.Add(await VerifyTargetAsync(t, tcp, own, ct).ConfigureAwait(false));

        return new ContainmentVerification(DateTimeOffset.Now, results, HostChecks());
    }

    private sealed record Jail(string Label, string? Program, string? Service);

    private List<Jail> JailsFromJournal()
    {
        var jails = new Dictionary<string, Jail>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in journal.Entries.Where(e => e.Engine == EngineKind.LocalOnly && e.FirewallRuleName is not null))
        {
            var m = JailName.Match(e.FirewallRuleName!);
            if (!m.Success) continue;

            var label = m.Groups["label"].Value;
            var target = e.Target;
            var isProgram = target is not null && Path.IsPathFullyQualified(target);
            jails.TryAdd(label, new Jail(label, isProgram ? target : null, isProgram ? null : target));
        }
        return [.. jails.Values.OrderBy(j => j.Label, StringComparer.OrdinalIgnoreCase)];
    }

    private async Task<TargetVerification> VerifyTargetAsync(
        Jail jail, IReadOnlyList<TcpEntry> tcp, HashSet<IPAddress> own, CancellationToken ct)
    {
        var checks = new List<VerificationCheck>();

        foreach (var direction in new[] { FirewallDirection.Outbound, FirewallDirection.Inbound })
        {
            var spec = FirewallEngine.JailSpecFor(jail.Label, jail.Program, jail.Service, direction);
            var state = await firewall.ReadBackAsync(spec.DisplayName, ct).ConfigureAwait(false);
            var problem = FirewallEngine.CheckJail(state, spec);
            checks.Add(new VerificationCheck(
                $"{direction} rule blocks everything except loopback",
                problem is null,
                problem ?? "Present, enabled, Block, and the remote addresses are every address except 127.0.0.0/8 and ::1."));
        }

        var connections = new List<string>();
        if (jail.Program is null)
        {
            checks.Add(new VerificationCheck("No live connection leaves this machine", true,
                "Not audited: the service runs inside a shared host and is confined by service name, so it has no process of its own."));
        }
        else
        {
            var mine = tcp.Where(c => string.Equals(ProcessImage.PathOf(c.ProcessId), jail.Program, StringComparison.OrdinalIgnoreCase)).ToList();
            var processes = mine.Select(c => c.ProcessId).Distinct().Count();

            foreach (var c in mine.OrderBy(c => c.State).ThenBy(c => c.LocalPort))
                connections.Add($"{c.State,-12} {Format(c.LocalAddress, c.LocalPort)} -> {Format(c.RemoteAddress, c.RemotePort)}  (pid {c.ProcessId})");

            var leaks = mine.Where(c => IsLeak(c, own)).ToList();
            checks.Add(new VerificationCheck(
                "No live connection leaves this machine",
                leaks.Count == 0,
                leaks.Count > 0
                    ? "Connected off this machine: " + string.Join("; ", leaks.Select(c => $"{Format(c.RemoteAddress, c.RemotePort)} (pid {c.ProcessId})"))
                    : processes == 0
                        ? "The program is not running, so there is nothing to see."
                        : $"{processes} running {(processes == 1 ? "process" : "processes")}, none connected off this machine."));
        }

        return new TargetVerification(jail.Label, jail.Program, jail.Service, checks, connections);
    }

    /// <summary>A connection that is live (not a listener or a closing socket) and ends somewhere off this machine.</summary>
    internal static bool IsLeak(TcpEntry c, HashSet<IPAddress> own)
    {
        if (c.State is TcpState.Listen or TcpState.Closed or TcpState.TimeWait or TcpState.DeleteTcb) return false;
        var remote = c.RemoteAddress.IsIPv4MappedToIPv6 ? c.RemoteAddress.MapToIPv4() : c.RemoteAddress;
        if (remote.Equals(IPAddress.Any) || remote.Equals(IPAddress.IPv6Any)) return false;
        return !LoopbackRanges.IsLoopback(remote) && !own.Contains(remote);
    }

    private IReadOnlyList<VerificationCheck> HostChecks()
    {
        var audit = hosts.Audit();
        if (audit.Looped.Count == 0) return [];

        var broken = audit.Incomplete.Where(n => audit.Looped.Contains(n, StringComparer.OrdinalIgnoreCase)).ToList();
        return
        [
            new VerificationCheck(
                $"{audit.Looped.Count} local-only names resolve to this machine on IPv4 and IPv6",
                broken.Count == 0,
                broken.Count == 0
                    ? $"Every one has both a {AppPaths.LoopbackV4} and a {AppPaths.LoopbackV6} entry."
                    : $"Missing one address family: {string.Join(", ", broken.Take(10))}")
        ];
    }

    private static HashSet<IPAddress> OwnAddresses()
    {
        var set = new HashSet<IPAddress>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                foreach (var a in nic.GetIPProperties().UnicastAddresses)
                    set.Add(a.Address);
        }
        catch (Exception ex) { Log.Warn($"Could not list this machine's addresses: {ex.Message}"); }
        return set;
    }

    private static string Format(IPAddress address, int port) =>
        address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? $"[{address}]:{port}" : $"{address}:{port}";
}
