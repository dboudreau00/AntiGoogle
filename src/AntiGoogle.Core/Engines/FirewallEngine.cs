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

using AntiGoogle.Core.Journal;
using AntiGoogle.Core.Model;
using AntiGoogle.Core.Platform;

namespace AntiGoogle.Core.Engines;

/// <summary>
/// Creates outbound block rules in Windows Defender Firewall.
///
/// Driven through the Net*Firewall cmdlets rather than netsh purely for -Group support: every rule
/// we create is tagged "Anti-Google", so a full cleanup is one command and cannot orphan rules even
/// if the journal is lost. That safety net matters more than avoiding a process spawn.
/// </summary>
public sealed class FirewallEngine : IRevertEngine
{
    public EngineKind Kind => EngineKind.Firewall;

    private readonly string _group;

    /// <param name="group">
    /// Firewall rule group every created rule is tagged with, and the target of
    /// <see cref="RemoveAllAsync"/>. Defaults to <see cref="AppPaths.FirewallGroup"/>. Tests MUST
    /// pass a distinct group: the revert sweep deletes the whole group, so a test running elevated
    /// against the default would wipe the user's real Anti-Google firewall rules.
    /// </param>
    public FirewallEngine(string? group = null) => _group = group ?? AppPaths.FirewallGroup;

    public static string RuleNameFor(string ruleId) => $"Anti-Google: {ruleId}";

    /// <summary>Names of every rule currently tagged as ours.</summary>
    public async Task<IReadOnlyList<string>> ExistingRulesAsync(CancellationToken ct = default)
    {
        var res = await ProcessRunner.PowerShellAsync(
            $"Get-NetFirewallRule -Group '{Escape(_group)}' -ErrorAction SilentlyContinue " +
            "| ForEach-Object { $_.DisplayName }", 60_000, ct).ConfigureAwait(false);

        return res.StdOut.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                         .Select(s => s.Trim())
                         .Where(s => s.Length > 0)
                         .ToList();
    }

    /// <summary>Blocks outbound traffic to a set of CIDR ranges, machine-wide.</summary>
    public Task<ChangeOutcome> ApplyRangeBlockAsync(
        BlockRule rule, ChangeJournal journal, CancellationToken ct)
        => CreateAsync(rule.Id, RuleNameFor(rule.Id),
            $"Anti-Google range block for {rule.Title}", rule.IpRanges, program: null, journal, ct);

    /// <summary>Blocks one executable from reaching the supplied ranges, leaving the rest of the machine alone.</summary>
    public Task<ChangeOutcome> ApplyProgramBlockAsync(
        string ruleId, string displayName, string programPath, IReadOnlyList<string> ranges,
        ChangeJournal journal, CancellationToken ct)
        => CreateAsync(ruleId, displayName,
            $"Anti-Google containment for {Path.GetFileName(programPath)}", ranges, programPath, journal, ct);

    private async Task<ChangeOutcome> CreateAsync(
        string ruleId, string displayName, string description,
        IReadOnlyList<string> ranges, string? program, ChangeJournal journal, CancellationToken ct)
    {
        if (ranges.Count == 0) return ChangeOutcome.NotPresent;

        if (await RuleExistsAsync(displayName, ct).ConfigureAwait(false))
            return ChangeOutcome.AlreadySatisfied;

        journal.Append(new JournalEntry
        {
            RuleId = ruleId,
            Engine = program is null ? EngineKind.Firewall : EngineKind.AppContainment,
            Description = program is null
                ? $"Created firewall rule '{displayName}' ({ranges.Count} ranges)"
                : $"Contained {Path.GetFileName(program)} ({ranges.Count} ranges)",
            Reverse = ReverseKind.RemoveFirewallRule,
            FirewallRuleName = displayName
        });

        var addressList = string.Join(",", ranges.Select(r => $"'{Escape(r)}'"));
        var cmd =
            $"New-NetFirewallRule -DisplayName '{Escape(displayName)}' " +
            $"-Group '{Escape(_group)}' " +
            $"-Description '{Escape(description)}' " +
            "-Direction Outbound -Action Block -Enabled True -Profile Any " +
            $"-RemoteAddress @({addressList}) ";

        if (program is not null)
            cmd += $"-Program '{Escape(program)}' ";

        cmd += "-ErrorAction Stop | Out-Null";

        var res = await ProcessRunner.PowerShellAsync(cmd, 90_000, ct).ConfigureAwait(false);
        if (!res.Ok)
            throw new InvalidOperationException($"Creating firewall rule '{displayName}' failed: {res.Combined}");

        Log.Info($"Firewall: created '{displayName}' ({ranges.Count} ranges{(program is null ? "" : $", program {program}")}).");
        return ChangeOutcome.Applied;
    }

    public async Task RevertAsync(JournalEntry entry, CancellationToken ct = default)
    {
        if (entry.FirewallRuleName is null) return;

        var res = await ProcessRunner.PowerShellAsync(
            $"Remove-NetFirewallRule -DisplayName '{Escape(entry.FirewallRuleName)}' -ErrorAction SilentlyContinue",
            60_000, ct).ConfigureAwait(false);

        if (!res.Ok) Log.Warn($"Removing firewall rule '{entry.FirewallRuleName}': {res.Combined}");
        else Log.Info($"Firewall: removed '{entry.FirewallRuleName}'.");
    }

    /// <summary>
    /// Last-resort cleanup. Removes every rule in our group regardless of what the journal knows,
    /// so a lost or corrupted journal can never strand firewall rules on the machine.
    /// </summary>
    public async Task RemoveAllAsync(CancellationToken ct = default)
    {
        var res = await ProcessRunner.PowerShellAsync(
            $"Remove-NetFirewallRule -Group '{Escape(_group)}' -ErrorAction SilentlyContinue",
            120_000, ct).ConfigureAwait(false);
        Log.Info($"Firewall: group sweep completed (exit {res.ExitCode}).");
    }

    private static async Task<bool> RuleExistsAsync(string displayName, CancellationToken ct)
    {
        var res = await ProcessRunner.PowerShellAsync(
            $"if (Get-NetFirewallRule -DisplayName '{Escape(displayName)}' -ErrorAction SilentlyContinue) " +
            "{ 'YES' } else { 'NO' }", 45_000, ct).ConfigureAwait(false);
        return res.StdOut.Contains("YES", StringComparison.Ordinal);
    }

    private static string Escape(string s) => s.Replace("'", "''");
}
