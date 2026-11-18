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

using System.Text.Json;
using System.Text.RegularExpressions;
using AntiGoogle.Core.Catalog;
using AntiGoogle.Core.Journal;
using AntiGoogle.Core.Model;
using AntiGoogle.Core.Platform;

namespace AntiGoogle.Core.Engines;

public enum FirewallDirection
{
    Outbound,
    Inbound
}

/// <summary>Everything needed to create one rule. Pure data, so the command built from it is testable.</summary>
public sealed record FirewallRuleSpec(
    string RuleId,
    string DisplayName,
    string Description,
    FirewallDirection Direction,
    IReadOnlyList<string> RemoteAddresses,
    string? ProgramPath = null,
    string? ServiceName = null,
    EngineKind JournalEngine = EngineKind.Firewall,
    string? JournalDescription = null);

/// <summary>What a rule actually looks like in Windows, read back after it was created.</summary>
public sealed record FirewallRuleState(
    string DisplayName,
    bool Enabled,
    string Direction,
    string Action,
    string? Group,
    string? Program,
    string? Service,
    IReadOnlyList<string> RemoteAddresses);

/// <summary>
/// Creates block rules in Windows Defender Firewall.
///
/// Driven through the Net*Firewall cmdlets rather than netsh purely for -Group support: every rule
/// we create is tagged "Anti-Google", so a full cleanup is one command and cannot orphan rules even
/// if the journal is lost. That safety net matters more than avoiding a process spawn.
/// </summary>
public class FirewallEngine : IRevertEngine
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

    public string Group => _group;

    public static string RuleNameFor(string ruleId) => $"Anti-Google: {ruleId}";

    /// <summary>The two names of a local-only jail: what it blocks leaving, and what it blocks arriving.</summary>
    public static string JailRuleName(string label, FirewallDirection direction) =>
        $"Anti-Google: local-only {label} ({(direction == FirewallDirection.Outbound ? "out" : "in")})";

    /// <summary>Names of every rule currently tagged as ours.</summary>
    public virtual async Task<IReadOnlyList<string>> ExistingRulesAsync(CancellationToken ct = default)
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
        => CreateAsync(new FirewallRuleSpec(
            rule.Id, RuleNameFor(rule.Id), $"Anti-Google range block for {rule.Title}",
            FirewallDirection.Outbound, rule.IpRanges,
            JournalDescription: $"Created firewall rule '{RuleNameFor(rule.Id)}' ({rule.IpRanges.Count} ranges)"),
            journal, ct);

    /// <summary>Blocks one executable from reaching the supplied ranges, leaving the rest of the machine alone.</summary>
    public virtual Task<ChangeOutcome> ApplyProgramBlockAsync(
        string ruleId, string displayName, string programPath, IReadOnlyList<string> ranges,
        ChangeJournal journal, CancellationToken ct)
        => CreateAsync(new FirewallRuleSpec(
            ruleId, displayName, $"Anti-Google containment for {Path.GetFileName(programPath)}",
            FirewallDirection.Outbound, ranges, ProgramPath: programPath,
            JournalEngine: EngineKind.AppContainment,
            JournalDescription: $"Contained {Path.GetFileName(programPath)} ({ranges.Count} ranges)"),
            journal, ct);

    /// <summary>
    /// Confines one program (or one service) to this machine: outbound AND inbound traffic to any
    /// address except loopback is blocked, so it keeps running and keeps talking to localhost, and to
    /// nothing else. Two rules, each journalled before it is created, each read back afterwards —
    /// a jail that quietly came out wrong is worse than no jail.
    /// </summary>
    /// <param name="label">Short stable name used in the rule names, e.g. "gupdate" or "app.chrome".</param>
    public virtual async Task<ChangeOutcome> ApplyLoopbackJailAsync(
        string ruleId, string label, string? programPath, string? serviceName,
        ChangeJournal journal, CancellationToken ct)
    {
        ValidateJailTarget(programPath, serviceName);

        var shown = programPath is not null ? Path.GetFileName(programPath) : serviceName!;
        var specs = new[]
        {
            JailSpec(ruleId, label, shown, programPath, serviceName, FirewallDirection.Outbound),
            JailSpec(ruleId, label, shown, programPath, serviceName, FirewallDirection.Inbound)
        };

        var outcome = ChangeOutcome.AlreadySatisfied;
        foreach (var spec in specs)
        {
            var one = await CreateAsync(spec, journal, ct).ConfigureAwait(false);
            if (one == ChangeOutcome.Applied) outcome = ChangeOutcome.Applied;
        }

        foreach (var spec in specs)
        {
            var state = await ReadBackAsync(spec.DisplayName, ct).ConfigureAwait(false);
            var problem = CheckJail(state, spec);
            if (problem is not null)
                throw new InvalidOperationException(
                    $"The local-only rule '{spec.DisplayName}' was created but does not read back correctly: {problem}");
        }

        return outcome;
    }

    /// <summary>The rule a jail is supposed to be, for checking what Windows actually holds against it.</summary>
    public static FirewallRuleSpec JailSpecFor(string label, string? programPath, string? serviceName, FirewallDirection direction) =>
        JailSpec("", label, programPath is not null ? Path.GetFileName(programPath) : serviceName!, programPath, serviceName, direction);

    private static FirewallRuleSpec JailSpec(
        string ruleId, string label, string shown, string? programPath, string? serviceName, FirewallDirection direction) =>
        new(ruleId, JailRuleName(label, direction),
            $"Anti-Google local-only: {shown} may talk to this machine only ({(direction == FirewallDirection.Outbound ? "outbound" : "inbound")})",
            direction, LoopbackRanges.NonLoopback,
            ProgramPath: programPath, ServiceName: serviceName,
            JournalEngine: EngineKind.LocalOnly,
            JournalDescription: $"Confined {shown} to this machine ({(direction == FirewallDirection.Outbound ? "outbound" : "inbound")})");

    /// <summary>
    /// Refuses targets that would confine the wrong thing. Fail closed: a path the engine cannot show
    /// to be an ordinary installed program is not jailed. Confining a program under the Windows
    /// directory (cmd, powershell, svchost, rundll32…) would break more than Google.
    /// </summary>
    internal static void ValidateJailTarget(string? programPath, string? serviceName)
    {
        if ((programPath is null) == (serviceName is null))
            throw new ArgumentException("Exactly one of a program path or a service name is required.");

        if (serviceName is not null)
        {
            if (!ServiceNamePattern.IsMatch(serviceName))
                throw new ArgumentException($"'{serviceName}' is not a plausible service name.");
            return;
        }

        if (!Path.IsPathFullyQualified(programPath!) || programPath!.Contains('*') || programPath.Contains('?'))
            throw new ArgumentException($"'{programPath}' is not a full path to one program.");
        if (IsUnderWindowsDirectory(programPath))
            throw new ArgumentException(
                $"'{programPath}' is inside the Windows directory. Local-only mode confines vendor programs; " +
                "confining a system binary would break the machine.");
        if (!File.Exists(programPath))
            throw new FileNotFoundException("The program to confine does not exist.", programPath);
    }

    private static readonly Regex ServiceNamePattern = new(@"^[A-Za-z0-9_.\-$ ]{1,256}$", RegexOptions.Compiled);

    internal static bool IsUnderWindowsDirectory(string path)
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrEmpty(windows)) return true; // cannot tell, so refuse
        var full = Path.GetFullPath(path);
        var root = windows.TrimEnd('\\') + "\\";
        return full.StartsWith(root, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Compares a rule read back from Windows with the spec it was created from. Null means correct.</summary>
    internal static string? CheckJail(FirewallRuleState? state, FirewallRuleSpec spec)
    {
        if (state is null) return "the rule does not exist";
        if (!state.Enabled) return "the rule is not enabled";
        if (!string.Equals(state.Direction, spec.Direction.ToString(), StringComparison.OrdinalIgnoreCase))
            return $"direction is {state.Direction}, expected {spec.Direction}";
        if (!string.Equals(state.Action, "Block", StringComparison.OrdinalIgnoreCase))
            return $"action is {state.Action}, expected Block";
        if (spec.ProgramPath is not null &&
            !string.Equals(state.Program, spec.ProgramPath, StringComparison.OrdinalIgnoreCase))
            return $"program is '{state.Program}', expected '{spec.ProgramPath}'";
        if (spec.ServiceName is not null &&
            !string.Equals(state.Service, spec.ServiceName, StringComparison.OrdinalIgnoreCase))
            return $"service is '{state.Service}', expected '{spec.ServiceName}'";

        var want = spec.RemoteAddresses.Select(a => a.Trim()).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var have = state.RemoteAddresses.Select(a => a.Trim()).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!want.SetEquals(have))
            return $"remote addresses are [{string.Join(", ", have)}], expected [{string.Join(", ", want)}]";

        return null;
    }

    private async Task<ChangeOutcome> CreateAsync(FirewallRuleSpec spec, ChangeJournal journal, CancellationToken ct)
    {
        if (spec.RemoteAddresses.Count == 0) return ChangeOutcome.NotPresent;

        if (await RuleExistsAsync(spec.DisplayName, ct).ConfigureAwait(false))
            return ChangeOutcome.AlreadySatisfied;

        var target = spec.ProgramPath ?? spec.ServiceName;
        journal.Append(new JournalEntry
        {
            RuleId = spec.RuleId,
            Engine = spec.JournalEngine,
            Description = spec.JournalDescription ?? $"Created firewall rule '{spec.DisplayName}'",
            Reverse = ReverseKind.RemoveFirewallRule,
            FirewallRuleName = spec.DisplayName,
            Target = target
        });

        var res = await ProcessRunner.PowerShellAsync(BuildCreateCommand(spec, _group), 90_000, ct).ConfigureAwait(false);
        if (!res.Ok)
            throw new InvalidOperationException($"Creating firewall rule '{spec.DisplayName}' failed: {res.Combined}");

        Log.Info($"Firewall: created '{spec.DisplayName}' ({spec.RemoteAddresses.Count} ranges" +
                 $"{(spec.ProgramPath is null ? "" : $", program {spec.ProgramPath}")}" +
                 $"{(spec.ServiceName is null ? "" : $", service {spec.ServiceName}")}).");
        return ChangeOutcome.Applied;
    }

    /// <summary>
    /// The PowerShell that creates the rule. Everything interpolated is escaped for a single-quoted
    /// PowerShell string (a quote is doubled), and the callers validate paths and service names first,
    /// so a payload cannot break out of its quotes.
    /// </summary>
    internal static string BuildCreateCommand(FirewallRuleSpec spec, string group)
    {
        var addressList = string.Join(",", spec.RemoteAddresses.Select(r => $"'{Escape(r)}'"));
        var cmd =
            $"New-NetFirewallRule -DisplayName '{Escape(spec.DisplayName)}' " +
            $"-Group '{Escape(group)}' " +
            $"-Description '{Escape(spec.Description)}' " +
            $"-Direction {spec.Direction} -Action Block -Enabled True -Profile Any " +
            $"-RemoteAddress @({addressList}) ";

        if (spec.ProgramPath is not null) cmd += $"-Program '{Escape(spec.ProgramPath)}' ";
        if (spec.ServiceName is not null) cmd += $"-Service '{Escape(spec.ServiceName)}' ";

        return cmd + "-ErrorAction Stop | Out-Null";
    }

    /// <summary>Reads one rule back from Windows. Null when there is no such rule.</summary>
    public virtual async Task<FirewallRuleState?> ReadBackAsync(string displayName, CancellationToken ct = default)
    {
        var res = await ProcessRunner.PowerShellAsync(
            $"$r = Get-NetFirewallRule -DisplayName '{Escape(displayName)}' -ErrorAction SilentlyContinue | Select-Object -First 1; " +
            $"if (-not $r) {{ '{{}}' }} else {{ {StateProjection("$r")} | ConvertTo-Json -Compress }}",
            60_000, ct).ConfigureAwait(false);

        return ParseStates(res.StdOut).FirstOrDefault();
    }

    /// <summary>Every rule in our group, read back. What the report is built from.</summary>
    public virtual async Task<IReadOnlyList<FirewallRuleState>> ListRulesAsync(CancellationToken ct = default)
    {
        var res = await ProcessRunner.PowerShellAsync(
            $"@(Get-NetFirewallRule -Group '{Escape(_group)}' -ErrorAction SilentlyContinue | ForEach-Object {{ {StateProjection("$_")} }}) " +
            "| ConvertTo-Json -Compress", 120_000, ct).ConfigureAwait(false);

        return ParseStates(res.StdOut);
    }

    private static string StateProjection(string rule) =>
        $"[pscustomobject]@{{ Name = {rule}.DisplayName; Enabled = [string]{rule}.Enabled; Direction = [string]{rule}.Direction; " +
        $"Action = [string]{rule}.Action; Group = {rule}.Group; " +
        $"Program = ({rule} | Get-NetFirewallApplicationFilter).Program; " +
        $"Service = ({rule} | Get-NetFirewallServiceFilter).Service; " +
        $"Remote = @(({rule} | Get-NetFirewallAddressFilter).RemoteAddress) }}";

    /// <summary>ConvertTo-Json emits a lone object for one rule and an array for several; accept both.</summary>
    internal static IReadOnlyList<FirewallRuleState> ParseStates(string json)
    {
        var states = new List<FirewallRuleState>();
        if (string.IsNullOrWhiteSpace(json)) return states;

        try
        {
            using var doc = JsonDocument.Parse(json.Trim());
            var items = doc.RootElement.ValueKind == JsonValueKind.Array
                ? doc.RootElement.EnumerateArray().ToList()
                : [doc.RootElement];

            foreach (var e in items)
            {
                if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty("Name", out var name)) continue;

                string? Str(string prop) =>
                    e.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

                var remote = new List<string>();
                if (e.TryGetProperty("Remote", out var r))
                {
                    if (r.ValueKind == JsonValueKind.Array)
                        remote.AddRange(r.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!));
                    else if (r.ValueKind == JsonValueKind.String)
                        remote.Add(r.GetString()!);
                }

                states.Add(new FirewallRuleState(
                    name.GetString() ?? "",
                    string.Equals(Str("Enabled"), "True", StringComparison.OrdinalIgnoreCase),
                    Str("Direction") ?? "", Str("Action") ?? "", Str("Group"),
                    string.IsNullOrWhiteSpace(Str("Program")) || Str("Program") == "Any" ? null : Str("Program"),
                    string.IsNullOrWhiteSpace(Str("Service")) || Str("Service") == "Any" ? null : Str("Service"),
                    remote));
            }
        }
        catch (JsonException ex)
        {
            Log.Warn($"Firewall read-back was not valid JSON: {ex.Message}");
        }

        return states;
    }

    public virtual async Task RevertAsync(JournalEntry entry, CancellationToken ct = default)
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
    public virtual async Task RemoveAllAsync(CancellationToken ct = default)
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
