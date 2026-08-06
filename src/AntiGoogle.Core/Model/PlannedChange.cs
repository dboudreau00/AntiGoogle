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
namespace AntiGoogle.Core.Model;

/// <summary>
/// One concrete edit an engine intends to make. Produced during planning (dry run) and then
/// executed. Nothing in this app writes to the OS without first appearing here.
/// </summary>
public sealed class PlannedChange
{
    public required string RuleId { get; init; }
    public required EngineKind Engine { get; init; }

    /// <summary>What the user sees in the preview list, e.g. "Disable service GoogleUpdaterService152.0.7933.0".</summary>
    public required string Description { get; init; }

    /// <summary>Engine-specific target key, used to correlate with the journal.</summary>
    public required string Target { get; init; }

    public ChangeOutcome Outcome { get; set; } = ChangeOutcome.Applied;
    public string? Error { get; set; }

    /// <summary>Set when a preflight check refuses the change; explains why to the user.</summary>
    public string? RefusalReason { get; set; }

    public override string ToString() => $"[{Engine}] {Description}";
}

/// <summary>The full set of edits an Apply would make, plus everything it would break.</summary>
public sealed class ChangePlan
{
    public List<PlannedChange> Changes { get; } = [];
    public List<BlockRule> Rules { get; } = [];

    /// <summary>Preflight findings that must be shown before the user can confirm.</summary>
    public List<Safety.PreflightFinding> Findings { get; } = [];

    public IEnumerable<PlannedChange> Actionable =>
        Changes.Where(c => c.Outcome != ChangeOutcome.NotPresent && c.Outcome != ChangeOutcome.Refused);

    /// <summary>
    /// Every distinct degradation this plan causes, worst first. This is what the impact screen renders.
    /// </summary>
    public IReadOnlyList<(Breakage Breakage, BlockRule Rule)> Degradations =>
        Rules.SelectMany(r => r.Breaks.Select(b => (Breakage: b, Rule: r)))
             .OrderByDescending(x => x.Breakage.Severity)
             .ThenBy(x => x.Breakage.What, StringComparer.OrdinalIgnoreCase)
             .ToList();

    public int SevereCount => Rules.SelectMany(r => r.Breaks).Count(b => b.Severity == BreakageSeverity.Severe);
    public int NotableCount => Rules.SelectMany(r => r.Breaks).Count(b => b.Severity == BreakageSeverity.Notable);
}

/// <summary>Outcome of executing a <see cref="ChangePlan"/>.</summary>
public sealed class ApplyReport
{
    public required ChangePlan Plan { get; init; }
    public int Applied => Plan.Changes.Count(c => c.Outcome == ChangeOutcome.Applied);
    public int Skipped => Plan.Changes.Count(c => c.Outcome is ChangeOutcome.AlreadySatisfied or ChangeOutcome.NotPresent);
    public int Failed => Plan.Changes.Count(c => c.Outcome == ChangeOutcome.Failed);
    public int Refused => Plan.Changes.Count(c => c.Outcome == ChangeOutcome.Refused);
    public bool AnyFailures => Failed > 0;
}
