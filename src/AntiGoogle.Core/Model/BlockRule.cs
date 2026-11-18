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
/// One reversible unit of de-Googling. A rule is declarative: it names what it wants gone and
/// what that costs. The engines decide how, and always journal a reverse before acting.
/// </summary>
public sealed class BlockRule
{
    /// <summary>Stable identity. Persisted in the journal and settings — never renumber these.</summary>
    public required string Id { get; init; }

    public required string Title { get; init; }

    /// <summary>One line the user reads in the rule list.</summary>
    public required string Summary { get; init; }

    public required RuleCategory Category { get; init; }
    public required RiskTier Tier { get; init; }
    public required EngineKind Engine { get; init; }

    /// <summary>Domains to sinkhole. Hosts engine writes both the bare and www forms it is given.</summary>
    public IReadOnlyList<string> Domains { get; init; } = [];

    /// <summary>CIDR ranges for outbound firewall blocks.</summary>
    public IReadOnlyList<string> IpRanges { get; init; } = [];

    /// <summary>Service key names; a trailing '*' makes it a prefix match.</summary>
    public IReadOnlyList<string> ServiceNamePatterns { get; init; } = [];

    /// <summary>Scheduled task name fragments; a trailing '*' makes it a prefix match.</summary>
    public IReadOnlyList<string> ScheduledTaskPatterns { get; init; } = [];

    public IReadOnlyList<RegistryPolicy> RegistryValues { get; init; } = [];

    /// <summary>Every capability this rule is known to degrade. Empty means genuinely no cost.</summary>
    public IReadOnlyList<Breakage> Breaks { get; init; } = [];

    /// <summary>
    /// Whether the shipped profile arms this rule. Note the app ships on the Aggressive profile,
    /// so a number of Severe-breakage rules are on out of the box by design.
    /// </summary>
    public bool DefaultEnabled { get; init; }

    /// <summary>Extra context shown in the expanded rule card.</summary>
    public string? Note { get; init; }

    /// <summary>
    /// True for rules whose failure mode can lock the user out of their own machine or network.
    /// The UI demands a separate typed confirmation for these.
    /// </summary>
    public bool RequiresExplicitConsent { get; init; }

    /// <summary>
    /// Who the rule is aimed at, for grouping and for the report: "Google", "Mandiant", "VirusTotal"…
    /// Null for the general rules that predate marker families.
    /// </summary>
    public string? Vendor { get; init; }

    /// <summary>
    /// True when keeping the target alive but confined to this machine is a meaningful alternative to
    /// blocking it: a service, a scheduled task, or a hosts group that some local program still needs
    /// to be able to resolve.
    /// </summary>
    public bool SupportsLocalOnly { get; init; }

    /// <summary>
    /// What degrades when the rule runs in <see cref="RuleMode.LocalOnly"/>. The cost is different from
    /// blocking — the program keeps running, but cannot reach anything off this machine. Required
    /// whenever <see cref="SupportsLocalOnly"/> is set (a test enforces it); it is never silently
    /// borrowed from <see cref="Breaks"/>, because that would state the wrong cost.
    /// </summary>
    public IReadOnlyList<Breakage> LocalOnlyBreaks { get; init; } = [];

    /// <summary>A copy of this rule that can also run local-only, with its own declared cost.</summary>
    public BlockRule WithLocalOnly(IReadOnlyList<Breakage> localOnlyBreaks) => new()
    {
        Id = Id, Title = Title, Summary = Summary, Category = Category, Tier = Tier, Engine = Engine,
        Domains = Domains, IpRanges = IpRanges, ServiceNamePatterns = ServiceNamePatterns,
        ScheduledTaskPatterns = ScheduledTaskPatterns, RegistryValues = RegistryValues,
        Breaks = Breaks, DefaultEnabled = DefaultEnabled, Note = Note,
        RequiresExplicitConsent = RequiresExplicitConsent, Vendor = Vendor,
        SupportsLocalOnly = true, LocalOnlyBreaks = localOnlyBreaks
    };

    /// <summary>The breakage list that applies in the given mode.</summary>
    public IReadOnlyList<Breakage> BreaksFor(RuleMode mode) =>
        mode == RuleMode.LocalOnly && SupportsLocalOnly ? LocalOnlyBreaks : Breaks;

    /// <summary>
    /// The rule as it behaves in the given mode. In local-only mode its declared cost is the local-only
    /// cost, so the impact report, the dashboard counts and the confirmation all state the right thing.
    /// </summary>
    public BlockRule ForMode(RuleMode mode) => mode == RuleMode.LocalOnly && SupportsLocalOnly
        ? new BlockRule
        {
            Id = Id, Title = Title, Summary = Summary, Category = Category, Tier = Tier, Engine = Engine,
            Domains = Domains, IpRanges = IpRanges, ServiceNamePatterns = ServiceNamePatterns,
            ScheduledTaskPatterns = ScheduledTaskPatterns, RegistryValues = RegistryValues,
            Breaks = LocalOnlyBreaks, DefaultEnabled = DefaultEnabled, Note = Note,
            RequiresExplicitConsent = RequiresExplicitConsent, Vendor = Vendor,
            SupportsLocalOnly = true, LocalOnlyBreaks = LocalOnlyBreaks
        }
        : this;

    public BreakageSeverity WorstBreakage =>
        Breaks.Count == 0 ? BreakageSeverity.None : Breaks.Max(b => b.Severity);

    public override string ToString() => $"{Id} ({Engine}, {Tier})";
}
