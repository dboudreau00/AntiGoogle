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

using System.Collections.ObjectModel;
using AntiGoogle.Core.Discovery;
using AntiGoogle.Core.Model;
using CommunityToolkit.Mvvm.ComponentModel;

namespace AntiGoogle.App.ViewModels;

public partial class RuleViewModel : ObservableObject
{
    private bool _suppress;

    public RuleViewModel(BlockRule rule, bool enabled)
    {
        Rule = rule;
        _isEnabled = enabled;
        Breaks = new ObservableCollection<Breakage>(rule.Breaks.OrderByDescending(b => b.Severity));
    }

    public BlockRule Rule { get; }
    public ObservableCollection<Breakage> Breaks { get; }

    [ObservableProperty] private bool _isEnabled;
    [ObservableProperty] private bool _isExpanded;

    /// <summary>Raised only for user-driven toggles, never for programmatic corrections.</summary>
    public event Action<RuleViewModel, bool>? EnabledChangedByUser;

    partial void OnIsEnabledChanged(bool value)
    {
        if (_suppress) return;
        EnabledChangedByUser?.Invoke(this, value);
    }

    /// <summary>Used when the VM has to correct the toggle itself — e.g. the user cancelled a consent prompt.</summary>
    public void SetEnabledSilently(bool value)
    {
        _suppress = true;
        IsEnabled = value;
        _suppress = false;
    }

    public string Id => Rule.Id;
    public string Title => Rule.Title;
    public string Summary => Rule.Summary;
    public string? Note => Rule.Note;
    public RiskTier Tier => Rule.Tier;
    public string TierLabel => Rule.Tier.ToString().ToUpperInvariant();
    public BreakageSeverity WorstBreakage => Rule.WorstBreakage;
    public bool NeedsConsent => Rule.RequiresExplicitConsent;
    public bool HasBreaks => Breaks.Count > 0;
    public bool HasNote => !string.IsNullOrWhiteSpace(Rule.Note);

    public string EngineLabel => Rule.Engine switch
    {
        EngineKind.Hosts => "HOSTS",
        EngineKind.Firewall => "FIREWALL",
        EngineKind.Service => "SERVICE",
        EngineKind.ScheduledTask => "TASK",
        EngineKind.Registry => "REGISTRY",
        _ => "CONTAIN"
    };

    /// <summary>
    /// What a screen reader announces for the toggle. Without it the control reads as
    /// "checkbox, unchecked" with no indication of WHICH system-wide rule is being armed.
    /// </summary>
    public string ToggleAutomationName =>
        NeedsConsent ? $"Arm rule, requires confirmation: {Title}" : $"Arm rule: {Title}";

    /// <summary>
    /// Without this every one of the 23 disclosure toggles announces the bare string "Show detail",
    /// so a screen-reader user tabbing the Rules page hears it repeatedly with no idea which rule
    /// each one belongs to.
    /// </summary>
    public string DetailToggleAutomationName => $"Show what {Title} breaks";

    public string BreakSummary => Breaks.Count switch
    {
        0 => "No known degradation",
        1 => "1 known degradation",
        _ => $"{Breaks.Count} known degradations"
    };

    public string TargetSummary
    {
        get
        {
            if (Rule.Domains.Count > 0) return $"{Rule.Domains.Count} domains";
            if (Rule.IpRanges.Count > 0) return $"{Rule.IpRanges.Count} IP ranges";
            if (Rule.RegistryValues.Count > 0) return $"{Rule.RegistryValues.Count} policy values";
            if (Rule.ServiceNamePatterns.Count > 0) return $"{Rule.ServiceNamePatterns.Count} service patterns";
            if (Rule.ScheduledTaskPatterns.Count > 0) return $"{Rule.ScheduledTaskPatterns.Count} task patterns";
            return "";
        }
    }
}

/// <summary>A category heading plus its rules, for the grouped rule list.</summary>
public sealed class RuleGroupViewModel(string name, IEnumerable<RuleViewModel> rules)
{
    public string Name { get; } = name;
    public ObservableCollection<RuleViewModel> Rules { get; } = new(rules);
    public int Count => Rules.Count;
}

/// <summary>One row on the impact screen: what breaks, how badly, and which rule caused it.</summary>
public sealed class DegradationRow(Breakage breakage, BlockRule rule)
{
    public Breakage Breakage { get; } = breakage;
    public BlockRule Rule { get; } = rule;

    public string What => Breakage.What;
    public string Detail => Breakage.Detail;
    public BreakageSeverity Severity => Breakage.Severity;
    public string SeverityLabel => Breakage.Severity.ToString().ToUpperInvariant();
    public string CausedBy => $"{Rule.Title}  ·  {Rule.Id}";
}

public partial class ContainedAppViewModel : ObservableObject
{
    public ContainedAppViewModel(DiscoveredApp app, bool contained)
    {
        App = app;
        _isContained = contained;
    }

    public DiscoveredApp App { get; }

    [ObservableProperty] private bool _isContained;

    public event Action<ContainedAppViewModel, bool>? ContainmentChanged;
    partial void OnIsContainedChanged(bool value) => ContainmentChanged?.Invoke(this, value);

    public string ToggleAutomationName => $"Contain application: {App.Name}";

    public string Name => App.Name;
    public string Path => App.ExecutablePath;
    public string OriginLabel => App.OriginLabel;
    public string Evidence => App.Evidence;
    public string Publisher => string.IsNullOrWhiteSpace(App.Publisher) ? "unsigned / unknown publisher" : App.Publisher!;
    public string SizeLabel => $"{App.SizeBytes / 1024.0 / 1024.0:0.#} MB";
}
