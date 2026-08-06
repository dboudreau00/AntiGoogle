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
using System.Diagnostics;
using System.Windows;
using AntiGoogle.Core;
using AntiGoogle.Core.Catalog;
using AntiGoogle.Core.Discovery;
using AntiGoogle.Core.Journal;
using AntiGoogle.Core.Model;
using AntiGoogle.Core.Platform;
using AntiGoogle.Core.Safety;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AntiGoogle.App.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly ProtectionService? _service;
    private readonly AppSettings _settings;
    private readonly GoogleAppScanner _scanner = new();
    private ChangePlan? _pendingPlan;

    public MainViewModel()
    {
        _settings = AppSettings.LoadOrDefault();

        try
        {
            _service = new ProtectionService();
        }
        catch (Exception ex)
        {
            // Almost always a corrupt journal. Say so precisely — the user's machine may be in a
            // modified state and they need to know undo information is at risk.
            InitError = ex.Message;
            Log.Error("ProtectionService could not start.", ex);
        }

        IsElevated = Elevation.IsElevated;

        AllRules = RuleCatalog.All
            .Select(r => new RuleViewModel(r, _settings.EnabledRuleIds.Contains(r.Id, StringComparer.OrdinalIgnoreCase)))
            .ToList();

        foreach (var vm in AllRules)
            vm.EnabledChangedByUser += OnRuleToggled;

        RuleGroups = new ObservableCollection<RuleGroupViewModel>(
            AllRules.GroupBy(r => r.Rule.Category)
                    .OrderBy(g => g.Key)
                    .Select(g => new RuleGroupViewModel(CategoryLabel(g.Key), g)));

        RecomputeDegradations();
        _ = RefreshStatusAsync();
    }

    // ---------------------------------------------------------------- state

    public string? InitError { get; }
    public bool HasInitError => !string.IsNullOrEmpty(InitError);

    public List<RuleViewModel> AllRules { get; }
    public ObservableCollection<RuleGroupViewModel> RuleGroups { get; }
    public ObservableCollection<DegradationRow> Degradations { get; } = [];
    public ObservableCollection<PreflightFinding> Findings { get; } = [];
    public ObservableCollection<PlannedChange> PlannedChanges { get; } = [];
    public ObservableCollection<ContainedAppViewModel> DiscoveredApps { get; } = [];
    public ObservableCollection<JournalEntry> JournalEntries { get; } = [];

    [ObservableProperty] private int _selectedPage;
    [ObservableProperty] private bool _isElevated;
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _busyMessage = "";
    [ObservableProperty] private string _statusHeadline = "Checking…";
    [ObservableProperty] private string _statusDetail = "";
    [ObservableProperty] private bool _isArmed;

    [ObservableProperty] private int _sinkholedDomains;
    [ObservableProperty] private int _firewallRules;
    [ObservableProperty] private int _disabledServices;
    [ObservableProperty] private int _registryValues;
    [ObservableProperty] private int _journalCount;

    [ObservableProperty] private int _severeCount;
    [ObservableProperty] private int _notableCount;
    [ObservableProperty] private int _minorCount;
    [ObservableProperty] private int _enabledRuleCount;

    [ObservableProperty] private string _lastResult = "";

    /// <summary>"info" | "ok" | "warn" | "error" — drives the result banner's colour and icon.</summary>
    [ObservableProperty] private string _lastResultLevel = "info";

    /// <summary>False until the containment scan has run once, so the page can show a real empty state.</summary>
    [ObservableProperty] private bool _hasScanned;

    /// <summary>Contained apps count as armed — they are changes the next Apply will make.</summary>
    public bool NothingArmed => EnabledRuleCount == 0 && _settings.ContainedApps.Count == 0;

    public bool HasPlanPreview => PlannedChanges.Count > 0;

    /// <summary>
    /// Only claim the machine is untouched when we can actually see the journal. An empty journal
    /// because nothing was applied and an empty journal because the file could not be READ look
    /// identical from here, and telling someone their machine is unmodified when it may be
    /// mid-modification is the worst thing this screen could say.
    /// </summary>
    public bool CanAssertUnmodified => JournalCount == 0 && !HasInitError;

    partial void OnJournalCountChanged(int value) => OnPropertyChanged(nameof(CanAssertUnmodified));

    // ---------------------------------------------------------------- overlay gating

    /// <summary>
    /// True while any modal is up. The shell binds IsEnabled to the inverse of this across BOTH
    /// columns, so a confirm dialog cannot be bypassed by tabbing to the rule toggles behind it —
    /// or, worse, by clicking "Restart as Administrator" (which shuts the process down) in the
    /// middle of an apply.
    /// </summary>
    public bool IsOverlayOpen => IsBusy || ShowConfirm || ShowConsent;

    partial void OnIsBusyChanged(bool value) => OnPropertyChanged(nameof(IsOverlayOpen));
    partial void OnShowConfirmChanged(bool value) => OnPropertyChanged(nameof(IsOverlayOpen));
    partial void OnShowConsentChanged(bool value) => OnPropertyChanged(nameof(IsOverlayOpen));

    /// <summary>Esc handler. Busy is deliberately not dismissible — the work is already running.</summary>
    [RelayCommand]
    private void DismissOverlay()
    {
        if (ShowConsent) { CancelConsent(); return; }
        if (ShowConfirm) { CancelConfirm(); }
    }

    // Confirm-before-apply overlay
    [ObservableProperty] private bool _showConfirm;
    [ObservableProperty] private bool _confirmAccepted;
    [ObservableProperty] private string _confirmHeadline = "";
    public ObservableCollection<DegradationRow> ConfirmDegradations { get; } = [];
    public ObservableCollection<PlannedChange> ConfirmChanges { get; } = [];

    // Typed-consent overlay for the rules that can lock you out
    [ObservableProperty] private bool _showConsent;
    [ObservableProperty] private string _consentTitle = "";
    [ObservableProperty] private string _consentBody = "";
    [ObservableProperty] private string _consentTyped = "";
    private RuleViewModel? _consentTarget;
    public string ConsentPhrase => "ARM";
    public bool ConsentSatisfied => string.Equals(ConsentTyped.Trim(), ConsentPhrase, StringComparison.Ordinal);
    partial void OnConsentTypedChanged(string value) => OnPropertyChanged(nameof(ConsentSatisfied));

    // ---------------------------------------------------------------- rules

    private void OnRuleToggled(RuleViewModel vm, bool enabled)
    {
        if (enabled && vm.NeedsConsent && !_settings.AcknowledgedRuleIds.Contains(vm.Id, StringComparer.OrdinalIgnoreCase))
        {
            // Do not let a single click arm something that can lock the user out of their accounts
            // or their network. Bounce the toggle back until they type the phrase.
            vm.SetEnabledSilently(false);
            _consentTarget = vm;
            ConsentTitle = vm.Title;
            ConsentBody = string.Join("\n\n", vm.Breaks.Select(b => $"[{b.Severity.ToString().ToUpperInvariant()}] {b.What}\n{b.Detail}"));
            ConsentTyped = "";
            ShowConsent = true;
            return;
        }

        PersistRuleState(vm, enabled);
    }

    private void PersistRuleState(RuleViewModel vm, bool enabled)
    {
        if (enabled)
        {
            if (!_settings.EnabledRuleIds.Contains(vm.Id, StringComparer.OrdinalIgnoreCase))
                _settings.EnabledRuleIds.Add(vm.Id);
        }
        else
        {
            _settings.EnabledRuleIds.RemoveAll(id => string.Equals(id, vm.Id, StringComparison.OrdinalIgnoreCase));
        }

        _settings.Save();
        RecomputeDegradations();
    }

    [RelayCommand]
    private void ConfirmConsent()
    {
        if (_consentTarget is null || !ConsentSatisfied) return;

        _settings.AcknowledgedRuleIds.Add(_consentTarget.Id);
        _consentTarget.SetEnabledSilently(true);
        PersistRuleState(_consentTarget, true);

        ShowConsent = false;
        _consentTarget = null;
    }

    [RelayCommand]
    private void CancelConsent()
    {
        _consentTarget?.SetEnabledSilently(false);
        ShowConsent = false;
        _consentTarget = null;
    }

    [RelayCommand]
    private void ApplyProfile(string tierName)
    {
        if (!Enum.TryParse<RiskTier>(tierName, ignoreCase: true, out var tier)) return;

        _settings.Profile = tier;
        foreach (var vm in AllRules)
        {
            // Consent-gated rules are never armed by a profile switch. A profile is a convenience;
            // it must not silently turn on something the user had to type a phrase to enable.
            vm.SetEnabledSilently(ProfileWants(vm.Rule, tier));
        }

        _settings.EnabledRuleIds = AllRules.Where(r => r.IsEnabled).Select(r => r.Id).ToList();
        _settings.Save();
        RecomputeDegradations();
        SetResult($"Switched to the {tier} profile — {EnabledRuleCount} rules armed. " +
                  "Nothing is applied until you press Apply.", "info");
    }

    private static bool ProfileWants(BlockRule rule, RiskTier tier) =>
        !rule.RequiresExplicitConsent && rule.DefaultEnabled && rule.Tier <= tier;

    /// <summary>
    /// Derived from the ACTUAL armed set rather than from the stored preference. Toggling a single
    /// rule after picking a profile used to leave the stored profile silently stale, so the UI
    /// claimed "Aggressive" while the machine was about to get something else entirely.
    /// </summary>
    private bool MatchesProfile(RiskTier tier)
    {
        var want = RuleCatalog.All.Where(r => ProfileWants(r, tier))
                                  .Select(r => r.Id)
                                  .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var have = AllRules.Where(r => r.IsEnabled).Select(r => r.Id)
                           .ToHashSet(StringComparer.OrdinalIgnoreCase);
        return want.SetEquals(have);
    }

    public bool IsConservativeActive => MatchesProfile(RiskTier.Conservative);
    public bool IsBalancedActive => MatchesProfile(RiskTier.Balanced);
    public bool IsAggressiveActive => MatchesProfile(RiskTier.Aggressive);

    // Sighted users see the active profile as a tinted, accent-bordered button. A screen reader
    // saw three identically named buttons, so the current profile was conveyed by colour alone.
    public string ConservativeAutomationName => ProfileName("Conservative", IsConservativeActive);
    public string BalancedAutomationName => ProfileName("Balanced", IsBalancedActive);
    public string AggressiveAutomationName => ProfileName("Aggressive", IsAggressiveActive);

    private static string ProfileName(string tier, bool active) =>
        active ? $"{tier} profile, currently selected" : $"Select the {tier} profile";

    public string ProfileLabel =>
        IsAggressiveActive ? "Aggressive" :
        IsBalancedActive ? "Balanced" :
        IsConservativeActive ? "Conservative" :
        "Custom";

    public void SetResult(string message, string level)
    {
        LastResultLevel = level;
        LastResult = message;
    }

    [RelayCommand]
    private void ClearResult() => SetResult("", "info");

    /// <summary>Shown on the About page and in the exe's file properties.</summary>
    public string VersionLabel
    {
        get
        {
            var asm = System.Reflection.Assembly.GetExecutingAssembly();
            var informational = asm
                .GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
                .OfType<System.Reflection.AssemblyInformationalVersionAttribute>()
                .FirstOrDefault()?.InformationalVersion;

            // The SDK appends "+<commit sha>" to the informational version; nobody needs that here.
            var version = informational?.Split('+')[0] ?? asm.GetName().Version?.ToString() ?? "unknown";
            return $"version {version}  ·  .NET {Environment.Version}";
        }
    }

    private void RecomputeDegradations()
    {
        var enabled = AllRules.Where(r => r.IsEnabled).ToList();
        EnabledRuleCount = enabled.Count;

        var sources = enabled.Select(r => r.Rule).ToList();

        // Contained apps are chosen at runtime and have no catalog entry, so without this they
        // contributed NOTHING to the dashboard counts or the impact list — including a Severe
        // breakage. The same synthetic rule the plan uses, so the two can never disagree.
        if (_settings.ContainedApps.Count > 0)
            sources.Add(ProtectionService.ContainmentWarningRule(_settings.ContainedApps));

        var rows = sources
            .SelectMany(r => r.Breaks.Select(b => new DegradationRow(b, r)))
            .OrderByDescending(d => d.Severity)
            .ThenBy(d => d.What, StringComparer.OrdinalIgnoreCase)
            .ToList();

        Degradations.Clear();
        foreach (var r in rows) Degradations.Add(r);

        SevereCount = rows.Count(r => r.Severity == BreakageSeverity.Severe);
        NotableCount = rows.Count(r => r.Severity == BreakageSeverity.Notable);
        MinorCount = rows.Count(r => r.Severity == BreakageSeverity.Minor);

        OnPropertyChanged(nameof(NothingArmed));
        OnPropertyChanged(nameof(IsConservativeActive));
        OnPropertyChanged(nameof(IsBalancedActive));
        OnPropertyChanged(nameof(IsAggressiveActive));
        OnPropertyChanged(nameof(ProfileLabel));
        OnPropertyChanged(nameof(ConservativeAutomationName));
        OnPropertyChanged(nameof(BalancedAutomationName));
        OnPropertyChanged(nameof(AggressiveAutomationName));
        OnPropertyChanged(nameof(ImpactVerdict));
        OnPropertyChanged(nameof(ImpactVerdictLevel));
    }

    /// <summary>
    /// The one-line answer the Impact screen opens with. Previously it opened with three
    /// equal-weight lists and no verdict, which buried the product's whole point.
    /// </summary>
    public string ImpactVerdict => EnabledRuleCount == 0
        ? "Nothing is armed. Anti-Google will not change this machine."
        : SevereCount > 0
            ? $"{SevereCount} things will break badly, and {NotableCount} will visibly degrade."
            : NotableCount > 0
                ? $"{NotableCount} things will visibly degrade. Nothing severe."
                : "Nothing important breaks. This is about as safe as de-Googling gets.";

    public string ImpactVerdictLevel =>
        EnabledRuleCount == 0 ? "info" : SevereCount > 0 ? "error" : NotableCount > 0 ? "warn" : "ok";

    // ---------------------------------------------------------------- status

    [RelayCommand]
    private async Task RefreshStatusAsync()
    {
        if (_service is null) return;

        try
        {
            var s = await _service.GetStatusAsync().ConfigureAwait(true);

            SinkholedDomains = s.SinkholedDomains;
            FirewallRules = s.FirewallRules;
            DisabledServices = s.DisabledServices;
            RegistryValues = s.RegistryValues;
            JournalCount = s.JournalEntries;
            IsArmed = s.AnyProtection;
            IsElevated = s.Elevated;

            StatusHeadline = s.AnyProtection ? "Protection active" : "Not protected";
            StatusDetail = s.AnyProtection
                ? $"{s.SinkholedDomains} domains sinkholed · {s.FirewallRules} firewall rules · {s.JournalEntries} reversible changes"
                : "No Anti-Google changes are currently applied to this machine.";

            JournalEntries.Clear();
            foreach (var e in _service.Journal.ReplayOrder()) JournalEntries.Add(e);
        }
        catch (Exception ex)
        {
            Log.Error("Status refresh failed.", ex);
            StatusHeadline = "Status unavailable";
            StatusDetail = ex.Message;
        }
    }

    // ---------------------------------------------------------------- preview & apply

    [RelayCommand]
    private async Task PreviewAsync()
    {
        if (_service is null) return;

        await RunBusyAsync("Building a change plan…", async () =>
        {
            var plan = await _service.BuildPlanAsync(
                _settings.EnabledRuleIds, _settings.ContainedApps).ConfigureAwait(true);

            _pendingPlan = plan;

            Findings.Clear();
            foreach (var f in plan.Findings.OrderByDescending(f => f.Level)) Findings.Add(f);

            PlannedChanges.Clear();
            foreach (var c in plan.Changes) PlannedChanges.Add(c);

            SetResult($"Plan built: {plan.Changes.Count} changes, {plan.SevereCount} severe degradations. Nothing has been applied.", plan.SevereCount > 0 ? "warn" : "info");
            OnPropertyChanged(nameof(HasPlanPreview));
        }).ConfigureAwait(true);

        SelectedPage = 2;
    }

    [RelayCommand]
    private async Task ApplyAsync()
    {
        if (_service is null) return;

        if (!IsElevated)
        {
            SetResult("Administrator rights are required to apply changes. Use \"Restart as Administrator\" in the sidebar.", "warn");
            return;
        }

        if (EnabledRuleCount == 0)
        {
            SetResult("No rules are armed — there is nothing to apply.", "warn");
            return;
        }

        await RunBusyAsync("Building a change plan…", async () =>
        {
            var plan = await _service.BuildPlanAsync(
                _settings.EnabledRuleIds, _settings.ContainedApps).ConfigureAwait(true);
            _pendingPlan = plan;

            Findings.Clear();
            foreach (var f in plan.Findings.OrderByDescending(f => f.Level)) Findings.Add(f);

            ConfirmDegradations.Clear();
            foreach (var (b, r) in plan.Degradations) ConfirmDegradations.Add(new DegradationRow(b, r));

            ConfirmChanges.Clear();
            foreach (var c in plan.Actionable) ConfirmChanges.Add(c);

            ConfirmHeadline =
                $"{plan.Actionable.Count()} changes · {plan.SevereCount} severe and {plan.NotableCount} notable degradations";
            ConfirmAccepted = false;
            ShowConfirm = true;
        }).ConfigureAwait(true);
    }

    [RelayCommand]
    private async Task ConfirmApplyAsync()
    {
        if (_service is null || _pendingPlan is null || !ConfirmAccepted) return;

        ShowConfirm = false;

        await RunBusyAsync("Applying…", async () =>
        {
            var progress = new Progress<string>(m => BusyMessage = m);
            var report = await _service.ApplyAsync(_pendingPlan, progress).ConfigureAwait(true);

            // PlannedChange is a plain object with no change notification, so the Outcome and
            // Error that ApplyAsync writes onto each item would never reach the Impact page's
            // bindings. Re-seed the collection so a failure is actually visible there.
            PlannedChanges.Clear();
            foreach (var c in _pendingPlan.Changes) PlannedChanges.Add(c);
            OnPropertyChanged(nameof(HasPlanPreview));

            SetResult(
                report.AnyFailures
                    ? $"Applied {report.Applied} changes, but {report.Failed} FAILED. Check the Impact report and the log."
                    : $"Applied {report.Applied} changes. {report.Skipped} were already in place, {report.Refused} were refused by safety checks.",
                report.AnyFailures ? "error" : "ok");
        }).ConfigureAwait(true);

        await RefreshStatusAsync().ConfigureAwait(true);
    }

    [RelayCommand]
    private void CancelConfirm()
    {
        ShowConfirm = false;
        _pendingPlan = null;
        SetResult("Cancelled — nothing was changed.", "info");
    }

    [RelayCommand]
    private async Task RestoreEverythingAsync()
    {
        if (_service is null) return;

        if (!IsElevated)
        {
            SetResult("Administrator rights are required to restore. Use \"Restart as Administrator\" in the sidebar.", "warn");
            return;
        }

        var answer = MessageBox.Show(
            $"Undo every change Anti-Google has made to this machine?\n\n" +
            $"{JournalCount} recorded changes will be reversed: hosts entries removed, firewall rules " +
            "deleted, services and scheduled tasks restored to their original start types, and registry " +
            "policy values put back exactly as they were.\n\nThis is safe and is the intended way out.",
            "Restore everything",
            MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.Yes);

        if (answer != MessageBoxResult.Yes) return;

        await RunBusyAsync("Restoring…", async () =>
        {
            var progress = new Progress<string>(m => BusyMessage = m);
            var errors = await _service.RevertAllAsync(progress).ConfigureAwait(true);

            SetResult(
                errors.Count == 0
                    ? "Everything restored. This machine is back to its original configuration."
                    : $"Restored, but {errors.Count} items had problems: {string.Join("; ", errors.Take(3))}",
                errors.Count == 0 ? "ok" : "error");
        }).ConfigureAwait(true);

        await RefreshStatusAsync().ConfigureAwait(true);
    }

    // ---------------------------------------------------------------- containment

    [RelayCommand]
    private async Task ScanAppsAsync()
    {
        await RunBusyAsync("Scanning for Chromium-derived binaries…", async () =>
        {
            var progress = new Progress<string>(m => BusyMessage = m);
            var found = await _scanner.ScanAsync(progress).ConfigureAwait(true);

            DiscoveredApps.Clear();
            foreach (var app in found)
            {
                var vm = new ContainedAppViewModel(app,
                    _settings.ContainedApps.Contains(app.ExecutablePath, StringComparer.OrdinalIgnoreCase));
                vm.ContainmentChanged += OnContainmentChanged;
                DiscoveredApps.Add(vm);
            }

            HasScanned = true;
            SetResult($"Found {found.Count} binaries that embed or derive from Chromium.", "info");
        }).ConfigureAwait(true);
    }

    private void OnContainmentChanged(ContainedAppViewModel vm, bool contained)
    {
        if (contained)
        {
            if (!_settings.ContainedApps.Contains(vm.Path, StringComparer.OrdinalIgnoreCase))
                _settings.ContainedApps.Add(vm.Path);
        }
        else
        {
            _settings.ContainedApps.RemoveAll(p => string.Equals(p, vm.Path, StringComparison.OrdinalIgnoreCase));
        }

        _settings.Save();
        // Containing an app changes what will break, so the impact report and the dashboard
        // counts have to move with it.
        RecomputeDegradations();
    }

    // ---------------------------------------------------------------- misc

    [RelayCommand]
    private void Elevate()
    {
        if (Elevation.TryRelaunchElevated())
            Application.Current.Shutdown();
        else
            SetResult("Elevation was declined, so nothing changed. Apply and Restore stay unavailable.", "warn");
    }

    [RelayCommand]
    private void OpenLogs()
    {
        try
        {
            AppPaths.EnsureCreated();
            Process.Start(new ProcessStartInfo(AppPaths.Root) { UseShellExecute = true });
        }
        catch (Exception ex) { SetResult($"Could not open {AppPaths.Root}: {ex.Message}", "error"); }
    }

    [RelayCommand]
    private void OpenHostsFile()
    {
        try { Process.Start(new ProcessStartInfo("notepad.exe", AppPaths.HostsFile) { UseShellExecute = true }); }
        catch (Exception ex) { SetResult($"Could not open the hosts file: {ex.Message}", "error"); }
    }

    private async Task RunBusyAsync(string message, Func<Task> work)
    {
        IsBusy = true;
        BusyMessage = message;
        try
        {
            await work().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            Log.Error($"Operation failed: {message}", ex);
            SetResult($"Failed: {ex.Message}", "error");
        }
        finally
        {
            IsBusy = false;
            BusyMessage = "";
        }
    }

    private static string CategoryLabel(RuleCategory c) => c switch
    {
        RuleCategory.Telemetry => "Telemetry & metrics",
        RuleCategory.CrashReporting => "Crash reporting",
        RuleCategory.Updates => "Updates",
        RuleCategory.AdsAnalytics => "Ads & analytics",
        RuleCategory.ApisCdn => "APIs & CDN",
        RuleCategory.AuthCaptcha => "Sign-in & captcha",
        RuleCategory.Push => "Push notifications",
        RuleCategory.Media => "Media & casting",
        RuleCategory.Sync => "Sync",
        RuleCategory.Search => "Search",
        RuleCategory.WindowsIntegration => "Windows & DNS",
        _ => "Containment"
    };
}
