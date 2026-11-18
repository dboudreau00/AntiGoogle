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

namespace AntiGoogle.Core.Reporting;

/// <summary>Everything the report says, as plain data. The HTML and the JSON are both made from this.</summary>
public sealed class ProtectionReport
{
    public DateTimeOffset GeneratedAt { get; set; }
    public string AppVersion { get; set; } = "";
    public string OsVersion { get; set; } = "";
    public bool Elevated { get; set; }
    public string Profile { get; set; } = "";

    public ReportCounts Counts { get; set; } = new();
    public List<ReportRule> ArmedRules { get; set; } = [];
    public List<string> LocalOnlyApps { get; set; } = [];
    public List<string> ContainedApps { get; set; } = [];

    public ReportHosts Hosts { get; set; } = new();
    public List<ReportFirewallRule> FirewallRules { get; set; } = [];
    public List<ReportService> Services { get; set; } = [];
    public List<ReportTask> Tasks { get; set; } = [];
    public List<ReportRegistryValue> Registry { get; set; } = [];

    public List<ReportQuarantined> Quarantined { get; set; } = [];
    public List<ReportMarker> Markers { get; set; } = [];
    public int MarkersNotFound { get; set; }

    public List<ReportTargetCheck> Verification { get; set; } = [];
    public bool? VerificationPassed { get; set; }
    public List<ReportFinding> Findings { get; set; } = [];
    public List<ReportEvent> Activity { get; set; } = [];
    public List<string> Limits { get; set; } = [];
}

public sealed class ReportCounts
{
    public int SinkholedDomains { get; set; }
    public int LoopbackDomains { get; set; }
    public int FirewallRules { get; set; }
    public int LocalOnlyJails { get; set; }
    public int DisabledServices { get; set; }
    public int DisabledTasks { get; set; }
    public int RegistryValues { get; set; }
    public int QuarantinedItems { get; set; }
    public int UndoableChanges { get; set; }
}

public sealed record ReportCost(string What, string Severity, string Detail);

public sealed record ReportRule(
    string Id, string Title, string Vendor, string Mode, string Layer, string Tier, string Worst, List<ReportCost> Costs);

public sealed class ReportHosts
{
    public List<ReportHostsGroup> Groups { get; set; } = [];
    public List<string> IncompleteNames { get; set; } = [];
}

public sealed record ReportHostsGroup(string RuleId, string Title, string Mode, List<string> Domains);

public sealed record ReportFirewallRule(
    string Name, string Direction, string Action, bool Enabled, string Scope, int RemoteRanges, string RemoteSummary);

public sealed record ReportService(string Name, string Was, string Now, string RuleId, DateTimeOffset At);
public sealed record ReportTask(string Path, string Was, string Now, string RuleId, DateTimeOffset At);
public sealed record ReportRegistryValue(string Location, string Was, string Now, string RuleId, DateTimeOffset At);

public sealed record ReportQuarantined(
    string Title, string Vendor, string OriginalPath, string Class, int Files, long Bytes, string Created, string Id);

public sealed record ReportMarker(
    string Id, string Vendor, string Title, string Class, string Action, string Confidence,
    string Location, string Size, string Note, string Why);

public sealed record ReportCheck(string Name, bool Passed, string Detail);

public sealed record ReportTargetCheck(string Label, string Scope, List<ReportCheck> Checks, List<string> Connections);

public sealed record ReportFinding(string Level, string Title, string Detail);

public sealed record ReportEvent(string At, string Kind, string Rule, string Engine, string Target, string Outcome, string Detail);
