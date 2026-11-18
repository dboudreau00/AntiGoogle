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

using AntiGoogle.Core.Model;

namespace AntiGoogle.Core.Markers;

/// <summary>What a marker is a trace of, and so what may be done about it.</summary>
public enum MarkerClass
{
    /// <summary>A persistent ID or an opt-in record: tells a vendor "this is the same machine or install as before".</summary>
    Identifier,

    /// <summary>Data the vendor's software left behind that nothing needs: crash dumps, metrics buffers.</summary>
    Leftover,

    /// <summary>
    /// A vendor component the vendor re-downloads by itself and the product works without, such as
    /// Chrome's Software Reporter Tool.
    /// </summary>
    OptionalComponent,

    /// <summary>Working software: Chrome, the updater, Drive. Reported, never moved.</summary>
    Component,

    /// <summary>
    /// An endpoint security agent. Reported, never moved, never stopped, and the network rules for its
    /// vendor are refused while it is installed: silently degrading a security control is not de-Googling.
    /// </summary>
    SecurityAgent
}

public enum MarkerKind
{
    File,
    Directory,
    RegistryKey,
    Service
}

public enum MarkerAction
{
    /// <summary>Found and listed; never changed.</summary>
    ReportOnly,

    /// <summary>May be moved into the quarantine vault, when the user asks, and restored exactly.</summary>
    Quarantine
}

/// <summary>How sure the catalog is that the location is right. Shown to the user, never hidden.</summary>
public enum Confidence
{
    /// <summary>Not confirmed against a vendor source or a live installation. Report-only.</summary>
    Low,

    /// <summary>Documented by a secondary source or known from the vendor's open-source code.</summary>
    Medium,

    /// <summary>Documented by the vendor, or seen on a real installation.</summary>
    High
}

/// <summary>
/// One thing that marks a machine as a vendor's: where it lives, what it is, why it matters, and what
/// removing it would cost. Like a <see cref="BlockRule"/> it is declarative, and like one it states
/// its cost honestly.
/// </summary>
public sealed record MarkerDefinition
{
    /// <summary>Stable identity. Persisted in settings and the journal; never renumber these.</summary>
    public required string Id { get; init; }

    /// <summary>"Google", "Mandiant / FireEye / Trellix" ...</summary>
    public required string Vendor { get; init; }

    public required string Title { get; init; }

    /// <summary>What it is and why it matters, in plain language.</summary>
    public required string Why { get; init; }

    public required MarkerKind Kind { get; init; }
    public required MarkerClass Class { get; init; }

    /// <summary>
    /// Where to look. Files and directories use environment tokens (%LOCALAPPDATA%, %PROGRAMDATA%,
    /// %PROGRAMFILES%, %PROGRAMFILES(X86)%, %APPDATA%, %USERPROFILE%); registry keys start with HKLM\ or
    /// HKCU\; services are names, a trailing * meaning "starts with".
    /// </summary>
    public required IReadOnlyList<string> Locations { get; init; }

    public MarkerAction Action { get; init; } = MarkerAction.ReportOnly;
    public Confidence Confidence { get; init; } = Confidence.Medium;

    /// <summary>What it costs to quarantine this marker. Required when <see cref="Action"/> is Quarantine.</summary>
    public IReadOnlyList<Breakage> Breaks { get; init; } = [];

    /// <summary>Quarantining it needs a typed confirmation, like the rules that can lock a user out.</summary>
    public bool RequiresExplicitConsent { get; init; }

    /// <summary>Where the location comes from, so a reviewer can check it.</summary>
    public string? Source { get; init; }

    public bool CanQuarantine => Action == MarkerAction.Quarantine;

    /// <summary>A stable rule id for the journal and audit log.</summary>
    public string JournalRuleId => "marker." + Id;

    public override string ToString() => $"{Id} ({Class}, {Action})";
}

/// <summary>One location of one definition, looked at.</summary>
/// <param name="Location">The expanded path, registry key or service name.</param>
/// <param name="SizeBytes">Files and directories only. A lower bound when <paramref name="Truncated"/>.</param>
/// <param name="Publisher">The signed company name of a file, when it has one.</param>
/// <param name="Note">A short factual note: product records found, value names present, why a size is partial.</param>
public sealed record MarkerFinding(
    MarkerDefinition Definition,
    string Location,
    bool Exists,
    long SizeBytes,
    int FileCount,
    DateTimeOffset? LastWrite,
    string? Publisher,
    bool Truncated,
    bool HasReparsePoint,
    string? Note)
{
    public string SizeLabel => Exists && Definition.Kind is MarkerKind.File or MarkerKind.Directory
        ? Definition.Kind == MarkerKind.Directory && FileCount == 0 && !Truncated ? "empty" : FormatSize(SizeBytes) + (Truncated ? "+" : "")
        : "";

    public static string FormatSize(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:0.#} KB",
        < 1024L * 1024 * 1024 => $"{bytes / 1024.0 / 1024.0:0.#} MB",
        _ => $"{bytes / 1024.0 / 1024.0 / 1024.0:0.##} GB"
    };
}
