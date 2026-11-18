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

namespace AntiGoogle.Core.Journal;

/// <summary>How a journalled change is undone.</summary>
public enum ReverseKind
{
    /// <summary>Restore the whole hosts file from a timestamped backup.</summary>
    RestoreHostsBackup,

    /// <summary>Delete a firewall rule we created.</summary>
    RemoveFirewallRule,

    /// <summary>Put a service's start type (and running state) back.</summary>
    RestoreServiceStartType,

    /// <summary>Re-enable a scheduled task we disabled.</summary>
    RestoreScheduledTask,

    /// <summary>Put a registry value back, or delete it if it did not exist before.</summary>
    RestoreRegistryValue
}

/// <summary>
/// One reversible fact: "before Anti-Google touched X, X looked like this."
/// Written BEFORE the corresponding change is made, so a crash mid-apply still leaves a way back.
/// </summary>
public sealed class JournalEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset At { get; set; } = DateTimeOffset.Now;
    public string RuleId { get; set; } = "";
    public EngineKind Engine { get; set; }
    public string Description { get; set; } = "";
    public ReverseKind Reverse { get; set; }

    // --- RestoreHostsBackup ---
    public string? BackupPath { get; set; }

    // --- RemoveFirewallRule ---
    public string? FirewallRuleName { get; set; }

    // --- RestoreServiceStartType ---
    public string? ServiceName { get; set; }
    /// <summary>Win32 service start type: 2=Automatic, 3=Manual, 4=Disabled.</summary>
    public int? PreviousStartType { get; set; }
    public bool? PreviousServiceRunning { get; set; }
    /// <summary>
    /// "Automatic (Delayed Start)" is Start=2 plus this separate flag. Without recording it a restore
    /// turns a delayed service into a plain automatic one.
    /// </summary>
    public bool? PreviousDelayedAutostart { get; set; }

    // --- RestoreScheduledTask ---
    public string? TaskPath { get; set; }
    public bool? TaskWasEnabled { get; set; }

    // --- RestoreRegistryValue ---
    public RegistryHive2? RegistryHive { get; set; }
    public string? RegistryKey { get; set; }
    public string? RegistryName { get; set; }
    /// <summary>Null means the value did not exist and must be deleted on revert.</summary>
    public string? PreviousValue { get; set; }
    public string? PreviousValueKind { get; set; }
    /// <summary>True when we created the key itself; revert removes it if we left it empty.</summary>
    public bool RegistryKeyCreated { get; set; }

    /// <summary>
    /// The shallowest key this change had to create (for instance SOFTWARE\Policies\Google when none of
    /// Policies\Google\Chrome existed). Revert removes the empty keys from the leaf up to and including
    /// it, so the machine does not keep an empty parent that was never there. Null in journals written
    /// before this field existed, which then only ever remove the leaf.
    /// </summary>
    public string? RegistryCreatedRoot { get; set; }

    public override string ToString() => $"{At:yyyy-MM-dd HH:mm} {Description}";
}
