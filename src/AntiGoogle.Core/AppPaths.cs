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
namespace AntiGoogle.Core;

/// <summary>
/// Every path the app touches, in one place. State lives under ProgramData because the changes
/// are machine-wide: a per-user AppData journal would be invisible to another admin trying to undo.
/// </summary>
public static class AppPaths
{
    public static string Root { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AntiGoogle");

    public static string Backups => Path.Combine(Root, "backups");
    public static string Logs => Path.Combine(Root, "logs");
    public static string JournalFile => Path.Combine(Root, "journal.json");
    public static string SettingsFile => Path.Combine(Root, "settings.json");

    public static string HostsFile { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");

    /// <summary>Marker written into the hosts file so our lines are removable without guesswork.</summary>
    public const string HostsBeginMarker = "# >>> ANTI-GOOGLE BEGIN — managed block, do not edit by hand >>>";
    public const string HostsEndMarker = "# <<< ANTI-GOOGLE END <<<";

    /// <summary>Firewall rule group. Every rule we create carries it, so cleanup is one sweep.</summary>
    public const string FirewallGroup = "Anti-Google";

    public static void EnsureCreated()
    {
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(Backups);
        Directory.CreateDirectory(Logs);
    }
}
