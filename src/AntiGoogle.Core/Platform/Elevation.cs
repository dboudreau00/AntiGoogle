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

using System.Diagnostics;
using System.Security.Principal;

namespace AntiGoogle.Core.Platform;

/// <summary>
/// The app runs as-invoker so it can boot, scan and show you exactly what it would do without
/// ever asking for admin. Only Apply and Revert need elevation, and both check here first.
/// </summary>
public static class Elevation
{
    public static bool IsElevated
    {
        get
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// Relaunches this executable through the UAC shell verb and asks the caller to shut down.
    /// Returns false if the user dismissed the consent prompt.
    /// </summary>
    public static bool TryRelaunchElevated(string? arguments = null)
    {
        try
        {
            var exe = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exe)) return false;

            var psi = new ProcessStartInfo
            {
                FileName = exe,
                UseShellExecute = true,   // required for the runas verb
                Verb = "runas",
                WorkingDirectory = AppContext.BaseDirectory
            };
            if (!string.IsNullOrWhiteSpace(arguments)) psi.Arguments = arguments;

            Process.Start(psi);
            return true;
        }
        catch (Exception ex)
        {
            // ERROR_CANCELLED (1223) when the user clicks No on the UAC dialog. Not an error worth shouting about.
            Log.Warn($"Elevation declined or failed: {ex.Message}");
            return false;
        }
    }
}
