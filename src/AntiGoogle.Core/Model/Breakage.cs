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
/// A single honest statement of what stops working when the owning rule is armed.
/// These are the whole point of the app: the user is told the cost before paying it, not after.
/// </summary>
/// <param name="What">The user-visible capability that degrades, in plain language.</param>
/// <param name="Severity">How badly.</param>
/// <param name="Detail">Concrete consequence, and the workaround if one exists.</param>
public sealed record Breakage(string What, BreakageSeverity Severity, string Detail)
{
    public static Breakage Minor(string what, string detail) => new(what, BreakageSeverity.Minor, detail);
    public static Breakage Notable(string what, string detail) => new(what, BreakageSeverity.Notable, detail);
    public static Breakage Severe(string what, string detail) => new(what, BreakageSeverity.Severe, detail);
}
