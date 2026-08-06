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

using Microsoft.Win32;

namespace AntiGoogle.Core.Model;

public enum RegistryHive2
{
    LocalMachine,
    CurrentUser
}

/// <summary>
/// One registry value a rule wants to own. The engine records whatever was there before
/// (including "the value did not exist") so revert is exact rather than best-effort.
/// </summary>
public sealed record RegistryPolicy(
    RegistryHive2 Hive,
    string Key,
    string Name,
    object Value,
    RegistryValueKind Kind)
{
    public string Display => $@"{(Hive == RegistryHive2.LocalMachine ? "HKLM" : "HKCU")}\{Key}\{Name} = {Value}";

    public static RegistryPolicy Dword(string key, string name, int value, RegistryHive2 hive = RegistryHive2.LocalMachine)
        => new(hive, key, name, value, RegistryValueKind.DWord);

    public static RegistryPolicy Str(string key, string name, string value, RegistryHive2 hive = RegistryHive2.LocalMachine)
        => new(hive, key, name, value, RegistryValueKind.String);
}
