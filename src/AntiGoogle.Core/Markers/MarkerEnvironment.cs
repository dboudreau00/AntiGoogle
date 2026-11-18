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

using AntiGoogle.Core.Engines;

namespace AntiGoogle.Core.Markers;

/// <summary>
/// Everything the scanner and the quarantine engine ask of the machine, so tests can point them at a
/// throwaway directory tree instead of the real user profile.
/// </summary>
public interface IMarkerEnvironment
{
    /// <summary>The folder an environment token stands for, e.g. "%LOCALAPPDATA%". Null when unknown.</summary>
    string? ResolveToken(string token);

    /// <summary>Services whose name matches the pattern (a trailing * means "starts with").</summary>
    IReadOnlyList<string> FindServices(string pattern);

    /// <summary>The Windows directory; nothing beneath it is ever quarantined.</summary>
    string WindowsDirectory { get; }
}

/// <summary>The real machine.</summary>
public sealed class SystemMarkerEnvironment : IMarkerEnvironment
{
    private readonly ServiceEngine _services;

    public SystemMarkerEnvironment(ServiceEngine? services = null) => _services = services ?? new ServiceEngine();

    public string? ResolveToken(string token) => token.ToUpperInvariant() switch
    {
        "%LOCALAPPDATA%" => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "%APPDATA%" => Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "%PROGRAMDATA%" => Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "%PROGRAMFILES%" => Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        "%PROGRAMFILES(X86)%" => Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        "%USERPROFILE%" => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        _ => null
    };

    public IReadOnlyList<string> FindServices(string pattern) =>
        _services.Resolve([pattern]).Select(s => s.Name).ToList();

    public string WindowsDirectory => Environment.GetFolderPath(Environment.SpecialFolder.Windows);
}

/// <summary>Turns a catalog location into a real path, and refuses anything that is not under a known root.</summary>
public static class MarkerPaths
{
    /// <summary>
    /// Expands a leading token. Returns null when the location does not start with a token the
    /// environment knows, so a malformed or hostile location can never become a path.
    /// </summary>
    public static string? Expand(string location, IMarkerEnvironment env, out string? root)
    {
        root = null;
        if (string.IsNullOrWhiteSpace(location) || !location.StartsWith('%')) return null;

        var end = location.IndexOf('%', 1);
        if (end < 0) return null;

        var token = location[..(end + 1)];
        var folder = env.ResolveToken(token);
        if (string.IsNullOrWhiteSpace(folder)) return null;

        var rest = location[(end + 1)..].TrimStart('\\', '/');
        var combined = rest.Length == 0 ? folder : Path.Combine(folder, rest);
        var full = Path.GetFullPath(combined);
        var rootFull = Path.GetFullPath(folder).TrimEnd('\\') + "\\";

        // A location is "root\something". It may not climb out of the root with .. segments.
        if (!(full + "\\").StartsWith(rootFull, StringComparison.OrdinalIgnoreCase)) return null;

        root = Path.GetFullPath(folder);
        return full;
    }

    public static bool IsRegistryLocation(string location) =>
        location.StartsWith(@"HKLM\", StringComparison.OrdinalIgnoreCase) ||
        location.StartsWith(@"HKCU\", StringComparison.OrdinalIgnoreCase);
}
