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
using Microsoft.Win32;

namespace AntiGoogle.Core.Markers;

/// <summary>
/// Looks for markers. Runs without elevation and changes nothing. It reads names, sizes, dates and the
/// signed company name of a program; it never opens a file's contents, because the files it is looking
/// for are the ones that hold identifiers.
/// </summary>
public sealed class MarkerScanner
{
    /// <summary>Bounds a scan so a pathological directory cannot stall it.</summary>
    private const int MaxFiles = 20_000;
    private const long MaxBytesCounted = 8L * 1024 * 1024 * 1024;
    private const int MaxValueNamesShown = 12;

    private readonly IMarkerEnvironment _env;

    public MarkerScanner(IMarkerEnvironment? env = null) => _env = env ?? new SystemMarkerEnvironment();

    public Task<IReadOnlyList<MarkerFinding>> ScanAsync(
        IEnumerable<MarkerDefinition>? definitions = null, CancellationToken ct = default) =>
        Task.Run(() => Scan(definitions ?? MarkerCatalog.All, ct), ct);

    public IReadOnlyList<MarkerFinding> Scan(IEnumerable<MarkerDefinition> definitions, CancellationToken ct = default)
    {
        var findings = new List<MarkerFinding>();
        foreach (var definition in definitions)
        foreach (var location in definition.Locations)
        {
            ct.ThrowIfCancellationRequested();
            try { findings.Add(Inspect(definition, location, ct)); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                Log.Warn($"Marker scan of {definition.Id} at {location} failed: {ex.Message}");
                findings.Add(Absent(definition, location, $"could not be read: {ex.Message}"));
            }
        }
        return findings;
    }

    internal MarkerFinding Inspect(MarkerDefinition definition, string location, CancellationToken ct) =>
        definition.Kind switch
        {
            MarkerKind.File => InspectFile(definition, location),
            MarkerKind.Directory => InspectDirectory(definition, location, ct),
            MarkerKind.RegistryKey => InspectRegistry(definition, location),
            MarkerKind.Service => InspectService(definition, location),
            _ => Absent(definition, location, "unsupported kind")
        };

    private MarkerFinding InspectFile(MarkerDefinition d, string location)
    {
        var path = MarkerPaths.Expand(location, _env, out _);
        if (path is null) return Absent(d, location, "location not understood");
        if (!File.Exists(path)) return Absent(d, path, null);

        var info = new FileInfo(path);
        if (IsLink(info)) return Link(d, path);

        string? publisher = null;
        if (path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
        {
            try { publisher = FileVersionInfo.GetVersionInfo(path).CompanyName?.Trim(); } catch { /* optional */ }
        }

        return new MarkerFinding(d, path, true, info.Length, 1, info.LastWriteTimeUtc, publisher, false, false, null);
    }

    private MarkerFinding InspectDirectory(MarkerDefinition d, string location, CancellationToken ct)
    {
        var path = MarkerPaths.Expand(location, _env, out _);
        if (path is null) return Absent(d, location, "location not understood");
        if (!Directory.Exists(path)) return Absent(d, path, null);

        var dir = new DirectoryInfo(path);
        if (IsLink(dir)) return Link(d, path);

        long bytes = 0;
        var files = 0;
        DateTimeOffset? newest = dir.LastWriteTimeUtc;
        var truncated = false;

        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint,
            ReturnSpecialDirectories = false
        };

        try
        {
            foreach (var file in dir.EnumerateFiles("*", options))
            {
                ct.ThrowIfCancellationRequested();
                files++;
                bytes += file.Length;
                if (newest is null || file.LastWriteTimeUtc > newest) newest = file.LastWriteTimeUtc;
                if (files >= MaxFiles || bytes >= MaxBytesCounted) { truncated = true; break; }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            truncated = true;
        }

        return new MarkerFinding(d, path, true, bytes, files, newest, null, truncated, false,
            files == 0 ? "empty folder" : null);
    }

    private static MarkerFinding InspectRegistry(MarkerDefinition d, string location)
    {
        var slash = location.IndexOf('\\');
        var hive = location[..slash].ToUpperInvariant() == "HKLM" ? RegistryHive.LocalMachine : RegistryHive.CurrentUser;
        var subKey = location[(slash + 1)..];

        using var root = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
        using var key = root.OpenSubKey(subKey);
        if (key is null) return Absent(d, location, null);

        var subKeys = key.GetSubKeyNames().Length;
        var names = key.GetValueNames().Where(n => n.Length > 0).OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList();

        var parts = new List<string>();
        if (subKeys > 0) parts.Add(subKeys == 1 ? "1 product record" : $"{subKeys} product records");
        if (names.Count > 0)
        {
            var shown = string.Join(", ", names.Take(MaxValueNamesShown));
            parts.Add($"values: {shown}{(names.Count > MaxValueNamesShown ? ", ..." : "")} (names only)");
        }

        return new MarkerFinding(d, location, true, 0, 0, null, null, false, false,
            parts.Count == 0 ? "empty key" : string.Join("; ", parts));
    }

    private MarkerFinding InspectService(MarkerDefinition d, string pattern)
    {
        var services = _env.FindServices(pattern);
        return services.Count == 0
            ? Absent(d, pattern, null)
            : new MarkerFinding(d, string.Join(", ", services), true, 0, 0, null, null, false, false, null);
    }

    private static bool IsLink(FileSystemInfo info) => info.Attributes.HasFlag(FileAttributes.ReparsePoint);

    private static MarkerFinding Absent(MarkerDefinition d, string location, string? note) =>
        new(d, location, false, 0, 0, null, null, false, false, note);

    private static MarkerFinding Link(MarkerDefinition d, string path) =>
        new(d, path, true, 0, 0, null, null, false, true, "is a link, so it is reported and never followed or moved");
}
