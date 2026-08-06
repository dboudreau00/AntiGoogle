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

namespace AntiGoogle.Core.Discovery;

public enum AppOrigin
{
    /// <summary>Published by Google: Chrome, Drive, Earth, the updater.</summary>
    GoogleFirstParty,

    /// <summary>A Chromium-derived browser. Google's engine, someone else's badge.</summary>
    ChromiumBrowser,

    /// <summary>An Electron/CEF app — Chromium embedded inside unrelated software.</summary>
    ChromiumEmbedded
}

/// <param name="Evidence">Why this binary was flagged, shown verbatim in the UI so the scan is auditable.</param>
public sealed record DiscoveredApp(
    string Name,
    string ExecutablePath,
    AppOrigin Origin,
    string Evidence,
    string? Publisher,
    long SizeBytes)
{
    public string OriginLabel => Origin switch
    {
        AppOrigin.GoogleFirstParty => "Google",
        AppOrigin.ChromiumBrowser => "Chromium browser",
        _ => "Embedded Chromium"
    };
}

/// <summary>
/// Finds binaries that inherit Google's networking stack.
///
/// The interesting detection is <see cref="AppOrigin.ChromiumEmbedded"/>: an Electron or CEF app
/// ships a whole Chromium inside itself, and that Chromium talks to Google endpoints — component
/// updates, crash upload, sometimes Safe Browsing — under the vendor's name, not Google's. The
/// tell is a sibling icudtl.dat / resources.pak next to the exe, which is very hard to fake and
/// very hard to miss.
/// </summary>
public sealed class GoogleAppScanner
{
    private static readonly string[] ChromiumMarkers = ["icudtl.dat", "resources.pak", "chrome_100_percent.pak", "v8_context_snapshot.bin"];

    private static readonly string[] KnownChromiumBrowsers =
        ["chrome.exe", "msedge.exe", "brave.exe", "vivaldi.exe", "opera.exe", "opera_gx.exe", "chromium.exe", "thorium.exe"];

    /// <summary>Bounded so a scan cannot walk an entire disk. Four levels covers every real install layout.</summary>
    private const int MaxDepth = 4;

    public async Task<IReadOnlyList<DiscoveredApp>> ScanAsync(
        IProgress<string>? progress = null, CancellationToken ct = default)
    {
        return await Task.Run(() =>
        {
            var results = new List<DiscoveredApp>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var root in SearchRoots())
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(root)) continue;

                progress?.Report($"Scanning {root}…");
                try
                {
                    Walk(root, 0, results, seen, ct);
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    Log.Warn($"Scan of {root} stopped early: {ex.Message}");
                }
            }

            progress?.Report($"Found {results.Count} Chromium-derived binaries.");
            return (IReadOnlyList<DiscoveredApp>)results
                .OrderBy(r => r.Origin)
                .ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }, ct).ConfigureAwait(false);
    }

    private static IEnumerable<string> SearchRoots()
    {
        yield return Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        yield return Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs");
        yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google");
        yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Google");
    }

    private void Walk(string dir, int depth, List<DiscoveredApp> results, HashSet<string> seen, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (depth > MaxDepth) return;

        var opts = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = false,
            AttributesToSkip = FileAttributes.ReparsePoint  // never follow junctions; they loop
        };

        string[] files;
        try { files = Directory.GetFiles(dir, "*.exe", opts); }
        catch { return; }

        // A directory holding Chromium data files means every exe beside it embeds Chromium.
        var hasChromiumMarker = ChromiumMarkers.Any(m => File.Exists(Path.Combine(dir, m)));

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            if (!seen.Add(file)) continue;

            var classified = Classify(file, hasChromiumMarker);
            if (classified is not null) results.Add(classified);
        }

        string[] subdirs;
        try { subdirs = Directory.GetDirectories(dir, "*", opts); }
        catch { return; }

        foreach (var sub in subdirs)
            Walk(sub, depth + 1, results, seen, ct);
    }

    private static DiscoveredApp? Classify(string file, bool dirHasChromiumMarker)
    {
        var name = Path.GetFileName(file);
        string? publisher = null;
        long size = 0;

        try
        {
            size = new FileInfo(file).Length;
            publisher = FileVersionInfo.GetVersionInfo(file).CompanyName?.Trim();
        }
        catch { /* signed-file metadata is a nicety, not a requirement */ }

        var isGooglePath = file.Contains(@"\Google\", StringComparison.OrdinalIgnoreCase);
        var isGooglePublisher = publisher?.StartsWith("Google", StringComparison.OrdinalIgnoreCase) == true;

        if (isGooglePath || isGooglePublisher)
        {
            var evidence = isGooglePublisher
                ? $"Signed by \"{publisher}\""
                : "Installed under a Google program directory";
            return new DiscoveredApp(FriendlyName(file, name), file, AppOrigin.GoogleFirstParty, evidence, publisher, size);
        }

        if (KnownChromiumBrowsers.Contains(name, StringComparer.OrdinalIgnoreCase))
        {
            return new DiscoveredApp(FriendlyName(file, name), file, AppOrigin.ChromiumBrowser,
                "Known Chromium-derived browser executable", publisher, size);
        }

        if (dirHasChromiumMarker)
        {
            // Electron ships several helper exes; only the main one is worth showing. Helpers are
            // small and live beside a much larger primary binary, so filter on size.
            if (size < 200 * 1024) return null;

            return new DiscoveredApp(FriendlyName(file, name), file, AppOrigin.ChromiumEmbedded,
                "Chromium runtime files (icudtl.dat / resources.pak) alongside this binary", publisher, size);
        }

        return null;
    }

    private static string FriendlyName(string file, string fallback)
    {
        try
        {
            var vi = FileVersionInfo.GetVersionInfo(file);
            if (!string.IsNullOrWhiteSpace(vi.ProductName)) return vi.ProductName.Trim();
            if (!string.IsNullOrWhiteSpace(vi.FileDescription)) return vi.FileDescription.Trim();
        }
        catch { /* fall through */ }
        return fallback;
    }
}
