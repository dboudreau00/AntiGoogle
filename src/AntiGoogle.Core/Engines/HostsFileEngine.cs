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

using System.Text;
using AntiGoogle.Core.Journal;
using AntiGoogle.Core.Model;

namespace AntiGoogle.Core.Engines;

/// <summary>
/// Owns a single delimited block inside the Windows hosts file.
///
/// Two decisions worth knowing about:
///  * Every domain gets BOTH an IPv4 (0.0.0.0) and an IPv6 (::) sinkhole. A v4-only blocklist is
///    routinely defeated by an app falling back to the AAAA record.
///  * Revert STRIPS the managed block from the current file rather than restoring the backup.
///    Restoring a stale backup would silently throw away any hosts edits the user made in the
///    meantime. The backup is still written and surfaced in the UI as a manual escape hatch.
/// </summary>
public sealed class HostsFileEngine : IRevertEngine
{
    public EngineKind Kind => EngineKind.Hosts;

    private readonly string _hostsPath;
    private readonly string _backupDir;

    /// <param name="hostsPath">Defaults to the real hosts file.</param>
    /// <param name="backupDir">
    /// Where the pre-apply backup is written. Defaults to <see cref="AppPaths.Backups"/>. Tests point
    /// this at a temp directory — without it, exercising the engine against a throwaway hosts file
    /// still deposits backups into the machine's real ProgramData.
    /// </param>
    public HostsFileEngine(string? hostsPath = null, string? backupDir = null)
    {
        _hostsPath = hostsPath ?? AppPaths.HostsFile;
        _backupDir = backupDir ?? AppPaths.Backups;
    }

    /// <summary>Domains currently sinkholed by our managed block.</summary>
    public IReadOnlyList<string> CurrentlyBlocked()
    {
        try
        {
            if (!File.Exists(_hostsPath)) return [];
            var (_, managed, _) = Split(File.ReadAllText(_hostsPath));
            return managed
                .Where(l => l.StartsWith("0.0.0.0", StringComparison.Ordinal))
                .Select(l => l.Split((char[])[' ', '\t'], StringSplitOptions.RemoveEmptyEntries))
                .Where(p => p.Length >= 2)
                .Select(p => p[1])
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch (Exception ex)
        {
            Log.Warn($"Could not read managed hosts block: {ex.Message}");
            return [];
        }
    }

    public bool HasManagedBlock()
    {
        try
        {
            return File.Exists(_hostsPath)
                && File.ReadAllText(_hostsPath).Contains(AppPaths.HostsBeginMarker, StringComparison.Ordinal);
        }
        catch { return false; }
    }

    /// <summary>
    /// Rewrites the managed block to cover exactly the supplied rules. Called once per apply with
    /// every enabled hosts rule — the block is regenerated wholesale, never appended to.
    /// </summary>
    public async Task ApplyAsync(IReadOnlyList<BlockRule> hostsRules, ChangeJournal journal, CancellationToken ct = default)
    {
        var domains = hostsRules
            .SelectMany(r => r.Domains)
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .Select(d => d.Trim().ToLowerInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(d => d, StringComparer.Ordinal)
            .ToList();

        var original = File.ReadAllText(_hostsPath);
        var backupPath = WriteBackup(original);

        // Journal BEFORE writing. If the process dies between these two lines the worst case is a
        // stale journal entry, which reverts to a no-op. The reverse is unrecoverable.
        journal.Append(new JournalEntry
        {
            RuleId = string.Join(",", hostsRules.Select(r => r.Id)),
            Engine = EngineKind.Hosts,
            Description = $"Sinkholed {domains.Count} Google domains in the hosts file",
            Reverse = ReverseKind.RestoreHostsBackup,
            BackupPath = backupPath
        });

        var (before, _, after) = Split(original);
        var sb = new StringBuilder();
        sb.Append(before.TrimEnd('\r', '\n'));
        if (before.Trim().Length > 0) sb.Append("\r\n\r\n");

        sb.Append(AppPaths.HostsBeginMarker).Append("\r\n");
        sb.Append($"# Generated {DateTime.Now:yyyy-MM-dd HH:mm:ss} by Anti-Google.\r\n");
        sb.Append($"# {domains.Count} domains from {hostsRules.Count} rules. Both A and AAAA are sinkholed.\r\n");
        sb.Append("# Do not hand-edit inside these markers — the block is regenerated on every apply.\r\n");
        sb.Append("# To remove: Anti-Google -> Restore Everything.\r\n");

        foreach (var rule in hostsRules.OrderBy(r => r.Id, StringComparer.Ordinal))
        {
            sb.Append($"#\r\n# --- {rule.Id}: {rule.Title}\r\n");
            foreach (var d in rule.Domains.Select(x => x.Trim().ToLowerInvariant())
                                          .Distinct(StringComparer.OrdinalIgnoreCase)
                                          .OrderBy(x => x, StringComparer.Ordinal))
            {
                sb.Append("0.0.0.0 ").Append(d).Append("\r\n");
                sb.Append(":: ").Append(d).Append("\r\n");
            }
        }

        sb.Append(AppPaths.HostsEndMarker).Append("\r\n");

        if (!string.IsNullOrWhiteSpace(after))
        {
            sb.Append("\r\n").Append(after.TrimStart('\r', '\n'));
        }

        await WriteAtomicAsync(sb.ToString(), ct).ConfigureAwait(false);
        Log.Info($"Hosts: wrote {domains.Count} sinkholed domains ({domains.Count * 2} lines).");
    }

    public async Task RevertAsync(JournalEntry entry, CancellationToken ct = default)
    {
        try
        {
            if (!File.Exists(_hostsPath)) return;

            var current = File.ReadAllText(_hostsPath);
            if (!current.Contains(AppPaths.HostsBeginMarker, StringComparison.Ordinal))
            {
                Log.Info("Hosts revert: no managed block present, nothing to do.");
                return;
            }

            var (before, _, after) = Split(current);
            var rebuilt = (before.TrimEnd('\r', '\n') + "\r\n" + after.TrimStart('\r', '\n')).TrimEnd() + "\r\n";
            await WriteAtomicAsync(rebuilt, ct).ConfigureAwait(false);
            Log.Info("Hosts: managed block removed; user entries preserved.");
        }
        catch (Exception ex)
        {
            Log.Error("Hosts revert failed.", ex);
            throw;
        }
    }

    private string WriteBackup(string content)
    {
        Directory.CreateDirectory(_backupDir);
        var path = Path.Combine(_backupDir, $"hosts-{DateTime.Now:yyyyMMdd-HHmmss-fff}.bak");
        File.WriteAllText(path, content, new UTF8Encoding(false));
        Log.Info($"Hosts backed up to {path}");
        return path;
    }

    /// <summary>
    /// Write to a temp file in the same directory, then replace. A half-written hosts file would
    /// break name resolution machine-wide, so this must never be a partial write.
    /// </summary>
    private async Task WriteAtomicAsync(string content, CancellationToken ct)
    {
        var dir = Path.GetDirectoryName(_hostsPath)!;
        var tmp = Path.Combine(dir, $"hosts.antigoogle.{Environment.ProcessId}.tmp");

        using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        using (var sw = new StreamWriter(fs, new UTF8Encoding(false)))
        {
            sw.Write(content);
            sw.Flush();
            fs.Flush(flushToDisk: true);
        }

        try
        {
            File.Replace(tmp, _hostsPath, null);
        }
        catch (Exception)
        {
            // File.Replace preserves ACLs but needs both files on one volume and can trip over
            // security software holding a handle. Fall back to a plain copy, which keeps the
            // original file's ACL because the destination already exists.
            File.Copy(tmp, _hostsPath, overwrite: true);
            try { File.Delete(tmp); } catch { /* leftover temp is harmless */ }
        }

        await FlushDnsCacheAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Without this the OS keeps serving stale answers and the block looks like it silently failed.
    /// Awaited rather than blocked on: this runs from the UI thread during Apply, and
    /// .GetAwaiter().GetResult() here would freeze the window for the duration.
    /// </summary>
    private static async Task FlushDnsCacheAsync(CancellationToken ct)
    {
        try
        {
            await Platform.ProcessRunner.RunAsync("ipconfig.exe", ["/flushdns"], 15_000, ct).ConfigureAwait(false);
            Log.Info("DNS cache flushed.");
        }
        catch (Exception ex)
        {
            Log.Warn($"DNS flush failed (entries still apply once cached records expire): {ex.Message}");
        }
    }

    /// <summary>Splits a hosts file into the text before, inside, and after our markers.</summary>
    private static (string Before, string[] Managed, string After) Split(string content)
    {
        var startIdx = content.IndexOf(AppPaths.HostsBeginMarker, StringComparison.Ordinal);
        if (startIdx < 0) return (content, [], "");

        var endIdx = content.IndexOf(AppPaths.HostsEndMarker, startIdx, StringComparison.Ordinal);
        if (endIdx < 0)
        {
            // Truncated block (a crash mid-write, or a hand edit). Treat everything from the begin
            // marker on as ours rather than leaving orphaned sinkholes behind.
            Log.Warn("Hosts: begin marker without end marker — treating the remainder as managed.");
            return (content[..startIdx], content[startIdx..].Split('\n'), "");
        }

        var endOfEnd = endIdx + AppPaths.HostsEndMarker.Length;
        var managed = content[startIdx..endOfEnd].Split('\n').Select(l => l.Trim()).ToArray();
        return (content[..startIdx], managed, content[endOfEnd..]);
    }
}
