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

    /// <summary>Domains our managed block resolves to this machine (127.0.0.1) — the local-only mode.</summary>
    public IReadOnlyList<string> CurrentlyLooped()
    {
        try
        {
            if (!File.Exists(_hostsPath)) return [];
            var (_, managed, _) = Split(File.ReadAllText(_hostsPath));
            return managed
                .Where(l => l.StartsWith(AppPaths.LoopbackV4, StringComparison.Ordinal))
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

    /// <summary>One rule's section of the managed block, read back from the live file.</summary>
    public sealed record HostsGroup(string RuleId, string Title, bool LocalOnly, IReadOnlyList<string> Domains);

    /// <summary>What the managed block holds right now, read back rather than assumed.</summary>
    public sealed record HostsAudit(
        IReadOnlyList<string> Sinkholed, IReadOnlyList<string> Looped,
        IReadOnlyList<string> Incomplete, IReadOnlyList<HostsGroup> Groups);

    /// <summary>
    /// Parses the live managed block: which names are sinkholed, which resolve to this machine, and which
    /// are missing one of the two address families (an IPv4-only entry is routinely defeated by an AAAA
    /// fallback, which is why every name must be written for both).
    /// </summary>
    public HostsAudit Audit()
    {
        var sinkholed = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        var looped = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        var families = new Dictionary<string, (bool V4, bool V6)>(StringComparer.OrdinalIgnoreCase);
        var groups = new List<(string Id, string Title, bool LocalOnly, List<string> Domains)>();

        try
        {
            if (File.Exists(_hostsPath))
            {
                var (_, managed, _) = Split(File.ReadAllText(_hostsPath));
                foreach (var line in managed)
                {
                    if (line.StartsWith("# --- ", StringComparison.Ordinal))
                    {
                        var header = line[6..];
                        var localOnly = header.Contains("[local-only", StringComparison.Ordinal);
                        var bracket = header.IndexOf(" [local-only", StringComparison.Ordinal);
                        if (bracket >= 0) header = header[..bracket];
                        var colon = header.IndexOf(": ", StringComparison.Ordinal);
                        groups.Add(colon > 0
                            ? (header[..colon], header[(colon + 2)..], localOnly, [])
                            : (header, header, localOnly, []));
                        continue;
                    }

                    if (line.StartsWith('#') || line.Length == 0) continue;
                    var parts = line.Split((char[])[' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 2) continue;

                    var (ip, name) = (parts[0], parts[1]);
                    var isLoop = ip is AppPaths.LoopbackV4 or AppPaths.LoopbackV6;
                    var isSink = ip is AppPaths.SinkholeV4 or AppPaths.SinkholeV6;
                    if (!isLoop && !isSink) continue;

                    (isLoop ? looped : sinkholed).Add(name);
                    var seen = families.GetValueOrDefault(name);
                    families[name] = ip.Contains(':') ? (seen.V4, true) : (true, seen.V6);
                    if (groups.Count > 0 && !groups[^1].Domains.Contains(name, StringComparer.OrdinalIgnoreCase))
                        groups[^1].Domains.Add(name);
                }
            }
        }
        catch (Exception ex)
        {
            Log.Warn($"Could not audit the managed hosts block: {ex.Message}");
        }

        return new HostsAudit(
            [.. sinkholed], [.. looped],
            families.Where(kv => !(kv.Value.V4 && kv.Value.V6)).Select(kv => kv.Key).OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList(),
            groups.Select(g => new HostsGroup(g.Id, g.Title, g.LocalOnly, g.Domains)).ToList());
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
    /// <param name="loopbackRuleIds">
    /// Rules in local-only mode. Their names resolve to this machine (127.0.0.1 and ::1) instead of
    /// being sinkholed. A name that ANY blocking rule also lists stays sinkholed: when two rules
    /// disagree, the stricter one wins, and the line says so.
    /// </param>
    public async Task ApplyAsync(
        IReadOnlyList<BlockRule> hostsRules, ChangeJournal journal, CancellationToken ct = default,
        IReadOnlySet<string>? loopbackRuleIds = null)
    {
        var loopRules = loopbackRuleIds ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var modes = EffectiveModes(hostsRules, loopRules);

        var domains = modes.Keys.OrderBy(d => d, StringComparer.Ordinal).ToList();
        var looped = modes.Count(kv => kv.Value);
        var sinkholed = domains.Count - looped;

        var original = File.ReadAllText(_hostsPath);
        var backupPath = WriteBackup(original);

        // Journal BEFORE writing. If the process dies between these two lines the worst case is a
        // stale journal entry, which reverts to a no-op. The reverse is unrecoverable.
        journal.Append(new JournalEntry
        {
            RuleId = string.Join(",", hostsRules.Select(r => r.Id)),
            Engine = EngineKind.Hosts,
            Description = looped == 0
                ? $"Sinkholed {domains.Count} Google domains in the hosts file"
                : $"Wrote {domains.Count} Google domains to the hosts file ({sinkholed} sinkholed, {looped} resolved to this machine)",
            Reverse = ReverseKind.RestoreHostsBackup,
            BackupPath = backupPath
        });

        var (before, _, after) = Split(original);
        var sb = new StringBuilder();
        sb.Append(before.TrimEnd('\r', '\n'));
        if (before.Trim().Length > 0) sb.Append("\r\n\r\n");

        sb.Append(AppPaths.HostsBeginMarker).Append("\r\n");
        sb.Append($"# Generated {DateTime.Now:yyyy-MM-dd HH:mm:ss} by Anti-Google.\r\n");
        sb.Append($"# {domains.Count} domains from {hostsRules.Count} rules. Both A and AAAA are covered: sinkholed to " +
                  $"{AppPaths.SinkholeV4} / {AppPaths.SinkholeV6}, or {AppPaths.LoopbackV4} / {AppPaths.LoopbackV6} for local-only rules.\r\n");
        sb.Append("# Do not hand-edit inside these markers — the block is regenerated on every apply.\r\n");
        sb.Append("# To remove: Anti-Google -> Restore Everything.\r\n");

        foreach (var rule in hostsRules.OrderBy(r => r.Id, StringComparer.Ordinal))
        {
            var ruleIsLocalOnly = loopRules.Contains(rule.Id);
            var tag = ruleIsLocalOnly ? " [local-only: resolves to this machine]" : "";
            sb.Append($"#\r\n# --- {rule.Id}: {rule.Title}{tag}\r\n");
            foreach (var d in rule.Domains.Select(x => x.Trim().ToLowerInvariant())
                                          .Where(x => x.Length > 0)
                                          .Distinct(StringComparer.OrdinalIgnoreCase)
                                          .OrderBy(x => x, StringComparer.Ordinal))
            {
                var loop = modes[d];
                var note = ruleIsLocalOnly && !loop ? "  # sinkholed: another armed rule also lists this name" : "";
                sb.Append(loop ? AppPaths.LoopbackV4 : AppPaths.SinkholeV4).Append(' ').Append(d).Append(note).Append("\r\n");
                sb.Append(loop ? AppPaths.LoopbackV6 : AppPaths.SinkholeV6).Append(' ').Append(d).Append(note).Append("\r\n");
            }
        }

        sb.Append(AppPaths.HostsEndMarker).Append("\r\n");

        if (!string.IsNullOrWhiteSpace(after))
        {
            sb.Append("\r\n").Append(after.TrimStart('\r', '\n'));
        }

        await WriteAtomicAsync(sb.ToString(), ct).ConfigureAwait(false);
        Log.Info($"Hosts: wrote {domains.Count} domains ({sinkholed} sinkholed, {looped} looped to this machine; {domains.Count * 2} lines).");
    }

    /// <summary>
    /// For every name any rule lists: does it resolve to this machine (true) or nowhere (false)?
    /// Loopback only when EVERY rule listing the name is local-only. Fail closed: a name one armed
    /// rule wants blocked is blocked, whatever another rule would have preferred.
    /// </summary>
    internal static Dictionary<string, bool> EffectiveModes(
        IReadOnlyList<BlockRule> hostsRules, IReadOnlySet<string> loopbackRuleIds)
    {
        var modes = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in hostsRules)
        {
            var wantsLoopback = loopbackRuleIds.Contains(rule.Id);
            foreach (var d in rule.Domains.Select(x => x.Trim().ToLowerInvariant()).Where(x => x.Length > 0))
                modes[d] = modes.TryGetValue(d, out var already) ? already && wantsLoopback : wantsLoopback;
        }
        return modes;
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
    /// Stage the new content in a temp file first (proof the directory is writable and the disk has the
    /// room), then overwrite the hosts file IN PLACE.
    ///
    /// In place, rather than File.Replace, because replacing swaps in a brand-new file, and a brand-new
    /// file carries its creator's owner and a default ACL: measured on Windows 11, apply followed by
    /// revert left the hosts file owned by Administrators instead of SYSTEM with an extra explicit ACE,
    /// which breaks the "revert is exact" promise and is exactly what tamper-detection tools watch for.
    /// Overwriting the same file object keeps its owner, ACL, attributes and creation time untouched.
    /// The file is a few kilobytes, written in one call after the staging copy proved it will fit, and
    /// a timestamped backup of the original is always on disk beside the journal.
    ///
    /// Only if the in-place write is refused (another process holds it open for writing, or security
    /// software has locked it) does this fall back to replacing the file.
    /// </summary>
    private async Task WriteAtomicAsync(string content, CancellationToken ct)
    {
        var dir = Path.GetDirectoryName(_hostsPath)!;
        var tmp = Path.Combine(dir, $"hosts.antigoogle.{Environment.ProcessId}.tmp");
        var bytes = new UTF8Encoding(false).GetBytes(content);

        using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            fs.Write(bytes, 0, bytes.Length);
            fs.Flush(flushToDisk: true);
        }

        try
        {
            if (!TryWriteInPlace(bytes))
            {
                try
                {
                    File.Replace(tmp, _hostsPath, null);
                }
                catch (Exception)
                {
                    // File.Replace needs both files on one volume and can trip over security software
                    // holding a handle. A plain overwrite-copy keeps the destination's ACL because the
                    // destination already exists.
                    File.Copy(tmp, _hostsPath, overwrite: true);
                }
            }
        }
        finally
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { /* leftover temp is harmless */ }
        }

        await FlushDnsCacheAsync(ct).ConfigureAwait(false);
    }

    private bool TryWriteInPlace(byte[] bytes)
    {
        try
        {
            using var fs = new FileStream(_hostsPath, FileMode.Open, FileAccess.Write, FileShare.Read);
            fs.SetLength(0);
            fs.Write(bytes, 0, bytes.Length);
            fs.Flush(flushToDisk: true);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Log.Warn($"Hosts: in-place write refused ({ex.Message}); falling back to replacing the file.");
            return false;
        }
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
