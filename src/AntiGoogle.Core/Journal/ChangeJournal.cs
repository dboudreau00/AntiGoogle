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

using System.Text.Json;
using System.Text.Json.Serialization;

namespace AntiGoogle.Core.Journal;

/// <summary>
/// The undo log. Every OS write this app performs has a matching entry recorded first.
/// Persisted to ProgramData so a later elevated run — or a different admin — can still revert.
/// </summary>
public sealed class ChangeJournal
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly List<JournalEntry> _entries = [];
    private readonly string _path;

    public ChangeJournal(string? path = null) => _path = path ?? AppPaths.JournalFile;

    public IReadOnlyList<JournalEntry> Entries => _entries;

    public bool HasChanges => _entries.Count > 0;

    public void Load()
    {
        _entries.Clear();
        try
        {
            if (!File.Exists(_path)) return;
            var json = File.ReadAllText(_path);
            if (string.IsNullOrWhiteSpace(json)) return;
            var loaded = JsonSerializer.Deserialize<List<JournalEntry>>(json, JsonOpts);
            if (loaded is not null) _entries.AddRange(loaded);
            Log.Info($"Journal loaded: {_entries.Count} reversible entries.");
        }
        catch (Exception ex)
        {
            // A corrupt journal must not be silently discarded — that would strand the user's
            // machine in a modified state with no record. Preserve it and surface the problem.
            Log.Error("Journal load failed; preserving the file for inspection.", ex);
            TryPreserveCorrupt();
            throw new InvalidOperationException(
                $"The change journal at {_path} could not be read, so Anti-Google cannot safely " +
                "revert. A copy was preserved alongside it. Restore changes manually or delete the " +
                "journal to start fresh (this abandons undo information).", ex);
        }
    }

    private void TryPreserveCorrupt()
    {
        try
        {
            if (File.Exists(_path))
                File.Copy(_path, _path + $".corrupt-{DateTime.Now:yyyyMMdd-HHmmss}", overwrite: false);
        }
        catch { /* best effort */ }
    }

    /// <summary>Record a reverse fact and flush immediately — durability matters more than speed here.</summary>
    public void Append(JournalEntry entry)
    {
        _entries.Add(entry);
        Save();
    }

    public void Remove(JournalEntry entry)
    {
        _entries.Remove(entry);
        Save();
    }

    public void Clear()
    {
        _entries.Clear();
        Save();
    }

    /// <summary>Newest first — the order a correct undo must replay in.</summary>
    public IReadOnlyList<JournalEntry> ReplayOrder() =>
        _entries.OrderByDescending(e => e.At).ThenByDescending(e => e.Id, StringComparer.Ordinal).ToList();

    public IEnumerable<JournalEntry> ForRule(string ruleId) =>
        _entries.Where(e => string.Equals(e.RuleId, ruleId, StringComparison.OrdinalIgnoreCase));

    /// <summary>Atomic write: temp file, flush to disk, then replace. A torn journal is unrecoverable.</summary>
    public void Save()
    {
        AppPaths.EnsureCreated();
        var json = JsonSerializer.Serialize(_entries, JsonOpts);
        var tmp = _path + ".tmp";

        using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        using (var sw = new StreamWriter(fs))
        {
            sw.Write(json);
            sw.Flush();
            fs.Flush(flushToDisk: true);
        }

        if (File.Exists(_path)) File.Replace(tmp, _path, null);
        else File.Move(tmp, _path);
    }
}
