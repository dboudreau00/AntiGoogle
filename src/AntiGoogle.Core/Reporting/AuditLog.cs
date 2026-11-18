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
using System.Text.Json;

namespace AntiGoogle.Core.Reporting;

/// <summary>One line of history: something Anti-Google did, or tried to, and how it went.</summary>
public sealed record AuditEvent(
    DateTimeOffset At,
    string Kind,
    string? RuleId,
    string? Engine,
    string? Target,
    string? Outcome,
    string? Detail);

/// <summary>
/// An append-only record of what was done to this machine, kept after the journal forgets it. The
/// journal says what can be undone; this says what happened. It is JSON Lines, one event per line, so a
/// torn write loses at most one line, and it never holds a secret: events carry rule ids, paths and
/// outcomes, nothing read from a file or the registry.
/// </summary>
public sealed class AuditLog
{
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = false };
    private static readonly Lock Gate = new();

    private readonly string? _path;

    /// <summary>Writes to <see cref="AppPaths.AuditFile"/> by default.</summary>
    public AuditLog(string? path = null) => _path = path ?? AppPaths.AuditFile;

    private AuditLog(bool disabled) => _path = null;

    /// <summary>Discards everything. What tests use so they never write to the real machine.</summary>
    public static AuditLog Disabled { get; } = new(disabled: true);

    public bool IsEnabled => _path is not null;
    public string? Path => _path;

    public void Append(string kind, string? ruleId = null, string? engine = null, string? target = null,
        string? outcome = null, string? detail = null) =>
        Append(new AuditEvent(DateTimeOffset.Now, kind, ruleId, engine, target, outcome, detail));

    public void Append(AuditEvent e)
    {
        if (_path is null) return;
        try
        {
            lock (Gate)
            {
                var dir = System.IO.Path.GetDirectoryName(_path);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                File.AppendAllText(_path, JsonSerializer.Serialize(e, JsonOpts) + "\n", new UTF8Encoding(false));
            }
        }
        catch (Exception ex)
        {
            // A history that cannot be written must never stop a system change from being undone.
            Log.Warn($"Audit log could not be written: {ex.Message}");
        }
    }

    /// <summary>The newest <paramref name="count"/> events, oldest first. Unreadable lines are skipped.</summary>
    public IReadOnlyList<AuditEvent> Tail(int count)
    {
        var events = new List<AuditEvent>();
        if (_path is null || !File.Exists(_path)) return events;

        try
        {
            string[] lines;
            lock (Gate) lines = File.ReadAllLines(_path, Encoding.UTF8);

            foreach (var line in lines.Skip(Math.Max(0, lines.Length - Math.Max(count, 0) * 2)))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var e = JsonSerializer.Deserialize<AuditEvent>(line, JsonOpts);
                    if (e is not null) events.Add(e);
                }
                catch (JsonException) { /* a torn or foreign line is not worth losing the rest for */ }
            }
        }
        catch (Exception ex)
        {
            Log.Warn($"Audit log could not be read: {ex.Message}");
        }

        return events.Count <= count ? events : events.GetRange(events.Count - count, count);
    }
}
