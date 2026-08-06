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

using AntiGoogle.Core.Journal;
using AntiGoogle.Core.Model;
using AntiGoogle.Core.Platform;

namespace AntiGoogle.Core.Engines;

/// <summary>
/// Disables scheduled tasks. Tasks are DISABLED, never deleted: a deleted task cannot be put back
/// by this app, and Google's updater recreates them anyway, so deleting buys nothing and costs
/// the ability to undo.
/// </summary>
/// <remarks>
/// Not sealed, and its entry points are virtual, purely so tests can substitute a fake:
/// Disable-ScheduledTask returns "Access is denied" without administrator rights, so orchestration
/// tests have no other way to reach <see cref="ProtectionService.ApplyAsync"/>'s task branch.
/// </remarks>
public class ScheduledTaskEngine : IRevertEngine
{
    public EngineKind Kind => EngineKind.ScheduledTask;

    public sealed record TaskInfo(string Path, bool Enabled);

    /// <summary>Finds tasks whose name matches any pattern. Trailing '*' means prefix match.</summary>
    public virtual async Task<IReadOnlyList<TaskInfo>> ResolveAsync(IReadOnlyList<string> patterns, CancellationToken ct = default)
    {
        var results = new List<TaskInfo>();
        if (patterns.Count == 0) return results;

        // Get-ScheduledTask is the only reliable way to read the enabled/disabled state; schtasks
        // /query output is localised and its column layout shifts between Windows builds.
        var res = await ProcessRunner.PowerShellAsync(
            "Get-ScheduledTask -ErrorAction SilentlyContinue | " +
            "ForEach-Object { \"$($_.TaskPath)$($_.TaskName)|$($_.State)\" }", 60_000, ct).ConfigureAwait(false);

        if (!res.Ok && string.IsNullOrWhiteSpace(res.StdOut))
        {
            Log.Warn($"Scheduled task enumeration failed: {res.Combined}");
            return results;
        }

        foreach (var line in res.StdOut.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = line.Trim().Split('|');
            if (parts.Length != 2) continue;

            var fullPath = parts[0];
            var name = fullPath.TrimEnd('\\').Split('\\').LastOrDefault() ?? "";
            if (string.IsNullOrWhiteSpace(name)) continue;

            var matches = patterns.Any(p =>
            {
                var isPrefix = p.EndsWith('*');
                var needle = isPrefix ? p[..^1] : p;
                return isPrefix
                    ? name.StartsWith(needle, StringComparison.OrdinalIgnoreCase)
                    : string.Equals(name, needle, StringComparison.OrdinalIgnoreCase);
            });
            if (!matches) continue;

            var enabled = !string.Equals(parts[1].Trim(), "Disabled", StringComparison.OrdinalIgnoreCase);
            if (results.Any(r => string.Equals(r.Path, fullPath, StringComparison.OrdinalIgnoreCase))) continue;
            results.Add(new TaskInfo(fullPath, enabled));
        }

        return results;
    }

    public virtual async Task<ChangeOutcome> ApplyAsync(BlockRule rule, TaskInfo task, ChangeJournal journal, CancellationToken ct)
    {
        if (!task.Enabled) return ChangeOutcome.AlreadySatisfied;

        journal.Append(new JournalEntry
        {
            RuleId = rule.Id,
            Engine = EngineKind.ScheduledTask,
            Description = $"Disabled scheduled task {task.Path}",
            Reverse = ReverseKind.RestoreScheduledTask,
            TaskPath = task.Path,
            TaskWasEnabled = true
        });

        var res = await ProcessRunner.PowerShellAsync(SetStateCommand(task.Path, enable: false), 45_000, ct)
                                     .ConfigureAwait(false);

        if (!res.Ok)
            throw new InvalidOperationException($"Disabling {task.Path} failed: {res.Combined}");

        Log.Info($"Scheduled task disabled: {task.Path}");
        return ChangeOutcome.Applied;
    }

    public virtual async Task RevertAsync(JournalEntry entry, CancellationToken ct = default)
    {
        if (entry.TaskPath is null || entry.TaskWasEnabled != true) return;

        var res = await ProcessRunner.PowerShellAsync(SetStateCommand(entry.TaskPath, enable: true), 45_000, ct)
                                     .ConfigureAwait(false);

        if (!res.Ok)
        {
            // The task can legitimately be gone if Google's software was uninstalled meanwhile.
            if (res.Combined.Contains("does not exist", StringComparison.OrdinalIgnoreCase) ||
                res.Combined.Contains("ObjectNotFound", StringComparison.OrdinalIgnoreCase))
            {
                Log.Info($"Scheduled task {entry.TaskPath} no longer exists; nothing to restore.");
                return;
            }
            throw new InvalidOperationException($"Re-enabling {entry.TaskPath} failed: {res.Combined}");
        }

        Log.Info($"Scheduled task re-enabled: {entry.TaskPath}");
    }

    /// <summary>
    /// Disable-/Enable-ScheduledTask take the folder and the name as SEPARATE parameters; handing
    /// a full path to -TaskName silently finds nothing. Split it and pipe from Get-ScheduledTask,
    /// which is the form that reliably resolves a task in a nested folder.
    /// </summary>
    private static string SetStateCommand(string fullPath, bool enable)
    {
        var (folder, name) = SplitTaskPath(fullPath);
        var verb = enable ? "Enable-ScheduledTask" : "Disable-ScheduledTask";
        return $"Get-ScheduledTask -TaskPath '{Escape(folder)}' -TaskName '{Escape(name)}' -ErrorAction Stop " +
               $"| {verb} -ErrorAction Stop | Out-Null";
    }

    /// <summary>"\Foo\Bar" → ("\Foo\", "Bar"). Root tasks come back as ("\", name).</summary>
    internal static (string Folder, string Name) SplitTaskPath(string fullPath)
    {
        var idx = fullPath.LastIndexOf('\\');
        if (idx < 0) return ("\\", fullPath);
        var folder = fullPath[..(idx + 1)];
        if (folder.Length == 0) folder = "\\";
        return (folder, fullPath[(idx + 1)..]);
    }

    /// <summary>Single quotes are the PowerShell string escape; doubling them neutralises injection.</summary>
    private static string Escape(string s) => s.Replace("'", "''");
}
