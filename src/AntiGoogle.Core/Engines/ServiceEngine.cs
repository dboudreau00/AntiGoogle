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
using Microsoft.Win32;

namespace AntiGoogle.Core.Engines;

/// <summary>
/// Disables Windows services by name pattern.
///
/// Start type is read from the registry (authoritative, and enumerable by prefix — Google's
/// updater services carry a version suffix like GoogleUpdaterService152.0.7933.0 that changes
/// on every Chrome release, so exact names are useless here) and written via sc.exe.
/// </summary>
/// <remarks>
/// Not sealed, and its three entry points are virtual, purely so tests can substitute a fake: the
/// mutating paths shell out to sc.exe and cannot run without administrator rights, so orchestration
/// tests have no other way to reach <see cref="ProtectionService.ApplyAsync"/>'s service branch.
/// </remarks>
public class ServiceEngine : IRevertEngine
{
    public EngineKind Kind => EngineKind.Service;

    private const string ServicesKey = @"SYSTEM\CurrentControlSet\Services";
    private const int StartDisabled = 4;

    /// <summary>Resolves a rule's patterns to services that actually exist on this machine.</summary>
    public virtual IReadOnlyList<(string Name, int StartType)> Resolve(IReadOnlyList<string> patterns)
    {
        var found = new List<(string, int)>();
        try
        {
            using var services = Registry.LocalMachine.OpenSubKey(ServicesKey);
            if (services is null) return found;

            var all = services.GetSubKeyNames();
            foreach (var pattern in patterns)
            {
                var isPrefix = pattern.EndsWith('*');
                var needle = isPrefix ? pattern[..^1] : pattern;

                foreach (var name in all)
                {
                    var match = isPrefix
                        ? name.StartsWith(needle, StringComparison.OrdinalIgnoreCase)
                        : string.Equals(name, needle, StringComparison.OrdinalIgnoreCase);
                    if (!match) continue;

                    using var svc = services.OpenSubKey(name);
                    if (svc?.GetValue("Start") is not int start) continue;
                    if (found.Any(f => string.Equals(f.Item1, name, StringComparison.OrdinalIgnoreCase))) continue;

                    found.Add((name, start));
                }
            }
        }
        catch (Exception ex)
        {
            Log.Warn($"Service enumeration failed: {ex.Message}");
        }
        return found;
    }

    public virtual async Task<ChangeOutcome> ApplyAsync(
        BlockRule rule, string serviceName, int previousStart, ChangeJournal journal, CancellationToken ct)
    {
        if (previousStart == StartDisabled)
            return ChangeOutcome.AlreadySatisfied;

        var wasRunning = await IsRunningAsync(serviceName, ct).ConfigureAwait(false);

        journal.Append(new JournalEntry
        {
            RuleId = rule.Id,
            Engine = EngineKind.Service,
            Description = $"Disabled service {serviceName}",
            Reverse = ReverseKind.RestoreServiceStartType,
            ServiceName = serviceName,
            PreviousStartType = previousStart,
            PreviousDelayedAutostart = ReadDelayedAutostart(serviceName),
            PreviousServiceRunning = wasRunning
        });

        if (wasRunning)
        {
            var stop = await ProcessRunner.RunAsync("sc.exe", ["stop", serviceName], 45_000, ct).ConfigureAwait(false);
            // 1062 = service not started; harmless race with something else stopping it first.
            if (!stop.Ok && !stop.Combined.Contains("1062"))
                Log.Warn($"sc stop {serviceName} returned {stop.ExitCode}: {stop.Combined}");
        }

        var cfg = await ProcessRunner.RunAsync("sc.exe", ["config", serviceName, "start=", "disabled"], 30_000, ct)
                                    .ConfigureAwait(false);
        if (!cfg.Ok)
            throw new InvalidOperationException($"sc config {serviceName} failed ({cfg.ExitCode}): {cfg.Combined}");

        Log.Info($"Service {serviceName} disabled (was start={previousStart}, running={wasRunning}).");
        return ChangeOutcome.Applied;
    }

    public virtual async Task RevertAsync(JournalEntry entry, CancellationToken ct = default)
    {
        if (entry.ServiceName is null || entry.PreviousStartType is null) return;

        var startWord = StartWord(entry.PreviousStartType.Value, entry.PreviousDelayedAutostart == true);

        var cfg = await ProcessRunner.RunAsync("sc.exe", ["config", entry.ServiceName, "start=", startWord], 30_000, ct)
                                    .ConfigureAwait(false);

        // 1060 = service no longer installed (Chrome was uninstalled since). Not a failure to revert.
        if (!cfg.Ok && cfg.Combined.Contains("1060"))
        {
            Log.Info($"Service {entry.ServiceName} no longer exists; nothing to restore.");
            return;
        }
        if (!cfg.Ok)
            throw new InvalidOperationException($"Restoring {entry.ServiceName} failed ({cfg.ExitCode}): {cfg.Combined}");

        if (entry.PreviousServiceRunning == true)
        {
            var start = await ProcessRunner.RunAsync("sc.exe", ["start", entry.ServiceName], 45_000, ct)
                                           .ConfigureAwait(false);
            if (!start.Ok) Log.Warn($"Service {entry.ServiceName} restored to '{startWord}' but did not restart: {start.Combined}");
        }

        Log.Info($"Service {entry.ServiceName} restored to start={startWord}.");
    }

    /// <summary>
    /// The sc.exe word that puts a start type back EXACTLY. "Automatic (Delayed Start)" is Start=2 plus a
    /// separate DelayedAutostart flag, and `sc config start= auto` clears that flag, so restoring a
    /// delayed service with plain "auto" silently changes it. Measured on Windows 11: gupdate went from
    /// AUTO_START (DELAYED) to AUTO_START after a round trip. Boot and system starts (drivers) get their
    /// own words rather than being flattened to "demand".
    /// </summary>
    internal static string StartWord(int startType, bool delayed) => startType switch
    {
        0 => "boot",
        1 => "system",
        2 => delayed ? "delayed-auto" : "auto",
        3 => "demand",
        4 => "disabled",
        _ => "demand"
    };

    /// <summary>The DelayedAutostart flag of a service; false when the value is absent, null when unreadable.</summary>
    public virtual bool? ReadDelayedAutostart(string name)
    {
        try
        {
            using var svc = Registry.LocalMachine.OpenSubKey($@"{ServicesKey}\{name}");
            if (svc is null) return null;
            return svc.GetValue("DelayedAutostart") is int d && d == 1;
        }
        catch { return null; }
    }

    private static async Task<bool> IsRunningAsync(string name, CancellationToken ct)
    {
        try
        {
            var res = await ProcessRunner.RunAsync("sc.exe", ["query", name], 20_000, ct).ConfigureAwait(false);
            return res.StdOut.Contains("RUNNING", StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }
}
