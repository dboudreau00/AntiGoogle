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

using System.Globalization;
using AntiGoogle.Core.Journal;
using AntiGoogle.Core.Model;
using Microsoft.Win32;

namespace AntiGoogle.Core.Engines;

/// <summary>
/// Writes Chrome/Edge enterprise policy values.
///
/// Uses the explicit 64-bit view. The Policies hive is not WOW64-redirected today, but pinning the
/// view means a future x86 build cannot silently write somewhere the browser never reads.
/// </summary>
public sealed class RegistryPolicyEngine : IRevertEngine
{
    public EngineKind Kind => EngineKind.Registry;

    private static RegistryKey BaseKey(RegistryHive2 hive) =>
        RegistryKey.OpenBaseKey(
            hive == RegistryHive2.LocalMachine ? RegistryHive.LocalMachine : RegistryHive.CurrentUser,
            RegistryView.Registry64);

    /// <summary>True when the value is already exactly what the rule wants.</summary>
    public bool IsSatisfied(RegistryPolicy policy)
    {
        try
        {
            using var root = BaseKey(policy.Hive);
            using var key = root.OpenSubKey(policy.Key);
            var current = key?.GetValue(policy.Name);
            if (current is null) return false;
            return string.Equals(Stringify(current), Stringify(policy.Value), StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }

    public ChangeOutcome Apply(BlockRule rule, RegistryPolicy policy, ChangeJournal journal)
    {
        if (IsSatisfied(policy)) return ChangeOutcome.AlreadySatisfied;

        using var root = BaseKey(policy.Hive);

        var keyExisted = root.OpenSubKey(policy.Key) is not null;
        object? previous = null;
        RegistryValueKind? previousKind = null;

        if (keyExisted)
        {
            using var read = root.OpenSubKey(policy.Key);
            previous = read?.GetValue(policy.Name);
            if (previous is not null)
            {
                try { previousKind = read!.GetValueKind(policy.Name); }
                catch { previousKind = RegistryValueKind.Unknown; }
            }
        }

        // Journal first. A null PreviousValue is meaningful — it means "delete on revert" — so it
        // must be distinguishable from "we never recorded this", which it is: no entry at all.
        journal.Append(new JournalEntry
        {
            RuleId = rule.Id,
            Engine = EngineKind.Registry,
            Description = previous is null
                ? $"Created {policy.Display}"
                : $"Changed {policy.Display} (was {Stringify(previous)})",
            Reverse = ReverseKind.RestoreRegistryValue,
            RegistryHive = policy.Hive,
            RegistryKey = policy.Key,
            RegistryName = policy.Name,
            PreviousValue = previous is null ? null : Stringify(previous),
            PreviousValueKind = previousKind?.ToString(),
            RegistryKeyCreated = !keyExisted
        });

        using var write = root.CreateSubKey(policy.Key, writable: true)
            ?? throw new InvalidOperationException($"Could not open or create {policy.Key} for writing.");

        write.SetValue(policy.Name, policy.Value, policy.Kind);
        Log.Info($"Registry: {policy.Display}");
        return ChangeOutcome.Applied;
    }

    public Task RevertAsync(JournalEntry entry, CancellationToken ct = default)
    {
        if (entry.RegistryHive is null || entry.RegistryKey is null || entry.RegistryName is null)
            return Task.CompletedTask;

        using var root = BaseKey(entry.RegistryHive.Value);
        using var key = root.OpenSubKey(entry.RegistryKey, writable: true);

        if (key is null)
        {
            Log.Info($"Registry revert: {entry.RegistryKey} no longer exists, nothing to restore.");
            return Task.CompletedTask;
        }

        if (entry.PreviousValue is null)
        {
            // The value did not exist before we wrote it — remove it entirely.
            try { key.DeleteValue(entry.RegistryName, throwOnMissingValue: false); }
            catch (Exception ex) { Log.Warn($"Could not delete {entry.RegistryName}: {ex.Message}"); }

            // If we also created the key and it is now empty, take it back out so the machine
            // looks untouched rather than carrying an empty policy key forever.
            if (entry.RegistryKeyCreated &&
                key.GetValueNames().Length == 0 &&
                key.GetSubKeyNames().Length == 0)
            {
                key.Dispose();
                try
                {
                    root.DeleteSubKey(entry.RegistryKey, throwOnMissingSubKey: false);
                    Log.Info($"Registry: removed empty key {entry.RegistryKey}");
                }
                catch (Exception ex) { Log.Warn($"Could not remove {entry.RegistryKey}: {ex.Message}"); }
            }
        }
        else
        {
            var kind = Enum.TryParse<RegistryValueKind>(entry.PreviousValueKind, out var k) ? k : RegistryValueKind.String;
            key.SetValue(entry.RegistryName, Parse(entry.PreviousValue, kind), kind);
            Log.Info($"Registry: restored {entry.RegistryName} = {entry.PreviousValue}");
        }

        return Task.CompletedTask;
    }


    /// <summary>NUL is the REG_MULTI_SZ element separator, so it can never occur inside an element.</summary>
    private const char MultiStringSeparator = '\u0000';

    private static string Stringify(object value) => value switch
    {
        int i => i.ToString(CultureInfo.InvariantCulture),
        long l => l.ToString(CultureInfo.InvariantCulture),
        string[] arr => string.Join(MultiStringSeparator, arr),
        byte[] bytes => Convert.ToBase64String(bytes),
        _ => value.ToString() ?? ""
    };

    private static object Parse(string raw, RegistryValueKind kind) => kind switch
    {
        RegistryValueKind.DWord => int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var i) ? i : 0,
        RegistryValueKind.QWord => long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var l) ? l : 0L,
        RegistryValueKind.MultiString => raw.Split(MultiStringSeparator),
        RegistryValueKind.Binary => Convert.FromBase64String(raw),
        _ => raw
    };
}
