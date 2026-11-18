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

using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using AntiGoogle.Core;
using Microsoft.Win32;

namespace AntiGoogle.Elevated;

/// <summary>
/// A canonical picture of everything Anti-Google can touch, taken with code that does not share a
/// path with the engines under test (registry through Microsoft.Win32, services through sc.exe,
/// tasks through Export-ScheduledTask, the firewall through Get-NetFirewallRule). Two snapshots
/// that are equal mean the revert really was exact — and a difference names the thing that moved.
/// </summary>
internal static class MachineSnapshot
{
    private static readonly string[] RegistryTrees =
    [
        @"SOFTWARE\Policies\Google",
        @"SOFTWARE\Policies\Microsoft\Edge"
    ];

    public static async Task<SortedDictionary<string, string>> CaptureAsync(
        IEnumerable<string> serviceNames, IEnumerable<string> taskNames, bool includeFirewallTotals = false)
    {
        var d = new SortedDictionary<string, string>(StringComparer.Ordinal);

        // ---- hosts file: content AND the security descriptor (File.Replace can change the ACL) ----
        var hosts = AppPaths.HostsFile;
        var bytes = File.ReadAllBytes(hosts);
        d["hosts.sha256"] = Convert.ToHexString(SHA256.HashData(bytes));
        d["hosts.length"] = bytes.Length.ToString();
        d["hosts.attributes"] = File.GetAttributes(hosts).ToString();
        d["hosts.sddl"] = new FileInfo(hosts).GetAccessControl()
            .GetSecurityDescriptorSddlForm(AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group);

        // ---- firewall ----
        var group = await Tools.PsAsync(
            $"Get-NetFirewallRule -Group '{AppPaths.FirewallGroup}' -ErrorAction SilentlyContinue | Sort-Object DisplayName | ForEach-Object {{ $_.DisplayName }}")
            .ConfigureAwait(false);
        d["fw.group"] = group.StdOut.Replace("\r", "").Trim();
        if (includeFirewallTotals)
        {
            var total = await Tools.PsAsync("@(Get-NetFirewallRule -ErrorAction SilentlyContinue).Count").ConfigureAwait(false);
            d["fw.total"] = total.StdOut.Trim();
        }

        // ---- services: config, state and EVERY registry value under the service key ----
        foreach (var name in serviceNames.OrderBy(n => n, StringComparer.Ordinal))
        {
            var qc = await Tools.ScAsync("qc", name).ConfigureAwait(false);
            d[$"svc.{name}.qc"] = Normalise(qc.StdOut);

            var q = await Tools.ScAsync("query", name).ConfigureAwait(false);
            d[$"svc.{name}.state"] = q.StdOut.Split('\n')
                .Select(l => l.Trim()).FirstOrDefault(l => l.StartsWith("STATE", StringComparison.Ordinal)) ?? "<none>";

            var fail = await Tools.ScAsync("qfailure", name).ConfigureAwait(false);
            d[$"svc.{name}.failure"] = Normalise(fail.StdOut);

            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{name}");
            var sb = new StringBuilder();
            DumpKey(key, $@"Services\{name}", sb);
            d[$"svc.{name}.registry"] = sb.ToString();
        }

        // ---- scheduled tasks: one PowerShell call for all of them, hashing the exported XML inside it ----
        var names = taskNames.OrderBy(n => n, StringComparer.Ordinal).ToList();
        if (names.Count > 0)
        {
            var list = string.Join(",", names.Select(n => $"'{n}'"));
            var res = await Tools.PsAsync(
                $"foreach ($n in @({list})) {{ $t = Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue; " +
                "if ($t) { $xml = (Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath | Out-String).Trim(); " +
                "$h = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($xml))) -replace '-',''; " +
                "\"$n|$($t.State)|$h\" } else { \"$n|<absent>|\" } }").ConfigureAwait(false);

            var seen = res.StdOut.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Select(l => l.Trim().Split('|')).Where(p => p.Length == 3).ToDictionary(p => p[0], p => p);
            foreach (var name in names)
                d[$"task.{name}"] = seen.TryGetValue(name, out var p)
                    ? (p[1] == "<absent>" ? "<absent>" : $"{p[1]} xml:{p[2]}")
                    : "<unreadable>";
        }

        // ---- policy registry trees ----
        foreach (var tree in RegistryTrees)
        {
            using var key = Registry.LocalMachine.OpenSubKey(tree);
            var sb = new StringBuilder();
            DumpKey(key, tree, sb);
            d[$"reg.{tree}"] = sb.ToString();
        }

        // ---- Anti-Google's own state ----
        // Whether journal.json exists is not machine state (an empty journal file is what a finished
        // revert leaves); whether it still holds entries is.
        d["journal.entries"] = File.Exists(AppPaths.JournalFile)
            ? File.ReadAllText(AppPaths.JournalFile).Trim() switch { "" or "[]" => "0", _ => "non-empty" }
            : "0";
        return d;
    }

    /// <summary>Every difference, as "key: before / after". Empty means the two snapshots are identical.</summary>
    public static List<string> Diff(IReadOnlyDictionary<string, string> before, IReadOnlyDictionary<string, string> after)
    {
        var lines = new List<string>();
        foreach (var key in before.Keys.Union(after.Keys).OrderBy(k => k, StringComparer.Ordinal))
        {
            before.TryGetValue(key, out var a);
            after.TryGetValue(key, out var b);
            if (string.Equals(a, b, StringComparison.Ordinal)) continue;
            lines.Add($"{key}:\n      before: {Short(a)}\n      after : {Short(b)}");
        }
        return lines;
    }

    private static string Short(string? s) =>
        s is null ? "<missing>" : s.Length <= 700 ? s.Replace("\n", " / ") : s[..700].Replace("\n", " / ") + " ...";

    private static string Normalise(string text) =>
        string.Join(" / ", text.Replace("\r", "").Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0));

    private static void DumpKey(RegistryKey? key, string path, StringBuilder sb)
    {
        if (key is null) { sb.AppendLine($"[{path}] <absent>"); return; }

        sb.AppendLine($"[{path}]");
        foreach (var name in key.GetValueNames().OrderBy(n => n, StringComparer.Ordinal))
        {
            var kind = key.GetValueKind(name);
            var value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            sb.AppendLine($"  {(name.Length == 0 ? "(default)" : name)}|{kind}|{Render(value)}");
        }

        foreach (var sub in key.GetSubKeyNames().OrderBy(n => n, StringComparer.Ordinal))
        {
            using var child = key.OpenSubKey(sub);
            DumpKey(child, $@"{path}\{sub}", sb);
        }
    }

    private static string Render(object? value) => value switch
    {
        null => "<null>",
        byte[] b => Convert.ToHexString(b),
        string[] s => string.Join(";", s),
        _ => value.ToString() ?? ""
    };
}
