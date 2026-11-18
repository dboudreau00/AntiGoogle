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
using AntiGoogle.Core;
using AntiGoogle.Core.Platform;

namespace AntiGoogle.Elevated;

internal sealed record Options(
    bool Confirmed, bool AllowPhysical, bool ForceDirty, string Scenario, string OutDir, string? OffBoxPeer)
{
    public static Options Parse(string[] args)
    {
        bool Has(string flag) => args.Contains(flag, StringComparer.OrdinalIgnoreCase);
        string? Value(string flag)
        {
            var i = Array.FindIndex(args, a => string.Equals(a, flag, StringComparison.OrdinalIgnoreCase));
            return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
        }

        return new Options(
            Confirmed: Has("--yes-modify-this-machine"),
            AllowPhysical: Has("--allow-physical"),
            ForceDirty: Has("--force-dirty"),
            Scenario: Value("--scenario") ?? "all",
            OutDir: Value("--out") ?? Path.Combine(FixtureSet.Root, "out"),
            OffBoxPeer: Value("--off-box-peer"));
    }
}

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        var opts = Options.Parse(args);

        Console.WriteLine("Anti-Google - elevated end-to-end harness");
        Console.WriteLine(new string('=', 70));

        if (!opts.Confirmed)
        {
            Console.WriteLine(
                "This harness MODIFIES the machine it runs on: it edits the hosts file, creates and removes\n" +
                "firewall rules, services, scheduled tasks and HKLM policy values, then reverts them.\n\n" +
                "Run it on a disposable virtual machine, from an elevated prompt:\n" +
                "  AntiGoogle.Elevated.exe --yes-modify-this-machine [--scenario <name|all>] [--off-box-peer <ip>]\n");
            return 2;
        }

        if (!Elevation.IsElevated)
        {
            Console.WriteLine("Refusing to run: this process is not elevated. Start an administrator prompt.");
            return 2;
        }

        var isVm = Tools.IsVirtualMachine(out var machine);
        Console.WriteLine($"machine : {machine} ({(isVm ? "virtual machine" : "NOT a virtual machine")})");
        Console.WriteLine($"os      : {Environment.OSVersion}");
        if (!isVm && !opts.AllowPhysical)
        {
            Console.WriteLine("Refusing to run on a physical machine. Pass --allow-physical only if you accept that.");
            return 2;
        }

        if (!opts.ForceDirty && LooksDirty(out var why))
        {
            Console.WriteLine($"Refusing to run: Anti-Google state is already present ({why}). Restore it first, or pass --force-dirty.");
            return 2;
        }

        var checks = new Checks();
        FixtureSet? fixtures = null;
        var started = DateTimeOffset.Now;

        try
        {
            checks.Scenario = "setup";
            fixtures = await FixtureSet.CreateAsync(checks).ConfigureAwait(false);
            var cx = new ScenarioContext(checks, fixtures, opts);

            foreach (var (name, run) in AllScenarios().Where(s =>
                         opts.Scenario == "all" || string.Equals(s.Name, opts.Scenario, StringComparison.OrdinalIgnoreCase)))
            {
                checks.Scenario = name;
                Console.WriteLine($"\n[{name}]");
                try { await run(cx).ConfigureAwait(false); }
                catch (Exception ex) { checks.Crash(name, ex); await TryRecoverAsync(checks).ConfigureAwait(false); }
            }
        }
        catch (Exception ex)
        {
            checks.Crash("setup", ex);
        }
        finally
        {
            await TryRecoverAsync(checks).ConfigureAwait(false);
            if (fixtures is not null)
            {
                try { Scenarios.RemoveUserHostsEntries(); } catch { /* best effort */ }
                try { await fixtures.CleanupAsync().ConfigureAwait(false); }
                catch (Exception ex) { Console.WriteLine($"fixture cleanup: {ex.Message}"); }
            }
        }

        WriteResults(opts, checks, machine, started);

        Console.WriteLine("\n" + new string('=', 70));
        Console.WriteLine($"{checks.Results.Count(r => r.Passed)} passed, {checks.Failed} failed");
        if (checks.Failed > 0)
        {
            Console.WriteLine("\nFailures:");
            foreach (var r in checks.Results.Where(r => !r.Passed))
                Console.WriteLine($"  - [{r.Scenario}] {r.Name}");
        }
        return checks.Failed == 0 ? 0 : 1;
    }

    private static IEnumerable<(string Name, Func<ScenarioContext, Task> Run)> AllScenarios() =>
        Scenarios.Baseline.Concat(Scenarios.Extended);

    /// <summary>
    /// Whatever a failed scenario left behind must not leak into the next one, or the machine.
    /// Journal-driven revert is exactly the recovery path a real user has, so use it here too.
    /// </summary>
    private static async Task TryRecoverAsync(Checks checks)
    {
        try
        {
            var service = new ProtectionService();
            if (service.Journal.HasChanges)
            {
                checks.Info($"recovering: {service.Journal.Entries.Count} journal entries still present");
                var errors = await service.RevertAllAsync().ConfigureAwait(false);
                foreach (var e in errors) checks.Info($"recovery problem: {e}");
            }
            else
            {
                await new AntiGoogle.Core.Engines.FirewallEngine().RemoveAllAsync().ConfigureAwait(false);
            }
        }
        catch (Exception ex) { Console.WriteLine($"recovery failed: {ex.Message}"); }
    }

    private static bool LooksDirty(out string why)
    {
        why = "";
        try
        {
            if (File.Exists(AppPaths.JournalFile) && File.ReadAllText(AppPaths.JournalFile).Trim() is not ("" or "[]"))
            { why = "journal.json has entries"; return true; }
            if (File.Exists(AppPaths.HostsFile) &&
                File.ReadAllText(AppPaths.HostsFile).Contains(AppPaths.HostsBeginMarker, StringComparison.Ordinal))
            { why = "the hosts file has a managed block"; return true; }
        }
        catch (Exception ex) { why = ex.Message; return true; }
        return false;
    }

    private static void WriteResults(Options opts, Checks checks, string machine, DateTimeOffset started)
    {
        try
        {
            Directory.CreateDirectory(opts.OutDir);
            var json = JsonSerializer.Serialize(new
            {
                started,
                finished = DateTimeOffset.Now,
                machine,
                os = Environment.OSVersion.ToString(),
                passed = checks.Results.Count(r => r.Passed),
                failed = checks.Failed,
                results = checks.Results
            }, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(Path.Combine(opts.OutDir, "results.json"), json);
        }
        catch (Exception ex) { Console.WriteLine($"could not write results.json: {ex.Message}"); }
    }
}
