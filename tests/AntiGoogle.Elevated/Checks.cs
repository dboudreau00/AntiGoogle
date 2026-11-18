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

namespace AntiGoogle.Elevated;

internal sealed record CheckResult(string Scenario, string Name, bool Passed, string Detail);

/// <summary>Records every assertion with its scenario so the run ends in one honest table.</summary>
internal sealed class Checks
{
    private readonly List<CheckResult> _results = [];

    public string Scenario { get; set; } = "";
    public IReadOnlyList<CheckResult> Results => _results;
    public int Failed => _results.Count(r => !r.Passed);

    public bool Check(string name, bool condition, string detail = "")
    {
        _results.Add(new CheckResult(Scenario, name, condition, detail));
        Console.WriteLine($"  {(condition ? "PASS" : "FAIL")}  {name}");
        if (!condition && detail.Length > 0)
            foreach (var line in detail.Split('\n'))
                Console.WriteLine($"        {line.TrimEnd()}");
        return condition;
    }

    /// <summary>Evidence worth keeping in the log that is not an assertion.</summary>
    public void Info(string message) => Console.WriteLine($"        - {message}");

    /// <summary>A scenario that threw is a failure, never a skipped pass.</summary>
    public void Crash(string scenario, Exception ex)
    {
        Scenario = scenario;
        Check($"{scenario} ran to completion", false, $"{ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}");
    }
}
