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

using System.Reflection;
using Xunit;

namespace AntiGoogle.Verify;

/// <summary>
/// Minimal xunit-compatible runner: discovers [Fact] and [Theory]/[InlineData] methods in this
/// assembly, runs them, and exits non-zero if any fail. Enough to verify the suite on a machine
/// where Smart App Control blocks the real test host.
/// </summary>
public static class Runner
{
    public static int Main()
    {
        var passed = 0;
        var failures = new List<string>();

        var testClasses = Assembly.GetExecutingAssembly().GetTypes()
            .Where(t => t is { IsClass: true, IsAbstract: false })
            .Where(t => t.GetMethods().Any(HasTestAttribute))
            .OrderBy(t => t.Name, StringComparer.Ordinal);

        Console.WriteLine("Anti-Google — verification run");
        Console.WriteLine(new string('=', 68));

        foreach (var type in testClasses)
        {
            Console.WriteLine($"\n{type.Name}");

            foreach (var method in type.GetMethods().Where(HasTestAttribute).OrderBy(m => m.Name, StringComparer.Ordinal))
            {
                foreach (var args in CasesFor(method))
                {
                    var label = args.Length == 0 ? method.Name : $"{method.Name}({string.Join(", ", args)})";
                    object? instance = null;
                    try
                    {
                        instance = Activator.CreateInstance(type);
                        var result = method.Invoke(instance, args);

                        // Async tests return a Task that must be awaited before judging the outcome.
                        if (result is Task task) task.GetAwaiter().GetResult();

                        passed++;
                        Console.WriteLine($"  PASS  {label}");
                    }
                    catch (Exception ex)
                    {
                        var real = ex is TargetInvocationException { InnerException: not null } tie
                            ? tie.InnerException!
                            : ex;
                        failures.Add($"{type.Name}.{label}: {real.Message}");
                        Console.WriteLine($"  FAIL  {label}");
                        Console.WriteLine($"        {real.Message}");
                    }
                    finally
                    {
                        (instance as IDisposable)?.Dispose();
                    }
                }
            }
        }

        Console.WriteLine("\n" + new string('=', 68));
        Console.WriteLine($"{passed} passed, {failures.Count} failed");

        if (failures.Count > 0)
        {
            Console.WriteLine("\nFailures:");
            foreach (var f in failures) Console.WriteLine($"  - {f}");
            return 1;
        }

        Console.WriteLine("All checks passed.");
        return 0;
    }

    private static bool HasTestAttribute(MethodInfo m) =>
        m.GetCustomAttribute<FactAttribute>() is not null || m.GetCustomAttribute<TheoryAttribute>() is not null;

    /// <summary>One empty argument set for a [Fact]; one per [InlineData] for a [Theory].</summary>
    private static IEnumerable<object?[]> CasesFor(MethodInfo m)
    {
        var inline = m.GetCustomAttributes<InlineDataAttribute>().ToList();
        if (inline.Count == 0) return [[]];
        return inline.Select(a => a.GetData(m).First());
    }
}
