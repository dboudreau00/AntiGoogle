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

using System.Diagnostics;
using System.Text;

namespace AntiGoogle.Core.Platform;

public sealed record ProcessResult(int ExitCode, string StdOut, string StdErr)
{
    public bool Ok => ExitCode == 0;
    public string Combined => string.IsNullOrWhiteSpace(StdErr) ? StdOut : $"{StdOut}\n{StdErr}".Trim();
}

/// <summary>
/// Runs the Windows tools we drive (sc, schtasks, powershell). Always redirected, never shell-executed,
/// and never with a visible window — this app must not flash consoles while modifying the system.
/// </summary>
public static class ProcessRunner
{
    public static async Task<ProcessResult> RunAsync(
        string fileName,
        IEnumerable<string> arguments,
        int timeoutMs = 60_000,
        CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        // ArgumentList quotes each element correctly — no hand-built command strings, so a path
        // with a space (Program Files, always) can never split into two arguments.
        foreach (var a in arguments) psi.ArgumentList.Add(a);

        using var proc = new Process { StartInfo = psi };
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();

        proc.OutputDataReceived += (sender, e) => { if (e.Data is not null) stdout.AppendLine(e.Data); };
        proc.ErrorDataReceived += (sender, e) => { if (e.Data is not null) stderr.AppendLine(e.Data); };

        if (!proc.Start())
            throw new InvalidOperationException($"Could not start {fileName}.");

        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeoutMs);

        try
        {
            await proc.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            try { proc.Kill(entireProcessTree: true); } catch { /* already gone */ }
            throw new TimeoutException($"{fileName} did not exit within {timeoutMs} ms.");
        }

        return new ProcessResult(proc.ExitCode, stdout.ToString().Trim(), stderr.ToString().Trim());
    }

    /// <summary>
    /// Runs a PowerShell command. Used only for the Net*Firewall and ScheduledTask cmdlets, which
    /// have no equivalent that netsh/schtasks expose as cleanly (rule groups, in particular).
    /// -NoProfile keeps a user's profile script from altering behaviour mid-operation.
    /// </summary>
    public static Task<ProcessResult> PowerShellAsync(string command, int timeoutMs = 120_000, CancellationToken ct = default)
        => RunAsync("powershell.exe",
            ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command],
            timeoutMs, ct);
}
