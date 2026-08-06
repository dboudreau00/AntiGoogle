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

namespace AntiGoogle.Core;

/// <summary>Thread-safe append-only file log. Never records anything user-identifying beyond paths.</summary>
public static class Log
{
    private static readonly Lock Gate = new();
    private static string? _file;

    public static void Initialize()
    {
        try
        {
            AppPaths.EnsureCreated();
            _file = Path.Combine(AppPaths.Logs, $"antigoogle-{DateTime.Now:yyyyMMdd}.log");
            Info($"=== Anti-Google session start (pid {Environment.ProcessId}) ===");
        }
        catch
        {
            // ProgramData may be unwritable without elevation. Logging is best-effort, never fatal.
            _file = null;
        }
    }

    public static void Info(string message) => Write("INFO ", message);
    public static void Warn(string message) => Write("WARN ", message);
    public static void Error(string message) => Write("ERROR", message);

    public static void Error(string message, Exception ex) => Write("ERROR", $"{message} :: {ex.GetType().Name}: {ex.Message}");

    private static void Write(string level, string message)
    {
        if (_file is null) return;
        try
        {
            lock (Gate)
            {
                File.AppendAllText(_file, $"{DateTime.Now:HH:mm:ss.fff} {level} {message}{Environment.NewLine}", Encoding.UTF8);
            }
        }
        catch
        {
            // A failed log write must never take down a system-modifying operation mid-flight.
        }
    }
}
