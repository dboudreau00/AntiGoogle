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

using System.Windows;
using System.Windows.Threading;
using AntiGoogle.Core;

namespace AntiGoogle.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        Log.Initialize();

        // A system-modifying tool must never die silently mid-operation. Surface the failure,
        // point at the log, and keep running so the user can still reach "Restore Everything".
        DispatcherUnhandledException += OnUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += (sender, args) =>
            Log.Error($"Fatal: {args.ExceptionObject}");

        base.OnStartup(e);
    }

    private static void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        // Walk the whole chain. A XAML load failure surfaces as a generic
        // TypeConverterMarkupExtension message whose outer text names neither the resource nor
        // the reason - the actual cause is always two or three InnerExceptions down.
        var chain = Describe(e.Exception);

        Log.Error($"Unhandled UI exception.\n{chain}\n{e.Exception.StackTrace}");

        MessageBox.Show(
            $"{chain}\n\nAnti-Google will keep running so you can still restore your machine." +
            $"\n\nFull details were written to:\n{AppPaths.Logs}",
            "Anti-Google — something went wrong",
            MessageBoxButton.OK, MessageBoxImage.Error);

        e.Handled = true;
    }

    private static string Describe(Exception ex)
    {
        var lines = new List<string>();
        var depth = 0;
        for (Exception? cur = ex; cur is not null && depth < 8; cur = cur.InnerException, depth++)
            lines.Add($"{new string(' ', depth * 2)}{cur.GetType().Name}: {cur.Message}");
        return string.Join("\n", lines);
    }
}
