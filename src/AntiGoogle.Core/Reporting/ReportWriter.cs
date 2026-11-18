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

namespace AntiGoogle.Core.Reporting;

public sealed record SavedReport(string HtmlPath, string JsonPath);

public static class ReportWriter
{
    /// <summary>
    /// Writes the HTML and the JSON side by side. Defaults to <see cref="AppPaths.Reports"/> in ProgramData.
    /// The app runs without administrator rights by default, and a standard user cannot write into a
    /// ProgramData folder an elevated run created, so the fallback is the user's own local app data.
    /// </summary>
    public static SavedReport Save(ProtectionReport report, string? directory = null)
    {
        var dir = directory ?? AppPaths.Reports;
        try { Directory.CreateDirectory(dir); File.WriteAllText(Path.Combine(dir, ".write-test"), ""); File.Delete(Path.Combine(dir, ".write-test")); }
        catch (Exception ex) when (directory is null && ex is UnauthorizedAccessException or IOException)
        {
            dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AntiGoogle", "reports");
            Directory.CreateDirectory(dir);
        }

        var stem = Path.Combine(dir, $"antigoogle-report-{report.GeneratedAt:yyyyMMdd-HHmmss}");
        var html = stem + ".html";
        var json = stem + ".json";

        File.WriteAllText(html, ReportRenderer.ToHtml(report), new UTF8Encoding(false));
        File.WriteAllText(json, ReportRenderer.ToJson(report), new UTF8Encoding(false));
        return new SavedReport(html, json);
    }
}
