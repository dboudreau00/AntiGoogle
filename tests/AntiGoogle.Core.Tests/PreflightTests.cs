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

using AntiGoogle.Core.Safety;
using Xunit;

namespace AntiGoogle.Core.Tests;

public sealed class PreflightTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "ag-preflight-" + Guid.NewGuid().ToString("N"));

    public PreflightTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void OnlyChromePolicyValuesTheJournalRecordsAreReportedAsOurs()
    {
        var journal = Path.Combine(_root, "journal.json");
        File.WriteAllText(journal, """
            [
              { "Id": "1", "Engine": "Registry", "RegistryKey": "SOFTWARE\\Policies\\Google\\Chrome", "RegistryName": "MetricsReportingEnabled" },
              { "Id": "2", "Engine": "Registry", "RegistryKey": "software\\policies\\google\\chrome", "RegistryName": "SyncDisabled" },
              { "Id": "3", "Engine": "Registry", "RegistryKey": "SOFTWARE\\Policies\\Microsoft\\Edge", "RegistryName": "DiagnosticData" },
              { "Id": "4", "Engine": "Hosts", "BackupPath": "C:\\x.bak" }
            ]
            """);

        var ours = Preflight.ChromePolicyValuesWrittenByUs(journal);

        Assert.Equal(2, ours.Count);
        Assert.Contains("MetricsReportingEnabled", ours);
        Assert.Contains("syncdisabled", ours);
        Assert.DoesNotContain("DiagnosticData", ours);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json at all")]
    [InlineData("{ \"RegistryKey\": \"x\" }")]
    [InlineData("[ 1, \"two\", null ]")]
    public void AnUnreadableOrOddJournalClaimsNothingAsOursAndLeavesNoFileBehind(string content)
    {
        var journal = Path.Combine(_root, "journal.json");
        File.WriteAllText(journal, content);

        var ours = Preflight.ChromePolicyValuesWrittenByUs(journal);

        Assert.Empty(ours);
        Assert.Equal([journal], Directory.GetFiles(_root));
    }

    [Fact]
    public void AMissingJournalClaimsNothing() =>
        Assert.Empty(Preflight.ChromePolicyValuesWrittenByUs(Path.Combine(_root, "absent.json")));
}
