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

using AntiGoogle.Core;
using AntiGoogle.Core.Engines;
using AntiGoogle.Core.Journal;
using AntiGoogle.Core.Model;
using Xunit;

namespace AntiGoogle.Core.Tests;

/// <summary>
/// The reversibility contract for the hosts file, tested against a throwaway file rather than the
/// real one. The property that matters most: a user's own hosts entries survive both apply and
/// revert untouched.
/// </summary>
public class HostsEngineTests : IDisposable
{
    private readonly string _dir;
    private readonly string _hosts;
    private readonly string _journalPath;
    /// <summary>Without this the engine deposits a backup in the machine's real ProgramData on every apply.</summary>
    private readonly string _backupDir;

    private const string UserContent =
        "# my own entries\r\n" +
        "127.0.0.1 localdev.test\r\n" +
        "10.0.0.5 nas.lan\r\n";

    public HostsEngineTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "antigoogle-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _hosts = Path.Combine(_dir, "hosts");
        _journalPath = Path.Combine(_dir, "journal.json");
        _backupDir = Path.Combine(_dir, "backups");
        File.WriteAllText(_hosts, UserContent);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* temp dir */ }
        GC.SuppressFinalize(this);
    }

    private static BlockRule Rule(string id, params string[] domains) => new()
    {
        Id = id,
        Title = $"Test rule {id}",
        Summary = "test",
        Category = RuleCategory.Telemetry,
        Tier = RiskTier.Balanced,
        Engine = EngineKind.Hosts,
        Domains = domains
    };

    [Fact]
    public async Task ApplyWritesBothIPv4AndIPv6Sinkholes()
    {
        var engine = new HostsFileEngine(_hosts, _backupDir);
        var journal = new ChangeJournal(_journalPath);

        await engine.ApplyAsync([Rule("t1", "example-telemetry.com")], journal);

        var text = await File.ReadAllTextAsync(_hosts);

        // An IPv4-only blocklist is routinely defeated by an app falling back to the AAAA record.
        Assert.Contains("0.0.0.0 example-telemetry.com", text);
        Assert.Contains(":: example-telemetry.com", text);
    }

    [Fact]
    public async Task ApplyPreservesExistingUserEntries()
    {
        var engine = new HostsFileEngine(_hosts, _backupDir);
        var journal = new ChangeJournal(_journalPath);

        await engine.ApplyAsync([Rule("t1", "a.example.com")], journal);

        var text = await File.ReadAllTextAsync(_hosts);
        Assert.Contains("127.0.0.1 localdev.test", text);
        Assert.Contains("10.0.0.5 nas.lan", text);
    }

    [Fact]
    public async Task RevertRemovesOnlyTheManagedBlock()
    {
        var engine = new HostsFileEngine(_hosts, _backupDir);
        var journal = new ChangeJournal(_journalPath);

        await engine.ApplyAsync([Rule("t1", "a.example.com")], journal);
        Assert.True(engine.HasManagedBlock());

        var entry = journal.Entries.Single();
        await engine.RevertAsync(entry);

        var text = await File.ReadAllTextAsync(_hosts);
        Assert.False(engine.HasManagedBlock());
        Assert.DoesNotContain("a.example.com", text);
        Assert.Contains("127.0.0.1 localdev.test", text);
        Assert.Contains("10.0.0.5 nas.lan", text);
    }

    [Fact]
    public async Task RevertKeepsUserEntriesAddedAfterApply()
    {
        // This is why revert strips the managed block instead of restoring the backup:
        // restoring a stale backup would silently destroy edits made in between.
        var engine = new HostsFileEngine(_hosts, _backupDir);
        var journal = new ChangeJournal(_journalPath);

        await engine.ApplyAsync([Rule("t1", "a.example.com")], journal);
        await File.AppendAllTextAsync(_hosts, "\r\n192.168.1.9 added-later.lan\r\n");

        await engine.RevertAsync(journal.Entries.Single());

        var text = await File.ReadAllTextAsync(_hosts);
        Assert.Contains("192.168.1.9 added-later.lan", text);
        Assert.DoesNotContain("a.example.com", text);
    }

    [Fact]
    public async Task ReapplyingReplacesTheBlockRatherThanStackingIt()
    {
        var engine = new HostsFileEngine(_hosts, _backupDir);
        var journal = new ChangeJournal(_journalPath);

        await engine.ApplyAsync([Rule("t1", "first.example.com")], journal);
        await engine.ApplyAsync([Rule("t2", "second.example.com")], journal);

        var text = await File.ReadAllTextAsync(_hosts);
        Assert.Single(FindAll(text, AppPaths.HostsBeginMarker));
        Assert.DoesNotContain("first.example.com", text);
        Assert.Contains("second.example.com", text);
    }

    [Fact]
    public async Task CurrentlyBlockedReportsTheSinkholedDomains()
    {
        var engine = new HostsFileEngine(_hosts, _backupDir);
        var journal = new ChangeJournal(_journalPath);

        await engine.ApplyAsync([Rule("t1", "one.example.com", "two.example.com")], journal);

        var blocked = engine.CurrentlyBlocked();
        Assert.Equal(2, blocked.Count);
        Assert.Contains("one.example.com", blocked);
        Assert.Contains("two.example.com", blocked);
    }

    [Fact]
    public async Task RevertIsIdempotent()
    {
        var engine = new HostsFileEngine(_hosts, _backupDir);
        var journal = new ChangeJournal(_journalPath);

        await engine.ApplyAsync([Rule("t1", "a.example.com")], journal);
        var entry = journal.Entries.Single();

        await engine.RevertAsync(entry);
        await engine.RevertAsync(entry);   // must not throw or mangle the file

        var text = await File.ReadAllTextAsync(_hosts);
        Assert.Contains("127.0.0.1 localdev.test", text);
    }

    private static List<int> FindAll(string haystack, string needle)
    {
        var hits = new List<int>();
        var i = haystack.IndexOf(needle, StringComparison.Ordinal);
        while (i >= 0)
        {
            hits.Add(i);
            i = haystack.IndexOf(needle, i + needle.Length, StringComparison.Ordinal);
        }
        return hits;
    }
}
