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

using AntiGoogle.Core.Engines;
using AntiGoogle.Core.Journal;
using AntiGoogle.Core.Model;
using Microsoft.Win32;
using Xunit;

namespace AntiGoogle.Core.Tests;

/// <summary>
/// Registry revert exactness, tested under HKCU so it needs no elevation. The production rules
/// write to HKLM, but the engine logic under test is identical.
/// </summary>
public class RegistryEngineTests : IDisposable
{
    private readonly string _testKey = $@"Software\AntiGoogleTests\{Guid.NewGuid():N}";
    private readonly string _journalPath = Path.Combine(Path.GetTempPath(), $"ag-journal-{Guid.NewGuid():N}.json");

    public void Dispose()
    {
        try { Registry.CurrentUser.DeleteSubKeyTree(_testKey, throwOnMissingSubKey: false); } catch { }
        try { File.Delete(_journalPath); } catch { }
        GC.SuppressFinalize(this);
    }

    private BlockRule RuleFor(params RegistryPolicy[] policies) => new()
    {
        Id = "test.registry",
        Title = "Test",
        Summary = "test",
        Category = RuleCategory.Telemetry,
        Tier = RiskTier.Balanced,
        Engine = EngineKind.Registry,
        RegistryValues = policies
    };

    [Fact]
    public async Task ValueThatDidNotExistIsDeletedOnRevert()
    {
        var engine = new RegistryPolicyEngine();
        var journal = new ChangeJournal(_journalPath);
        var policy = RegistryPolicy.Dword(_testKey, "SomeFlag", 0, RegistryHive2.CurrentUser);

        var outcome = engine.Apply(RuleFor(policy), policy, journal);
        Assert.Equal(ChangeOutcome.Applied, outcome);

        using (var check = Registry.CurrentUser.OpenSubKey(_testKey))
            Assert.Equal(0, check!.GetValue("SomeFlag"));

        await engine.RevertAsync(journal.Entries.Single());

        using var after = Registry.CurrentUser.OpenSubKey(_testKey);
        // The key itself is removed too, because we created it and left it empty.
        Assert.True(after is null || after.GetValue("SomeFlag") is null);
    }

    [Fact]
    public async Task PreexistingValueIsRestoredExactly()
    {
        using (var seed = Registry.CurrentUser.CreateSubKey(_testKey))
            seed!.SetValue("SomeFlag", 7, RegistryValueKind.DWord);

        var engine = new RegistryPolicyEngine();
        var journal = new ChangeJournal(_journalPath);
        var policy = RegistryPolicy.Dword(_testKey, "SomeFlag", 0, RegistryHive2.CurrentUser);

        engine.Apply(RuleFor(policy), policy, journal);

        using (var mid = Registry.CurrentUser.OpenSubKey(_testKey))
            Assert.Equal(0, mid!.GetValue("SomeFlag"));

        await engine.RevertAsync(journal.Entries.Single());

        using var after = Registry.CurrentUser.OpenSubKey(_testKey);
        Assert.Equal(7, after!.GetValue("SomeFlag"));
    }

    [Fact]
    public void AlreadySatisfiedValueIsNotRewrittenOrJournalled()
    {
        using (var seed = Registry.CurrentUser.CreateSubKey(_testKey))
            seed!.SetValue("SomeFlag", 0, RegistryValueKind.DWord);

        var engine = new RegistryPolicyEngine();
        var journal = new ChangeJournal(_journalPath);
        var policy = RegistryPolicy.Dword(_testKey, "SomeFlag", 0, RegistryHive2.CurrentUser);

        var outcome = engine.Apply(RuleFor(policy), policy, journal);

        // No journal entry, because nothing changed — reverting later must not "restore" a value
        // we never actually touched.
        Assert.Equal(ChangeOutcome.AlreadySatisfied, outcome);
        Assert.Empty(journal.Entries);
    }

    [Fact]
    public async Task StringValuesRoundTrip()
    {
        using (var seed = Registry.CurrentUser.CreateSubKey(_testKey))
            seed!.SetValue("Mode", "automatic", RegistryValueKind.String);

        var engine = new RegistryPolicyEngine();
        var journal = new ChangeJournal(_journalPath);
        var policy = RegistryPolicy.Str(_testKey, "Mode", "off", RegistryHive2.CurrentUser);

        engine.Apply(RuleFor(policy), policy, journal);
        await engine.RevertAsync(journal.Entries.Single());

        using var after = Registry.CurrentUser.OpenSubKey(_testKey);
        Assert.Equal("automatic", after!.GetValue("Mode"));
    }
}

public class JournalTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"ag-journal-{Guid.NewGuid():N}.json");

    public void Dispose()
    {
        try { File.Delete(_path); } catch { }
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void EntriesSurviveASaveLoadRoundTrip()
    {
        var journal = new ChangeJournal(_path);
        journal.Append(new JournalEntry
        {
            RuleId = "svc.google-updater",
            Engine = EngineKind.Service,
            Description = "Disabled service GoogleUpdaterService152",
            Reverse = ReverseKind.RestoreServiceStartType,
            ServiceName = "GoogleUpdaterService152",
            PreviousStartType = 2,
            PreviousServiceRunning = true
        });

        var reloaded = new ChangeJournal(_path);
        reloaded.Load();

        var entry = Assert.Single(reloaded.Entries);
        Assert.Equal("GoogleUpdaterService152", entry.ServiceName);
        Assert.Equal(2, entry.PreviousStartType);
        Assert.True(entry.PreviousServiceRunning);
        Assert.Equal(ReverseKind.RestoreServiceStartType, entry.Reverse);
    }

    [Fact]
    public void ReplayOrderIsNewestFirst()
    {
        var journal = new ChangeJournal(_path);
        var baseTime = new DateTimeOffset(2026, 8, 6, 12, 0, 0, TimeSpan.Zero);

        journal.Append(new JournalEntry { Description = "first", At = baseTime });
        journal.Append(new JournalEntry { Description = "second", At = baseTime.AddMinutes(1) });
        journal.Append(new JournalEntry { Description = "third", At = baseTime.AddMinutes(2) });

        var order = journal.ReplayOrder().Select(e => e.Description).ToList();
        Assert.Equal(["third", "second", "first"], order);
    }

    [Fact]
    public void CorruptJournalThrowsRatherThanSilentlyLosingUndoData()
    {
        File.WriteAllText(_path, "{ this is not valid json");

        var journal = new ChangeJournal(_path);

        // Silently starting from an empty journal would strand a modified machine with no way back.
        Assert.Throws<InvalidOperationException>(() => journal.Load());
    }
}

public class ScheduledTaskPathTests
{
    [Theory]
    [InlineData(@"\GoogleUpdateTaskMachineCore", @"\", "GoogleUpdateTaskMachineCore")]
    [InlineData(@"\Microsoft\Windows\Foo\BarTask", @"\Microsoft\Windows\Foo\", "BarTask")]
    public void SplitsFolderFromName(string full, string folder, string name)
    {
        var (f, n) = ScheduledTaskEngine.SplitTaskPath(full);
        Assert.Equal(folder, f);
        Assert.Equal(name, n);
    }
}
