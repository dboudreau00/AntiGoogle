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
/// Regression tests for the two ways a real Windows 11 round trip found revert to be inexact. Each
/// of these was measured on a virtual machine by the elevated harness before it was fixed; the unit
/// tests pin the part of each fix that can be reached without administrator rights.
/// </summary>
public class EngineExactnessTests : IDisposable
{
    private readonly string _dir;
    private readonly string _journalPath;
    private readonly string _regBase = $@"Software\AntiGoogleTests\{Guid.NewGuid():N}";

    public EngineExactnessTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "antigoogle-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _journalPath = Path.Combine(_dir, "journal.json");
    }

    public void Dispose()
    {
        try { Registry.CurrentUser.DeleteSubKeyTree(_regBase, throwOnMissingSubKey: false); } catch { }
        try { Directory.Delete(_dir, recursive: true); } catch { }
        GC.SuppressFinalize(this);
    }

    // ------------------------------------------------------------------ services: delayed start

    [Theory]
    [InlineData(2, true, "delayed-auto")]
    [InlineData(2, false, "auto")]
    [InlineData(3, false, "demand")]
    [InlineData(4, false, "disabled")]
    [InlineData(0, false, "boot")]
    [InlineData(1, false, "system")]
    [InlineData(9, false, "demand")]
    public void RestoringAServiceUsesTheWordThatKeepsItsExactStartType(int startType, bool delayed, string expected)
    {
        // `sc config start= auto` clears DelayedAutostart, so a delayed service restored with plain
        // "auto" came back as a different service. Measured: gupdate, AUTO_START (DELAYED) -> AUTO_START.
        Assert.Equal(expected, ServiceEngine.StartWord(startType, delayed));
    }

    // ------------------------------------------------------------------ registry: created parents

    private static BlockRule RegRule(params RegistryPolicy[] p) => new()
    {
        Id = "test.reg",
        Title = "Test",
        Summary = "test",
        Category = RuleCategory.Telemetry,
        Tier = RiskTier.Balanced,
        Engine = EngineKind.Registry,
        RegistryValues = p
    };

    [Fact]
    public async Task KeysCreatedOnTheWayToAPolicyAreRemovedOnRevert()
    {
        // Policies\Google\Chrome on a machine with no Google policies creates TWO keys. Reverting only
        // the leaf left an empty Policies\Google behind, so the machine did not look untouched.
        using (Registry.CurrentUser.CreateSubKey(_regBase)) { }
        var leaf = _regBase + @"\Policies\Google\Chrome";

        var engine = new RegistryPolicyEngine();
        var journal = new ChangeJournal(_journalPath);
        var policy = RegistryPolicy.Dword(leaf, "MetricsReportingEnabled", 0, RegistryHive2.CurrentUser);

        engine.Apply(RegRule(policy), policy, journal);
        var entry = journal.Entries.Single();
        Assert.True(entry.RegistryKeyCreated);
        Assert.Equal(_regBase + @"\Policies", entry.RegistryCreatedRoot);

        await engine.RevertAsync(entry);

        using var gone = Registry.CurrentUser.OpenSubKey(_regBase + @"\Policies");
        Assert.Null(gone);
        using var baseStillThere = Registry.CurrentUser.OpenSubKey(_regBase);
        Assert.NotNull(baseStillThere); // never above the key the engine created
    }

    [Fact]
    public async Task AParentThatGainedSomeoneElsesValueIsLeftStrictlyAlone()
    {
        using (Registry.CurrentUser.CreateSubKey(_regBase)) { }
        var leaf = _regBase + @"\Policies\Google\Chrome";

        var engine = new RegistryPolicyEngine();
        var journal = new ChangeJournal(_journalPath);
        var policy = RegistryPolicy.Dword(leaf, "MetricsReportingEnabled", 0, RegistryHive2.CurrentUser);
        engine.Apply(RegRule(policy), policy, journal);

        // Somebody else puts a policy into the parent we created, after we applied.
        using (var parent = Registry.CurrentUser.OpenSubKey(_regBase + @"\Policies\Google", writable: true))
            parent!.SetValue("TheirPolicy", 5, RegistryValueKind.DWord);

        await engine.RevertAsync(journal.Entries.Single());

        using var chrome = Registry.CurrentUser.OpenSubKey(leaf);
        Assert.Null(chrome); // our leaf is gone
        using var kept = Registry.CurrentUser.OpenSubKey(_regBase + @"\Policies\Google");
        Assert.NotNull(kept);
        Assert.Equal(5, kept!.GetValue("TheirPolicy")); // their value, and the key that holds it, survive
    }

    [Fact]
    public async Task ARevertWrittenBeforeTheCreatedRootWasRecordedStillRemovesTheLeaf()
    {
        // Journals from earlier versions have no RegistryCreatedRoot. They must keep working.
        var engine = new RegistryPolicyEngine();
        var journal = new ChangeJournal(_journalPath);
        var leaf = _regBase + @"\Old\Chrome";
        var policy = RegistryPolicy.Dword(leaf, "Flag", 0, RegistryHive2.CurrentUser);
        engine.Apply(RegRule(policy), policy, journal);

        var entry = journal.Entries.Single();
        entry.RegistryCreatedRoot = null;

        await engine.RevertAsync(entry);

        using var gone = Registry.CurrentUser.OpenSubKey(leaf);
        Assert.Null(gone);
    }
}
