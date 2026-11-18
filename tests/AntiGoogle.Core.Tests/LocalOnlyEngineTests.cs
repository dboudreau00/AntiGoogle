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

using System.Net;
using System.Text;
using AntiGoogle.Core.Catalog;
using AntiGoogle.Core.Engines;
using AntiGoogle.Core.Journal;
using AntiGoogle.Core.Model;
using Xunit;

namespace AntiGoogle.Core.Tests;

/// <summary>
/// The parts of local-only mode that need no administrator rights: how names are written to the
/// hosts file, and how firewall rules are specified, validated, escaped and read back. What the
/// firewall actually does with the rules is measured by the elevated harness, not here.
/// </summary>
public class LocalOnlyEngineTests : IDisposable
{
    private readonly string _dir;
    private readonly string _hosts;
    private readonly string _backups;
    private readonly string _journalPath;

    private const string UserHosts = "# my own entries\r\n127.0.0.1 localdev.test\r\n10.0.0.5 nas.lan\r\n";

    public LocalOnlyEngineTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "antigoogle-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _hosts = Path.Combine(_dir, "hosts");
        _backups = Path.Combine(_dir, "backups");
        _journalPath = Path.Combine(_dir, "journal.json");
        File.WriteAllText(_hosts, UserHosts, new UTF8Encoding(false));
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
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

    private static HashSet<string> Ids(params string[] ids) => new(ids, StringComparer.OrdinalIgnoreCase);

    // ------------------------------------------------------------------ hosts: loopback mapping

    [Fact]
    public async Task ALocalOnlyRuleResolvesItsNamesToThisMachineOnBothAddressFamilies()
    {
        var engine = new HostsFileEngine(_hosts, _backups);
        await engine.ApplyAsync([Rule("t.loop", "update.example.invalid")], new ChangeJournal(_journalPath),
            loopbackRuleIds: Ids("t.loop"));

        var text = await File.ReadAllTextAsync(_hosts);
        Assert.Contains("127.0.0.1 update.example.invalid", text);
        Assert.Contains("::1 update.example.invalid", text);
        Assert.DoesNotContain("0.0.0.0 update.example.invalid", text);
        Assert.DoesNotContain(":: update.example.invalid", text);
        Assert.Contains("[local-only: resolves to this machine]", text);
    }

    [Fact]
    public async Task TheStatusViewsSeparateSinkholedNamesFromLoopedOnes()
    {
        var engine = new HostsFileEngine(_hosts, _backups);
        await engine.ApplyAsync(
            [Rule("t.block", "tracker.example.invalid"), Rule("t.loop", "update.example.invalid")],
            new ChangeJournal(_journalPath), loopbackRuleIds: Ids("t.loop"));

        Assert.Equal(["tracker.example.invalid"], engine.CurrentlyBlocked());
        Assert.Equal(["update.example.invalid"], engine.CurrentlyLooped());
    }

    [Fact]
    public async Task WhenABlockingRuleAndALocalOnlyRuleListTheSameNameTheBlockWins()
    {
        // Fail closed: the stricter rule decides. A name that one armed rule wants gone must not
        // quietly keep resolving because another rule would have been content with loopback.
        var engine = new HostsFileEngine(_hosts, _backups);
        await engine.ApplyAsync(
            [Rule("t.block", "shared.example.invalid"), Rule("t.loop", "shared.example.invalid", "only-loop.example.invalid")],
            new ChangeJournal(_journalPath), loopbackRuleIds: Ids("t.loop"));

        var text = await File.ReadAllTextAsync(_hosts);
        Assert.DoesNotContain("127.0.0.1 shared.example.invalid", text);
        Assert.DoesNotContain("::1 shared.example.invalid", text);
        Assert.Contains("0.0.0.0 shared.example.invalid", text);
        Assert.Contains(":: shared.example.invalid", text);
        Assert.Contains("127.0.0.1 only-loop.example.invalid", text);
        Assert.Contains("another armed rule also lists this name", text);
    }

    [Fact]
    public async Task ARevertAfterALocalOnlyApplyIsByteIdenticalAndKeepsTheUsersEntries()
    {
        var engine = new HostsFileEngine(_hosts, _backups);
        var journal = new ChangeJournal(_journalPath);
        var before = await File.ReadAllBytesAsync(_hosts);

        await engine.ApplyAsync([Rule("t.loop", "update.example.invalid")], journal, loopbackRuleIds: Ids("t.loop"));
        await engine.RevertAsync(journal.Entries.Single());

        Assert.Equal(before, await File.ReadAllBytesAsync(_hosts));
        Assert.Empty(engine.CurrentlyLooped());
    }

    [Fact]
    public async Task TheJournalEntryDescribesBothKindsOfName()
    {
        var engine = new HostsFileEngine(_hosts, _backups);
        var journal = new ChangeJournal(_journalPath);
        await engine.ApplyAsync(
            [Rule("t.block", "a.example.invalid"), Rule("t.loop", "b.example.invalid")],
            journal, loopbackRuleIds: Ids("t.loop"));

        var description = journal.Entries.Single().Description;
        Assert.Contains("1 sinkholed", description);
        Assert.Contains("1 resolved to this machine", description);
    }

    [Fact]
    public void WithoutLocalOnlyRulesNothingChangesFromTheOriginalBehaviour()
    {
        var modes = HostsFileEngine.EffectiveModes([Rule("a", "x.example.invalid")], Ids());
        Assert.False(modes["x.example.invalid"]);
    }

    // ------------------------------------------------------------------ the address vocabulary

    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("127.255.255.254", true)]
    [InlineData("::1", true)]
    [InlineData("::ffff:127.0.0.1", true)]
    [InlineData("192.168.1.10", false)]
    [InlineData("8.8.8.8", false)]
    [InlineData("::", false)]
    [InlineData("2001:4860:4860::8888", false)]
    public void LoopbackIsRecognisedInEveryFormItCanArriveIn(string address, bool expected)
    {
        Assert.Equal(expected, LoopbackRanges.IsLoopback(IPAddress.Parse(address)));
    }

    [Fact]
    public void TheNonLoopbackRangesCoverEveryIPv4AddressExceptThe127Block()
    {
        var ranges = LoopbackRanges.NonLoopbackV4
            .Select(r => r.Split('-'))
            .Select(p => (Lo: ToUInt(p[0]), Hi: ToUInt(p[1])))
            .OrderBy(r => r.Lo).ToList();

        Assert.Equal(2, ranges.Count);
        Assert.Equal(0u, ranges[0].Lo);
        Assert.Equal(ToUInt("126.255.255.255"), ranges[0].Hi);
        Assert.Equal(ToUInt("128.0.0.0"), ranges[1].Lo);
        Assert.Equal(uint.MaxValue, ranges[1].Hi);
        // Nothing overlaps 127.0.0.0/8 and nothing else is missing: the gap is exactly that block.
        Assert.Equal(ToUInt("127.0.0.0") - 1, ranges[0].Hi);
        Assert.Equal(ToUInt("127.255.255.255") + 1, ranges[1].Lo);
    }

    [Fact]
    public void TheIPv6RangeLeavesOutTheLoopbackAddressAndNothingElseUseful()
    {
        var range = Assert.Single(LoopbackRanges.NonLoopbackV6).Split('-');
        Assert.Equal(IPAddress.Parse("::2"), IPAddress.Parse(range[0]));
        Assert.Equal(IPAddress.Parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), IPAddress.Parse(range[1]));
    }

    private static uint ToUInt(string ip) => BitConverter.ToUInt32(IPAddress.Parse(ip).GetAddressBytes().Reverse().ToArray(), 0);

    // ------------------------------------------------------------------ firewall: validation

    [Fact]
    public void AProgramInsideTheWindowsDirectoryIsRefused()
    {
        var cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        var ex = Assert.Throws<ArgumentException>(() => FirewallEngine.ValidateJailTarget(cmd, null));
        Assert.Contains("Windows directory", ex.Message);
    }

    [Theory]
    [InlineData(@"relative\app.exe")]
    [InlineData(@"app.exe")]
    [InlineData(@"C:\Program Files\Vendor\*.exe")]
    [InlineData(@"C:\Program Files\Vendor\app?.exe")]
    public void APathThatIsNotOneFullyQualifiedProgramIsRefused(string path)
    {
        Assert.Throws<ArgumentException>(() => FirewallEngine.ValidateJailTarget(path, null));
    }

    [Fact]
    public void AProgramThatDoesNotExistIsRefused()
    {
        var missing = Path.Combine(_dir, "nope", "nope.exe");
        Assert.Throws<FileNotFoundException>(() => FirewallEngine.ValidateJailTarget(missing, null));
    }

    [Fact]
    public void AnOrdinaryInstalledProgramIsAccepted()
    {
        var exe = Path.Combine(_dir, "vendor.exe");
        File.WriteAllBytes(exe, [0x4D, 0x5A]);
        FirewallEngine.ValidateJailTarget(exe, null); // no exception
    }

    [Theory]
    [InlineData("gupdate")]
    [InlineData("GoogleUpdaterService152.0.7933.0")]
    [InlineData("Google Chrome Elevation")]
    public void APlausibleServiceNameIsAccepted(string name) => FirewallEngine.ValidateJailTarget(null, name);

    [Theory]
    [InlineData("x'; Remove-Item C:\\ -Recurse; '")]
    [InlineData("")]
    [InlineData("svc\nname")]
    [InlineData("a|b")]
    public void ADodgyServiceNameIsRefused(string name)
    {
        Assert.Throws<ArgumentException>(() => FirewallEngine.ValidateJailTarget(null, name));
    }

    [Fact]
    public void ExactlyOneOfAProgramOrAServiceIsRequired()
    {
        var exe = Path.Combine(_dir, "vendor.exe");
        File.WriteAllBytes(exe, [0x4D, 0x5A]);
        Assert.Throws<ArgumentException>(() => FirewallEngine.ValidateJailTarget(exe, "gupdate"));
        Assert.Throws<ArgumentException>(() => FirewallEngine.ValidateJailTarget(null, null));
    }

    // ------------------------------------------------------------------ firewall: the command

    private static FirewallRuleSpec Spec(string? program, string? service, FirewallDirection direction) =>
        new("rule.id", "Anti-Google: local-only x (out)", "desc", direction, LoopbackRanges.NonLoopback,
            ProgramPath: program, ServiceName: service);

    [Fact]
    public void AJailRuleBlocksEverythingExceptLoopbackAndNamesTheProgram()
    {
        var cmd = FirewallEngine.BuildCreateCommand(Spec(@"C:\Program Files\Vendor\app.exe", null, FirewallDirection.Outbound), "Anti-Google");

        Assert.Contains("-Direction Outbound", cmd);
        Assert.Contains("-Action Block", cmd);
        Assert.Contains("-Group 'Anti-Google'", cmd);
        Assert.Contains("-Program 'C:\\Program Files\\Vendor\\app.exe'", cmd);
        Assert.DoesNotContain("-Service", cmd);
        Assert.Contains("'0.0.0.0-126.255.255.255'", cmd);
        Assert.Contains("'128.0.0.0-255.255.255.255'", cmd);
        Assert.Contains("'::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'", cmd);
        Assert.DoesNotContain("127.", cmd);
    }

    [Fact]
    public void TheInboundJailRuleIsTheSameRuleInTheOtherDirection()
    {
        var cmd = FirewallEngine.BuildCreateCommand(Spec(null, "gupdate", FirewallDirection.Inbound), "Anti-Google");
        Assert.Contains("-Direction Inbound", cmd);
        Assert.Contains("-Service 'gupdate'", cmd);
        Assert.DoesNotContain("-Program", cmd);
    }

    [Fact]
    public void ASingleQuoteInAPathCannotBreakOutOfThePowerShellString()
    {
        var cmd = FirewallEngine.BuildCreateCommand(
            Spec(@"C:\Program Files\O'Brien'; Remove-Item C:\x; '\app.exe", null, FirewallDirection.Outbound), "Anti-Google");

        // Every quote in the payload is doubled, so the whole thing stays inside one quoted string.
        Assert.Contains("-Program 'C:\\Program Files\\O''Brien''; Remove-Item C:\\x; ''\\app.exe'", cmd);
        Assert.DoesNotContain("O'Brien'; Remove-Item", cmd.Replace("''", ""));
    }

    [Fact]
    public void TheRuleNamesAreStableAndTellTheDirectionsApart()
    {
        Assert.Equal("Anti-Google: local-only gupdate (out)", FirewallEngine.JailRuleName("gupdate", FirewallDirection.Outbound));
        Assert.Equal("Anti-Google: local-only gupdate (in)", FirewallEngine.JailRuleName("gupdate", FirewallDirection.Inbound));
    }

    // ------------------------------------------------------------------ firewall: read-back

    private static FirewallRuleState GoodState(FirewallRuleSpec spec) => new(
        spec.DisplayName, true, spec.Direction.ToString(), "Block", "Anti-Google",
        spec.ProgramPath, spec.ServiceName, [.. spec.RemoteAddresses]);

    [Fact]
    public void ARuleThatReadsBackExactlyAsSpecifiedPassesTheCheck()
    {
        var spec = Spec(@"C:\v\app.exe", null, FirewallDirection.Outbound);
        Assert.Null(FirewallEngine.CheckJail(GoodState(spec), spec));
    }

    [Fact]
    public void EveryWayAJailCanBeWrongIsReportedByName()
    {
        var spec = Spec(@"C:\v\app.exe", null, FirewallDirection.Outbound);
        var good = GoodState(spec);

        Assert.Contains("does not exist", FirewallEngine.CheckJail(null, spec));
        Assert.Contains("not enabled", FirewallEngine.CheckJail(good with { Enabled = false }, spec));
        Assert.Contains("direction", FirewallEngine.CheckJail(good with { Direction = "Inbound" }, spec));
        Assert.Contains("Block", FirewallEngine.CheckJail(good with { Action = "Allow" }, spec));
        Assert.Contains("program", FirewallEngine.CheckJail(good with { Program = @"C:\other.exe" }, spec));
        Assert.Contains("remote addresses", FirewallEngine.CheckJail(good with { RemoteAddresses = ["Any"] }, spec));
        Assert.Contains("remote addresses", FirewallEngine.CheckJail(good with { RemoteAddresses = [.. spec.RemoteAddresses, "10.0.0.0/8"] }, spec));
    }

    [Fact]
    public void AServiceRuleIsCheckedAgainstTheServiceNameNotAProgram()
    {
        var spec = Spec(null, "gupdate", FirewallDirection.Inbound);
        var good = GoodState(spec);
        Assert.Null(FirewallEngine.CheckJail(good, spec));
        Assert.Contains("service", FirewallEngine.CheckJail(good with { Service = "other" }, spec));
    }

    [Fact]
    public void ReadBackAcceptsALoneObjectAnArrayAndNothing()
    {
        const string one = """{"Name":"R1","Enabled":"True","Direction":"Outbound","Action":"Block","Group":"Anti-Google","Program":"C:\\v\\a.exe","Service":"Any","Remote":["1.0.0.0-2.0.0.0","::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]}""";
        var single = Assert.Single(FirewallEngine.ParseStates(one));
        Assert.Equal("R1", single.DisplayName);
        Assert.True(single.Enabled);
        Assert.Equal(@"C:\v\a.exe", single.Program);
        Assert.Null(single.Service); // "Any" means no service filter
        Assert.Equal(2, single.RemoteAddresses.Count);

        Assert.Equal(2, FirewallEngine.ParseStates($"[{one},{one.Replace("R1", "R2")}]").Count);
        Assert.Empty(FirewallEngine.ParseStates("{}"));
        Assert.Empty(FirewallEngine.ParseStates(""));
        Assert.Empty(FirewallEngine.ParseStates("not json"));
    }

    [Fact]
    public void AScalarRemoteAddressIsReadAsOneEntry()
    {
        const string json = """{"Name":"R","Enabled":"True","Direction":"Inbound","Action":"Block","Program":"Any","Service":"gupdate","Remote":"Any"}""";
        var state = Assert.Single(FirewallEngine.ParseStates(json));
        Assert.Equal(["Any"], state.RemoteAddresses);
        Assert.Null(state.Program);
        Assert.Equal("gupdate", state.Service);
    }
}
