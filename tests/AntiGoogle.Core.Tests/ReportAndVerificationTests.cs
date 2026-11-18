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
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using AntiGoogle.Core.Engines;
using AntiGoogle.Core.Journal;
using AntiGoogle.Core.Markers;
using AntiGoogle.Core.Model;
using AntiGoogle.Core.Platform;
using AntiGoogle.Core.Reporting;
using AntiGoogle.Core.Safety;
using AntiGoogle.Core.Verification;
using Xunit;

namespace AntiGoogle.Core.Tests;

public class AuditLogTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "antigoogle-tests", Guid.NewGuid().ToString("N"));

    public AuditLogTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void EventsAreAppendedOnePerLineAndReadBackInOrder()
    {
        var log = new AuditLog(Path.Combine(_dir, "audit.jsonl"));
        log.Append("apply.start", detail: "3 planned");
        log.Append("change", "rule.a", "Hosts", "hosts", "Applied");
        log.Append("apply.done");

        var lines = File.ReadAllLines(log.Path!);
        Assert.Equal(3, lines.Length);
        Assert.All(lines, l => JsonDocument.Parse(l).Dispose());

        var events = log.Tail(10);
        Assert.Equal(["apply.start", "change", "apply.done"], events.Select(e => e.Kind));
        Assert.Equal("rule.a", events[1].RuleId);
    }

    [Fact]
    public void TailReturnsOnlyTheNewestAndSkipsALineThatIsNotJson()
    {
        var path = Path.Combine(_dir, "audit.jsonl");
        var log = new AuditLog(path);
        for (var i = 0; i < 10; i++) log.Append("k" + i);
        File.AppendAllText(path, "{ this line was torn\n");
        log.Append("k10");

        var events = log.Tail(3);

        Assert.Equal(["k8", "k9", "k10"], events.Select(e => e.Kind));
    }

    [Fact]
    public void ADisabledLogWritesNothingAndReadsNothing()
    {
        AuditLog.Disabled.Append("anything");
        Assert.False(AuditLog.Disabled.IsEnabled);
        Assert.Empty(AuditLog.Disabled.Tail(10));
    }

    [Fact]
    public void ALogThatCannotBeWrittenNeverThrows()
    {
        var log = new AuditLog(Path.Combine(_dir, "con", "x", "audit.jsonl").Replace("con", "CON:"));
        log.Append("still fine");
    }

    [Fact]
    public void ManyWritersDoNotCorruptTheLog()
    {
        var log = new AuditLog(Path.Combine(_dir, "audit.jsonl"));
        Parallel.For(0, 200, i => log.Append("k", detail: new string('x', 50) + i));

        var lines = File.ReadAllLines(log.Path!);
        Assert.Equal(200, lines.Length);
        Assert.All(lines, l => JsonDocument.Parse(l).Dispose());
    }
}

public class NetTablesTests
{
    [Fact]
    public void ALoopbackListenerAndItsConnectionAreAttributedToThisProcess()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        using var client = new TcpClient();
        client.Connect(IPAddress.Loopback, port);
        using var accepted = listener.AcceptTcpClient();

        var mine = NetTables.Tcp().Where(e => e.ProcessId == Environment.ProcessId).ToList();

        Assert.Contains(mine, e => e.State == TcpState.Listen && e.LocalPort == port && e.LocalAddress.Equals(IPAddress.Loopback));
        Assert.Contains(mine, e => e.State == TcpState.Established && e.RemotePort == port && e.RemoteAddress.Equals(IPAddress.Loopback));
        Assert.Contains(mine, e => e.State == TcpState.Established && e.LocalPort == port && e.RemoteAddress.Equals(IPAddress.Loopback));
    }

    [Fact]
    public void AnIPv6ListenerIsReadWithItsPortIntact()
    {
        TcpListener listener;
        try { listener = new TcpListener(IPAddress.IPv6Loopback, 0); listener.Start(); }
        catch (SocketException) { return; } // a machine with IPv6 switched off cannot run this check
        using (listener)
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            Assert.Contains(NetTables.Tcp(), e => e.ProcessId == Environment.ProcessId && e.State == TcpState.Listen
                                                  && e.LocalPort == port && e.LocalAddress.Equals(IPAddress.IPv6Loopback));
        }
    }

    [Fact]
    public void ABoundUdpSocketIsListedWithItsOwner()
    {
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)udp.Client.LocalEndPoint!).Port;

        Assert.Contains(NetTables.Udp(), e => e.ProcessId == Environment.ProcessId && e.LocalPort == port);
    }

    [Fact]
    public void TheProgramBehindAProcessIdIsItsFullImagePath()
    {
        var path = ProcessImage.PathOf(Environment.ProcessId);
        Assert.NotNull(path);
        Assert.Equal(Environment.ProcessPath, path, ignoreCase: true);
    }

    [Fact]
    public void ProtectedAndMissingProcessesYieldNullNotAnException()
    {
        Assert.Null(ProcessImage.PathOf(0));
        Assert.Null(ProcessImage.PathOf(4));
        Assert.Null(ProcessImage.PathOf(int.MaxValue));
    }
}

public class LoopbackVerifierTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "antigoogle-tests", Guid.NewGuid().ToString("N"));
    private readonly FakeFirewall _firewall = new();
    private readonly string _hostsPath;
    private readonly ChangeJournal _journal;
    private readonly HostsFileEngine _hosts;

    public LoopbackVerifierTests()
    {
        Directory.CreateDirectory(_root);
        _hostsPath = Path.Combine(_root, "hosts");
        File.WriteAllText(_hostsPath, "# mine\r\n", new UTF8Encoding(false));
        _journal = new ChangeJournal(Path.Combine(_root, "journal.json"));
        _hosts = new HostsFileEngine(_hostsPath, Path.Combine(_root, "backups"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
        GC.SuppressFinalize(this);
    }

    private string Exe()
    {
        var path = Path.Combine(_root, "Vendor", "vendor.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, [0x4D, 0x5A]);
        return path;
    }

    private Task Jail(string program, string? service = null) =>
        _firewall.ApplyLoopbackJailAsync("rule", "vendor-1234", service is null ? program : null, service, _journal, default);

    private LoopbackVerifier Verifier() => new(_firewall, _hosts, _journal);

    [Fact]
    public async Task AJailThatReadsBackExactlyPassesBothRuleChecks()
    {
        await Jail(Exe());

        var result = await Verifier().VerifyAsync();

        var target = Assert.Single(result.Targets);
        Assert.Equal(3, target.Checks.Count);
        Assert.All(target.Checks, c => Assert.True(c.Passed, c.Detail));
        Assert.True(result.Passed);
    }

    [Fact]
    public async Task ARuleThatWindowsHoldsDifferentlyFailsTheCheckAndSaysHow()
    {
        await Jail(Exe());
        _firewall.ReadBackOverride = (name, state) => name.EndsWith("(out)") ? state! with { Action = "Allow" } : state;

        var result = await Verifier().VerifyAsync();

        var failed = Assert.Single(result.Targets.Single().Checks, c => !c.Passed);
        Assert.Contains("Outbound", failed.Name);
        Assert.Contains("Allow", failed.Detail);
        Assert.False(result.Passed);
    }

    [Fact]
    public async Task ARuleThatIsMissingFromWindowsFails()
    {
        await Jail(Exe());
        _firewall.ReadBackOverride = (name, state) => name.EndsWith("(in)") ? null : state;

        var failed = Assert.Single((await Verifier().VerifyAsync()).Targets.Single().Checks, c => !c.Passed);
        Assert.Contains("does not exist", failed.Detail);
    }

    [Fact]
    public async Task AServiceJailIsCheckedByNameAndSaysItsLiveSocketsAreNotAudited()
    {
        await Jail("unused", service: "gupdate");

        var target = Assert.Single((await Verifier().VerifyAsync()).Targets);

        Assert.Equal("gupdate", target.ServiceName);
        Assert.Contains(target.Checks, c => c.Name.Contains("No live connection") && c.Detail.Contains("shared host"));
    }

    [Fact]
    public async Task AConfinedProgramThatIsNotRunningHasNothingToLeak()
    {
        await Jail(Exe());
        var check = (await Verifier().VerifyAsync()).Targets.Single().Checks.Single(c => c.Name.StartsWith("No live"));
        Assert.True(check.Passed);
        Assert.Contains("not running", check.Detail);
    }

    [Fact]
    public async Task AConfinedProgramThatIsRunningAndTalkingOnlyToLoopbackPasses()
    {
        // The test process is the "confined program": it holds a real loopback connection.
        await Jail(Environment.ProcessPath!);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var client = new TcpClient();
        client.Connect(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
        using var accepted = listener.AcceptTcpClient();

        var target = Assert.Single((await Verifier().VerifyAsync()).Targets);

        var live = target.Checks.Single(c => c.Name.StartsWith("No live"));
        Assert.True(live.Passed, live.Detail);
        Assert.Contains("none connected off this machine", live.Detail);
        Assert.NotEmpty(target.Connections);
    }

    private static readonly HashSet<IPAddress> Own = [IPAddress.Parse("192.168.1.20")];

    private static TcpEntry Tcp(string remote, TcpState state) =>
        new(IPAddress.Parse("192.168.1.20"), 50000, IPAddress.Parse(remote), 443, state, 1);

    [Theory]
    [InlineData("142.250.80.46", TcpState.Established, true)]
    [InlineData("142.250.80.46", TcpState.SynSent, true)]
    [InlineData("127.0.0.1", TcpState.Established, false)]
    [InlineData("::1", TcpState.Established, false)]
    [InlineData("::ffff:127.0.0.1", TcpState.Established, false)]
    [InlineData("192.168.1.20", TcpState.Established, false)]
    [InlineData("::ffff:192.168.1.20", TcpState.Established, false)]
    [InlineData("0.0.0.0", TcpState.Listen, false)]
    [InlineData("142.250.80.46", TcpState.TimeWait, false)]
    [InlineData("142.250.80.46", TcpState.Closed, false)]
    public void OnlyALiveConnectionToSomewhereOffThisMachineIsALeak(string remote, TcpState state, bool leak)
    {
        Assert.Equal(leak, LoopbackVerifier.IsLeak(Tcp(remote, state), Own));
    }

    [Fact]
    public async Task LocalOnlyNamesInTheHostsFileAreCheckedForBothAddressFamilies()
    {
        var rule = new BlockRule
        {
            Id = "test.hosts", Title = "t", Summary = "s", Category = RuleCategory.Telemetry, Tier = RiskTier.Balanced,
            Engine = EngineKind.Hosts, Domains = ["a.example.invalid"], SupportsLocalOnly = true,
            LocalOnlyBreaks = [Breakage.Minor("x", "y")]
        };
        await _hosts.ApplyAsync([rule], _journal, loopbackRuleIds: new HashSet<string> { "test.hosts" });

        var good = await Verifier().VerifyAsync();
        var check = Assert.Single(good.Hosts);
        Assert.True(check.Passed, check.Detail);

        // Strip the IPv6 line: an IPv4-only entry is exactly what a client defeats with its AAAA fallback.
        File.WriteAllText(_hostsPath, File.ReadAllText(_hostsPath).Replace("::1 a.example.invalid\r\n", ""));
        var bad = await Verifier().VerifyAsync();
        Assert.False(Assert.Single(bad.Hosts).Passed);
        Assert.Contains("a.example.invalid", bad.Hosts[0].Detail);
    }

    [Fact]
    public async Task WithNothingConfinedThereIsNothingToVerify()
    {
        var result = await Verifier().VerifyAsync();
        Assert.False(result.AnythingToVerify);
    }
}

public class ReportTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "antigoogle-tests", Guid.NewGuid().ToString("N"));
    private readonly string _hostsPath;
    private readonly FakeFirewall _firewall = new();
    private readonly TempMarkerEnvironment _markerEnv;

    public ReportTests()
    {
        Directory.CreateDirectory(_root);
        _hostsPath = Path.Combine(_root, "hosts");
        File.WriteAllText(_hostsPath, "# mine\r\n", new UTF8Encoding(false));
        _markerEnv = new TempMarkerEnvironment(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
        GC.SuppressFinalize(this);
    }

    private ProtectionService Service() => new(new ProtectionServiceOptions
    {
        Hosts = new HostsFileEngine(_hostsPath, Path.Combine(_root, "backups")),
        Firewall = _firewall,
        Services = new FakeServices(),
        Tasks = new FakeTasks(),
        Quarantine = new QuarantineEngine(Path.Combine(_root, "vault"), _markerEnv),
        Markers = new MarkerScanner(_markerEnv),
        Journal = new ChangeJournal(Path.Combine(_root, "journal.json")),
        Audit = new AuditLog(Path.Combine(_root, "audit.jsonl")),
        Catalog = [], Preflight = _ => Task.FromResult(new List<PreflightFinding>()),
        IsElevated = () => true, SweepFirewallGroupOnRevert = false, WebListeners = () => []
    });

    private ReportBuilder Builder(ProtectionService s) => new(s, "9.9.9", new MarkerScanner(_markerEnv),
        _ => Task.FromResult(new List<PreflightFinding> { PreflightFinding.Info("All good", "Nothing to see.") }));

    private string Exe(string name)
    {
        var path = Path.Combine(_root, "Vendor", name);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, [0x4D, 0x5A]);
        return path;
    }

    // ------------------------------------------------------------------ rendering

    [Fact]
    public void EveryValueIsEncodedAndTheFileHasNoScriptAndLoadsNothing()
    {
        const string hostile = "<script>alert('x')</script>\"><img src=http://evil.example/p.png onerror=alert(1)>";
        var r = new ProtectionReport
        {
            GeneratedAt = DateTimeOffset.Now, AppVersion = hostile, OsVersion = hostile, Profile = hostile,
            LocalOnlyApps = [hostile], ContainedApps = [hostile],
            ArmedRules = [new ReportRule(hostile, hostile, hostile, "Blocked", hostile, hostile, "Severe",
                [new ReportCost(hostile, "Severe", hostile)])],
            Hosts = new ReportHosts { Groups = [new ReportHostsGroup(hostile, hostile, "Blocked", [hostile])], IncompleteNames = [hostile] },
            FirewallRules = [new ReportFirewallRule(hostile, hostile, hostile, true, hostile, 1, hostile)],
            Services = [new ReportService(hostile, hostile, hostile, hostile, DateTimeOffset.Now)],
            Quarantined = [new ReportQuarantined(hostile, hostile, hostile, hostile, 1, 1, hostile, hostile)],
            Markers = [new ReportMarker(hostile, hostile, hostile, hostile, hostile, hostile, hostile, hostile, hostile, hostile)],
            Verification = [new ReportTargetCheck(hostile, hostile, [new ReportCheck(hostile, false, hostile)], [hostile])],
            Findings = [new ReportFinding("Warning", hostile, hostile)],
            Activity = [new ReportEvent(hostile, hostile, hostile, hostile, hostile, hostile, hostile)],
            Limits = [hostile]
        };

        var html = ReportRenderer.ToHtml(r);

        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<img", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<link", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<iframe", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("onerror=", html.Replace("&#39;", "'").Replace("onerror=alert(1)&gt;", ""), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("&lt;script&gt;", html);
        Assert.DoesNotContain("src=\"http", html);
        Assert.DoesNotContain("href=", html);
    }

    [Fact]
    public void TheStaticTextOfTheReportUsesNoEmOrEnDashes()
    {
        var html = ReportRenderer.ToHtml(new ProtectionReport { GeneratedAt = DateTimeOffset.Now, AppVersion = "1", OsVersion = "w", Profile = "p" });
        Assert.DoesNotContain('—', html);
        Assert.DoesNotContain('–', html);
    }

    [Fact]
    public void EverySectionTheReportOpensIsClosedSoTheyAreSiblingsNotNested()
    {
        var html = ReportRenderer.ToHtml(new ProtectionReport { GeneratedAt = DateTimeOffset.Now, AppVersion = "1", OsVersion = "w", Profile = "p" });

        var opened = System.Text.RegularExpressions.Regex.Matches(html, "<section>").Count;
        var closed = System.Text.RegularExpressions.Regex.Matches(html, "</section>").Count;

        Assert.Equal(10, opened);
        Assert.Equal(opened, closed);
        // Sibling sections: none is opened while another is still open.
        Assert.DoesNotMatch(@"<section>(?:(?!</section>).)*<section>", html);
    }

    [Fact]
    public void APathMayWrapAfterABackslashButReadsTheSameOtherwise()
    {
        const string path = @"C:\ProgramData\Vendor\App.exe";
        var html = ReportRenderer.ToHtml(new ProtectionReport
        {
            GeneratedAt = DateTimeOffset.Now, AppVersion = "1", OsVersion = "w", Profile = "p",
            FirewallRules = [new ReportFirewallRule("rule", "Outbound", "Block", true, path, 1, "everything except loopback")],
            Activity = [new ReportEvent("t", "change", "rule.x", "LocalOnly", path, "Applied", "Keep " + path + " running")]
        });

        Assert.Contains(@"C:\<wbr>ProgramData\<wbr>Vendor\<wbr>App.exe", html);
        Assert.Contains(path, html.Replace("<wbr>", ""));
    }

    [Fact]
    public void TheActivityLogUsesWordsNotEnumNamesAndDoesNotRepeatATargetItsDetailAlreadyNames()
    {
        var html = ReportRenderer.ToHtml(new ProtectionReport
        {
            GeneratedAt = DateTimeOffset.Now, AppVersion = "1", OsVersion = "w", Profile = "p",
            Activity =
            [
                new ReportEvent("t1", "change", "svc.google-updater", "LocalOnly", "gupdate", "AlreadySatisfied", "Keep service gupdate running"),
                new ReportEvent("t2", "change", "rule.x", "Hosts", "hosts", "Applied", "Write 3 domains"),
                new ReportEvent("t3", "change", "marker.thing-id", "Quarantine", "thing-id", "Refused", "Reported only"),
                new ReportEvent("t4", "undo", "svc.x", "Service", "097433e8dce449a4a52caa2ef6483c6f", "Applied", "Undo: Disabled service gupdatem")
            ]
        });

        Assert.DoesNotContain("097433e8dce449a4a52caa2ef6483c6f", html);

        Assert.Contains("Local-only", html);
        Assert.Contains("Already satisfied", html);
        Assert.DoesNotContain("AlreadySatisfied", html);
        Assert.DoesNotContain("<span class=\"muted\">gupdate</span>", html);
        Assert.DoesNotContain("<span class=\"muted\">thing-id</span>", html);
        Assert.Contains("<span class=\"muted\">hosts</span>", html);
    }

    [Fact]
    public void TheJsonCarriesTheSameNumbersAsTheHtml()
    {
        var r = new ProtectionReport
        {
            GeneratedAt = DateTimeOffset.Now, AppVersion = "1.2.3", OsVersion = "w", Profile = "Aggressive",
            Counts = new ReportCounts { SinkholedDomains = 116, LoopbackDomains = 7, LocalOnlyJails = 2, QuarantinedItems = 3 }
        };

        var json = JsonDocument.Parse(ReportRenderer.ToJson(r)).RootElement;
        var html = ReportRenderer.ToHtml(r);

        Assert.Equal(116, json.GetProperty("Counts").GetProperty("SinkholedDomains").GetInt32());
        Assert.Equal(7, json.GetProperty("Counts").GetProperty("LoopbackDomains").GetInt32());
        Assert.Contains(">116<", html);
        Assert.Contains(">7<", html);
        Assert.Contains("1.2.3", html);
    }

    [Fact]
    public void ThePathsInAReportNeverCarryTheAccountName()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var redacted = ReportBuilder.Redact(Path.Combine(profile, ".android", "analytics.settings"));

        Assert.StartsWith("%USERPROFILE%", redacted);
        Assert.DoesNotContain(Path.GetFileName(profile), redacted.Replace("%USERPROFILE%", ""), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TheReportWriterPutsTheHtmlAndTheJsonSideBySide()
    {
        var saved = ReportWriter.Save(new ProtectionReport { GeneratedAt = new DateTimeOffset(2026, 11, 18, 9, 30, 0, TimeSpan.Zero) },
            Path.Combine(_root, "reports"));

        Assert.True(File.Exists(saved.HtmlPath));
        Assert.True(File.Exists(saved.JsonPath));
        Assert.Equal(Path.GetFileNameWithoutExtension(saved.HtmlPath), Path.GetFileNameWithoutExtension(saved.JsonPath));
        Assert.StartsWith("<!doctype html>", File.ReadAllText(saved.HtmlPath));
    }

    // ------------------------------------------------------------------ building

    [Fact]
    public async Task TheReportSaysWhatIsConfinedAndShowsTheEvidenceItHolds()
    {
        var app = Exe("FakeApp.exe");
        var svc = Service();
        await svc.ApplyAsync(await svc.BuildPlanAsync(new PlanRequest { LocalOnlyApps = [app] }));

        var report = await Builder(svc).BuildAsync(new AppSettings { LocalOnlyApps = [app] });

        Assert.Equal(1, report.Counts.LocalOnlyJails);
        Assert.Equal(2, report.FirewallRules.Count);
        Assert.Contains(report.FirewallRules, f => f.Direction == "Outbound" && f.RemoteSummary == "everything except loopback");
        Assert.True(report.VerificationPassed);
        var target = Assert.Single(report.Verification);
        Assert.All(target.Checks, c => Assert.True(c.Passed, c.Detail));
        Assert.Equal(1, report.Counts.UndoableChanges / 2); // two journal entries for one jail
        Assert.Contains(report.Activity, e => e.Kind == "change" && e.Engine == "LocalOnly");

        var html = ReportRenderer.ToHtml(report);
        Assert.Contains("Verification passed", html);
        Assert.Contains("everything except loopback", html);
    }

    [Fact]
    public async Task AFailedCheckAppearsInTheReportAsAFailureNotAsAPass()
    {
        var svc = Service();
        await svc.ApplyAsync(await svc.BuildPlanAsync(new PlanRequest { LocalOnlyApps = [Exe("FakeApp.exe")] }));
        _firewall.ReadBackOverride = (_, state) => state is null ? null : state with { Enabled = false };

        var report = await Builder(svc).BuildAsync(new AppSettings());

        Assert.False(report.VerificationPassed);
        var html = ReportRenderer.ToHtml(report);
        Assert.Contains("Verification found a problem", html);
        Assert.Contains("FAIL", html);
    }

    [Fact]
    public async Task TheReportListsWhatIsInQuarantineAndWhatWasFoundButLeftAlone()
    {
        var local = _markerEnv.ResolveToken("%LOCALAPPDATA%")!;
        var idFile = Path.Combine(local, "Vendor", "id.dat");
        Directory.CreateDirectory(Path.GetDirectoryName(idFile)!);
        File.WriteAllText(idFile, "identifier");
        Directory.CreateDirectory(Path.Combine(_markerEnv.ResolveToken("%PROGRAMDATA%")!, "FireEye", "xagt"));

        var markers = new[]
        {
            new MarkerDefinition { Id = "t.id", Vendor = "Test", Title = "Test identifier", Why = "w", Kind = MarkerKind.File,
                Class = MarkerClass.Identifier, Locations = [@"%LOCALAPPDATA%\Vendor\id.dat"], Action = MarkerAction.Quarantine,
                Confidence = Confidence.High, Source = "t", Breaks = [Breakage.Minor("a", "b")] }
        };
        var svc = new ProtectionService(new ProtectionServiceOptions
        {
            Hosts = new HostsFileEngine(_hostsPath, Path.Combine(_root, "backups")), Firewall = _firewall,
            Quarantine = new QuarantineEngine(Path.Combine(_root, "vault"), _markerEnv), Markers = new MarkerScanner(_markerEnv),
            MarkerCatalog = markers, Journal = new ChangeJournal(Path.Combine(_root, "journal.json")),
            Audit = AuditLog.Disabled, Catalog = [], Preflight = _ => Task.FromResult(new List<PreflightFinding>()),
            IsElevated = () => true, SweepFirewallGroupOnRevert = false
        });
        await svc.ApplyAsync(await svc.BuildPlanAsync(new PlanRequest { QuarantineMarkerIds = ["t.id"] }));

        var report = await Builder(svc).BuildAsync(new AppSettings());

        var held = Assert.Single(report.Quarantined);
        Assert.Equal("Test identifier", held.Title);
        Assert.Equal(1, report.Counts.QuarantinedItems);
        // The catalog's own FireEye folder is found, listed, and marked as reported only.
        Assert.Contains(report.Markers, m => m.Id == "mandiant.endpoint-agent-files" && m.Action == "Reported only");
        Assert.True(report.MarkersNotFound > 0);

        var html = ReportRenderer.ToHtml(report);
        Assert.Contains("What was quarantined", html);
        Assert.Contains("Test identifier", html);
    }

    [Fact]
    public async Task TheHostsSectionIsReadFromTheLiveFileWithEachRulesMode()
    {
        var rules = new[]
        {
            new BlockRule { Id = "t.block", Title = "Blocked group", Summary = "s", Category = RuleCategory.Telemetry, Tier = RiskTier.Balanced,
                Engine = EngineKind.Hosts, Domains = ["a.example.invalid"] },
            new BlockRule { Id = "t.loop", Title = "Looped group", Summary = "s", Category = RuleCategory.Telemetry, Tier = RiskTier.Balanced,
                Engine = EngineKind.Hosts, Domains = ["b.example.invalid"], SupportsLocalOnly = true, LocalOnlyBreaks = [Breakage.Minor("x", "y")] }
        };
        var svc = Service();
        await new HostsFileEngine(_hostsPath, Path.Combine(_root, "backups")).ApplyAsync(rules, svc.Journal,
            loopbackRuleIds: new HashSet<string> { "t.loop" });

        var report = await Builder(svc).BuildAsync(new AppSettings(), verify: false);

        Assert.Equal(1, report.Counts.SinkholedDomains);
        Assert.Equal(1, report.Counts.LoopbackDomains);
        Assert.Contains(report.Hosts.Groups, g => g.RuleId == "t.block" && g.Mode == "Blocked" && g.Domains.SequenceEqual(["a.example.invalid"]));
        Assert.Contains(report.Hosts.Groups, g => g.RuleId == "t.loop" && g.Mode == "Local-only" && g.Domains.SequenceEqual(["b.example.invalid"]));
    }

    [Fact]
    public async Task APlainMachineProducesACalmReportRatherThanAnError()
    {
        var report = await Builder(Service()).BuildAsync(new AppSettings());
        var html = ReportRenderer.ToHtml(report);

        Assert.Contains("Nothing is armed", html);
        Assert.Contains("Nothing is confined to this machine", html);
        Assert.Contains("Nothing is in quarantine", html);
        Assert.Null(report.VerificationPassed);
    }
}
