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
using System.Security.Cryptography;
using System.Text;
using AntiGoogle.Core.Journal;
using AntiGoogle.Core.Markers;
using AntiGoogle.Core.Model;
using Microsoft.Win32;
using Xunit;

namespace AntiGoogle.Core.Tests;

/// <summary>A machine made of temp directories: tokens resolve under one root, and the "Windows directory" is a subfolder.</summary>
internal sealed class TempMarkerEnvironment(string root) : IMarkerEnvironment
{
    public string Root { get; } = root;
    public List<string> Services { get; } = [];
    public string WindowsDirectory { get; set; } = Path.Combine(root, "WindowsDir");

    public string? ResolveToken(string token) => token.ToUpperInvariant() switch
    {
        "%LOCALAPPDATA%" => Path.Combine(Root, "Local"),
        "%APPDATA%" => Path.Combine(Root, "Roaming"),
        "%PROGRAMDATA%" => Path.Combine(Root, "ProgramData"),
        "%PROGRAMFILES%" => Path.Combine(Root, "ProgramFiles"),
        "%PROGRAMFILES(X86)%" => Path.Combine(Root, "ProgramFilesX86"),
        "%USERPROFILE%" => Path.Combine(Root, "User"),
        _ => null
    };

    public IReadOnlyList<string> FindServices(string pattern) => Services
        .Where(s => pattern.EndsWith('*')
            ? s.StartsWith(pattern[..^1], StringComparison.OrdinalIgnoreCase)
            : string.Equals(s, pattern, StringComparison.OrdinalIgnoreCase))
        .ToList();
}

public class MarkerCatalogTests
{
    [Fact]
    public void MarkerIdsAreUnique()
    {
        var dupes = MarkerCatalog.All.GroupBy(m => m.Id, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1).Select(g => g.Key).ToList();
        Assert.Empty(dupes);
    }

    [Fact]
    public void OnlyIdentifiersLeftoversAndOptionalComponentsCanBeQuarantined()
    {
        foreach (var m in MarkerCatalog.All.Where(m => m.Action == MarkerAction.Quarantine))
            Assert.True(m.Class is MarkerClass.Identifier or MarkerClass.Leftover or MarkerClass.OptionalComponent,
                $"{m.Id} is a {m.Class} marker and must not be quarantinable.");

        foreach (var m in MarkerCatalog.All.Where(m => m.Class is MarkerClass.Component or MarkerClass.SecurityAgent))
            Assert.Equal(MarkerAction.ReportOnly, m.Action);
    }

    [Fact]
    public void ASecurityAgentCanNeverBeMoved()
    {
        foreach (var m in MarkerCatalog.All.Where(m => m.Class == MarkerClass.SecurityAgent))
            Assert.False(QuarantineEngine.IsQuarantinable(m), $"{m.Id} is a security agent.");

        // Even a mislabelled definition cannot get past the engine: the class decides, not the action.
        var rogue = new MarkerDefinition
        {
            Id = "x", Vendor = "x", Title = "x", Why = "x", Kind = MarkerKind.Directory,
            Class = MarkerClass.SecurityAgent, Locations = [@"%LOCALAPPDATA%\x"], Action = MarkerAction.Quarantine,
            Confidence = Confidence.High
        };
        Assert.False(QuarantineEngine.IsQuarantinable(rogue));
    }

    [Fact]
    public void TheReasonAMarkerIsOnlyReportedIsInPlainWordsAndMatchesTheCause()
    {
        MarkerDefinition Def(MarkerClass c, MarkerAction a, Confidence k) => new()
        {
            Id = "x", Vendor = "x", Title = "Thing", Why = "x", Kind = MarkerKind.Directory, Class = c,
            Locations = [@"%LOCALAPPDATA%\x"], Action = a, Confidence = k
        };

        Assert.Equal("Thing is an endpoint security agent and is reported only.",
            QuarantineEngine.WhyReportedOnly(Def(MarkerClass.SecurityAgent, MarkerAction.Quarantine, Confidence.High)));
        Assert.Equal("Thing is working software and is reported only.",
            QuarantineEngine.WhyReportedOnly(Def(MarkerClass.Component, MarkerAction.ReportOnly, Confidence.High)));
        Assert.Contains("enough confidence",
            QuarantineEngine.WhyReportedOnly(Def(MarkerClass.Leftover, MarkerAction.Quarantine, Confidence.Low)));
        Assert.Equal("Thing is reported only.",
            QuarantineEngine.WhyReportedOnly(Def(MarkerClass.Identifier, MarkerAction.ReportOnly, Confidence.Medium)));

        foreach (var m in MarkerCatalog.All.Where(m => !QuarantineEngine.IsQuarantinable(m)))
        {
            var why = QuarantineEngine.WhyReportedOnly(m);
            Assert.StartsWith(m.Title, why);
            Assert.EndsWith("reported only.", why);
        }
    }

    [Fact]
    public void EveryQuarantinableMarkerStatesItsCostAndIsNotGuesswork()
    {
        foreach (var m in MarkerCatalog.All.Where(m => m.CanQuarantine))
        {
            Assert.NotEmpty(m.Breaks);
            Assert.NotEqual(Confidence.Low, m.Confidence);
            Assert.False(string.IsNullOrWhiteSpace(m.Source), $"{m.Id} must say where its location comes from.");
            foreach (var b in m.Breaks.Where(b => b.Severity == BreakageSeverity.Severe))
                Assert.True(b.Detail.Length > 40, $"{m.Id}: a severe cost needs a real explanation.");
        }
    }

    [Fact]
    public void ALowConfidenceMarkerIsReportOnly()
    {
        foreach (var m in MarkerCatalog.All.Where(m => m.Confidence == Confidence.Low))
            Assert.Equal(MarkerAction.ReportOnly, m.Action);
    }

    [Fact]
    public void EveryLocationIsWellFormedForItsKind()
    {
        string[] tokens = ["%LOCALAPPDATA%", "%APPDATA%", "%PROGRAMDATA%", "%PROGRAMFILES%", "%PROGRAMFILES(X86)%", "%USERPROFILE%"];
        foreach (var m in MarkerCatalog.All)
        {
            Assert.NotEmpty(m.Locations);
            foreach (var l in m.Locations)
            {
                switch (m.Kind)
                {
                    case MarkerKind.File:
                    case MarkerKind.Directory:
                        Assert.Contains(tokens, t => l.StartsWith(t + "\\", StringComparison.OrdinalIgnoreCase));
                        Assert.DoesNotContain("..", l);
                        Assert.DoesNotContain("*", l);
                        break;
                    case MarkerKind.RegistryKey:
                        Assert.True(MarkerPaths.IsRegistryLocation(l), $"{m.Id}: {l}");
                        break;
                    case MarkerKind.Service:
                        Assert.DoesNotContain("\\", l);
                        break;
                }
            }
        }
    }

    [Fact]
    public void NoMarkerPointsAtACredentialStoreOrABrowserDataFile()
    {
        // Credentials, cookies and saved logins are not markers. Listing one here would be an invitation
        // to lose them, so the guard is a test rather than a code review habit.
        string[] forbidden =
        [
            "login data", "cookies", "web data", "history", "bookmarks", "preferences", "extensions",
            "credentials", "access_tokens", "legacy_credentials", "firebase-tools", "adbkey", ".ssh", "password"
        ];
        foreach (var m in MarkerCatalog.All.Where(m => m.Kind is MarkerKind.File or MarkerKind.Directory))
        foreach (var l in m.Locations)
        {
            var leaf = l.ToLowerInvariant();
            foreach (var word in forbidden)
                Assert.DoesNotContain(word, leaf);
        }
    }

    [Fact]
    public void TheCopyUsesNoEmOrEnDashes()
    {
        foreach (var m in MarkerCatalog.All)
        foreach (var text in new[] { m.Title, m.Why }.Concat(m.Breaks.SelectMany(b => new[] { b.What, b.Detail })))
        {
            Assert.DoesNotContain('\u2014', text);
            Assert.DoesNotContain('\u2013', text);
        }
    }

    [Fact]
    public void TheMandiantAndFireEyeMarkersAreAllReportOnly()
    {
        var mandiant = MarkerCatalog.All.Where(m => m.Vendor == MarkerCatalog.Mandiant).ToList();
        Assert.NotEmpty(mandiant);
        Assert.All(mandiant, m => Assert.Equal(MarkerAction.ReportOnly, m.Action));
    }
}

public class MarkerScannerTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "antigoogle-tests", Guid.NewGuid().ToString("N"));
    private readonly TempMarkerEnvironment _env;
    private readonly string _regKey = $@"Software\AntiGoogleTests\{Guid.NewGuid():N}";

    public MarkerScannerTests()
    {
        Directory.CreateDirectory(_root);
        _env = new TempMarkerEnvironment(_root);
    }

    public void Dispose()
    {
        try { Registry.CurrentUser.DeleteSubKeyTree(_regKey, throwOnMissingSubKey: false); } catch { }
        try { Directory.Delete(_root, recursive: true); } catch { }
        GC.SuppressFinalize(this);
    }

    internal static MarkerDefinition Def(string id, MarkerKind kind, MarkerClass cls, string location,
        MarkerAction action = MarkerAction.ReportOnly, Confidence confidence = Confidence.High) => new()
    {
        Id = id, Vendor = "Test", Title = $"Test {id}", Why = "test", Kind = kind, Class = cls,
        Locations = [location], Action = action, Confidence = confidence, Source = "test",
        Breaks = action == MarkerAction.Quarantine ? [Breakage.Minor("Nothing real", "Test marker.")] : []
    };

    private string Make(string token, string relative, string? content = null)
    {
        var folder = _env.ResolveToken(token)!;
        var path = Path.Combine(folder, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content ?? "data");
        return path;
    }

    [Fact]
    public void AFileIsFoundWithItsSizeAndNothingIsReadFromIt()
    {
        var path = Make("%LOCALAPPDATA%", @"Vendor\settings.dat", new string('x', 1500));
        var scanner = new MarkerScanner(_env);

        var f = Assert.Single(scanner.Scan([Def("t.file", MarkerKind.File, MarkerClass.Identifier, @"%LOCALAPPDATA%\Vendor\settings.dat")]));

        Assert.True(f.Exists);
        Assert.Equal(path, f.Location);
        Assert.Equal(1500, f.SizeBytes);
        Assert.Equal(1, f.FileCount);
    }

    [Fact]
    public void ADirectoryIsSummedWithItsSubfolders()
    {
        Make("%LOCALAPPDATA%", @"Vendor\Crash\reports\a.dmp", new string('a', 100));
        Make("%LOCALAPPDATA%", @"Vendor\Crash\reports\sub\b.dmp", new string('b', 250));
        var scanner = new MarkerScanner(_env);

        var f = Assert.Single(scanner.Scan([Def("t.dir", MarkerKind.Directory, MarkerClass.Leftover, @"%LOCALAPPDATA%\Vendor\Crash\reports")]));

        Assert.True(f.Exists);
        Assert.Equal(350, f.SizeBytes);
        Assert.Equal(2, f.FileCount);
        Assert.False(f.Truncated);
    }

    [Fact]
    public void AFolderWithNoFilesInItIsLabelledEmptyRatherThanZeroBytes()
    {
        Directory.CreateDirectory(Path.Combine(_env.ResolveToken("%LOCALAPPDATA%")!, @"Vendor\Crash\reports"));
        var scanner = new MarkerScanner(_env);

        var empty = Assert.Single(scanner.Scan([Def("t.empty", MarkerKind.Directory, MarkerClass.Leftover, @"%LOCALAPPDATA%\Vendor\Crash\reports")]));
        Assert.True(empty.Exists);
        Assert.Equal("empty", empty.SizeLabel);

        Make("%LOCALAPPDATA%", @"Vendor\Crash\reports\a.dmp", new string('a', 100));
        var held = Assert.Single(scanner.Scan([Def("t.empty", MarkerKind.Directory, MarkerClass.Leftover, @"%LOCALAPPDATA%\Vendor\Crash\reports")]));
        Assert.Equal("100 B", held.SizeLabel);
    }

    [Fact]
    public void AMissingLocationIsReportedAsAbsentRatherThanSkipped()
    {
        var f = Assert.Single(new MarkerScanner(_env).Scan([Def("t.gone", MarkerKind.File, MarkerClass.Identifier, @"%LOCALAPPDATA%\Nope\nope.dat")]));
        Assert.False(f.Exists);
    }

    [Theory]
    [InlineData(@"%LOCALAPPDATA%\..\..\Windows\System32\config")]
    [InlineData(@"C:\Windows\System32")]
    [InlineData(@"%UNKNOWNTOKEN%\x")]
    [InlineData(@"no-token\x")]
    public void ALocationThatClimbsOutOfItsRootOrHasNoKnownRootIsNotUnderstood(string location)
    {
        var f = Assert.Single(new MarkerScanner(_env).Scan([Def("t.bad", MarkerKind.Directory, MarkerClass.Leftover, location)]));
        Assert.False(f.Exists);
        Assert.Contains("not understood", f.Note);
    }

    [Fact]
    public void AJunctionIsReportedAsALinkAndNeverFollowed()
    {
        var target = Path.Combine(_root, "elsewhere");
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "big.bin"), new string('z', 5000));
        var folder = _env.ResolveToken("%LOCALAPPDATA%")!;
        Directory.CreateDirectory(folder);
        var link = Path.Combine(folder, "LinkedDir");
        if (!TryJunction(link, target)) return; // a machine that will not make a junction cannot run this check

        var f = Assert.Single(new MarkerScanner(_env).Scan([Def("t.link", MarkerKind.Directory, MarkerClass.Leftover, @"%LOCALAPPDATA%\LinkedDir")]));

        Assert.True(f.HasReparsePoint);
        Assert.Equal(0, f.SizeBytes);
        Assert.Contains("never followed", f.Note);
    }

    [Fact]
    public void ARegistryMarkerReportsValueNamesAndNeverValueData()
    {
        using (var k = Registry.CurrentUser.CreateSubKey(_regKey))
        {
            k!.SetValue("iid", "SECRET-INSTALL-ID-1234", RegistryValueKind.String);
            using var product = k.CreateSubKey("{8A69D345-D564-463C-AFF1-A69D9E530F96}");
        }

        var f = Assert.Single(new MarkerScanner(_env).Scan([Def("t.reg", MarkerKind.RegistryKey, MarkerClass.Identifier, @"HKCU\" + _regKey)]));

        Assert.True(f.Exists);
        Assert.Contains("1 product record", f.Note);
        Assert.Contains("iid", f.Note);
        Assert.DoesNotContain("SECRET-INSTALL-ID", f.Note);
    }

    [Fact]
    public void AServiceIsFoundByNameAndByPrefix()
    {
        _env.Services.AddRange(["xagt", "FireEyeHelper"]);
        var scanner = new MarkerScanner(_env);
        var defs = new[]
        {
            Def("t.svc1", MarkerKind.Service, MarkerClass.SecurityAgent, "xagt"),
            Def("t.svc2", MarkerKind.Service, MarkerClass.SecurityAgent, "FireEye*"),
            Def("t.svc3", MarkerKind.Service, MarkerClass.SecurityAgent, "NotInstalled")
        };

        var found = scanner.Scan(defs);
        Assert.True(found[0].Exists);
        Assert.True(found[1].Exists);
        Assert.False(found[2].Exists);
    }

    [Fact]
    public void ADefinitionWithSeveralLocationsYieldsOneFindingPerLocation()
    {
        Make("%PROGRAMDATA%", @"FireEye\xagt\x.log");
        var d = Def("t.multi", MarkerKind.Directory, MarkerClass.SecurityAgent, @"%PROGRAMFILES%\FireEye") with
        {
            Locations = [@"%PROGRAMFILES%\FireEye", @"%PROGRAMDATA%\FireEye"]
        };

        var findings = new MarkerScanner(_env).Scan([d]);
        Assert.Equal(2, findings.Count);
        Assert.False(findings[0].Exists);
        Assert.True(findings[1].Exists);
    }

    private static bool TryJunction(string link, string target)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{target}\"")
            { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true });
            p!.WaitForExit(15000);
            return p.ExitCode == 0 && Directory.Exists(link);
        }
        catch { return false; }
    }
}

public class QuarantineEngineTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "antigoogle-tests", Guid.NewGuid().ToString("N"));
    private readonly TempMarkerEnvironment _env;
    private readonly string _vault;
    private readonly string _journalPath;

    public QuarantineEngineTests()
    {
        Directory.CreateDirectory(_root);
        _env = new TempMarkerEnvironment(_root);
        _vault = Path.Combine(_root, "vault");
        _journalPath = Path.Combine(_root, "journal.json");
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
        GC.SuppressFinalize(this);
    }

    private QuarantineEngine Engine() => new(_vault, _env);

    private static MarkerDefinition FileDef(string location = @"%LOCALAPPDATA%\Vendor\id.dat") =>
        MarkerScannerTests.Def("t.file", MarkerKind.File, MarkerClass.Identifier, location, MarkerAction.Quarantine);

    private static MarkerDefinition DirDef(string location = @"%LOCALAPPDATA%\Vendor\reports") =>
        MarkerScannerTests.Def("t.dir", MarkerKind.Directory, MarkerClass.Leftover, location, MarkerAction.Quarantine);

    private string Make(string relative, string content)
    {
        var path = Path.Combine(_env.ResolveToken("%LOCALAPPDATA%")!, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    private MarkerFinding Find(MarkerDefinition d) => new MarkerScanner(_env).Scan([d]).Single();

    private static string TreeHash(string dir) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("|",
            Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories).OrderBy(f => f, StringComparer.Ordinal)
                .Select(f => Path.GetRelativePath(dir, f) + ":" + Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(f))))))));

    [Fact]
    public async Task AFileGoesIntoTheVaultAndComesBackByteForByte()
    {
        var path = Make(@"Vendor\id.dat", "the identifier");
        var before = File.ReadAllBytes(path);
        var journal = new ChangeJournal(_journalPath);
        var engine = Engine();
        var d = FileDef();

        var result = await engine.QuarantineAsync(d, Find(d), journal);

        Assert.Equal(ChangeOutcome.Applied, result.Outcome);
        Assert.False(File.Exists(path));
        var entry = Assert.Single(journal.Entries);
        Assert.Equal(ReverseKind.RestoreQuarantine, entry.Reverse);
        Assert.Equal(EngineKind.Quarantine, entry.Engine);
        Assert.Equal("marker.t.file", entry.RuleId);
        Assert.Equal(path, entry.Target);
        var held = Assert.Single(engine.List());
        Assert.Equal(path, held.OriginalPath);
        Assert.Equal(before.Length, held.TotalBytes);

        await engine.RevertAsync(entry);

        Assert.Equal(before, File.ReadAllBytes(path));
        Assert.Empty(engine.List());
        Assert.False(Directory.Exists(Path.Combine(_vault, result.Id!)));
    }

    [Fact]
    public async Task ADirectoryTreeIsRestoredExactly()
    {
        var root = Path.GetDirectoryName(Make(@"Vendor\reports\a.dmp", new string('a', 300)))!;
        Make(@"Vendor\reports\deep\er\b.dmp", new string('b', 700));
        Make(@"Vendor\reports\deep\c.txt", "c");
        var before = TreeHash(root);
        var journal = new ChangeJournal(_journalPath);
        var d = DirDef();

        var result = await Engine().QuarantineAsync(d, Find(d), journal);

        Assert.Equal(ChangeOutcome.Applied, result.Outcome);
        Assert.False(Directory.Exists(root));
        Assert.Equal(3, Engine().List().Single().FileCount);

        await Engine().RevertAsync(journal.Entries.Single());

        Assert.Equal(before, TreeHash(root));
    }

    [Fact]
    public async Task TheReverseIsJournalledBeforeAnythingMoves()
    {
        var path = Make(@"Vendor\id.dat", "keep me");
        var unwritable = new ChangeJournal(Path.Combine(_root, "no-such-dir", "nested", "journal.json"));
        var d = FileDef();

        var result = await Engine().QuarantineAsync(d, Find(d), unwritable);

        Assert.Equal(ChangeOutcome.Failed, result.Outcome);
        Assert.True(File.Exists(path)); // not moved, because the way back could not be recorded
        Assert.Equal("keep me", File.ReadAllText(path));
        Assert.Empty(Directory.Exists(_vault) ? Directory.GetDirectories(_vault) : []);
    }

    [Fact]
    public async Task AReportOnlyMarkerIsRefusedWhateverIsAskedOfIt()
    {
        var path = Make(@"Vendor\id.dat", "x");
        var d = MarkerScannerTests.Def("t.agent", MarkerKind.File, MarkerClass.SecurityAgent, @"%LOCALAPPDATA%\Vendor\id.dat", MarkerAction.Quarantine);

        var result = await Engine().QuarantineAsync(d, Find(d), new ChangeJournal(_journalPath));

        Assert.Equal(ChangeOutcome.Refused, result.Outcome);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public async Task APathThatIsNotOneOfTheMarkersCatalogLocationsIsRefused()
    {
        var other = Make(@"Vendor\other.dat", "x");
        var d = FileDef();
        var forged = Find(d) with { Location = other, Exists = true };

        var result = await Engine().QuarantineAsync(d, forged, new ChangeJournal(_journalPath));

        Assert.Equal(ChangeOutcome.Refused, result.Outcome);
        Assert.Contains("catalog locations", result.Message);
        Assert.True(File.Exists(other));
    }

    [Fact]
    public async Task NothingInsideTheWindowsDirectoryIsEverMoved()
    {
        _env.WindowsDirectory = Path.Combine(_env.ResolveToken("%LOCALAPPDATA%")!, "Vendor");
        var path = Make(@"Vendor\id.dat", "x");
        var d = FileDef();

        var result = await Engine().QuarantineAsync(d, Find(d), new ChangeJournal(_journalPath));

        Assert.Equal(ChangeOutcome.Refused, result.Outcome);
        Assert.Contains("Windows directory", result.Message);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public async Task ALowConfidenceMarkerIsRefused()
    {
        Make(@"Vendor\id.dat", "x");
        var d = MarkerScannerTests.Def("t.low", MarkerKind.File, MarkerClass.Identifier, @"%LOCALAPPDATA%\Vendor\id.dat",
            MarkerAction.Quarantine, Confidence.Low);

        var result = await Engine().QuarantineAsync(d, Find(d), new ChangeJournal(_journalPath));
        Assert.Equal(ChangeOutcome.Refused, result.Outcome);
    }

    [Fact]
    public async Task ARecreatedOriginalIsNeverOverwrittenByARestore()
    {
        var path = Make(@"Vendor\id.dat", "old identifier");
        var journal = new ChangeJournal(_journalPath);
        var d = FileDef();
        await Engine().QuarantineAsync(d, Find(d), journal);

        // The program writes a new file at the same path before the user restores.
        File.WriteAllText(path, "brand new identifier");

        await Engine().RevertAsync(journal.Entries.Single());

        Assert.Equal("brand new identifier", File.ReadAllText(path));
        var beside = Assert.Single(Directory.GetFiles(Path.GetDirectoryName(path)!, "id.dat.antigoogle-restored-*"));
        Assert.Equal("old identifier", File.ReadAllText(beside));
    }

    [Fact]
    public async Task ARestoreRefusesFilesThatNoLongerMatchTheirRecordedHash()
    {
        Make(@"Vendor\id.dat", "original bytes");
        var journal = new ChangeJournal(_journalPath);
        var d = FileDef();
        var result = await Engine().QuarantineAsync(d, Find(d), journal);

        var inVault = Directory.GetFiles(Path.Combine(_vault, result.Id!, "payload")).Single();
        File.WriteAllText(inVault, "tampered bytes");

        await Assert.ThrowsAsync<InvalidDataException>(() => Engine().RevertAsync(journal.Entries.Single()));

        Assert.True(File.Exists(inVault)); // still held, nothing moved back
        Assert.Single(Engine().List());
    }

    [Fact]
    public async Task ARestoreIsIdempotent()
    {
        Make(@"Vendor\id.dat", "x");
        var journal = new ChangeJournal(_journalPath);
        var d = FileDef();
        await Engine().QuarantineAsync(d, Find(d), journal);
        var entry = journal.Entries.Single();

        await Engine().RevertAsync(entry);
        await Engine().RevertAsync(entry); // the vault is gone; nothing to do, no error
    }

    [Fact]
    public async Task AFileThatIsInUseStaysWhereItIsAndLeavesNoJournalEntry()
    {
        var path = Make(@"Vendor\id.dat", "in use");
        var journal = new ChangeJournal(_journalPath);
        var d = FileDef();
        var finding = Find(d);

        using var holder = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read); // no Delete share
        var result = await Engine().QuarantineAsync(d, finding, journal);

        Assert.Equal(ChangeOutcome.Failed, result.Outcome);
        Assert.Contains("in use", result.Message);
        Assert.True(File.Exists(path));
        Assert.Empty(journal.Entries);
        Assert.Empty(Directory.Exists(_vault) ? Directory.GetDirectories(_vault) : []);
    }

    [Fact]
    public async Task AFolderContainingALinkIsNotMoved()
    {
        var dir = Path.GetDirectoryName(Make(@"Vendor\reports\a.dmp", "a"))!;
        var target = Path.Combine(_root, "elsewhere");
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "keep.txt"), "keep");
        if (!TryJunction(Path.Combine(dir, "inner"), target)) return;

        var d = DirDef();
        var result = await Engine().QuarantineAsync(d, Find(d), new ChangeJournal(_journalPath));

        Assert.NotEqual(ChangeOutcome.Applied, result.Outcome);
        Assert.True(Directory.Exists(dir));
        Assert.True(File.Exists(Path.Combine(target, "keep.txt")));
    }

    [Fact]
    public async Task OnlyWhatIsHeldIsListed()
    {
        Make(@"Vendor\id.dat", "x");
        var journal = new ChangeJournal(_journalPath);
        var d = FileDef();
        Assert.Empty(Engine().List());

        await Engine().QuarantineAsync(d, Find(d), journal);
        Assert.Single(Engine().List());

        await Engine().RevertAsync(journal.Entries.Single());
        Assert.Empty(Engine().List());
    }

    private static bool TryJunction(string link, string target)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{target}\"")
            { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true });
            p!.WaitForExit(15000);
            return p.ExitCode == 0 && Directory.Exists(link);
        }
        catch { return false; }
    }
}
