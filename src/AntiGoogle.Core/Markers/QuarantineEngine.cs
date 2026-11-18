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

using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using AntiGoogle.Core.Engines;
using AntiGoogle.Core.Journal;
using AntiGoogle.Core.Model;

namespace AntiGoogle.Core.Markers;

public sealed class QuarantinedFile
{
    public string RelativePath { get; set; } = "";
    public long Length { get; set; }
    public string Sha256 { get; set; } = "";
    public FileAttributes Attributes { get; set; }
    public DateTimeOffset LastWriteUtc { get; set; }
}

/// <summary>What the vault holds for one quarantined item. Written before anything moves.</summary>
public sealed class QuarantineManifest
{
    public int Version { get; set; } = 1;
    public string Id { get; set; } = "";
    public string DefinitionId { get; set; } = "";
    public string Vendor { get; set; } = "";
    public string Title { get; set; } = "";
    public string OriginalPath { get; set; } = "";
    public MarkerKind Kind { get; set; }

    /// <summary>pending, quarantined, restored or failed.</summary>
    public string Status { get; set; } = "pending";
    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;
    public long TotalBytes { get; set; }
    public string? AccessDescriptor { get; set; }
    public List<QuarantinedFile> Files { get; set; } = [];

    public int FileCount => Files.Count;
}

public sealed record QuarantineResult(ChangeOutcome Outcome, string? Id, string? Message);

/// <summary>
/// Moves a marker into the vault and back. It never deletes anything.
///
/// Order matters: the manifest is written first, then the reverse is journalled, then the item moves. A
/// process killed at any point leaves either nothing moved, or a manifest and a journal entry that put
/// it back. Restore checks every file against the recorded SHA-256 before it moves anything, and it
/// never overwrites: if the original path has been recreated meanwhile, the restored copy is placed
/// beside it.
/// </summary>
public sealed class QuarantineEngine : IRevertEngine
{
    public EngineKind Kind => EngineKind.Quarantine;

    /// <summary>Larger than this is not a marker, and is refused rather than hashed and moved.</summary>
    public const long MaxBytes = 1024L * 1024 * 1024;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly string _vault;
    private readonly IMarkerEnvironment _env;

    public QuarantineEngine(string? vaultDirectory = null, IMarkerEnvironment? env = null)
    {
        _vault = vaultDirectory ?? AppPaths.Quarantine;
        _env = env ?? new SystemMarkerEnvironment();
    }

    public string VaultDirectory => _vault;

    /// <summary>Whether the catalog allows this marker to be moved at all.</summary>
    public static bool IsQuarantinable(MarkerDefinition d) =>
        d.CanQuarantine &&
        d.Class is MarkerClass.Identifier or MarkerClass.Leftover or MarkerClass.OptionalComponent &&
        d.Kind is MarkerKind.File or MarkerKind.Directory &&
        d.Confidence != Confidence.Low;

    /// <summary>The plain reason a marker is only ever reported, for the plan and the audit log.</summary>
    public static string WhyReportedOnly(MarkerDefinition d) => d.Class switch
    {
        MarkerClass.SecurityAgent => $"{d.Title} is an endpoint security agent and is reported only.",
        MarkerClass.Component => $"{d.Title} is working software and is reported only.",
        _ when d.Confidence == Confidence.Low => $"{d.Title} is not matched with enough confidence to move, so it is reported only.",
        _ => $"{d.Title} is reported only."
    };

    // ------------------------------------------------------------------ quarantine

    public Task<QuarantineResult> QuarantineAsync(
        MarkerDefinition definition, MarkerFinding finding, ChangeJournal journal, CancellationToken ct = default) =>
        Task.Run(() => Quarantine(definition, finding, journal, ct), ct);

    private QuarantineResult Quarantine(
        MarkerDefinition definition, MarkerFinding finding, ChangeJournal journal, CancellationToken ct)
    {
        var refusal = Refusal(definition, finding);
        if (refusal is not null) return new QuarantineResult(ChangeOutcome.Refused, null, refusal);

        var source = finding.Location;
        var isDirectory = definition.Kind == MarkerKind.Directory;
        var id = NewId(definition);
        var vaultDir = Path.Combine(_vault, id);
        var payload = Path.Combine(vaultDir, "payload", Path.GetFileName(source.TrimEnd('\\')));

        var manifest = new QuarantineManifest
        {
            Id = id,
            DefinitionId = definition.Id,
            Vendor = definition.Vendor,
            Title = definition.Title,
            OriginalPath = source,
            Kind = definition.Kind
        };

        try
        {
            ct.ThrowIfCancellationRequested();
            Describe(source, isDirectory, manifest);
            if (manifest.TotalBytes > MaxBytes)
                return new QuarantineResult(ChangeOutcome.Refused, null,
                    $"{definition.Title} is {MarkerFinding.FormatSize(manifest.TotalBytes)}, which is too large to be a marker.");

            Directory.CreateDirectory(Path.Combine(vaultDir, "payload"));
            WriteManifest(vaultDir, manifest);

            journal.Append(new JournalEntry
            {
                RuleId = definition.JournalRuleId,
                Engine = EngineKind.Quarantine,
                Description = $"Quarantined {definition.Title} ({MarkerFinding.FormatSize(manifest.TotalBytes)}, " +
                              $"{manifest.FileCount} {(manifest.FileCount == 1 ? "file" : "files")})",
                Reverse = ReverseKind.RestoreQuarantine,
                QuarantineId = id,
                Target = source
            });
        }
        catch (Exception ex)
        {
            TryDelete(vaultDir);
            return new QuarantineResult(ChangeOutcome.Failed, null, ex.Message);
        }

        try
        {
            MoveItem(source, payload, isDirectory, manifest);
            manifest.Status = "quarantined";
            WriteManifest(vaultDir, manifest);
            Log.Info($"Quarantine: moved {definition.Id} from {source} into {id}.");
            return new QuarantineResult(ChangeOutcome.Applied, id, null);
        }
        catch (Exception ex)
        {
            // Nothing was lost: put back whatever moved, and drop the journal entry only when the
            // original is whole again. If it is not, the entry stays so Restore can finish the job.
            var whole = TryRollback(source, payload, isDirectory);
            manifest.Status = "failed";
            try { WriteManifest(vaultDir, manifest); } catch { /* the vault copy is the evidence */ }
            if (whole)
            {
                var entry = journal.Entries.FirstOrDefault(e => e.QuarantineId == id);
                if (entry is not null) journal.Remove(entry);
                TryDelete(vaultDir);
            }

            var hint = ex is IOException or UnauthorizedAccessException
                ? " It is probably in use. Close the program that owns it and try again."
                : "";
            return new QuarantineResult(ChangeOutcome.Failed, id, ex.Message + hint);
        }
    }

    /// <summary>Why this marker must not be moved, or null when it may be. Fail closed.</summary>
    private string? Refusal(MarkerDefinition d, MarkerFinding f)
    {
        if (!IsQuarantinable(d))
            return WhyReportedOnly(d);
        if (!f.Exists) return "It is not there.";
        if (f.HasReparsePoint) return "It is a link, and links are never followed or moved.";
        if (f.Truncated) return "It is too large to be a marker.";

        var allowed = d.Locations
            .Select(l => MarkerPaths.Expand(l, _env, out _))
            .Where(p => p is not null)
            .Any(p => string.Equals(p, f.Location, StringComparison.OrdinalIgnoreCase));
        if (!allowed) return "The path is not one of this marker's catalog locations.";

        if (!Path.IsPathFullyQualified(f.Location)) return "The path is not fully qualified.";
        var windows = _env.WindowsDirectory;
        if (!string.IsNullOrEmpty(windows) &&
            (f.Location + "\\").StartsWith(windows.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase))
            return "It is inside the Windows directory.";

        return null;
    }

    private static string NewId(MarkerDefinition d) =>
        $"{DateTime.UtcNow:yyyyMMdd-HHmmss}-{d.Id}-{Guid.NewGuid().ToString("N")[..6]}";

    // ------------------------------------------------------------------ restore

    public Task RevertAsync(JournalEntry entry, CancellationToken ct = default) =>
        Task.Run(() => Restore(entry), ct);

    private void Restore(JournalEntry entry)
    {
        if (entry.QuarantineId is null) return;

        var vaultDir = Path.Combine(_vault, entry.QuarantineId);
        var manifestPath = Path.Combine(vaultDir, "manifest.json");
        if (!File.Exists(manifestPath))
        {
            Log.Info($"Quarantine restore: {entry.QuarantineId} is no longer in the vault; nothing to restore.");
            return;
        }

        var manifest = ReadManifest(manifestPath);
        var isDirectory = manifest.Kind == MarkerKind.Directory;
        var payload = Path.Combine(vaultDir, "payload", Path.GetFileName(manifest.OriginalPath.TrimEnd('\\')));

        if (!(isDirectory ? Directory.Exists(payload) : File.Exists(payload)))
        {
            // The item is not in the vault. If the original is whole, there is nothing left to do.
            Log.Info($"Quarantine restore: nothing in the vault for {entry.QuarantineId}.");
            if (manifest.Status != "quarantined") TryDelete(vaultDir);
            return;
        }

        VerifyAgainstManifest(payload, isDirectory, manifest);

        var target = manifest.OriginalPath;
        var exists = isDirectory ? Directory.Exists(target) : File.Exists(target);
        if (exists)
        {
            // Never overwrite what the program has recreated since. Keep both.
            target = $"{manifest.OriginalPath.TrimEnd('\\')}.antigoogle-restored-{DateTime.Now:yyyyMMddHHmmss}";
            Log.Warn($"Quarantine restore: {manifest.OriginalPath} exists again; restoring beside it as {target}.");
        }

        Directory.CreateDirectory(Path.GetDirectoryName(target.TrimEnd('\\'))!);
        MoveItem(payload, target, isDirectory, manifest);

        if (!exists) TryRestoreAccess(target, isDirectory, manifest);

        manifest.Status = "restored";
        TryDelete(vaultDir);
        Log.Info($"Quarantine: restored {manifest.DefinitionId} to {target}.");
    }

    // ------------------------------------------------------------------ the vault, as data

    /// <summary>Every item currently held in the vault, for the report and the Markers page.</summary>
    public IReadOnlyList<QuarantineManifest> List()
    {
        var items = new List<QuarantineManifest>();
        try
        {
            if (!Directory.Exists(_vault)) return items;
            foreach (var dir in Directory.EnumerateDirectories(_vault).OrderBy(d => d, StringComparer.Ordinal))
            {
                var path = Path.Combine(dir, "manifest.json");
                if (!File.Exists(path)) continue;
                try
                {
                    var m = ReadManifest(path);
                    if (m.Status == "quarantined") items.Add(m);
                }
                catch (Exception ex) { Log.Warn($"Unreadable quarantine manifest {path}: {ex.Message}"); }
            }
        }
        catch (Exception ex) { Log.Warn($"Could not list the quarantine vault: {ex.Message}"); }
        return items;
    }

    // ------------------------------------------------------------------ moving and checking

    private static void Describe(string path, bool isDirectory, QuarantineManifest manifest)
    {
        if (!isDirectory)
        {
            AddFile(manifest, path, Path.GetFileName(path));
        }
        else
        {
            var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = false, AttributesToSkip = 0 };
            foreach (var file in Directory.EnumerateFiles(path, "*", options))
            {
                if (File.GetAttributes(file).HasFlag(FileAttributes.ReparsePoint))
                    throw new InvalidOperationException($"'{file}' inside the folder is a link, so the folder is not moved.");
                AddFile(manifest, file, Path.GetRelativePath(path, file));
            }
            foreach (var sub in Directory.EnumerateDirectories(path, "*", options))
                if (File.GetAttributes(sub).HasFlag(FileAttributes.ReparsePoint))
                    throw new InvalidOperationException($"'{sub}' inside the folder is a link, so the folder is not moved.");
        }

        manifest.TotalBytes = manifest.Files.Sum(f => f.Length);
        try
        {
            FileSystemSecurity sec = isDirectory ? new DirectoryInfo(path).GetAccessControl() : new FileInfo(path).GetAccessControl();
            manifest.AccessDescriptor = sec.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        }
        catch { /* the descriptor is a nicety; the move keeps it anyway on one volume */ }
    }

    private static void AddFile(QuarantineManifest manifest, string fullPath, string relative)
    {
        var info = new FileInfo(fullPath);
        manifest.Files.Add(new QuarantinedFile
        {
            RelativePath = relative,
            Length = info.Length,
            Sha256 = Hash(fullPath),
            Attributes = info.Attributes,
            LastWriteUtc = info.LastWriteTimeUtc
        });
    }

    private static string Hash(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    /// <summary>Every recorded file is present, the right size and the right hash. Throws if not.</summary>
    private static void VerifyAgainstManifest(string root, bool isDirectory, QuarantineManifest manifest)
    {
        foreach (var f in manifest.Files)
        {
            var path = isDirectory ? Path.Combine(root, f.RelativePath) : root;
            if (!File.Exists(path))
                throw new InvalidDataException($"The quarantined file '{f.RelativePath}' is missing from the vault.");
            if (new FileInfo(path).Length != f.Length || !string.Equals(Hash(path), f.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"The quarantined file '{f.RelativePath}' no longer matches its recorded hash. It was not restored.");
        }
    }

    private static bool SameVolume(string a, string b) =>
        string.Equals(Path.GetPathRoot(Path.GetFullPath(a)), Path.GetPathRoot(Path.GetFullPath(b)), StringComparison.OrdinalIgnoreCase);

    /// <summary>A rename on one volume, a verified copy and delete across volumes.</summary>
    private static void MoveItem(string from, string to, bool isDirectory, QuarantineManifest manifest)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(to.TrimEnd('\\'))!);

        if (SameVolume(from, to))
        {
            if (isDirectory) Directory.Move(from, to); else File.Move(from, to);
            return;
        }

        if (isDirectory) CopyDirectory(from, to); else File.Copy(from, to);
        VerifyAgainstManifest(to, isDirectory, manifest);

        if (isDirectory) Directory.Delete(from, recursive: true); else File.Delete(from);
    }

    private static void CopyDirectory(string from, string to)
    {
        Directory.CreateDirectory(to);
        foreach (var dir in Directory.EnumerateDirectories(from, "*", SearchOption.AllDirectories))
            Directory.CreateDirectory(Path.Combine(to, Path.GetRelativePath(from, dir)));
        foreach (var file in Directory.EnumerateFiles(from, "*", SearchOption.AllDirectories))
        {
            var dest = Path.Combine(to, Path.GetRelativePath(from, file));
            File.Copy(file, dest);
            File.SetLastWriteTimeUtc(dest, File.GetLastWriteTimeUtc(file));
            File.SetAttributes(dest, File.GetAttributes(file));
        }
    }

    private static bool TryRollback(string source, string payload, bool isDirectory)
    {
        try
        {
            var inVault = isDirectory ? Directory.Exists(payload) : File.Exists(payload);
            var atSource = isDirectory ? Directory.Exists(source) : File.Exists(source);
            if (!inVault) return atSource;
            if (atSource) return false; // both exist: a half-finished copy; keep the vault copy and the entry
            if (isDirectory) Directory.Move(payload, source); else File.Move(payload, source);
            return true;
        }
        catch { return false; }
    }

    private static void TryRestoreAccess(string target, bool isDirectory, QuarantineManifest manifest)
    {
        if (string.IsNullOrEmpty(manifest.AccessDescriptor)) return;
        try
        {
            FileSystemSecurity current = isDirectory ? new DirectoryInfo(target).GetAccessControl() : new FileInfo(target).GetAccessControl();
            if (string.Equals(current.GetSecurityDescriptorSddlForm(AccessControlSections.Access), manifest.AccessDescriptor, StringComparison.Ordinal))
                return;

            FileSystemSecurity wanted = isDirectory ? new DirectorySecurity() : new FileSecurity();
            wanted.SetSecurityDescriptorSddlForm(manifest.AccessDescriptor, AccessControlSections.Access);
            if (isDirectory) new DirectoryInfo(target).SetAccessControl((DirectorySecurity)wanted);
            else new FileInfo(target).SetAccessControl((FileSecurity)wanted);
        }
        catch (Exception ex) { Log.Warn($"Quarantine restore: could not reapply the original access list to {target}: {ex.Message}"); }
    }

    // ------------------------------------------------------------------ manifest io

    private static void WriteManifest(string vaultDir, QuarantineManifest manifest)
    {
        Directory.CreateDirectory(vaultDir);
        var path = Path.Combine(vaultDir, "manifest.json");
        var tmp = path + ".tmp";
        using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        using (var sw = new StreamWriter(fs))
        {
            sw.Write(JsonSerializer.Serialize(manifest, JsonOpts));
            sw.Flush();
            fs.Flush(flushToDisk: true);
        }
        if (File.Exists(path)) File.Replace(tmp, path, null); else File.Move(tmp, path);
    }

    private static QuarantineManifest ReadManifest(string path) =>
        JsonSerializer.Deserialize<QuarantineManifest>(File.ReadAllText(path), JsonOpts)
        ?? throw new InvalidDataException($"{path} is empty.");

    private static void TryDelete(string dir)
    {
        try { if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true); } catch { /* leftover vault folder is harmless */ }
    }
}
