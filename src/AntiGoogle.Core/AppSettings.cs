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

using System.Text.Json;
using System.Text.Json.Serialization;
using AntiGoogle.Core.Catalog;
using AntiGoogle.Core.Model;

namespace AntiGoogle.Core;

/// <summary>
/// Persisted user choices. Note this stores INTENT (which rules you want armed), never state —
/// what is actually applied to the machine is derived from the journal, so the two can be
/// compared and a drift between them surfaced rather than assumed away.
/// </summary>
public sealed class AppSettings
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public List<string> EnabledRuleIds { get; set; } = [];

    /// <summary>Executables the user has chosen to contain, by full path.</summary>
    public List<string> ContainedApps { get; set; } = [];

    /// <summary>The profile the user last selected. Shipped default is Aggressive.</summary>
    public RiskTier Profile { get; set; } = RiskTier.Aggressive;

    /// <summary>Rules whose severe-breakage confirmation the user has already typed through.</summary>
    public List<string> AcknowledgedRuleIds { get; set; } = [];

    public bool FirstRunCompleted { get; set; }

    public static AppSettings LoadOrDefault()
    {
        try
        {
            if (File.Exists(AppPaths.SettingsFile))
            {
                var json = File.ReadAllText(AppPaths.SettingsFile);
                var loaded = JsonSerializer.Deserialize<AppSettings>(json, JsonOpts);
                if (loaded is not null)
                {
                    // Drop ids from an older catalog so a renamed rule cannot silently stay "armed".
                    var known = RuleCatalog.All.Select(r => r.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
                    loaded.EnabledRuleIds = loaded.EnabledRuleIds.Where(known.Contains).ToList();
                    return loaded;
                }
            }
        }
        catch (Exception ex)
        {
            Log.Warn($"Settings unreadable, falling back to the shipped defaults: {ex.Message}");
        }

        return CreateDefault();
    }

    /// <summary>The shipped profile: armed out of the box, per the Aggressive default.</summary>
    public static AppSettings CreateDefault() => new()
    {
        EnabledRuleIds = RuleCatalog.DefaultEnabledIds.ToList(),
        Profile = RiskTier.Aggressive,
        FirstRunCompleted = false
    };

    public void Save()
    {
        try
        {
            AppPaths.EnsureCreated();
            File.WriteAllText(AppPaths.SettingsFile, JsonSerializer.Serialize(this, JsonOpts));
        }
        catch (Exception ex)
        {
            // Unelevated runs cannot write to ProgramData. Losing a preference is survivable;
            // crashing the UI over it is not.
            Log.Warn($"Could not save settings: {ex.Message}");
        }
    }
}
