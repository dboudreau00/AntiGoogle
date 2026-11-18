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

using AntiGoogle.Core.Model;

namespace AntiGoogle.Core.Markers;

/// <summary>
/// The host markers: what on this machine marks it as a vendor's.
///
/// Only Identifier, Leftover and OptionalComponent markers can be quarantined. Components and
/// security agents are reported and never touched, and a test pins that. Nothing here points at a
/// credential store, a browser profile or a token file: those are not markers, and listing them as
/// removable would be an invitation to lose data.
///
/// Confidence is stated per entry. A location that has not been confirmed against a vendor source or a
/// live installation is Medium or Low, and a Low entry cannot be quarantined.
/// </summary>
public static class MarkerCatalog
{
    public const string Google = "Google";
    public const string Mandiant = "Mandiant / FireEye / Trellix";

    private const string ChromeUserData = @"%LOCALAPPDATA%\Google\Chrome\User Data";

    private static IReadOnlyList<MarkerDefinition>? _cache;

    public static IReadOnlyList<MarkerDefinition> All => _cache ??= Build();

    public static MarkerDefinition? ById(string id) =>
        All.FirstOrDefault(m => string.Equals(m.Id, id, StringComparison.OrdinalIgnoreCase));

    private static List<MarkerDefinition> Build() =>
    [
        // ------------------------------------------------------------------ Google: quarantinable

        new MarkerDefinition
        {
            Id = "google.crashpad-reports",
            Vendor = Google,
            Title = "Chrome crash dumps",
            Why = "Snapshots of Chrome's memory saved to be uploaded to Google's crash servers. A dump can contain page contents, addresses and form data.",
            Kind = MarkerKind.Directory,
            Class = MarkerClass.Leftover,
            Locations = [ChromeUserData + @"\Crashpad\reports"],
            Action = MarkerAction.Quarantine,
            Confidence = Confidence.High,
            Source = "Crashpad's standard database layout (chromium.googlesource.com/crashpad).",
            Breaks =
            [
                Breakage.Minor("Saved Chrome crash dumps are set aside",
                    "Any dump waiting to be uploaded or inspected is moved out of Chrome's folder. Chrome keeps working and writes a new dump if it crashes again. The upload endpoints are already blocked by the crash reporting rule.")
            ]
        },

        new MarkerDefinition
        {
            Id = "google.crashpad-settings",
            Vendor = Google,
            Title = "Chrome crash reporting ID",
            Why = "The settings file Crashpad keeps beside its reports, including the random client ID attached to every crash upload.",
            Kind = MarkerKind.File,
            Class = MarkerClass.Identifier,
            Locations = [ChromeUserData + @"\Crashpad\settings.dat"],
            Action = MarkerAction.Quarantine,
            Confidence = Confidence.Medium,
            Source = "Crashpad's standard database layout (chromium.googlesource.com/crashpad).",
            Breaks =
            [
                Breakage.Minor("Chrome gets a new crash reporting ID",
                    "Chrome writes a fresh settings file, with a new random ID, the next time it needs one. Quarantining rotates the ID. It does not stop Chrome having one, and it cannot move the file while Chrome is running.")
            ]
        },

        new MarkerDefinition
        {
            Id = "google.chrome-swreporter",
            Vendor = Google,
            Title = "Chrome Software Reporter Tool",
            Why = "The scanner Chrome downloads to look through your computer for unwanted software and report what it finds. It runs in the background.",
            Kind = MarkerKind.Directory,
            Class = MarkerClass.OptionalComponent,
            Locations = [ChromeUserData + @"\SwReporter"],
            Action = MarkerAction.Quarantine,
            Confidence = Confidence.High,
            Source = "Chrome's component layout; described by Google's Chrome Cleanup policy documentation.",
            Breaks =
            [
                Breakage.Notable("Chrome's unwanted software scan",
                    "Chrome stops scanning for unwanted software. Chrome can download the tool again unless the Chrome telemetry policy rule is also armed, which switches the cleanup scan off.")
            ]
        },

        new MarkerDefinition
        {
            Id = "google.chrome-browsermetrics",
            Vendor = Google,
            Title = "Chrome pending usage metrics",
            Why = "Buffers where Chrome collects usage metrics before they are sent.",
            Kind = MarkerKind.Directory,
            Class = MarkerClass.Leftover,
            Locations = [ChromeUserData + @"\BrowserMetrics"],
            Action = MarkerAction.Quarantine,
            Confidence = Confidence.Medium,
            Source = "Chrome's metrics persistence (BrowserMetrics, chromium.googlesource.com).",
            Breaks =
            [
                Breakage.Minor("Collected usage metrics are discarded",
                    "Chrome loses whatever it had gathered and not yet sent. Nothing you use depends on it, and Chrome cannot release the files while it is running.")
            ]
        },

        new MarkerDefinition
        {
            Id = "google.android-analytics-id",
            Vendor = Google,
            Title = "Android Studio and SDK usage ID",
            Why = "Android Studio and the SDK tools keep a random user ID and your usage-statistics choice in this file.",
            Kind = MarkerKind.File,
            Class = MarkerClass.Identifier,
            Locations = [@"%USERPROFILE%\.android\analytics.settings"],
            Action = MarkerAction.Quarantine,
            Confidence = Confidence.Medium,
            Source = "The analytics library in the Android Open Source Project tools.",
            Breaks =
            [
                Breakage.Minor("Android tools forget your usage-statistics choice",
                    "The next run asks again or creates a new random ID. Nothing else in the Android SDK depends on this file.")
            ]
        },

        new MarkerDefinition
        {
            Id = "google.gcloud-metrics-id",
            Vendor = Google,
            Title = "Google Cloud CLI usage ID",
            Why = "The anonymous ID the Google Cloud CLI attaches to its usage statistics.",
            Kind = MarkerKind.File,
            Class = MarkerClass.Identifier,
            Locations = [@"%APPDATA%\gcloud\.metricsUUID"],
            Action = MarkerAction.Quarantine,
            Confidence = Confidence.Medium,
            Source = "The Google Cloud SDK source (core/config.py). Usage reporting is documented at docs.cloud.google.com/sdk/docs/usage-statistics.",
            Breaks =
            [
                Breakage.Minor("The Cloud CLI gets a new usage ID",
                    "If usage reporting is on, gcloud creates a new ID the next time it runs. Run 'gcloud config set disable_usage_reporting true' so it is not created again.")
            ]
        },

        // ------------------------------------------------------------------ Google: report only

        new MarkerDefinition
        {
            Id = "google.update-client-state",
            Vendor = Google,
            Title = "Google Update install records",
            Why = "Per-product records Google Update keeps for every Google program it manages. They carry install identifiers and update channel values that go into its update checks.",
            Kind = MarkerKind.RegistryKey,
            Class = MarkerClass.Identifier,
            Locations =
            [
                @"HKLM\SOFTWARE\WOW6432Node\Google\Update\ClientState",
                @"HKLM\SOFTWARE\Google\Update\ClientState",
                @"HKCU\Software\Google\Update\ClientState"
            ],
            Confidence = Confidence.Medium,
            Source = "Chromium's google_update_settings.cc reads the ClientState keys.",
            Breaks = []
        },

        new MarkerDefinition
        {
            Id = "google.chrome-launch-beacon",
            Vendor = Google,
            Title = "Chrome launch beacon",
            Why = "A small record of Chrome's last launch (version, whether it exited cleanly) that Chrome keeps in the user registry.",
            Kind = MarkerKind.RegistryKey,
            Class = MarkerClass.Identifier,
            Locations = [@"HKCU\Software\Google\Chrome\BLBeacon"],
            Confidence = Confidence.Medium,
            Source = "Chromium's browser launcher beacon (chrome/installer/util).",
            Breaks = []
        },

        new MarkerDefinition
        {
            Id = "google.chrome-local-state",
            Vendor = Google,
            Title = "Chrome metrics client ID",
            Why = "Chrome keeps its metrics client ID inside Local State, the same file that holds your Chrome settings. It is reported but never moved, because moving it would reset Chrome.",
            Kind = MarkerKind.File,
            Class = MarkerClass.Identifier,
            Locations = [ChromeUserData + @"\Local State"],
            Confidence = Confidence.Medium,
            Source = "Chrome's metrics service stores its client ID in Local State.",
            Breaks = []
        },

        new MarkerDefinition
        {
            Id = "google.update-install",
            Vendor = Google,
            Title = "Google Update",
            Why = "The updater Chrome and other Google programs install. The updater rules disable it or confine it to this machine.",
            Kind = MarkerKind.Directory,
            Class = MarkerClass.Component,
            Locations = [@"%PROGRAMFILES(X86)%\Google\Update", @"%PROGRAMFILES%\Google\Update", @"%LOCALAPPDATA%\Google\Update"],
            Confidence = Confidence.High,
            Source = "The standard Google Update install locations.",
            Breaks = []
        },

        new MarkerDefinition
        {
            Id = "google.chrome-install",
            Vendor = Google,
            Title = "Google Chrome",
            Why = "The browser itself, machine-wide or per user.",
            Kind = MarkerKind.Directory,
            Class = MarkerClass.Component,
            Locations = [@"%PROGRAMFILES%\Google\Chrome", @"%PROGRAMFILES(X86)%\Google\Chrome", @"%LOCALAPPDATA%\Google\Chrome\Application"],
            Confidence = Confidence.High,
            Source = "The standard Chrome install locations.",
            Breaks = []
        },

        new MarkerDefinition
        {
            Id = "google.drive-desktop",
            Vendor = Google,
            Title = "Google Drive for desktop",
            Why = "Google's sync client. Its cache holds your files, so it is reported and never moved.",
            Kind = MarkerKind.Directory,
            Class = MarkerClass.Component,
            Locations = [@"%PROGRAMFILES%\Google\Drive File Stream", @"%LOCALAPPDATA%\Google\DriveFS"],
            Confidence = Confidence.Medium,
            Source = "The standard Drive for desktop install and data locations.",
            Breaks = []
        },

        new MarkerDefinition
        {
            Id = "google.earth",
            Vendor = Google,
            Title = "Google Earth",
            Why = "A Google desktop program that phones home for imagery and updates.",
            Kind = MarkerKind.Directory,
            Class = MarkerClass.Component,
            Locations = [@"%PROGRAMFILES%\Google\Google Earth Pro", @"%PROGRAMFILES(X86)%\Google\Google Earth Pro"],
            Confidence = Confidence.Medium,
            Source = "The standard Google Earth Pro install location.",
            Breaks = []
        },

        // ------------------------------------------------------------------ Mandiant: report only, always

        new MarkerDefinition
        {
            Id = "mandiant.endpoint-agent-files",
            Vendor = Mandiant,
            Title = "FireEye / Trellix endpoint agent",
            Why = "The files of the FireEye endpoint agent, now sold as Trellix Endpoint Security (HX). It is a security product, usually installed by an employer. It is reported and never touched.",
            Kind = MarkerKind.Directory,
            Class = MarkerClass.SecurityAgent,
            Locations = [@"%PROGRAMFILES(X86)%\FireEye", @"%PROGRAMFILES%\FireEye", @"%PROGRAMDATA%\FireEye"],
            Confidence = Confidence.High,
            Source = "Trellix documentation: the default install directory is %ProgramFiles%\\FireEye\\xagt with data under %ProgramData%\\FireEye\\xagt.",
            Breaks = []
        },

        new MarkerDefinition
        {
            Id = "mandiant.endpoint-agent-service",
            Vendor = Mandiant,
            Title = "FireEye / Trellix endpoint agent service",
            Why = "The agent's Windows service. Its presence means a security product is monitoring this machine.",
            Kind = MarkerKind.Service,
            Class = MarkerClass.SecurityAgent,
            Locations = ["xagt", "FireEye*"],
            Confidence = Confidence.Medium,
            Source = "The HX agent runs as the service xagt.",
            Breaks = []
        },

        new MarkerDefinition
        {
            Id = "mandiant.vendor-directories",
            Vendor = Mandiant,
            Title = "Mandiant software",
            Why = "Folders named for Mandiant under the usual install and data locations. Reported so you can see what is there. Not confirmed against a live installation.",
            Kind = MarkerKind.Directory,
            Class = MarkerClass.SecurityAgent,
            Locations =
            [
                @"%PROGRAMFILES%\Mandiant", @"%PROGRAMFILES(X86)%\Mandiant",
                @"%PROGRAMDATA%\Mandiant", @"%LOCALAPPDATA%\Mandiant"
            ],
            Confidence = Confidence.Low,
            Source = "Vendor-named folders. Unverified.",
            Breaks = []
        },

        new MarkerDefinition
        {
            Id = "mandiant.vendor-registry",
            Vendor = Mandiant,
            Title = "Mandiant and FireEye registry keys",
            Why = "Vendor-named registry keys left by Mandiant or FireEye software. Reported only. Not confirmed against a live installation.",
            Kind = MarkerKind.RegistryKey,
            Class = MarkerClass.SecurityAgent,
            Locations =
            [
                @"HKLM\SOFTWARE\FireEye", @"HKLM\SOFTWARE\WOW6432Node\FireEye",
                @"HKLM\SOFTWARE\Mandiant", @"HKLM\SOFTWARE\WOW6432Node\Mandiant",
                @"HKCU\Software\Mandiant"
            ],
            Confidence = Confidence.Low,
            Source = "Vendor-named keys. Unverified.",
            Breaks = []
        }
    ];
}
