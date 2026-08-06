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

namespace AntiGoogle.Core.Catalog;

/// <summary>
/// The complete rule set.
///
/// Editorial policy for <see cref="BlockRule.Breaks"/>: state the cost plainly, including when the
/// cost is a SECURITY loss rather than a convenience loss. A privacy tool that hides the fact it
/// just turned off your browser's malware warnings is not a privacy tool, it is a liability.
///
/// The shipped default profile is <see cref="RiskTier.Aggressive"/>. That arms the googleapis /
/// gstatic blackhole out of the box. It does NOT arm content blocks (Search, YouTube, sign-in) or
/// IP-range sledgehammers — those remain opt-in behind an explicit typed confirmation, because
/// removing telemetry is a different thing from removing your ability to use the web.
/// </summary>
public static class RuleCatalog
{
    private const string ChromePolicyKey = @"SOFTWARE\Policies\Google\Chrome";
    private const string ChromeUpdateKey = @"SOFTWARE\Policies\Google\Update";
    private const string EdgePolicyKey = @"SOFTWARE\Policies\Microsoft\Edge";

    private static IReadOnlyList<BlockRule>? _cache;

    public static IReadOnlyList<BlockRule> All => _cache ??= Build();

    public static BlockRule? ById(string id) =>
        All.FirstOrDefault(r => string.Equals(r.Id, id, StringComparison.OrdinalIgnoreCase));

    /// <summary>Rule ids armed by the shipped profile.</summary>
    public static IReadOnlyList<string> DefaultEnabledIds =>
        All.Where(r => r.DefaultEnabled).Select(r => r.Id).ToList();

    private static List<BlockRule> Build()
    {
        var rules = new List<BlockRule>();

        // ------------------------------------------------------------------
        // TELEMETRY — the core promise. Low cost, high value.
        // ------------------------------------------------------------------

        rules.Add(new BlockRule
        {
            Id = "hosts.chrome-telemetry",
            Title = "Chrome usage & feature telemetry",
            Summary = "Sinkholes Chrome's field-trial, autofill-server and optimization-hint endpoints.",
            Category = RuleCategory.Telemetry,
            Tier = RiskTier.Conservative,
            Engine = EngineKind.Hosts,
            Domains = GoogleEndpoints.ChromeTelemetry,
            DefaultEnabled = true,
            Breaks =
            [
                Breakage.Minor("Chrome A/B feature rollouts",
                    "Chrome stops fetching its field-trial seed, so you stay on default feature flags. Most users never notice."),
                Breakage.Minor("Page-load optimization hints",
                    "Chrome loses server-provided loading hints. Pages may feel marginally slower on a slow connection.")
            ]
        });

        rules.Add(new BlockRule
        {
            Id = "hosts.beacons",
            Title = "Chrome background beacons",
            Summary = "Blocks the gvt2/gvt3 beacon hosts Chrome pings continuously.",
            Category = RuleCategory.Telemetry,
            Tier = RiskTier.Conservative,
            Engine = EngineKind.Hosts,
            Domains = GoogleEndpoints.Beacons,
            DefaultEnabled = true,
            Breaks =
            [
                Breakage.Minor("Network quality estimation",
                    "Chrome's connection-speed estimate gets less accurate. No user-visible feature depends on it.")
            ]
        });

        rules.Add(new BlockRule
        {
            Id = "hosts.crash",
            Title = "Crash & stability reporting",
            Summary = "Blocks Crashlytics and Firebase crash upload endpoints.",
            Category = RuleCategory.CrashReporting,
            Tier = RiskTier.Conservative,
            Engine = EngineKind.Hosts,
            Domains = GoogleEndpoints.CrashReporting,
            DefaultEnabled = true,
            Note = "Chrome's own crash uploads go to clients2.google.com, which also serves extension " +
                   "updates. That host is handled by the update-delivery rule instead, so you can " +
                   "choose whether losing extension updates is worth it.",
            Breaks =
            [
                Breakage.Minor("Crash reports to app vendors",
                    "Apps you use will no longer report their crashes upstream. Nothing on your machine changes.")
            ]
        });

        rules.Add(new BlockRule
        {
            Id = "reg.chrome.telemetry",
            Title = "Chrome telemetry policy lockdown",
            Summary = "Enterprise policy: metrics reporting off, URL-keyed collection off, surveys off.",
            Category = RuleCategory.Telemetry,
            Tier = RiskTier.Conservative,
            Engine = EngineKind.Registry,
            DefaultEnabled = true,
            RegistryValues =
            [
                RegistryPolicy.Dword(ChromePolicyKey, "MetricsReportingEnabled", 0),
                RegistryPolicy.Dword(ChromePolicyKey, "UrlKeyedAnonymizedDataCollectionEnabled", 0),
                RegistryPolicy.Dword(ChromePolicyKey, "DomainReliabilityAllowed", 0),
                RegistryPolicy.Dword(ChromePolicyKey, "FeedbackSurveysEnabled", 0),
                RegistryPolicy.Dword(ChromePolicyKey, "ChromeCleanupReportingEnabled", 0),
                RegistryPolicy.Dword(ChromePolicyKey, "ChromeCleanupEnabled", 0)
            ],
            Breaks =
            [
                Breakage.Minor("Chrome's built-in cleanup tool",
                    "Chrome's unwanted-software scanner is disabled. Use a real anti-malware tool instead — you should anyway."),
                Breakage.Minor("Settings appear greyed out",
                    "These now show as 'managed by your organization' in chrome://settings. That banner is Anti-Google, not an employer.")
            ]
        });

        rules.Add(new BlockRule
        {
            Id = "reg.edge.telemetry",
            Title = "Edge telemetry lockdown (Chromium-inherited)",
            Summary = "Edge is Chromium underneath and carries the same reporting plumbing.",
            Category = RuleCategory.Telemetry,
            Tier = RiskTier.Conservative,
            Engine = EngineKind.Registry,
            DefaultEnabled = true,
            RegistryValues =
            [
                RegistryPolicy.Dword(EdgePolicyKey, "MetricsReportingEnabled", 0),
                RegistryPolicy.Dword(EdgePolicyKey, "SendSiteInfoToImproveServices", 0),
                RegistryPolicy.Dword(EdgePolicyKey, "PersonalizationReportingEnabled", 0),
                RegistryPolicy.Dword(EdgePolicyKey, "DiagnosticData", 0),
                RegistryPolicy.Dword(EdgePolicyKey, "UserFeedbackAllowed", 0),
                RegistryPolicy.Dword(EdgePolicyKey, "AutofillAddressEnabled", 0)
            ],
            Breaks =
            [
                Breakage.Minor("Edge address autofill",
                    "Saved addresses stop auto-filling in Edge. Passwords are unaffected.")
            ]
        });

        // ------------------------------------------------------------------
        // ADS & ANALYTICS — near-free wins.
        // ------------------------------------------------------------------

        rules.Add(new BlockRule
        {
            Id = "hosts.analytics",
            Title = "Google Analytics & Tag Manager",
            Summary = "Includes the regional GA4 collectors (region1-5) most blocklists miss.",
            Category = RuleCategory.AdsAnalytics,
            Tier = RiskTier.Balanced,
            Engine = EngineKind.Hosts,
            Domains = GoogleEndpoints.Analytics,
            DefaultEnabled = true,
            Breaks =
            [
                Breakage.Notable("Badly-built sites that load features via Tag Manager",
                    "A minority of sites route real functionality (chat widgets, consent flows, even checkout steps) through GTM. Those pieces will not load.")
            ]
        });

        rules.Add(new BlockRule
        {
            Id = "hosts.ads",
            Title = "DoubleClick & ad serving",
            Summary = "Blocks doubleclick.net, googlesyndication, googleadservices and 2mdn.",
            Category = RuleCategory.AdsAnalytics,
            Tier = RiskTier.Balanced,
            Engine = EngineKind.Hosts,
            Domains = GoogleEndpoints.Advertising,
            DefaultEnabled = true,
            Breaks =
            [
                Breakage.Minor("Anti-adblock nag screens",
                    "Some sites detect the blocked requests and demand you disable your ad blocker before showing content.")
            ]
        });

        // ------------------------------------------------------------------
        // UPDATES — genuine security tradeoff. Say so loudly.
        // ------------------------------------------------------------------

        rules.Add(new BlockRule
        {
            Id = "svc.google-updater",
            Title = "Google Updater services",
            Summary = "Disables GoogleUpdaterService / GoogleUpdaterInternalService / gupdate / gupdatem.",
            Category = RuleCategory.Updates,
            Tier = RiskTier.Balanced,
            Engine = EngineKind.Service,
            DefaultEnabled = true,
            ServiceNamePatterns = ["GoogleUpdaterService*", "GoogleUpdaterInternalService*", "gupdate", "gupdatem"],
            Note = "Prior start type and running state are recorded, so revert restores them exactly.",
            Breaks =
            [
                Breakage.Severe("Chrome security updates",
                    "Chrome will NOT auto-update. A browser is the most exposed program on your machine; an unpatched one is a genuine risk. Plan to update Chrome by hand, or accept that risk knowingly.")
            ]
        });

        rules.Add(new BlockRule
        {
            Id = "task.google-updater",
            Title = "Google Updater scheduled tasks",
            Summary = "Disables GoogleUpdateTaskMachineCore / UA and the GoogleUpdater system tasks.",
            Category = RuleCategory.Updates,
            Tier = RiskTier.Balanced,
            Engine = EngineKind.ScheduledTask,
            DefaultEnabled = true,
            ScheduledTaskPatterns = ["GoogleUpdateTaskMachine*", "GoogleUpdaterTaskSystem*", "GoogleSystemUpdate*", "GoogleUpdaterTaskUser*"],
            Breaks =
            [
                Breakage.Severe("Chrome security updates",
                    "Same tradeoff as the updater services: the scheduled fallback path is gone too, so nothing will quietly patch Chrome for you.")
            ]
        });

        rules.Add(new BlockRule
        {
            Id = "svc.chrome-elevation",
            Title = "Google Chrome Elevation Service",
            Summary = "Disables the helper Chrome uses for privileged operations.",
            Category = RuleCategory.Updates,
            Tier = RiskTier.Balanced,
            Engine = EngineKind.Service,
            DefaultEnabled = true,
            ServiceNamePatterns = ["GoogleChromeElevationService"],
            Breaks =
            [
                Breakage.Notable("System-wide Chrome install operations",
                    "Chrome cannot perform elevated actions such as promoting a user install to a machine install. Normal browsing is unaffected.")
            ]
        });

        rules.Add(new BlockRule
        {
            Id = "reg.google-update-policy",
            Title = "Google Update policy: auto-update off",
            Summary = "Sets the Omaha policy keys so the updater stands down even if re-enabled.",
            Category = RuleCategory.Updates,
            Tier = RiskTier.Balanced,
            Engine = EngineKind.Registry,
            DefaultEnabled = true,
            RegistryValues =
            [
                RegistryPolicy.Dword(ChromeUpdateKey, "UpdateDefault", 0),
                RegistryPolicy.Dword(ChromeUpdateKey, "AutoUpdateCheckPeriodMinutes", 0),
                RegistryPolicy.Dword(ChromeUpdateKey, "DisableAutoUpdateChecksCheckboxValue", 1)
            ],
            Breaks =
            [
                Breakage.Severe("All Google product updates",
                    "Covers Chrome, Drive and Earth. Nothing Google-made will update itself until you revert this.")
            ]
        });

        rules.Add(new BlockRule
        {
            Id = "hosts.update-delivery",
            Title = "Update & component delivery CDN",
            Summary = "Blocks dl.google.com, tools.google.com, update.googleapis.com and the gvt1/2/3 CDN.",
            Category = RuleCategory.Updates,
            Tier = RiskTier.Aggressive,
            Engine = EngineKind.Hosts,
            Domains = GoogleEndpoints.UpdateDelivery,
            DefaultEnabled = true,
            Breaks =
            [
                Breakage.Severe("Widevine DRM — paid streaming in Chrome",
                    "Widevine ships as a Chrome component from this CDN. If it is missing or expires, Netflix, Spotify Web, Amazon Prime and Disney+ stop playing in Chrome. This is the single most common surprise from aggressive Google blocking."),
                Breakage.Notable("Chrome extension updates",
                    "clients2.google.com also serves the extension update manifest, so installed extensions freeze at their current version."),
                Breakage.Notable("Chrome component updates",
                    "Certificate revocation lists, the Safe Browsing list and origin trials stop refreshing.")
            ]
        });

        // ------------------------------------------------------------------
        // SAFE BROWSING — security loss, isolated so it can be kept.
        // ------------------------------------------------------------------

        rules.Add(new BlockRule
        {
            Id = "hosts.safebrowsing",
            Title = "Safe Browsing reputation lookups",
            Summary = "Stops Chrome sending URL reputation queries to Google.",
            Category = RuleCategory.Telemetry,
            Tier = RiskTier.Aggressive,
            Engine = EngineKind.Hosts,
            Domains = GoogleEndpoints.SafeBrowsing,
            DefaultEnabled = false,
            Note = "Kept OFF even on the Aggressive profile. Safe Browsing is real protection; " +
                   "turning it off to gain privacy is a trade you should make deliberately, not by default.",
            Breaks =
            [
                Breakage.Severe("Phishing and malware warnings",
                    "Chrome will no longer warn you before a known phishing page or a malicious download. You lose a genuinely effective safety net.")
            ]
        });

        rules.Add(new BlockRule
        {
            Id = "reg.chrome.safebrowsing",
            Title = "Chrome policy: Safe Browsing & leak detection off",
            Summary = "Disables reputation checks and breached-password alerts at policy level.",
            Category = RuleCategory.Telemetry,
            Tier = RiskTier.Aggressive,
            Engine = EngineKind.Registry,
            DefaultEnabled = false,
            RegistryValues =
            [
                RegistryPolicy.Dword(ChromePolicyKey, "SafeBrowsingProtectionLevel", 0),
                RegistryPolicy.Dword(ChromePolicyKey, "SafeBrowsingExtendedReportingEnabled", 0),
                RegistryPolicy.Dword(ChromePolicyKey, "PasswordLeakDetectionEnabled", 0)
            ],
            Breaks =
            [
                Breakage.Severe("Phishing, malware and breached-password warnings",
                    "Chrome stops warning you about dangerous sites AND stops telling you when a saved password has appeared in a public breach.")
            ]
        });

        // ------------------------------------------------------------------
        // DNS-over-HTTPS — the rule that makes hosts blocking work at all.
        // ------------------------------------------------------------------

        rules.Add(new BlockRule
        {
            Id = "reg.chrome.doh",
            Title = "Force Chrome/Edge DNS through the system resolver",
            Summary = "Turns off browser DNS-over-HTTPS so hosts-file blocking actually applies.",
            Category = RuleCategory.WindowsIntegration,
            Tier = RiskTier.Balanced,
            Engine = EngineKind.Registry,
            DefaultEnabled = true,
            RegistryValues =
            [
                RegistryPolicy.Str(ChromePolicyKey, "DnsOverHttpsMode", "off"),
                RegistryPolicy.Str(EdgePolicyKey, "DnsOverHttpsMode", "off")
            ],
            Note = "Without this, Chrome resolves names over its own encrypted DNS and walks straight " +
                   "past every hosts entry this app writes. It is the load-bearing rule for the whole hosts engine.",
            Breaks =
            [
                Breakage.Notable("Encrypted DNS in the browser",
                    "Read this one carefully: it is a privacy TRADE, not a privacy win. Your DNS queries go back to plaintext, so your ISP can see the names you look up again. You are choosing local control over transport secrecy. If you run your own encrypted resolver system-wide, you get both.")
            ]
        });

        // ------------------------------------------------------------------
        // AGGRESSIVE — the blackhole. On by default per the selected profile.
        // ------------------------------------------------------------------

        rules.Add(new BlockRule
        {
            Id = "hosts.api-frontdoors",
            Title = "googleapis.com API front doors",
            Summary = "Sinkholes the generic Google API hosts.",
            Category = RuleCategory.ApisCdn,
            Tier = RiskTier.Aggressive,
            Engine = EngineKind.Hosts,
            Domains = GoogleEndpoints.ApiFrontDoors,
            DefaultEnabled = true,
            Breaks =
            [
                Breakage.Severe("Any desktop app built on Google APIs",
                    "Android Studio, the Android emulator, Google Drive for desktop, Google Earth and any Firebase-backed app lose their backend. Third-party Gmail and Calendar desktop clients are in this category too — they talk to googleapis.com just as Google's own software does."),
                Breakage.Severe("Embedded Google Maps",
                    "maps.googleapis.com is included, so Maps embeds on third-party sites render blank."),
                Breakage.Notable("In-page translation",
                    "Chrome's 'translate this page' stops working."),
                Breakage.Notable("Cloud storage on googleapis-hosted buckets",
                    "storage.googleapis.com serves assets for many unrelated products; some downloads will fail.")
            ]
        });

        rules.Add(new BlockRule
        {
            Id = "hosts.static-cdn",
            Title = "gstatic.com static CDN",
            Summary = "Blocks Google's shared asset CDN.",
            Category = RuleCategory.ApisCdn,
            Tier = RiskTier.Aggressive,
            Engine = EngineKind.Hosts,
            Domains = GoogleEndpoints.StaticCdn,
            DefaultEnabled = true,
            Breaks =
            [
                Breakage.Severe("Images, CSS and scripts on many third-party sites",
                    "gstatic.com is not Google-only infrastructure — thousands of unrelated sites pull assets from it. Expect visibly broken pages."),
                Breakage.Notable("Windows/Chrome captive-portal detection",
                    "connectivitycheck.gstatic.com is included, so Chrome may misjudge whether you are behind a hotel or airport wifi login page.")
            ]
        });

        rules.Add(new BlockRule
        {
            Id = "hosts.fonts",
            Title = "Google Fonts",
            Summary = "Blocks fonts.googleapis.com and fonts.gstatic.com.",
            Category = RuleCategory.ApisCdn,
            Tier = RiskTier.Aggressive,
            Engine = EngineKind.Hosts,
            Domains = GoogleEndpoints.Fonts,
            DefaultEnabled = true,
            Breaks =
            [
                Breakage.Notable("Web page typography",
                    "Sites fall back to local fonts. Usually just uglier, but layouts that assume specific glyph widths can visibly break, and icon fonts render as empty boxes or stray letters.")
            ]
        });

        rules.Add(new BlockRule
        {
            Id = "hosts.push",
            Title = "Firebase Cloud Messaging (push)",
            Summary = "Blocks FCM/GCM, the transport behind most desktop and web push notifications.",
            Category = RuleCategory.Push,
            Tier = RiskTier.Aggressive,
            Engine = EngineKind.Hosts,
            Domains = GoogleEndpoints.Push,
            DefaultEnabled = true,
            Breaks =
            [
                Breakage.Severe("Push notifications, broadly",
                    "Not just Google apps. FCM carries push for a large share of Windows desktop and web apps, so notifications from unrelated software go quiet with no error message — they simply never arrive."),
                Breakage.Notable("Remote config and feature flags",
                    "Apps using Firebase Remote Config fall back to their built-in defaults.")
            ]
        });

        rules.Add(new BlockRule
        {
            Id = "hosts.recaptcha",
            Title = "reCAPTCHA (separable hosts)",
            Summary = "Blocks recaptcha.net and recaptcha.google.com.",
            Category = RuleCategory.AuthCaptcha,
            Tier = RiskTier.Aggressive,
            Engine = EngineKind.Hosts,
            Domains = GoogleEndpoints.Recaptcha,
            DefaultEnabled = true,
            Note = "Partial by nature. The main reCAPTCHA endpoint is a PATH under www.google.com, and a " +
                   "hosts file cannot block a path — only a whole name. Removing it entirely means blocking " +
                   "Google Search wholesale (a separate, off-by-default rule).",
            Breaks =
            [
                Breakage.Severe("Logins and signup forms behind a captcha",
                    "Where a site uses the recaptcha.net variant, its captcha widget never loads and the form cannot be submitted. You can be locked out of an account with no obvious cause.")
            ]
        });

        rules.Add(new BlockRule
        {
            Id = "hosts.cast",
            Title = "Chromecast discovery",
            Summary = "Blocks cast.google.com and the clients3/4 discovery hosts.",
            Category = RuleCategory.Media,
            Tier = RiskTier.Aggressive,
            Engine = EngineKind.Hosts,
            Domains = GoogleEndpoints.Cast,
            DefaultEnabled = true,
            Breaks =
            [
                Breakage.Notable("Casting to a TV or speaker",
                    "Chromecast and Google Home devices stop appearing in the cast menu.")
            ]
        });

        rules.Add(new BlockRule
        {
            Id = "reg.chrome.cast",
            Title = "Chrome policy: disable Media Router",
            Summary = "Removes the Cast integration from Chrome entirely.",
            Category = RuleCategory.Media,
            Tier = RiskTier.Aggressive,
            Engine = EngineKind.Registry,
            DefaultEnabled = true,
            RegistryValues =
            [
                RegistryPolicy.Dword(ChromePolicyKey, "EnableMediaRouter", 0)
            ],
            Breaks =
            [
                Breakage.Notable("The Cast menu item",
                    "Cast disappears from Chrome's menu. Local DIAL/mDNS discovery traffic stops as a side benefit.")
            ]
        });

        rules.Add(new BlockRule
        {
            Id = "hosts.play",
            Title = "Google Play services endpoints",
            Summary = "Blocks play.google.com and the Android client hosts.",
            Category = RuleCategory.ApisCdn,
            Tier = RiskTier.Aggressive,
            Engine = EngineKind.Hosts,
            Domains = GoogleEndpoints.Play,
            DefaultEnabled = true,
            Breaks =
            [
                Breakage.Notable("Google Play on the web, Google Play Games for PC",
                    "The Play store site and the Windows Play Games client stop working."),
                Breakage.Notable("Android development tooling",
                    "Android Studio's SDK manager and emulator image downloads fail.")
            ]
        });

        rules.Add(new BlockRule
        {
            Id = "reg.chrome.search",
            Title = "Chrome policy: no search suggestions or prediction",
            Summary = "Stops keystroke-level omnibox suggestions and network prefetching.",
            Category = RuleCategory.Search,
            Tier = RiskTier.Balanced,
            Engine = EngineKind.Registry,
            DefaultEnabled = true,
            RegistryValues =
            [
                RegistryPolicy.Dword(ChromePolicyKey, "SearchSuggestEnabled", 0),
                RegistryPolicy.Dword(ChromePolicyKey, "SpellCheckServiceEnabled", 0),
                RegistryPolicy.Dword(ChromePolicyKey, "NetworkPredictionOptions", 2),
                RegistryPolicy.Dword(ChromePolicyKey, "PaymentMethodQueryEnabled", 0)
            ],
            Breaks =
            [
                Breakage.Minor("Omnibox autocomplete",
                    "The address bar stops suggesting searches as you type. This also stops every keystroke going to Google, which is the point."),
                Breakage.Minor("Enhanced spell check",
                    "Chrome falls back to the local dictionary instead of the server-side one.")
            ]
        });

        rules.Add(new BlockRule
        {
            Id = "reg.chrome.signin",
            Title = "Chrome policy: no browser sign-in or sync",
            Summary = "Blocks signing into Chrome with a Google account and disables sync.",
            Category = RuleCategory.Sync,
            Tier = RiskTier.Aggressive,
            Engine = EngineKind.Registry,
            DefaultEnabled = true,
            RegistryValues =
            [
                RegistryPolicy.Dword(ChromePolicyKey, "BrowserSignin", 0),
                RegistryPolicy.Dword(ChromePolicyKey, "SyncDisabled", 1)
            ],
            Breaks =
            [
                Breakage.Severe("Bookmark, password and history sync",
                    "Chrome cannot sign in at all. Anything currently synced ONLY to your Google account stays in the cloud and will not appear on this machine. Export your bookmarks and passwords before arming this if you have not already.")
            ]
        });

        // ------------------------------------------------------------------
        // OFF BY DEFAULT — content blocking and sledgehammers.
        // These are not telemetry removal, so the Aggressive profile leaves them alone.
        // ------------------------------------------------------------------

        rules.Add(new BlockRule
        {
            Id = "hosts.accounts",
            Title = "Google account sign-in",
            Summary = "Blocks accounts.google.com and the OAuth front door.",
            Category = RuleCategory.AuthCaptcha,
            Tier = RiskTier.Aggressive,
            Engine = EngineKind.Hosts,
            Domains = GoogleEndpoints.Accounts,
            DefaultEnabled = false,
            RequiresExplicitConsent = true,
            Breaks =
            [
                Breakage.Severe("'Sign in with Google' everywhere",
                    "Every third-party site where you log in via Google — not just Google's own sites — becomes unreachable. If that is your only login method somewhere, you are locked out until you revert.")
            ]
        });

        rules.Add(new BlockRule
        {
            Id = "hosts.search",
            Title = "Google Search",
            Summary = "Blocks google.com outright.",
            Category = RuleCategory.Search,
            Tier = RiskTier.Aggressive,
            Engine = EngineKind.Hosts,
            Domains = GoogleEndpoints.Search,
            DefaultEnabled = false,
            RequiresExplicitConsent = true,
            Note = "Content blocking rather than telemetry removal, so it stays off even on the " +
                   "Aggressive profile. Arm it only if you have already moved to another search engine.",
            Breaks =
            [
                Breakage.Severe("Google Search",
                    "Unusable. Switch your default search engine first or your address bar stops working."),
                Breakage.Severe("reCAPTCHA on most sites",
                    "The main captcha endpoint lives under www.google.com, so this takes captcha-gated logins down across the web."),
                Breakage.Severe("Google OAuth redirects",
                    "Sign-in flows that bounce through google.com fail mid-redirect.")
            ]
        });

        rules.Add(new BlockRule
        {
            Id = "hosts.youtube",
            Title = "YouTube",
            Summary = "Blocks YouTube and its image/API hosts.",
            Category = RuleCategory.Media,
            Tier = RiskTier.Aggressive,
            Engine = EngineKind.Hosts,
            Domains = GoogleEndpoints.YouTube,
            DefaultEnabled = false,
            RequiresExplicitConsent = true,
            Note = "Content blocking rather than telemetry removal — off by default by design.",
            Breaks =
            [
                Breakage.Severe("YouTube, and every embedded video anywhere",
                    "Embedded YouTube players on unrelated sites — documentation, courses, news articles — all go dead, not just youtube.com itself.")
            ]
        });

        rules.Add(new BlockRule
        {
            Id = "fw.google-ranges",
            Title = "Firewall: block Google IP ranges",
            Summary = "Outbound block on core AS15169 netblocks — catches hardcoded IPs and DoH.",
            Category = RuleCategory.ApisCdn,
            Tier = RiskTier.Aggressive,
            Engine = EngineKind.Firewall,
            IpRanges = GoogleIpRanges.Core,
            DefaultEnabled = false,
            RequiresExplicitConsent = true,
            Note = "The only layer that stops software which ignores DNS entirely. Also the bluntest: " +
                   "it cannot distinguish telemetry from anything else Google-hosted.",
            Breaks =
            [
                Breakage.Severe("Everything Google-hosted, with no exceptions",
                    "Unlike hosts entries, this applies regardless of DNS. Any app that reaches a Google IP for any reason fails, including ones you want working."),
                Breakage.Notable("Confusing failure modes",
                    "Apps see connection timeouts rather than DNS failures, so their error messages will be vague and unhelpful.")
            ]
        });

        rules.Add(new BlockRule
        {
            Id = "fw.google-dns",
            Title = "Firewall: block Google Public DNS (8.8.8.8)",
            Summary = "Stops anything on this machine using Google's resolvers.",
            Category = RuleCategory.WindowsIntegration,
            Tier = RiskTier.Aggressive,
            Engine = EngineKind.Firewall,
            IpRanges = GoogleIpRanges.PublicDns,
            DefaultEnabled = false,
            RequiresExplicitConsent = true,
            Note = "Preflight refuses this automatically if 8.8.8.8 or 8.8.4.4 is one of your configured resolvers.",
            Breaks =
            [
                Breakage.Severe("All name resolution, if Google DNS is your resolver",
                    "If your adapter or router points at 8.8.8.8, arming this takes your entire internet connection down until you revert. Anti-Google checks for this and refuses, but a router-level setting is invisible from here.")
            ]
        });

        rules.Add(new BlockRule
        {
            Id = "fw.gcp-ranges",
            Title = "Firewall: block Google Cloud Platform ranges",
            Summary = "Outbound block on GCP netblocks.",
            Category = RuleCategory.ApisCdn,
            Tier = RiskTier.Aggressive,
            Engine = EngineKind.Firewall,
            IpRanges = GoogleIpRanges.CloudPlatform,
            DefaultEnabled = false,
            RequiresExplicitConsent = true,
            Note = "Included for completeness, but be honest with yourself about what it does.",
            Breaks =
            [
                Breakage.Severe("A large share of the internet that has nothing to do with Google",
                    "GCP hosts countless unrelated companies' backends. This is not de-Googling; it is disconnecting from every startup that picked the wrong cloud. Expect widespread, hard-to-diagnose failures.")
            ]
        });

        return rules;
    }
}
