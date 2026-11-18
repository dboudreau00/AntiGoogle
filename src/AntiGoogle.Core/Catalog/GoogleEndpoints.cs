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
namespace AntiGoogle.Core.Catalog;

/// <summary>
/// Curated Google endpoint groups.
///
/// IMPORTANT — hosts-file semantics: a hosts entry matches one exact name. There are no wildcards.
/// Listing "googleapis.com" does NOT block "fcm.googleapis.com". Every subdomain that matters has
/// to be enumerated by hand, which is why these lists are long and explicit rather than clever.
/// </summary>
public static class GoogleEndpoints
{
    /// <summary>Chrome's own phone-home: field trials, usage stats, background feature pings.</summary>
    public static readonly string[] ChromeTelemetry =
    [
        "clientservices.googleapis.com",       // variations / field-trial seed
        "chromereporting-pa.googleapis.com",   // enterprise reporting
        "optimizationguide-pa.googleapis.com", // page-load hint fetching (heavy, chatty)
        "content-autofill.googleapis.com",     // autofill server round-trips
        "growth-pa.googleapis.com",
        "notifications-pa.googleapis.com",
        "ogads-pa.googleapis.com",
        "chromesyncpasswords-pa.googleapis.com",
        "chromeosquota-pa.googleapis.com",
        "chromemoto.l.google.com",
        "chrome-devtools-frontend.appspot.com",
        "chromewebstore.googleapis.com"
    ];

    /// <summary>Network-quality beacons Chrome fires continuously in the background.</summary>
    public static readonly string[] Beacons =
    [
        "beacons.gcp.gvt2.com",
        "beacons.gvt2.com",
        "beacons1.gvt2.com",
        "beacons2.gvt2.com",
        "beacons3.gvt2.com",
        "beacons4.gvt2.com",
        "beacons5.gvt2.com",
        "beacons3.gvt3.com"
    ];

    /// <summary>Crash and stability upload endpoints.</summary>
    public static readonly string[] CrashReporting =
    [
        "crashlyticsreports-pa.googleapis.com",
        "mobilecrashreporting.googleapis.com",
        "firebasecrashlytics.googleapis.com",
        "firebase-settings.crashlytics.com",
        "crashpad.chromium.org"
    ];

    /// <summary>Google Analytics, including the regional GA4 collectors most blocklists miss.</summary>
    public static readonly string[] Analytics =
    [
        "google-analytics.com",
        "www.google-analytics.com",
        "ssl.google-analytics.com",
        "analytics.google.com",
        "region1.google-analytics.com",
        "region2.google-analytics.com",
        "region3.google-analytics.com",
        "region4.google-analytics.com",
        "region5.google-analytics.com",
        "analytic.google.com",
        "googletagmanager.com",
        "www.googletagmanager.com",
        "googletagservices.com",
        "www.googletagservices.com",
        "ampcid.google.com"
    ];

    /// <summary>Ad serving and conversion tracking.</summary>
    public static readonly string[] Advertising =
    [
        "doubleclick.net",
        "www.doubleclick.net",
        "ad.doubleclick.net",
        "ads.doubleclick.net",
        "stats.g.doubleclick.net",
        "cm.g.doubleclick.net",
        "googleads.g.doubleclick.net",
        "googlesyndication.com",
        "www.googlesyndication.com",
        "pagead2.googlesyndication.com",
        "tpc.googlesyndication.com",
        "adservice.google.com",
        "googleadservices.com",
        "www.googleadservices.com",
        "pagead.l.doubleclick.net",
        "2mdn.net",
        "s0.2mdn.net",
        "googleadapis.l.google.com"
    ];

    /// <summary>Safe Browsing reputation lookups. Blocking these is a real security tradeoff.</summary>
    public static readonly string[] SafeBrowsing =
    [
        "safebrowsing.googleapis.com",
        "safebrowsing.google.com",
        "sb-ssl.google.com",
        "safebrowsing-cache.google.com"
    ];

    /// <summary>Update delivery and the GVT CDN that carries Chrome component payloads.</summary>
    public static readonly string[] UpdateDelivery =
    [
        "update.googleapis.com",
        "tools.google.com",
        "dl.google.com",
        "dl-ssl.google.com",
        "edgedl.me.gvt1.com",
        "redirector.gvt1.com",
        "gvt1.com",
        "www.gvt1.com",
        "gvt2.com",
        "gvt3.com",
        "clients2.google.com",
        "clients5.google.com",
        "omahaproxy.appspot.com"
    ];

    /// <summary>Firebase Cloud Messaging / GCM — the transport for most desktop and web push.</summary>
    public static readonly string[] Push =
    [
        "fcm.googleapis.com",
        "fcmconnection.googleapis.com",
        "mtalk.google.com",
        "alt1-mtalk.google.com",
        "alt2-mtalk.google.com",
        "alt3-mtalk.google.com",
        "alt4-mtalk.google.com",
        "alt5-mtalk.google.com",
        "alt6-mtalk.google.com",
        "alt7-mtalk.google.com",
        "alt8-mtalk.google.com",
        "android.googleapis.com",
        "firebaseinstallations.googleapis.com",
        "firebaseremoteconfig.googleapis.com",
        "firebaselogging-pa.googleapis.com",
        "firebaselogging.googleapis.com",
        "firebasedynamiclinks.googleapis.com"
    ];

    /// <summary>The generic API front doors. Enormous blast radius.</summary>
    public static readonly string[] ApiFrontDoors =
    [
        "googleapis.com",
        "www.googleapis.com",
        "storage.googleapis.com",
        "content.googleapis.com",
        "people-pa.googleapis.com",
        "oauth2.googleapis.com",
        "translate.googleapis.com",
        "translate-pa.googleapis.com",
        "maps.googleapis.com",
        "youtubei.googleapis.com",
        "apis.google.com"
    ];

    /// <summary>Static asset CDN used by Google properties and a great many third-party sites.</summary>
    public static readonly string[] StaticCdn =
    [
        "gstatic.com",
        "www.gstatic.com",
        "ssl.gstatic.com",
        "encrypted-tbn0.gstatic.com",
        "connectivitycheck.gstatic.com"
    ];

    /// <summary>Web fonts. Separate from the CDN because the breakage is purely visual.</summary>
    public static readonly string[] Fonts =
    [
        "fonts.googleapis.com",
        "fonts.gstatic.com"
    ];

    /// <summary>
    /// reCAPTCHA. Note the primary endpoint is a PATH on www.google.com, which a hosts file
    /// cannot target — see the rule note. These are the separable ones.
    /// </summary>
    public static readonly string[] Recaptcha =
    [
        "recaptcha.net",
        "www.recaptcha.net",
        "recaptcha.google.com"
    ];

    public static readonly string[] Cast =
    [
        "cast.google.com",
        "clients3.google.com",
        "clients4.google.com"
    ];

    public static readonly string[] Play =
    [
        "play.google.com",
        "play.googleapis.com",
        "android.clients.google.com",
        "androidtvchannels-pa.googleapis.com"
    ];

    /// <summary>Sign-in. Blocking this kills "Sign in with Google" on third-party sites too.</summary>
    public static readonly string[] Accounts =
    [
        "accounts.google.com",
        "accounts.youtube.com",
        "myaccount.google.com",
        "signaler-pa.googleapis.com"
    ];

    /// <summary>Google Search itself. Content blocking, not telemetry — off by default.</summary>
    public static readonly string[] Search =
    [
        "google.com",
        "www.google.com",
        "encrypted.google.com",
        "ipv4.google.com",
        "ipv6.google.com"
    ];

    /// <summary>YouTube. Content blocking, not telemetry — off by default.</summary>
    public static readonly string[] YouTube =
    [
        "youtube.com",
        "www.youtube.com",
        "m.youtube.com",
        "youtube-nocookie.com",
        "www.youtube-nocookie.com",
        "ytimg.com",
        "i.ytimg.com",
        "s.ytimg.com",
        "youtubei.googleapis.com"
    ];

    /// <summary>
    /// Tracking and measurement hosts beyond the base Analytics and Advertising groups: Firebase
    /// Analytics, ad-serving and conversion hosts, client metrics, and the ad traffic quality
    /// endpoints. Cross-checked against two public blocklists (StevenBlack hosts and the AdGuard DNS
    /// filter); each name appears in at least one. Dashboards and consoles (ads.google.com, admob.com,
    /// marketingplatform.google.com) are deliberately NOT here: they are services, not trackers.
    /// </summary>
    public static readonly string[] MeasurementExtended =
    [
        "app-measurement.com",
        "csi.gstatic.com",
        "clientmetrics-pa.googleapis.com",
        "clouderrorreporting.googleapis.com",
        "federatedcompute-pa.googleapis.com",
        "fcmatch.google.com",
        "fundingchoicesmessages.google.com",
        "adtrafficquality.google",
        "ep1.adtrafficquality.google",
        "ep2.adtrafficquality.google",
        "video-stats.video.google.com",
        "crashlytics.com",
        "e.crashlytics.com",
        "googleanalytics.com",
        "ssl.googleanalytics.com",
        "ssl-google-analytics.l.google.com",
        "www-google-analytics.l.google.com",
        "ade.googlesyndication.com",
        "afs.googlesyndication.com",
        "buttons.googlesyndication.com",
        "pagead.googlesyndication.com",
        "video-ad-stats.googlesyndication.com",
        "partner.googleadservices.com",
        "pagead2.googleadservices.com",
        "adclick.g.doubleclick.net",
        "adx.g.doubleclick.net",
        "bid.g.doubleclick.net",
        "dp.g.doubleclick.net",
        "pubads.g.doubleclick.net",
        "securepubads.g.doubleclick.net",
        "feedads.g.doubleclick.net",
        "g.doubleclick.net",
        "fls.doubleclick.net",
        "static.doubleclick.net",
        "m.doubleclick.net",
        "mediavisor.doubleclick.net",
        "googleads2.g.doubleclick.net",
        "googleads4.g.doubleclick.net",
        "ad-g.doubleclick.net",
        "pagead.l.google.com",
        "pagead-googlehosted.l.google.com",
        "partnerad.l.google.com",
        "partnerad.l.doubleclick.net",
        "m.2mdn.net",
        "static.2mdn.net",
        "gcdn.2mdn.net"
    ];

    /// <summary>
    /// Mandiant marketing trackers. Both hosts are flagged as trackers by the AdGuard DNS filter. They
    /// are web-form and marketing-automation hosts, not part of any security product's channel.
    /// </summary>
    public static readonly string[] MandiantTracking =
    [
        "app.connect.mandiant.com",
        "images.connect.mandiant.com"
    ];

    /// <summary>
    /// Mandiant's portal, API and website. advantage.mandiant.com and api.intelligence.mandiant.com
    /// are named by third-party integration documentation (Google Cloud SOAR, Sumo Logic), not by a
    /// Mandiant network requirements page, which could not be found.
    /// </summary>
    public static readonly string[] MandiantServices =
    [
        "mandiant.com",
        "www.mandiant.com",
        "advantage.mandiant.com",
        "api.intelligence.mandiant.com"
    ];

    /// <summary>VirusTotal. Documented API base is https://www.virustotal.com/api/v3/.</summary>
    public static readonly string[] VirusTotal =
    [
        "virustotal.com",
        "www.virustotal.com"
    ];

    /// <summary>
    /// Google SecOps (Chronicle) legacy ingestion endpoints, from Google's ingestion API reference. The
    /// newer API uses chronicle.REGION.rep.googleapis.com, and a hosts file cannot match a name it does
    /// not list, so regions beyond these are not covered.
    /// </summary>
    public static readonly string[] SecOps =
    [
        "malachiteingestion-pa.googleapis.com",
        "europe-malachiteingestion-pa.googleapis.com",
        "europe-west2-malachiteingestion-pa.googleapis.com",
        "asia-northeast1-malachiteingestion-pa.googleapis.com",
        "southamerica-east1-malachiteingestion-pa.googleapis.com"
    ];

    /// <summary>Every domain the catalog knows about — used by the per-app containment engine.</summary>
    public static IEnumerable<string> All() =>
        ChromeTelemetry.Concat(Beacons).Concat(CrashReporting).Concat(Analytics)
            .Concat(Advertising).Concat(SafeBrowsing).Concat(UpdateDelivery).Concat(Push)
            .Concat(ApiFrontDoors).Concat(StaticCdn).Concat(Fonts).Concat(Recaptcha)
            .Concat(Cast).Concat(Play).Concat(Accounts)
            .Distinct(StringComparer.OrdinalIgnoreCase);
}
