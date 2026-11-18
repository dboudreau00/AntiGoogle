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
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AntiGoogle.Core.Reporting;

/// <summary>
/// Turns a <see cref="ProtectionReport"/> into one self-contained HTML file or into JSON. The HTML has
/// no script and loads nothing from anywhere: every value is HTML-encoded, and it opens the same on a
/// machine with no network. That matters for a report you may want to hand to someone.
/// </summary>
public static class ReportRenderer
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public static string ToJson(ProtectionReport report) => JsonSerializer.Serialize(report, JsonOpts);

    public static string ToHtml(ProtectionReport r)
    {
        var sb = new StringBuilder(64 * 1024);
        sb.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
          .Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
          .Append("<meta name=\"robots\" content=\"noindex\">")
          .Append("<title>Anti-Google report</title><style>").Append(Css).Append("</style></head><body><main>");

        Header(sb, r);

        // Each part opens its own <section>; closing it here keeps the sections siblings, not nested.
        Action<StringBuilder, ProtectionReport>[] parts =
            [Glance, HowItWorks, Armed, ChangedOnThisMachine, LocalOnly, Quarantine, FoundAndLeftAlone, Checks, Activity, Limits];
        foreach (var part in parts)
        {
            part(sb, r);
            sb.Append("</section>");
        }

        sb.Append("</main></body></html>");
        return sb.ToString();
    }

    // ------------------------------------------------------------------ sections

    private static void Header(StringBuilder sb, ProtectionReport r)
    {
        sb.Append("<header><h1>Anti-Google report</h1><p class=\"meta\">")
          .Append(H(r.GeneratedAt.ToString("yyyy-MM-dd HH:mm"))).Append(" · version ").Append(H(r.AppVersion))
          .Append(" · ").Append(H(r.OsVersion)).Append(" · ")
          .Append(r.Elevated ? "run as administrator" : "run without administrator rights")
          .Append(" · profile ").Append(H(r.Profile)).Append("</p></header>");
    }

    private static void Glance(StringBuilder sb, ProtectionReport r)
    {
        var c = r.Counts;
        Section(sb, "At a glance");
        sb.Append("<div class=\"tiles\">");
        Tile(sb, c.SinkholedDomains, "names sinkholed");
        Tile(sb, c.LoopbackDomains, "names looped to this machine");
        Tile(sb, c.LocalOnlyJails, "programs confined to this machine");
        Tile(sb, c.FirewallRules, "firewall rules");
        Tile(sb, c.DisabledServices, "services disabled");
        Tile(sb, c.DisabledTasks, "scheduled tasks disabled");
        Tile(sb, c.RegistryValues, "policy values set");
        Tile(sb, c.QuarantinedItems, "items in quarantine");
        Tile(sb, c.UndoableChanges, "changes that can be undone");
        sb.Append("</div>");
        if (r.VerificationPassed is bool ok)
            sb.Append("<p class=\"").Append(ok ? "ok" : "bad").Append("\">")
              .Append(ok ? "Verification passed: every local-only check below holds." : "Verification found a problem. See the checks below.")
              .Append("</p>");
    }

    private static void HowItWorks(StringBuilder sb, ProtectionReport r)
    {
        Section(sb, "How this works on this machine");
        sb.Append("<dl>");
        Def(sb, "Hosts file",
            $"Windows looks in the hosts file before it asks any DNS server. Anti-Google keeps one marked block in it. " +
            $"A name written as 0.0.0.0 and :: gets no answer, so the program asking cannot connect ({r.Counts.SinkholedDomains} names now). " +
            $"A name written as 127.0.0.1 and ::1 resolves to this machine, so a connection attempt loops back and is refused unless something local answers ({r.Counts.LoopbackDomains} names now).");
        Def(sb, "Firewall",
            "Rules in the Windows Firewall group \"Anti-Google\". A local-only rule blocks every address except 127.0.0.0/8 and ::1, outbound and inbound, for one program or one service. " +
            "Windows does not filter loopback traffic, so a confined program keeps working locally and cannot reach anything else.");
        Def(sb, "Services and scheduled tasks",
            "Blocking disables the service or task and records how it was set. Local-only leaves it enabled and running, and confines it with the firewall rules instead.");
        Def(sb, "Registry policy",
            "Chrome, Edge and Google Update policy values. The value each one replaced, or the fact that it did not exist, is recorded first.");
        Def(sb, "Markers",
            "Network markers are names, blocked like any other. Host markers are found by looking in known places. Only identifiers, leftovers and optional components can be moved, " +
            "into a vault with a manifest and a hash for every file. Restore puts them back byte for byte. Security agents are reported and never touched.");
        Def(sb, "Undoing",
            "The way back is written to the journal before each change is made. Restore everything replays it, newest first, and sweeps the firewall group as a backstop.");
        sb.Append("</dl>");
    }

    private static void Armed(StringBuilder sb, ProtectionReport r)
    {
        Section(sb, "What is armed, and what each rule costs");
        if (r.ArmedRules.Count == 0 && r.LocalOnlyApps.Count == 0 && r.ContainedApps.Count == 0)
        {
            sb.Append("<p class=\"muted\">Nothing is armed.</p>");
            return;
        }

        sb.Append("<table><thead><tr><th>Rule</th><th>Vendor</th><th>Layer</th><th class=\"n\">Mode</th><th class=\"n\">Worst cost</th></tr></thead><tbody>");
        foreach (var rule in r.ArmedRules)
        {
            sb.Append("<tr><td>").Append(H(rule.Title)).Append("<br><span class=\"id\">").Append(H(rule.Id)).Append("</span></td>")
              .Append("<td>").Append(H(rule.Vendor)).Append("</td><td>").Append(H(rule.Layer)).Append("</td>")
              .Append("<td>").Append(Badge(rule.Mode, rule.Mode == "Local-only" ? "lo" : "blk")).Append("</td>")
              .Append("<td>").Append(Badge(rule.Worst, Severity(rule.Worst))).Append("</td></tr>");
            if (rule.Costs.Count > 0)
            {
                sb.Append("<tr class=\"sub\"><td colspan=\"5\"><details><summary>").Append(rule.Costs.Count)
                  .Append(rule.Costs.Count == 1 ? " known cost" : " known costs").Append("</summary><ul>");
                foreach (var cost in rule.Costs)
                    sb.Append("<li>").Append(Badge(cost.Severity, Severity(cost.Severity))).Append(" <strong>").Append(H(cost.What))
                      .Append("</strong>. ").Append(H(cost.Detail)).Append("</li>");
                sb.Append("</ul></details></td></tr>");
            }
        }
        sb.Append("</tbody></table>");

        if (r.LocalOnlyApps.Count > 0) List(sb, "Programs kept running, confined to this machine", r.LocalOnlyApps);
        if (r.ContainedApps.Count > 0) List(sb, "Programs blocked from Google's address ranges", r.ContainedApps);
    }

    private static void ChangedOnThisMachine(StringBuilder sb, ProtectionReport r)
    {
        Section(sb, "What was changed on this machine");

        sb.Append("<h3>Hosts file</h3>");
        if (r.Hosts.Groups.Count == 0) sb.Append("<p class=\"muted\">No managed block is present.</p>");
        foreach (var g in r.Hosts.Groups)
        {
            sb.Append("<details><summary>").Append(H(g.Title)).Append(" ").Append(Badge(g.Mode, g.Mode == "Local-only" ? "lo" : "blk"))
              .Append(" <span class=\"muted\">").Append(g.Domains.Count).Append(" names</span></summary><p class=\"names\">")
              .Append(string.Join(" ", g.Domains.Select(d => $"<code>{H(d)}</code>"))).Append("</p></details>");
        }
        if (r.Hosts.IncompleteNames.Count > 0)
            sb.Append("<p class=\"bad\">Missing one address family: ").Append(H(string.Join(", ", r.Hosts.IncompleteNames.Take(20)))).Append("</p>");

        sb.Append("<h3>Firewall rules</h3>");
        if (r.FirewallRules.Count == 0) sb.Append("<p class=\"muted\">No rules in the Anti-Google group.</p>");
        else
        {
            Table(sb, ["Rule", "Direction", "Action", "Applies to", "Remote addresses", "Enabled"],
                r.FirewallRules.Select(f => new[] { f.Name, f.Direction, f.Action, f.Scope, f.RemoteSummary, f.Enabled ? "yes" : "no" }),
                "", "tnnptn");
        }

        sb.Append("<h3>Services</h3>");
        Table(sb, ["Service", "Was", "Now", "Rule"], r.Services.Select(s => new[] { s.Name, s.Was, s.Now, s.RuleId }), "No services were changed.");

        sb.Append("<h3>Scheduled tasks</h3>");
        Table(sb, ["Task", "Was", "Now", "Rule"], r.Tasks.Select(t => new[] { t.Path, t.Was, t.Now, t.RuleId }), "No scheduled tasks were changed.", "pttt");

        sb.Append("<h3>Registry policy values</h3>");
        Table(sb, ["Value", "Was", "Now", "Rule"], r.Registry.Select(v => new[] { v.Location, v.Was, v.Now, v.RuleId }), "No registry values were changed.", "pttt");
    }

    private static void LocalOnly(StringBuilder sb, ProtectionReport r)
    {
        Section(sb, "Confined to this machine, and the evidence");
        if (r.Verification.Count == 0)
        {
            sb.Append("<p class=\"muted\">Nothing is confined to this machine right now.</p>");
            return;
        }

        foreach (var t in r.Verification)
        {
            sb.Append("<div class=\"target\"><h3>").Append(H(t.Label)).Append(" <span class=\"muted\">").Append(H(t.Scope)).Append("</span></h3><ul class=\"checks\">");
            foreach (var c in t.Checks)
                sb.Append("<li class=\"").Append(c.Passed ? "ok" : "bad").Append("\"><strong>").Append(c.Passed ? "Pass" : "FAIL").Append("</strong> ")
                  .Append(H(c.Name)).Append(". <span class=\"muted\">").Append(H(c.Detail)).Append("</span></li>");
            sb.Append("</ul>");
            if (t.Connections.Count > 0)
            {
                sb.Append("<details><summary>").Append(t.Connections.Count).Append(" open sockets right now</summary><pre>")
                  .Append(H(string.Join("\n", t.Connections))).Append("</pre></details>");
            }
            sb.Append("</div>");
        }
    }

    private static void Quarantine(StringBuilder sb, ProtectionReport r)
    {
        Section(sb, "What was quarantined");
        if (r.Quarantined.Count == 0)
        {
            sb.Append("<p class=\"muted\">Nothing is in quarantine.</p>");
            return;
        }

        Table(sb, ["Item", "Vendor", "Original location", "Size", "Files", "Moved", "Vault folder"],
            r.Quarantined.Select(q => new[] { q.Title, q.Vendor, q.OriginalPath, Size(q.Bytes), q.Files.ToString(), q.Created, q.Id }), "", "ttpnnnp");
        sb.Append("<p class=\"muted\">Each item is held with a manifest and a SHA-256 for every file. Restore everything puts them back byte for byte.</p>");
    }

    private static void FoundAndLeftAlone(StringBuilder sb, ProtectionReport r)
    {
        Section(sb, "Markers found on this machine");
        if (r.Markers.Count == 0)
        {
            sb.Append("<p class=\"muted\">None of the ").Append(r.MarkersNotFound).Append(" known locations holds anything.</p>");
            return;
        }

        sb.Append("<table><thead><tr><th>Marker</th><th>Vendor</th><th>What</th><th>Location</th><th class=\"n\">Size</th><th>Handling</th><th class=\"n\">Confidence</th></tr></thead><tbody>");
        foreach (var m in r.Markers)
            sb.Append("<tr><td>").Append(H(m.Title)).Append("</td><td>").Append(H(m.Vendor)).Append("</td><td>").Append(H(m.Class))
              .Append("</td><td class=\"p\">").Append(Breakable(m.Location)).Append(m.Note.Length > 0 ? $"<br><span class=\"muted\">{H(m.Note)}</span>" : "")
              .Append("</td><td class=\"n\">").Append(H(m.Size)).Append("</td><td>").Append(H(m.Action)).Append("</td><td class=\"n\">").Append(H(m.Confidence)).Append("</td></tr>");
        sb.Append("</tbody></table><p class=\"muted\">").Append(r.MarkersNotFound).Append(" other known locations hold nothing.</p>");
    }

    private static void Checks(StringBuilder sb, ProtectionReport r)
    {
        Section(sb, "Safety checks");
        if (r.Findings.Count == 0) { sb.Append("<p class=\"muted\">No findings.</p>"); return; }

        sb.Append("<ul class=\"checks\">");
        foreach (var f in r.Findings.OrderByDescending(f => f.Level))
            sb.Append("<li class=\"").Append(f.Level == "Blocker" ? "bad" : f.Level == "Warning" ? "warn" : "ok").Append("\"><strong>").Append(H(f.Level)).Append("</strong> ")
              .Append(H(f.Title)).Append(". <span class=\"muted\">").Append(H(f.Detail)).Append("</span></li>");
        sb.Append("</ul>");
    }

    private static void Activity(StringBuilder sb, ProtectionReport r)
    {
        Section(sb, "Recent activity");
        if (r.Activity.Count == 0) { sb.Append("<p class=\"muted\">No activity has been recorded yet.</p>"); return; }

        sb.Append("<table><thead><tr><th class=\"n\">Time</th><th class=\"n\">Event</th><th class=\"n\">Layer</th><th class=\"n\">Outcome</th><th>Detail</th></tr></thead><tbody>");
        foreach (var e in r.Activity.AsEnumerable().Reverse())
        {
            sb.Append("<tr><td class=\"n\">").Append(H(e.At)).Append("</td><td class=\"n\">").Append(H(e.Kind))
              .Append("</td><td class=\"n\">").Append(Humanize(e.Engine)).Append("</td><td class=\"n\">").Append(Humanize(e.Outcome))
              .Append("</td><td class=\"p\">").Append(Breakable(e.Detail));
            if (e.Rule.Length > 0) sb.Append("<br><span class=\"muted\">").Append(Breakable(e.Rule)).Append("</span>");
            // The target is shown only when it adds something: not when the detail or rule already names it,
            // and not for a journal entry id, which audit.jsonl and the JSON report keep.
            if (e.Target.Length > 0 && !e.Detail.Contains(e.Target, StringComparison.OrdinalIgnoreCase)
                && !e.Rule.Contains(e.Target, StringComparison.OrdinalIgnoreCase)
                && !(e.Target.Length == 32 && e.Target.All(Uri.IsHexDigit)))
                sb.Append("<br><span class=\"muted\">").Append(Breakable(e.Target)).Append("</span>");
            sb.Append("</td></tr>");
        }
        sb.Append("</tbody></table>");
    }

    private static void Limits(StringBuilder sb, ProtectionReport r)
    {
        Section(sb, "What this does not cover");
        sb.Append("<ul>");
        foreach (var l in r.Limits) sb.Append("<li>").Append(H(l)).Append("</li>");
        sb.Append("</ul>");
    }

    // ------------------------------------------------------------------ small pieces

    private static void Section(StringBuilder sb, string title) => sb.Append("<section><h2>").Append(H(title)).Append("</h2>");

    private static void Tile(StringBuilder sb, int value, string label) =>
        sb.Append("<div class=\"tile\"><div class=\"n\">").Append(value).Append("</div><div class=\"l\">").Append(H(label)).Append("</div></div>");

    private static void Def(StringBuilder sb, string term, string text) =>
        sb.Append("<dt>").Append(H(term)).Append("</dt><dd>").Append(H(text)).Append("</dd>");

    private static void List(StringBuilder sb, string title, IEnumerable<string> items)
    {
        sb.Append("<h3>").Append(H(title)).Append("</h3><ul>");
        foreach (var i in items) sb.Append("<li><code>").Append(H(i)).Append("</code></li>");
        sb.Append("</ul>");
    }

    /// <param name="kinds">One letter per column: t text, p path (may break anywhere), n never wraps.</param>
    private static void Table(StringBuilder sb, string[] headers, IEnumerable<string[]> rows, string empty, string kinds = "")
    {
        var list = rows.ToList();
        if (list.Count == 0) { if (empty.Length > 0) sb.Append("<p class=\"muted\">").Append(H(empty)).Append("</p>"); return; }

        string Cls(int i) => i < kinds.Length && kinds[i] != 't' ? $" class=\"{kinds[i]}\"" : "";
        string Cell(int i, string v) => i < kinds.Length && kinds[i] == 'p' ? Breakable(v) : H(v);

        sb.Append("<table><thead><tr>");
        for (var i = 0; i < headers.Length; i++) sb.Append("<th").Append(Cls(i)).Append('>').Append(H(headers[i])).Append("</th>");
        sb.Append("</tr></thead><tbody>");
        foreach (var row in list)
        {
            sb.Append("<tr>");
            for (var i = 0; i < row.Length; i++) sb.Append("<td").Append(Cls(i)).Append('>').Append(Cell(i, row[i])).Append("</td>");
            sb.Append("</tr>");
        }
        sb.Append("</tbody></table>");
    }

    private static string Badge(string text, string kind) => $"<span class=\"badge {kind}\">{H(text)}</span>";

    private static string Severity(string s) => s switch { "Severe" => "sev", "Notable" => "not", "Minor" => "min", _ => "none" };

    private static string Size(long bytes) => Markers.MarkerFinding.FormatSize(bytes);

    private static string H(string? s) => WebUtility.HtmlEncode(s ?? "");

    /// <summary>Encoded text that may wrap after a backslash, so a path breaks between names and not inside one.</summary>
    private static string Breakable(string? s) => H(s).Replace("\\", "\\<wbr>");

    /// <summary>"AlreadySatisfied" becomes "Already satisfied". Anything that already has a space or a dot is left alone.</summary>
    private static string Humanize(string s)
    {
        if (s.Length < 2 || s.Contains(' ') || s.Contains('.')) return H(s);
        var sb = new StringBuilder(s.Length + 4);
        for (var i = 0; i < s.Length; i++)
        {
            if (i > 0 && char.IsUpper(s[i]) && char.IsLower(s[i - 1])) sb.Append(' ').Append(char.ToLowerInvariant(s[i]));
            else sb.Append(s[i]);
        }
        return H(sb.ToString().Replace("Local only", "Local-only"));
    }

    private const string Css = """
        :root{color-scheme:light dark;--bg:#fff;--fg:#14171c;--mut:#5b6370;--line:#dfe3e8;--card:#f5f7fa;--acc:#c9362b;--ok:#17724a;--warn:#9a6a00;--bad:#b3261e}
        @media (prefers-color-scheme:dark){:root{--bg:#0e1013;--fg:#e6e9ef;--mut:#9aa3b2;--line:#252a33;--card:#161a20;--acc:#ff5a4e;--ok:#4cc38a;--warn:#e2b340;--bad:#ff7a70}}
        *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 "Segoe UI",system-ui,sans-serif}
        main{max-width:1080px;margin:0 auto;padding:28px 20px 64px}h1{margin:0 0 4px;font-size:26px}h2{margin:34px 0 10px;font-size:18px;border-bottom:1px solid var(--line);padding-bottom:6px}
        h3{margin:20px 0 6px;font-size:15px}.meta,.muted{color:var(--mut)}.id{color:var(--mut);font:12px Consolas,monospace}
        .tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:10px}.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
        .tile .n{font-size:24px;font-weight:600}.tile .l{color:var(--mut);font-size:13px}
        dl{margin:0}dt{font-weight:600;margin-top:12px}dd{margin:2px 0 0;color:var(--fg)}
        table{width:100%;border-collapse:collapse;font-size:14px;margin:8px 0}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:break-word}td.p{overflow-wrap:anywhere}td.n,th.n{white-space:nowrap}
        th{color:var(--mut);font-weight:600;font-size:13px}tr.sub td{padding-top:0}
        code{font:12.5px Consolas,monospace;background:var(--card);padding:1px 4px;border-radius:4px}.names code{margin-right:4px;line-height:2}
        pre{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:10px;overflow:auto;font:12.5px Consolas,monospace}
        details{margin:4px 0}summary{cursor:pointer}ul{margin:6px 0 6px 18px;padding:0}.checks{list-style:none;margin-left:0}.checks li{margin:5px 0}
        .ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}.checks .muted{color:var(--mut)}
        .badge{display:inline-block;font-size:11.5px;font-weight:600;padding:1px 7px;border-radius:999px;border:1px solid var(--line);background:var(--card)}
        .badge.sev{color:var(--bad);border-color:var(--bad)}.badge.not{color:var(--warn);border-color:var(--warn)}.badge.min,.badge.none{color:var(--mut)}
        .badge.lo{color:var(--ok);border-color:var(--ok)}.badge.blk{color:var(--acc);border-color:var(--acc)}
        .target{border:1px solid var(--line);border-radius:8px;padding:2px 14px 10px;margin:10px 0}
        @media print{body{background:#fff;color:#000}details>*{display:block!important}}
        """;
}
