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
/// Static Google netblocks for firewall-level blocking.
///
/// Deliberately NOT fetched from https://www.gstatic.com/ipranges/goog.json at runtime: a privacy
/// tool that phones Google to ask which addresses to block is self-defeating, and it would also
/// make the app's behaviour depend on a network call Google controls. These are long-lived
/// AS15169 allocations; refresh them by hand when you care to.
/// </summary>
public static class GoogleIpRanges
{
    /// <summary>
    /// Core Google service ranges. Stable, and do not host meaningful third-party infrastructure.
    /// </summary>
    public static readonly string[] Core =
    [
        "8.34.208.0/20",
        "8.35.192.0/20",
        "23.236.48.0/20",
        "23.251.128.0/19",
        "64.233.160.0/19",
        "66.102.0.0/20",
        "66.249.64.0/19",
        "70.32.128.0/19",
        "72.14.192.0/18",
        "74.125.0.0/16",
        "108.177.0.0/17",
        "142.250.0.0/15",
        "142.251.0.0/16",
        "172.217.0.0/16",
        "172.253.0.0/16",
        "173.194.0.0/16",
        "209.85.128.0/17",
        "216.58.192.0/19",
        "216.239.32.0/19",
        "2001:4860::/32"
    ];

    /// <summary>
    /// Google Public DNS. Split out on purpose: if these ARE the machine's resolvers, blocking
    /// them takes the entire internet down. Preflight refuses this rule when that is the case.
    /// </summary>
    public static readonly string[] PublicDns =
    [
        "8.8.8.8/32",
        "8.8.4.4/32",
        "2001:4860:4860::8888/128",
        "2001:4860:4860::8844/128"
    ];

    /// <summary>
    /// Google Cloud Platform. These host a large share of the internet's SaaS — Snapchat, Spotify
    /// pieces, countless startups. Blocking them is not "de-Googling", it is "de-internet-ing".
    /// Off by default and gated behind explicit consent.
    /// </summary>
    public static readonly string[] CloudPlatform =
    [
        "34.64.0.0/10",
        "35.184.0.0/13",
        "35.192.0.0/14",
        "35.196.0.0/15",
        "35.198.0.0/16",
        "35.199.0.0/17",
        "35.200.0.0/13",
        "104.154.0.0/15",
        "104.196.0.0/14",
        "130.211.0.0/16",
        "146.148.0.0/17"
    ];
}
