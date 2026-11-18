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

namespace AntiGoogle.Core.Catalog;

/// <summary>
/// The address vocabulary of local-only mode.
///
/// A local-only program may talk to this machine and to nothing else, so its firewall rules block
/// "every address except loopback". The firewall's remote-address field takes ranges, not
/// "everything except", so the complement is spelled out. Windows accepts these range forms for both
/// families and stores them as written (measured on Windows 11, see docs/SPEC.md section 8).
/// </summary>
public static class LoopbackRanges
{
    public const string IPv4 = "127.0.0.1";
    public const string IPv6 = "::1";

    /// <summary>Every IPv4 address except 127.0.0.0/8.</summary>
    public static readonly IReadOnlyList<string> NonLoopbackV4 =
        ["0.0.0.0-126.255.255.255", "128.0.0.0-255.255.255.255"];

    /// <summary>Every IPv6 address except the unspecified address and ::1.</summary>
    public static readonly IReadOnlyList<string> NonLoopbackV6 =
        ["::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];

    /// <summary>What a local-only firewall rule blocks.</summary>
    public static readonly IReadOnlyList<string> NonLoopback = [.. NonLoopbackV4, .. NonLoopbackV6];

    /// <summary>True for 127.0.0.0/8, ::1 and the IPv4-mapped forms of both.</summary>
    public static bool IsLoopback(IPAddress address) =>
        IPAddress.IsLoopback(address) ||
        (address.IsIPv4MappedToIPv6 && IPAddress.IsLoopback(address.MapToIPv4()));
}
