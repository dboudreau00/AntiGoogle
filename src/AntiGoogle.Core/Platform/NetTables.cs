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
using System.Runtime.InteropServices;
using System.Text;

namespace AntiGoogle.Core.Platform;

public sealed record TcpEntry(
    IPAddress LocalAddress, int LocalPort, IPAddress RemoteAddress, int RemotePort, TcpState State, int ProcessId);

public sealed record UdpEntry(IPAddress LocalAddress, int LocalPort, int ProcessId);

/// <summary>
/// The system's TCP and UDP tables with the owning process of every endpoint, from the IP Helper API.
/// The managed IPGlobalProperties has no owner, and "which program holds this connection" is the whole
/// question when checking that a confined program really is confined.
/// </summary>
public static class NetTables
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;
    private const uint ErrorInsufficientBuffer = 122;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int af, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool order, int af, int tableClass, uint reserved);

    public static IReadOnlyList<TcpEntry> Tcp()
    {
        var entries = new List<TcpEntry>();
        ReadTable((IntPtr p, ref int s) => GetExtendedTcpTable(p, ref s, false, AfInet, TcpTableOwnerPidAll, 0), buffer =>
        {
            var count = Marshal.ReadInt32(buffer);
            for (var i = 0; i < count; i++)
            {
                var row = buffer + 4 + i * 24;
                entries.Add(new TcpEntry(
                    new IPAddress((uint)Marshal.ReadInt32(row, 4)), Port(Marshal.ReadInt32(row, 8)),
                    new IPAddress((uint)Marshal.ReadInt32(row, 12)), Port(Marshal.ReadInt32(row, 16)),
                    (TcpState)Marshal.ReadInt32(row, 0), Marshal.ReadInt32(row, 20)));
            }
        });

        ReadTable((IntPtr p, ref int s) => GetExtendedTcpTable(p, ref s, false, AfInet6, TcpTableOwnerPidAll, 0), buffer =>
        {
            var count = Marshal.ReadInt32(buffer);
            for (var i = 0; i < count; i++)
            {
                var row = buffer + 4 + i * 56;
                entries.Add(new TcpEntry(
                    Address6(row, 0, Marshal.ReadInt32(row, 16)), Port(Marshal.ReadInt32(row, 20)),
                    Address6(row, 24, Marshal.ReadInt32(row, 40)), Port(Marshal.ReadInt32(row, 44)),
                    (TcpState)Marshal.ReadInt32(row, 48), Marshal.ReadInt32(row, 52)));
            }
        });

        return entries;
    }

    public static IReadOnlyList<UdpEntry> Udp()
    {
        var entries = new List<UdpEntry>();
        ReadTable((IntPtr p, ref int s) => GetExtendedUdpTable(p, ref s, false, AfInet, UdpTableOwnerPid, 0), buffer =>
        {
            var count = Marshal.ReadInt32(buffer);
            for (var i = 0; i < count; i++)
            {
                var row = buffer + 4 + i * 12;
                entries.Add(new UdpEntry(new IPAddress((uint)Marshal.ReadInt32(row, 0)), Port(Marshal.ReadInt32(row, 4)), Marshal.ReadInt32(row, 8)));
            }
        });

        ReadTable((IntPtr p, ref int s) => GetExtendedUdpTable(p, ref s, false, AfInet6, UdpTableOwnerPid, 0), buffer =>
        {
            var count = Marshal.ReadInt32(buffer);
            for (var i = 0; i < count; i++)
            {
                var row = buffer + 4 + i * 28;
                entries.Add(new UdpEntry(Address6(row, 0, Marshal.ReadInt32(row, 16)), Port(Marshal.ReadInt32(row, 20)), Marshal.ReadInt32(row, 24)));
            }
        });

        return entries;
    }

    private delegate uint Fetch(IntPtr buffer, ref int size);

    private static void ReadTable(Fetch fetch, Action<IntPtr> parse)
    {
        var size = 0;
        var result = fetch(IntPtr.Zero, ref size);

        for (var attempt = 0; attempt < 5 && result == ErrorInsufficientBuffer; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                result = fetch(buffer, ref size);
                if (result == 0)
                {
                    parse(buffer);
                    return;
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        if (result != 0 && result != ErrorInsufficientBuffer)
            Log.Warn($"IP Helper table read failed with {result}.");
    }

    /// <summary>The port is stored in network byte order in the low 16 bits.</summary>
    private static int Port(int raw) => ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF);

    private static IPAddress Address6(IntPtr row, int offset, int scope)
    {
        var bytes = new byte[16];
        Marshal.Copy(row + offset, bytes, 0, 16);
        return new IPAddress(bytes, scope);
    }
}

/// <summary>The program behind a process id.</summary>
public static class ProcessImage
{
    private const int QueryLimitedInformation = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageNameW(IntPtr process, int flags, StringBuilder name, ref int size);

    /// <summary>The full path of the process's program, or null when it cannot be read (protected, or exited).</summary>
    public static string? PathOf(int pid)
    {
        if (pid <= 4) return null;
        var handle = OpenProcess(QueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero) return null;
        try
        {
            var size = 1024;
            var name = new StringBuilder(size);
            return QueryFullProcessImageNameW(handle, 0, name, ref size) ? name.ToString() : null;
        }
        finally { CloseHandle(handle); }
    }
}
