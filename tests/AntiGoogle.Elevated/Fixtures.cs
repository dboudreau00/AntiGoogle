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

using AntiGoogle.Core.Platform;
using Microsoft.Win32;

namespace AntiGoogle.Elevated;

/// <summary>One synthetic Windows service that wears the name of a real Google updater service.</summary>
internal sealed record ServiceFixture(string Name, string StartType, bool Run, bool MatchesCatalog);

/// <summary>One synthetic scheduled task. RunsAppExe makes it run the fake Google app instead of cmd.exe.</summary>
internal sealed record TaskFixture(string Name, bool MatchesCatalog, bool RunsAppExe = false)
{
    public void Deconstruct(out string name, out bool matchesCatalog) => (name, matchesCatalog) = (Name, MatchesCatalog);
}

/// <summary>
/// Synthetic Google-named services, scheduled tasks and files, created on the test machine so the
/// engines have something real to mutate. Nothing here is Google software: the service binary is a
/// 20-line .NET Framework ServiceBase that does nothing, compiled on the spot with the csc.exe that
/// ships in Windows. That keeps the harness free of downloads and of any extra dependency.
/// </summary>
internal sealed class FixtureSet
{
    public static string Root { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AntiGoogleElevatedTest");

    public string Dir => Path.Combine(Root, "fixture");
    public string ServiceExe => Path.Combine(Dir, "agsvc.exe");

    /// <summary>A stand-in "Google app" for containment and local-only tests. Lives outside the Windows directory.</summary>
    public string AppExe => Path.Combine(Dir, "app", "AgFakeGoogleApp.exe");

    public string ProbeExe => Path.Combine(Dir, "probe", "agprobe.exe");

    public static readonly IReadOnlyList<ServiceFixture> Services =
    [
        // gupdate is DELAYED automatic on a real Chrome install; that is the case a naive revert loses.
        new("gupdate", "delayed-auto", Run: true, MatchesCatalog: true),
        new("gupdatem", "demand", Run: false, MatchesCatalog: true),
        new("GoogleUpdaterService999.0.0.1", "auto", Run: true, MatchesCatalog: true),
        new("GoogleUpdaterInternalService999.0.0.1", "demand", Run: false, MatchesCatalog: true),
        new("GoogleChromeElevationService", "demand", Run: false, MatchesCatalog: true),
        new("AgDecoyService", "auto", Run: true, MatchesCatalog: false)
    ];

    public static readonly IReadOnlyList<TaskFixture> Tasks =
    [
        new("GoogleUpdateTaskMachineCore{AGTEST-0001}", true),
        new("GoogleUpdateTaskMachineUA{AGTEST-0001}", true),
        new("GoogleUpdaterTaskSystem999.0.0.1{AGTEST-0001}", true),
        new("GoogleUpdaterTaskUser999.0.0.1{AGTEST-0001}", true, RunsAppExe: true),
        new("AgDecoyTask", false)
    ];

    public IEnumerable<string> ServiceNames => Services.Select(s => s.Name);
    public IEnumerable<string> TaskNames => Tasks.Select(t => t.Name);

    private readonly List<string> _log = [];

    public static async Task<FixtureSet> CreateAsync(Checks checks)
    {
        var set = new FixtureSet();
        Directory.CreateDirectory(set.Dir);
        Directory.CreateDirectory(Path.GetDirectoryName(set.AppExe)!);
        Directory.CreateDirectory(Path.GetDirectoryName(set.ProbeExe)!);

        await set.CompileAsync(ServiceSource, set.ServiceExe, "/r:System.ServiceProcess.dll").ConfigureAwait(false);
        await set.CompileAsync(ProbeSource, set.ProbeExe).ConfigureAwait(false);
        File.Copy(set.ProbeExe, set.AppExe, overwrite: true);

        foreach (var s in Services)
        {
            await Tools.ScAsync("delete", s.Name).ConfigureAwait(false); // a previous crashed run
            var create = await Tools.ScAsync("create", s.Name, "binPath=", set.ServiceExe,
                "start=", s.StartType, "DisplayName=", $"AG test {s.Name}").ConfigureAwait(false);
            if (!create.Ok) throw new InvalidOperationException($"sc create {s.Name}: {create.Combined}");
            if (s.Run)
            {
                var start = await Tools.ScAsync("start", s.Name).ConfigureAwait(false);
                if (!start.Ok) throw new InvalidOperationException($"sc start {s.Name}: {start.Combined}");
            }
        }

        // Failure actions are state a sloppy revert could disturb; give one service some.
        await Tools.ScAsync("failure", "gupdate", "reset=", "86400", "actions=", "restart/60000/restart/60000//")
                   .ConfigureAwait(false);

        foreach (var task in Tasks)
        {
            var name = task.Name;
            var action = task.RunsAppExe
                ? $"-Execute '{set.AppExe}'"
                : "-Execute 'C:\\Windows\\System32\\cmd.exe' -Argument '/c exit 0'";
            var cmd =
                $"$a = New-ScheduledTaskAction {action}; " +
                "$t = New-ScheduledTaskTrigger -Daily -At 3:00AM; " +
                $"Register-ScheduledTask -TaskName '{name}' -Action $a -Trigger $t -User 'SYSTEM' -RunLevel Highest -Force | Out-Null";
            var res = await ProcessRunner.PowerShellAsync(cmd, 90_000).ConfigureAwait(false);
            if (!res.Ok) throw new InvalidOperationException($"Register-ScheduledTask {name}: {res.Combined}");
        }

        // Let the service control manager settle so the "before" snapshot is a stable one.
        await Task.Delay(3000).ConfigureAwait(false);
        checks.Info($"fixtures ready: {Services.Count} services, {Tasks.Count} scheduled tasks, 2 executables");
        return set;
    }

    public async Task CleanupAsync()
    {
        foreach (var s in Services)
        {
            await Tools.ScAsync("stop", s.Name).ConfigureAwait(false);
            await Tools.ScAsync("delete", s.Name).ConfigureAwait(false);
        }

        foreach (var (name, _) in Tasks)
            await ProcessRunner.PowerShellAsync(
                $"Unregister-ScheduledTask -TaskName '{name}' -Confirm:$false -ErrorAction SilentlyContinue", 60_000)
                .ConfigureAwait(false);

        // A stopped service can keep its image open for a moment.
        for (var attempt = 0; attempt < 5; attempt++)
        {
            try { if (Directory.Exists(Dir)) Directory.Delete(Dir, recursive: true); break; }
            catch { await Task.Delay(1000).ConfigureAwait(false); }
        }
    }

    private async Task CompileAsync(string source, string outExe, params string[] extraArgs)
    {
        var csc = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "Microsoft.NET", "Framework64", "v4.0.30319", "csc.exe");
        if (!File.Exists(csc))
            throw new FileNotFoundException("The .NET Framework compiler (csc.exe) is missing; the fixtures cannot be built.", csc);

        var src = Path.ChangeExtension(outExe, ".cs");
        File.WriteAllText(src, source);
        var args = new List<string> { "/nologo", "/target:exe", $"/out:{outExe}" };
        args.AddRange(extraArgs);
        args.Add(src);
        var res = await ProcessRunner.RunAsync(csc, args, 120_000).ConfigureAwait(false);
        if (!res.Ok) throw new InvalidOperationException($"csc failed for {Path.GetFileName(outExe)}: {res.Combined}");
    }

    // ---------------------------------------------------------------------------------------------
    // C# 5 sources, because they are compiled by the .NET Framework csc.exe, not by this project.
    // ---------------------------------------------------------------------------------------------

    private const string ServiceSource = """
        using System.ServiceProcess;
        public class AgSvc : ServiceBase
        {
            public AgSvc() { ServiceName = "AgSvc"; }
            protected override void OnStart(string[] args) { }
            protected override void OnStop() { }
            public static void Main() { ServiceBase.Run(new AgSvc()); }
        }
        """;

    /// <summary>
    /// A socket probe. It is copied to a path the harness then contains, so the firewall rule under
    /// test applies to THIS copy and never to the listener copy the harness runs unrestricted.
    /// </summary>
    internal const string ProbeSource = """
        using System;
        using System.Diagnostics;
        using System.Net;
        using System.Net.Sockets;
        using System.Text;
        using System.Threading;

        static class P
        {
            static readonly byte[] Ping = Encoding.ASCII.GetBytes("PING");
            static readonly byte[] Pong = Encoding.ASCII.GetBytes("PONG");

            static int Main(string[] a)
            {
                try
                {
                    switch (a[0])
                    {
                        case "listen": return Listen(int.Parse(a[1]), a.Length > 2 ? int.Parse(a[2]) : 60);
                        case "connect": return Connect(a[1], int.Parse(a[2]), a.Length > 3 ? int.Parse(a[3]) : 3000);
                        case "resolve": return Resolve(a[1]);
                    }
                }
                catch (Exception ex) { Console.WriteLine("EXC " + ex.GetType().Name + " " + ex.Message); return 3; }
                return 2;
            }

            static IPAddress Parse(string host)
            {
                IPAddress ip;
                if (IPAddress.TryParse(host, out ip)) return ip;
                return Dns.GetHostAddresses(host)[0];
            }

            static int Resolve(string host)
            {
                try { foreach (IPAddress ip in Dns.GetHostAddresses(host)) Console.WriteLine("ADDR " + ip); return 0; }
                catch (SocketException e) { Console.WriteLine("RESOLVE-FAIL " + e.SocketErrorCode); return 1; }
            }

            static void Serve(object o)
            {
                Socket s = (Socket)o;
                try
                {
                    byte[] b = new byte[64];
                    while (true) { int n = s.Receive(b); if (n <= 0) break; s.Send(Pong); }
                }
                catch (Exception) { }
                finally { try { s.Close(); } catch (Exception) { } }
            }

            static void AcceptLoop(object o)
            {
                TcpListener l = (TcpListener)o;
                while (true)
                {
                    try { Socket s = l.AcceptSocket(); ThreadPool.QueueUserWorkItem(Serve, s); }
                    catch (Exception) { return; }
                }
            }

            static int Listen(int port, int secs)
            {
                TcpListener l4 = new TcpListener(IPAddress.Any, port);
                l4.Start();
                Thread t4 = new Thread(AcceptLoop); t4.IsBackground = true; t4.Start(l4);
                try
                {
                    TcpListener l6 = new TcpListener(IPAddress.IPv6Any, port);
                    l6.Server.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, true);
                    l6.Start();
                    Thread t6 = new Thread(AcceptLoop); t6.IsBackground = true; t6.Start(l6);
                }
                catch (Exception) { }
                Console.WriteLine("LISTENING " + port);
                Thread.Sleep(secs * 1000);
                return 0;
            }

            static int Connect(string host, int port, int timeoutMs)
            {
                IPAddress ip = Parse(host);
                Socket s = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                IAsyncResult ar = s.BeginConnect(new IPEndPoint(ip, port), null, null);
                if (!ar.AsyncWaitHandle.WaitOne(timeoutMs)) { Console.WriteLine("CONNECT-TIMEOUT " + ip); return 1; }
                try { s.EndConnect(ar); }
                catch (SocketException e) { Console.WriteLine("CONNECT-FAIL " + ip + " " + e.SocketErrorCode + " " + e.ErrorCode); return 1; }
                Console.WriteLine("CONNECT-OK " + s.RemoteEndPoint);
                s.ReceiveTimeout = 2000;
                s.Send(Ping);
                byte[] b = new byte[16];
                try { int n = s.Receive(b); Console.WriteLine("ECHO-OK " + Encoding.ASCII.GetString(b, 0, n)); return 0; }
                catch (SocketException e) { Console.WriteLine("ECHO-FAIL " + e.SocketErrorCode); return 1; }
            }
        }
        """;
}

/// <summary>Small wrappers over the tools the harness uses to read the machine back.</summary>
internal static class Tools
{
    public static Task<ProcessResult> ScAsync(params string[] args) =>
        ProcessRunner.RunAsync("sc.exe", args, 60_000);

    public static Task<ProcessResult> PsAsync(string command, int timeoutMs = 90_000) =>
        ProcessRunner.PowerShellAsync(command, timeoutMs);

    /// <summary>reg.exe sees the same registry through a different code path than Microsoft.Win32.</summary>
    public static Task<ProcessResult> RegAsync(params string[] args) =>
        ProcessRunner.RunAsync("reg.exe", args, 30_000);

    public static bool IsVirtualMachine(out string description)
    {
        string manufacturer = "", product = "";
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
            manufacturer = k?.GetValue("SystemManufacturer") as string ?? "";
            product = k?.GetValue("SystemProductName") as string ?? "";
        }
        catch { /* unreadable means unknown, and unknown is not a VM */ }

        description = $"{manufacturer} / {product}".Trim(' ', '/');
        var both = (manufacturer + " " + product).ToLowerInvariant();
        return both.Contains("vmware") || both.Contains("virtualbox") || both.Contains("qemu")
            || both.Contains("kvm") || both.Contains("xen") || both.Contains("parallels")
            || both.Contains("virtual machine") || both.Contains("hyper-v");
    }
}
