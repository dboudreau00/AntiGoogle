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

using System.IO;
using System.Windows;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Imaging;

// System.Windows.Shapes.Path (a UI element) and System.IO.Path (the path helper) collide in a
// WPF project. Alias the one we actually want rather than fully qualifying it a dozen times.
using IOPath = System.IO.Path;

namespace AntiGoogle.IconGen;

/// <summary>
/// Renders Logo.xaml to a multi-resolution .ico plus a set of PNGs.
///
/// Every size is rendered from the vector at its native resolution rather than downscaling one
/// large bitmap - downscaling a 256px render to 16px turns crisp edges into grey mush, which is
/// precisely the size where the icon has to work hardest.
/// </summary>
internal static class Program
{
    /// <summary>
    /// Windows picks the nearest size and scales the rest, so covering the standard rungs avoids
    /// the shell ever having to interpolate. 256 is required for the extra-large / Explorer view.
    /// </summary>
    private static readonly int[] Sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256];

    [STAThread]
    private static int Main(string[] args)
    {
        try
        {
            var repoRoot = FindRepoRoot();
            var logoXaml = IOPath.Combine(repoRoot, "src", "AntiGoogle.App", "Logo.xaml");
            var outDir = IOPath.Combine(repoRoot, "src", "AntiGoogle.App", "Assets");
            Directory.CreateDirectory(outDir);

            Console.WriteLine($"Reading  {logoXaml}");
            var dict = LoadDictionary(logoXaml);

            var canonical = Require<Geometry>(dict, "LogoGeometry");
            var smallFrame = Require<Geometry>(dict, "LogoGeometryIcon");
            var brush = dict["LogoBrush"] as Brush ?? Brushes.White;

            // Only drawn if Logo.xaml defines it. It deliberately does not: a rounded-square
            // coloured tile is Google/Material app-icon grammar, and the mark carries its own
            // padding. Left in so the option survives if that judgement is ever revisited.
            var plate = dict.Contains("LogoPlateBrush") ? dict["LogoPlateBrush"] as Brush : null;

            var pngs = new List<(int Size, byte[] Data)>();
            foreach (var size in Sizes)
            {
                // The small frames use the wider arrowhead gap so the mark's one load-bearing
                // feature lands on whole pixels instead of smearing across a boundary.
                var geometry = size <= 32 ? smallFrame : canonical;

                var png = Render(geometry, brush, plate, size);
                pngs.Add((size, png));

                var pngPath = IOPath.Combine(outDir, $"logo-{size}.png");
                File.WriteAllBytes(pngPath, png);
            }

            var icoPath = IOPath.Combine(outDir, "AntiGoogle.ico");
            WriteIco(icoPath, pngs);

            Console.WriteLine($"Wrote    {icoPath}");
            Console.WriteLine($"Wrote    {pngs.Count} PNGs to {outDir}");
            Console.WriteLine($"Sizes    {string.Join(", ", Sizes)}");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"FAILED: {ex.Message}");
            return 1;
        }
    }

    private static ResourceDictionary LoadDictionary(string path)
    {
        if (!File.Exists(path)) throw new FileNotFoundException($"Logo definition not found at {path}");
        using var stream = File.OpenRead(path);
        return (ResourceDictionary)XamlReader.Load(stream);
    }

    private static T Require<T>(ResourceDictionary dict, string key) where T : class
    {
        if (dict[key] is not T value)
            throw new InvalidOperationException($"Logo.xaml is missing a {typeof(T).Name} with x:Key=\"{key}\".");
        return value;
    }

    /// <summary>
    /// Draws the mark centred in a square of the requested pixel size. The geometry is authored on
    /// a 64x64 viewbox; it is scaled to fit with a small margin so the mark never touches the edge.
    /// </summary>
    private static byte[] Render(Geometry geometry, Brush brush, Brush? plate, int size)
    {
        const double Authored = 64.0;

        // Proportionally more breathing room at large sizes; at 16px every pixel counts, so the
        // mark is allowed to run closer to the edge.
        var marginFraction = size <= 24 ? 0.04 : 0.10;
        var inset = size * marginFraction;
        var available = size - (inset * 2);
        var scale = available / Authored;

        var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen())
        {
            if (plate is not null)
            {
                var radius = size * 0.22;
                dc.DrawRoundedRectangle(plate, null, new Rect(0, 0, size, size), radius, radius);
            }

            dc.PushTransform(new TranslateTransform(inset, inset));
            dc.PushTransform(new ScaleTransform(scale, scale));
            dc.DrawGeometry(brush, null, geometry);
            dc.Pop();
            dc.Pop();
        }

        var bmp = new RenderTargetBitmap(size, size, 96, 96, PixelFormats.Pbgra32);
        bmp.Render(visual);

        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bmp));

        using var ms = new MemoryStream();
        encoder.Save(ms);
        return ms.ToArray();
    }

    /// <summary>
    /// Packs PNG payloads into an .ico. PNG-compressed entries are supported by Windows Vista and
    /// later at every size, so there is no need for the legacy BMP+AND-mask encoding.
    /// </summary>
    private static void WriteIco(string path, IReadOnlyList<(int Size, byte[] Data)> images)
    {
        using var fs = File.Create(path);
        using var w = new BinaryWriter(fs);

        // ICONDIR
        w.Write((ushort)0);                  // reserved
        w.Write((ushort)1);                  // type: 1 = icon
        w.Write((ushort)images.Count);

        // ICONDIRENTRY is 16 bytes; image data starts after the directory.
        var offset = 6 + (16 * images.Count);

        foreach (var (size, data) in images)
        {
            w.Write((byte)(size >= 256 ? 0 : size));   // 0 means 256
            w.Write((byte)(size >= 256 ? 0 : size));
            w.Write((byte)0);                // palette count (0 = no palette)
            w.Write((byte)0);                // reserved
            w.Write((ushort)1);              // colour planes
            w.Write((ushort)32);             // bits per pixel
            w.Write(data.Length);
            w.Write(offset);
            offset += data.Length;
        }

        foreach (var (_, data) in images) w.Write(data);
    }

    /// <summary>Walks up from the executable until it finds the solution, so the tool works from any cwd.</summary>
    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(IOPath.Combine(dir.FullName, "AntiGoogle.sln"))) return dir.FullName;
            dir = dir.Parent;
        }
        throw new InvalidOperationException("Could not locate AntiGoogle.sln above the tool's output directory.");
    }
}
