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

using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using AntiGoogle.Core.Model;
using AntiGoogle.Core.Safety;

namespace AntiGoogle.App;

public sealed class BoolToVisibility : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c)
        => value is true ? Visibility.Visible : Visibility.Collapsed;
    public object ConvertBack(object? value, Type t, object? p, CultureInfo c)
        => value is Visibility.Visible;
}

public sealed class InverseBoolToVisibility : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c)
        => value is true ? Visibility.Collapsed : Visibility.Visible;
    public object ConvertBack(object? value, Type t, object? p, CultureInfo c)
        => value is not Visibility.Visible;
}

public sealed class InverseBool : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c) => value is not true;
    public object ConvertBack(object? value, Type t, object? p, CultureInfo c) => value is not true;
}

/// <summary>
/// Any non-zero count becomes Visible, so empty sections disappear entirely rather than leaving
/// a stranded header. Pass ConverterParameter="invert" to show something only when the count IS
/// zero — that is how the empty-state cards are driven.
/// </summary>
public sealed class CountToVisibility : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c)
    {
        var any = value is int i && i > 0;
        if (string.Equals(p as string, "invert", StringComparison.OrdinalIgnoreCase)) any = !any;
        return any ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type t, object? p, CultureInfo c) => Binding.DoNothing;
}

public sealed class StringToVisibility : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c)
        => string.IsNullOrWhiteSpace(value as string) ? Visibility.Collapsed : Visibility.Visible;
    public object ConvertBack(object? value, Type t, object? p, CultureInfo c) => Binding.DoNothing;
}

/// <summary>Severity drives colour everywhere — one mapping, so the UI cannot contradict itself.</summary>
public sealed class SeverityToBrush : IValueConverter
{
    public static Brush For(BreakageSeverity s) => s switch
    {
        BreakageSeverity.Severe => new SolidColorBrush(Color.FromRgb(0xFF, 0x4D, 0x4F)),
        BreakageSeverity.Notable => new SolidColorBrush(Color.FromRgb(0xFF, 0xA9, 0x40)),
        BreakageSeverity.Minor => new SolidColorBrush(Color.FromRgb(0xFF, 0xD6, 0x66)),
        _ => new SolidColorBrush(Color.FromRgb(0x52, 0xC4, 0x1A))
    };

    public object Convert(object? value, Type t, object? p, CultureInfo c)
        => value is BreakageSeverity s ? For(s) : For(BreakageSeverity.None);
    public object ConvertBack(object? value, Type t, object? p, CultureInfo c) => Binding.DoNothing;
}

public sealed class FindingLevelToBrush : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c) => value switch
    {
        FindingLevel.Blocker => new SolidColorBrush(Color.FromRgb(0xFF, 0x4D, 0x4F)),
        FindingLevel.Warning => new SolidColorBrush(Color.FromRgb(0xFF, 0xA9, 0x40)),
        _ => new SolidColorBrush(Color.FromRgb(0x4D, 0xA3, 0xFF))
    };
    public object ConvertBack(object? value, Type t, object? p, CultureInfo c) => Binding.DoNothing;
}

/// <summary>
/// Shows a page only when its index is the selected one.
///
/// Replaces what used to be a TabControl with a stripped template. That template removed the
/// TabPanel and, with it, the automation tree for everything inside — screen readers could not
/// see a single control on any page. Plain Visibility keeps the automation tree intact, and
/// Collapsed elements are correctly excluded from it.
/// </summary>
public sealed class IndexToVisibility : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c)
    {
        var selected = value as int? ?? -1;
        var mine = int.TryParse(p as string, NumberStyles.Integer, CultureInfo.InvariantCulture, out var i) ? i : -2;
        return selected == mine ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type t, object? p, CultureInfo c) => Binding.DoNothing;
}

/// <summary>
/// Maps a level string ("info" | "ok" | "warn" | "error") to a brush. Used by the result banner
/// and the impact verdict so a failed Apply is not rendered in the quietest style in the app.
/// </summary>
public sealed class LevelToBrush : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c) => (value as string) switch
    {
        "error" => new SolidColorBrush(Color.FromRgb(0xFF, 0x4D, 0x4F)),
        "warn" => new SolidColorBrush(Color.FromRgb(0xFF, 0xA9, 0x40)),
        "ok" => new SolidColorBrush(Color.FromRgb(0x52, 0xC4, 0x1A)),
        _ => new SolidColorBrush(Color.FromRgb(0x4D, 0xA3, 0xFF))
    };
    public object ConvertBack(object? value, Type t, object? p, CultureInfo c) => Binding.DoNothing;
}

/// <summary>Same levels, but a translucent fill for the banner background.</summary>
public sealed class LevelToFill : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c) => (value as string) switch
    {
        "error" => new SolidColorBrush(Color.FromArgb(0x26, 0xFF, 0x4D, 0x4F)),
        "warn" => new SolidColorBrush(Color.FromArgb(0x22, 0xFF, 0xA9, 0x40)),
        "ok" => new SolidColorBrush(Color.FromArgb(0x22, 0x52, 0xC4, 0x1A)),
        _ => new SolidColorBrush(Color.FromArgb(0x1E, 0x4D, 0xA3, 0xFF))
    };
    public object ConvertBack(object? value, Type t, object? p, CultureInfo c) => Binding.DoNothing;
}

/// <summary>
/// Spells out a severity as a word. The per-rule breakage list previously carried severity in
/// colour alone, which is invisible to a screen reader and to a colour-blind user.
/// </summary>
public sealed class SeverityToLabel : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c) =>
        value is BreakageSeverity s ? s.ToString().ToUpperInvariant() : "";
    public object ConvertBack(object? value, Type t, object? p, CultureInfo c) => Binding.DoNothing;
}

public sealed class FindingLevelToLabel : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c) => value switch
    {
        FindingLevel.Blocker => "BLOCKER",
        FindingLevel.Warning => "WARNING",
        _ => "INFO"
    };
    public object ConvertBack(object? value, Type t, object? p, CultureInfo c) => Binding.DoNothing;
}

public sealed class TierToBrush : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c) => value switch
    {
        // Lighter than SevSevere on purpose. The tier chip sits on Surface3, where #FF4D4F
        // measures 4.41:1 at 10px — the shipped default profile's own badge failing AA.
        // #FF8285 measures 6.02:1 and still reads unmistakably as the loud tier.
        RiskTier.Aggressive => new SolidColorBrush(Color.FromRgb(0xFF, 0x82, 0x85)),
        RiskTier.Balanced => new SolidColorBrush(Color.FromRgb(0xFF, 0xA9, 0x40)),
        _ => new SolidColorBrush(Color.FromRgb(0x52, 0xC4, 0x1A))
    };
    public object ConvertBack(object? value, Type t, object? p, CultureInfo c) => Binding.DoNothing;
}
