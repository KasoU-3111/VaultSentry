using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace VaultSentry.Client.Converters;

public class NullToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value != null ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotImplementedException();
}

public class StringToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        (value is string s && !string.IsNullOrWhiteSpace(s)) ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotImplementedException();
}

public class BooleanToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        (value is bool b && b) ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotImplementedException();
}

public class BooleanToInverseVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        (value is bool b && b) ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotImplementedException();
}

public class SeverityToBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        string severity = value?.ToString()?.ToUpperInvariant() ?? "INFO";
        return severity switch
        {
            "CRITICAL" or "MALICIOUS" => new SolidColorBrush(Color.FromRgb(239, 68, 68)),   // Red
            "HIGH" or "SUSPICIOUS"    => new SolidColorBrush(Color.FromRgb(245, 158, 11)),  // Amber
            "MEDIUM"                  => new SolidColorBrush(Color.FromRgb(234, 179, 8)),   // Yellow
            "SAFE" or "LOW"           => new SolidColorBrush(Color.FromRgb(16, 185, 129)),  // Green
            _                         => new SolidColorBrush(Color.FromRgb(59, 130, 246))   // Blue
        };
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotImplementedException();
}