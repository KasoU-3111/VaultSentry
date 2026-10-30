using System;
using System.IO;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;

namespace VaultSentry.Client.Views;

public partial class DashboardView : UserControl
{
    public DashboardView()
    {
        InitializeComponent();
        Unloaded += DashboardView_OnUnloaded;
    }

    private bool _isPreviewLoading;
    private bool _isPreviewPlaying;
    private bool _previewLoadFailed;

    private void WorkflowPreviewButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (_isPreviewLoading)
        {
            return;
        }

        if (WorkflowPreviewMedia.Source is null || _previewLoadFailed)
        {
            string videoPath = Path.Combine(AppContext.BaseDirectory, "assets", "video-rep.mp4");
            if (!File.Exists(videoPath))
            {
                WorkflowPreviewStatus.Text = "The workflow preview video is missing from the application assets.";
                return;
            }

            _previewLoadFailed = false;
            _isPreviewLoading = true;
            WorkflowPreviewButton.Content = "Loading preview...";
            AutomationProperties.SetName(WorkflowPreviewButton, "Loading VQS workflow preview");
            WorkflowPreviewStatus.Text = "Loading the illustrative workflow preview...";
            WorkflowPreviewMedia.Visibility = Visibility.Visible;
            WorkflowPreviewMedia.LoadedBehavior = MediaState.Play;
            WorkflowPreviewMedia.Source = new Uri(videoPath, UriKind.Absolute);
            return;
        }

        if (_isPreviewPlaying)
        {
            WorkflowPreviewMedia.Pause();
            _isPreviewPlaying = false;
            WorkflowPreviewButton.Content = "Resume preview";
            AutomationProperties.SetName(WorkflowPreviewButton, "Resume VQS workflow preview");
            WorkflowPreviewStatus.Text = "Preview paused. The animation is illustrative, not live scan telemetry.";
            return;
        }

        WorkflowPreviewMedia.Play();
        _isPreviewPlaying = true;
        WorkflowPreviewButton.Content = "Pause preview";
        AutomationProperties.SetName(WorkflowPreviewButton, "Pause VQS workflow preview");
        WorkflowPreviewStatus.Text = "Illustrative workflow animation — not live scan telemetry.";
    }

    private void WorkflowPreviewMedia_OnMediaOpened(object sender, RoutedEventArgs e)
    {
        _isPreviewLoading = false;
        WorkflowPreviewMedia.LoadedBehavior = MediaState.Manual;
        WorkflowPreviewMedia.Visibility = Visibility.Visible;
        WorkflowPreviewPlaceholder.Visibility = Visibility.Collapsed;
        WorkflowPreviewMedia.Play();
        _isPreviewPlaying = true;
        WorkflowPreviewButton.Content = "Pause preview";
        AutomationProperties.SetName(WorkflowPreviewButton, "Pause VQS workflow preview");
        WorkflowPreviewStatus.Text = "Illustrative workflow animation — not live scan telemetry.";
    }

    private void WorkflowPreviewMedia_OnMediaEnded(object sender, RoutedEventArgs e)
    {
        if (!_isPreviewPlaying)
        {
            return;
        }

        WorkflowPreviewMedia.Position = TimeSpan.Zero;
        WorkflowPreviewMedia.Play();
        WorkflowPreviewStatus.Text = "Looping illustrative workflow animation — not live scan telemetry.";
    }

    private void WorkflowPreviewMedia_OnMediaFailed(object sender, ExceptionRoutedEventArgs e)
    {
        _isPreviewLoading = false;
        _isPreviewPlaying = false;
        _previewLoadFailed = true;
        WorkflowPreviewMedia.Visibility = Visibility.Collapsed;
        WorkflowPreviewPlaceholder.Visibility = Visibility.Visible;
        WorkflowPreviewButton.Content = "Retry preview";
        AutomationProperties.SetName(WorkflowPreviewButton, "Retry VQS workflow preview");
        WorkflowPreviewStatus.Text = $"Windows could not play the preview video: {e.ErrorException.Message}";
    }

    private void DashboardView_OnUnloaded(object sender, RoutedEventArgs e)
    {
        if (!_isPreviewLoading && WorkflowPreviewMedia.Source is null)
        {
            return;
        }

        WorkflowPreviewMedia.Stop();
        WorkflowPreviewMedia.Source = null;
        WorkflowPreviewMedia.Visibility = Visibility.Collapsed;
        WorkflowPreviewPlaceholder.Visibility = Visibility.Visible;
        WorkflowPreviewButton.Content = "Play 5-second preview";
        AutomationProperties.SetName(WorkflowPreviewButton, "Play 5-second VQS workflow preview");
        WorkflowPreviewStatus.Text = "Illustrative animation, not live scan telemetry. Actual findings appear in the scan report; deletion is not guaranteed secure erasure.";
        _isPreviewLoading = false;
        _isPreviewPlaying = false;
        _previewLoadFailed = false;
    }
}