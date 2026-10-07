using System;
using System.IO;
using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;
using VaultSentry.Core.Models;
using VaultSentry.Core.Services;

namespace VaultSentry.UI
{
    public partial class MainWindow : Window
    {
        private readonly EngineBridgeService _bridgeService;
        private string? _stagedFilePath;
        private ScanReportModel? _currentReport;

        public MainWindow()
        {
            InitializeComponent();
            _bridgeService = new EngineBridgeService();
        }

        private void BtnBrowse_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog
            {
                Title = "Select File for VaultSentry Quarantine Staging",
                Filter = "All Files (*.*)|*.*"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                StageFile(openFileDialog.FileName);
            }
        }

        private void FileDropZone_Drop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (files.Length > 0)
                {
                    StageFile(files[0]);
                }
            }
        }

        private void StageFile(string filePath)
        {
            _stagedFilePath = filePath;
            TxtSelectedFile.Text = Path.GetFileName(filePath);
            TxtFilePath.Text = filePath;
            BtnStartScan.IsEnabled = true;
            TxtStatus.Text = "File staged in Virtual Quarantine Space. Ready to scan.";
            
            // Reset report panels
            PnlAssessment.Visibility = Visibility.Hidden;
            PnlFindings.Visibility = Visibility.Hidden;
            DisableActionButtons();
        }

        private async void BtnStartScan_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_stagedFilePath)) return;

            BtnStartScan.IsEnabled = false;
            TxtStatus.Text = "Executing multi-layer static scanning engine...";

            try
            {
                _currentReport = await _bridgeService.ExecuteScanAsync(_stagedFilePath);

                if (_currentReport != null)
                {
                    RenderReport(_currentReport);
                    TxtStatus.Text = "Analysis complete.";
                }
                else
                {
                    TxtStatus.Text = "Scan failed: Engine returned empty response.";
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Engine Bridge Error: {ex.Message}", "VaultSentry Scan Failure", MessageBoxButton.OK, MessageBoxImage.Error);
                TxtStatus.Text = "Scan execution error.";
            }
            finally
            {
                BtnStartScan.IsEnabled = true;
            }
        }

        private void RenderReport(ScanReportModel report)
        {
            PnlAssessment.Visibility = Visibility.Visible;
            PnlFindings.Visibility = Visibility.Visible;

            // Render Score and Verdict
            int score = report.Assessment.RiskScore;
            TxtRiskScore.Text = $"{score} / 100";
            PbRiskScore.Value = score;
            TxtVerdict.Text = report.Assessment.Verdict;
            TxtRecommendation.Text = report.Assessment.Recommendation;

            // Verdict Styling
            if (score < 20)
            {
                BdrVerdict.Background = new SolidColorBrush(Color.FromRgb(34, 197, 94)); // Green
                PbRiskScore.Foreground = new SolidColorBrush(Color.FromRgb(34, 197, 94));
            }
            else if (score < 55)
            {
                BdrVerdict.Background = new SolidColorBrush(Color.FromRgb(234, 179, 8)); // Yellow
                PbRiskScore.Foreground = new SolidColorBrush(Color.FromRgb(234, 179, 8));
            }
            else
            {
                BdrVerdict.Background = new SolidColorBrush(Color.FromRgb(220, 38, 38)); // Red
                PbRiskScore.Foreground = new SolidColorBrush(Color.FromRgb(220, 38, 38));
            }

            // Render Findings List
            LvFindings.ItemsSource = report.Assessment.Findings;

            // Enable Action Controls
            BtnDelete.IsEnabled = true;
            BtnKeepQuarantine.IsEnabled = true;
            BtnMoveStorage.IsEnabled = true;
        }

        private void BtnMoveStorage_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_stagedFilePath) || !File.Exists(_stagedFilePath)) return;

            var saveFileDialog = new SaveFileDialog
            {
                Title = "Select Destination to Move Verified File",
                FileName = Path.GetFileName(_stagedFilePath)
            };

            if (saveFileDialog.ShowDialog() == true)
            {
                try
                {
                    File.Move(_stagedFilePath, saveFileDialog.FileName, overwrite: true);
                    MessageBox.Show("File successfully moved to local storage.", "VaultSentry File Release", MessageBoxButton.OK, MessageBoxImage.Information);
                    ResetUI();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to move file: {ex.Message}", "File Move Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void BtnKeepQuarantine_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("File retained safely inside Virtual Quarantine Space.", "VaultSentry Quarantine", MessageBoxButton.OK, MessageBoxImage.Information);
            ResetUI();
        }

        private void BtnDelete_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_stagedFilePath) || !File.Exists(_stagedFilePath)) return;

            var confirm = MessageBox.Show("Are you sure you want to permanently delete this file?", "Confirm Purge", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (confirm == MessageBoxResult.Yes)
            {
                try
                {
                    File.Delete(_stagedFilePath);
                    MessageBox.Show("File permanently purged from disk.", "Purge Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                    ResetUI();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to delete file: {ex.Message}", "Delete Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void DisableActionButtons()
        {
            BtnDelete.IsEnabled = false;
            BtnKeepQuarantine.IsEnabled = false;
            BtnMoveStorage.IsEnabled = false;
        }

        private void ResetUI()
        {
            _stagedFilePath = null;
            _currentReport = null;
            TxtSelectedFile.Text = "Drag & Drop Downloaded File Here, or Click Browse";
            TxtFilePath.Text = "No file staged for scanning.";
            PnlAssessment.Visibility = Visibility.Hidden;
            PnlFindings.Visibility = Visibility.Hidden;
            BtnStartScan.IsEnabled = false;
            DisableActionButtons();
            TxtStatus.Text = "Ready.";
        }
    }
}