using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using VaultSentry.Client.Models;
using VaultSentry.Client.Services;
using VaultSentry.Client.Utils;
using VaultSentry.Core.Interfaces;

namespace VaultSentry.Client.ViewModels;

public sealed record GuidedDemoStage(string Number, string Title, string Detail, string Status);

public sealed class DownloadSimulationViewModel : ViewModelBase
{
    private readonly IEngineProcessBridge _engineBridge;
    private readonly QuarantineRepository _repository;
    private readonly QuarantineReleaseService _releaseService;
    private readonly QuarantineDownloadService _downloadService;
    private readonly string _simulationInbox;
    private readonly string _guidedDemoSamplePath;
    private string _sourceUrl = string.Empty;
    private string _sampleFilePath = string.Empty;
    private string _phase = "Enter an HTTPS URL or choose a local sample.";
    private string _errorMessage = string.Empty;
    private bool _isRunning;
    private bool _isDownloading;
    private bool _isProgressIndeterminate;
    private bool _isGuidedDemo;
    private bool _hasReport;
    private int _progress;
    private SecurityReport? _report;
    private PlainLanguageAssessment? _humanAssessment;
    private CancellationTokenSource? _downloadCancellation;

    public DownloadSimulationViewModel(
        IEngineProcessBridge engineBridge,
        QuarantineRepository repository,
        QuarantineReleaseService releaseService,
        QuarantineDownloadService downloadService,
        DownloadIngressOptions ingressOptions)
    {
        _engineBridge = engineBridge ?? throw new ArgumentNullException(nameof(engineBridge));
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _releaseService = releaseService ?? throw new ArgumentNullException(nameof(releaseService));
        _downloadService = downloadService ?? throw new ArgumentNullException(nameof(downloadService));
        ArgumentNullException.ThrowIfNull(ingressOptions);
        _simulationInbox = Path.Combine(ingressOptions.QuarantineStoragePath, "SimulationInbox");
        BrowserDropZonePath = ingressOptions.DropZonePath;
        _guidedDemoSamplePath = Path.Combine(
            ingressOptions.WorkspaceRoot,
            "src",
            "VaultSentry.Engine",
            "tests",
            "samples",
            "sample_spoofed_invoice.pdf");

        BrowseCommand = new RelayCommand(BrowseForSample, () => !IsRunning);
        DownloadAndScanCommand = new AsyncRelayCommand(DownloadAndScanAsync, CanDownload);
        ScanSampleCommand = new AsyncRelayCommand(ScanSampleAsync, () => !IsRunning && File.Exists(SampleFilePath));
        GuidedDemoCommand = new AsyncRelayCommand(StartGuidedDemoAsync, () => !IsRunning && !HasReport);
        CancelDownloadCommand = new RelayCommand(CancelDownload, () => IsDownloading);
        DeleteCommand = new AsyncRelayCommand(DeleteQuarantinedFileAsync, () => HasReport && !IsRunning);
        StoreCommand = new AsyncRelayCommand(ReleaseFileAsync, CanReleaseFile);
        UpdateGuidedDemoStages(0);
    }

    public IRelayCommand BrowseCommand { get; }
    public IAsyncRelayCommand DownloadAndScanCommand { get; }
    public IAsyncRelayCommand ScanSampleCommand { get; }
    public IAsyncRelayCommand GuidedDemoCommand { get; }
    public IRelayCommand CancelDownloadCommand { get; }
    public IAsyncRelayCommand DeleteCommand { get; }
    public IAsyncRelayCommand StoreCommand { get; }

    public ObservableCollection<SecurityFinding> Findings { get; } = new();
    public ObservableCollection<GuidedDemoStage> GuidedDemoStages { get; } = new();

    public bool IsGuidedDemo
    {
        get => _isGuidedDemo;
        private set => SetProperty(ref _isGuidedDemo, value);
    }

    private string _guidedDemoMessage = "Run the bundled synthetic sample through local static analysis.";
    public string GuidedDemoMessage
    {
        get => _guidedDemoMessage;
        private set => SetProperty(ref _guidedDemoMessage, value);
    }

    public string SourceUrl
    {
        get => _sourceUrl;
        set
        {
            if (SetProperty(ref _sourceUrl, value ?? string.Empty))
            {
                DownloadAndScanCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public string SampleFilePath
    {
        get => _sampleFilePath;
        private set
        {
            if (SetProperty(ref _sampleFilePath, value ?? string.Empty))
            {
                ScanSampleCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public string Phase
    {
        get => _phase;
        private set => SetProperty(ref _phase, value);
    }

    public string ErrorMessage
    {
        get => _errorMessage;
        private set => SetProperty(ref _errorMessage, value);
    }

    public bool IsRunning
    {
        get => _isRunning;
        private set
        {
            if (SetProperty(ref _isRunning, value))
            {
                DownloadAndScanCommand.NotifyCanExecuteChanged();
                ScanSampleCommand.NotifyCanExecuteChanged();
                BrowseCommand.NotifyCanExecuteChanged();
                DeleteCommand.NotifyCanExecuteChanged();
                StoreCommand.NotifyCanExecuteChanged();
                GuidedDemoCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public bool IsDownloading
    {
        get => _isDownloading;
        private set
        {
            if (SetProperty(ref _isDownloading, value))
            {
                CancelDownloadCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public bool IsProgressIndeterminate
    {
        get => _isProgressIndeterminate;
        private set => SetProperty(ref _isProgressIndeterminate, value);
    }

    public bool HasReport
    {
        get => _hasReport;
        private set
        {
            if (SetProperty(ref _hasReport, value))
            {
                OnPropertyChanged(nameof(CanStoreReport));
                DeleteCommand.NotifyCanExecuteChanged();
                StoreCommand.NotifyCanExecuteChanged();
                GuidedDemoCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public int Progress
    {
        get => _progress;
        private set => SetProperty(ref _progress, Math.Clamp(value, 0, 100));
    }

    public SecurityReport? Report
    {
        get => _report;
        private set
        {
            if (SetProperty(ref _report, value))
            {
                OnPropertyChanged(nameof(CanStoreReport));
            }
        }
    }

    public PlainLanguageAssessment? HumanAssessment
    {
        get => _humanAssessment;
        private set => SetProperty(ref _humanAssessment, value);
    }

    public bool CanStoreReport => HasReport && Report is not null;

    public string QuarantineInboxPath => _simulationInbox;

    public string BrowserDropZonePath { get; }

    private void BrowseForSample()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Choose a local sample for download simulation",
            Filter = "All Files (*.*)|*.*",
            CheckFileExists = true,
            CheckPathExists = true,
            Multiselect = false
        };

        if (dialog.ShowDialog() == true)
        {
            SampleFilePath = dialog.FileName;
            ErrorMessage = string.Empty;
            Phase = "Ready to scan local sample " + Path.GetFileName(SampleFilePath) + ".";
        }
    }

    private bool CanDownload() =>
        !IsRunning &&
        Uri.TryCreate(SourceUrl, UriKind.Absolute, out Uri? uri) &&
        uri.Scheme == Uri.UriSchemeHttps;

    private async Task StartGuidedDemoAsync()
    {
        if (!File.Exists(_guidedDemoSamplePath))
        {
            ErrorMessage = "The bundled synthetic sample is unavailable. Choose another local sample or restore the engine test samples.";
            GuidedDemoMessage = "The synthetic sample is unavailable.";
            return;
        }

        IsGuidedDemo = true;
        SampleFilePath = _guidedDemoSamplePath;
        SourceUrl = string.Empty;
        ErrorMessage = string.Empty;
        GuidedDemoMessage = "Submitting the synthetic file-type mismatch sample for static analysis only.";
        UpdateGuidedDemoStages(1);

        string samplePath = _guidedDemoSamplePath;
        await RunScanWorkflowAsync(async (sessionDirectory, progress, token) =>
        {
            Phase = "Staging the synthetic diagnostic sample in the app-managed intake folder...";
            string incomingPath = Path.Combine(sessionDirectory, Path.GetFileName(samplePath));
            await CopyWithProgressAsync(samplePath, incomingPath, progress, token);
            return (incomingPath, "VaultSentry synthetic diagnostic sample: " + samplePath);
        }, guidedDemo: true);
    }

    private async Task DownloadAndScanAsync()
    {
        if (!CanDownload())
        {
            ErrorMessage = "Enter a complete HTTPS URL.";
            return;
        }

        string sourceUrl = SourceUrl;
        await RunScanWorkflowAsync(async (sessionDirectory, progress, token) =>
        {
            Phase = "Downloading over HTTPS into the app-managed intake folder...";
            var result = await _downloadService.DownloadToQuarantineAsync(
                sourceUrl,
                sessionDirectory,
                progress,
                token);
            return (result.FilePath, sourceUrl);
        });
    }

    private async Task ScanSampleAsync()
    {
        if (!File.Exists(SampleFilePath))
        {
            ErrorMessage = "Choose an existing local sample file first.";
            return;
        }

        await RunScanWorkflowAsync(async (sessionDirectory, progress, token) =>
        {
            Phase = "Copying the selected sample into the app-managed intake folder...";
            string incomingPath = Path.Combine(sessionDirectory, Path.GetFileName(SampleFilePath));
            await CopyWithProgressAsync(SampleFilePath, incomingPath, progress, token);
            return (incomingPath, SampleFilePath);
        });
    }

    private async Task RunScanWorkflowAsync(
        Func<string, IProgress<DownloadProgress>, CancellationToken, Task<(string FilePath, string OriginalSource)>> acquireFile,
        bool guidedDemo = false)
    {
        IsGuidedDemo = guidedDemo;
        if (!guidedDemo)
        {
            GuidedDemoMessage = "Run the bundled synthetic sample through local static analysis.";
            UpdateGuidedDemoStages(0);
        }

        IsRunning = true;
        HasReport = false;
        Report = null;
        HumanAssessment = null;
        Findings.Clear();
        Progress = 0;
        IsProgressIndeterminate = false;
        ErrorMessage = string.Empty;

        string? sessionDirectory = null;
        string? incomingFile = null;
        string? stagedPath = null;
        _downloadCancellation?.Dispose();
        _downloadCancellation = new CancellationTokenSource(TimeSpan.FromMinutes(10));

        try
        {
            sessionDirectory = Path.Combine(_simulationInbox, Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(sessionDirectory);
            if (!VqsSecurityDescriptor.InitializeAndHardenDirectory(sessionDirectory))
            {
                throw new InvalidOperationException("Windows could not apply the quarantine inbox execution restriction.");
            }

            IsDownloading = true;
            IProgress<DownloadProgress> progress = new Progress<DownloadProgress>(value =>
            {
                IsProgressIndeterminate = value.TotalBytes is not > 0;
                if (value.TotalBytes is > 0)
                {
                    Progress = (int)Math.Clamp(value.BytesReceived * 100 / value.TotalBytes.Value, 0, 100);
                }
            });
            var acquiredFile = await acquireFile(
                sessionDirectory,
                progress,
                _downloadCancellation.Token);
            incomingFile = acquiredFile.FilePath;
            string originalSource = acquiredFile.OriginalSource;
            IsDownloading = false;
            IsProgressIndeterminate = false;
            Progress = 100;

            if (guidedDemo)
            {
                UpdateGuidedDemoStages(2);
                GuidedDemoMessage = "The sample is staged. VaultSentry is inspecting its file type, hashes, and applicable security signals.";
            }
            Phase = guidedDemo
                ? "Fixture staged. Running static security analysis..."
                : "Download complete. Running static security analysis...";
            string jsonResult = await _engineBridge.RunScanAsync(incomingFile);
            using JsonDocument document = JsonDocument.Parse(jsonResult);
            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                !document.RootElement.TryGetProperty("status", out JsonElement status) ||
                status.GetString() != "SUCCESS")
            {
                string message = document.RootElement.TryGetProperty("message", out JsonElement error)
                    ? error.GetString() ?? "The scan engine did not complete successfully."
                    : "The scan engine did not complete successfully.";
                throw new InvalidOperationException(message);
            }

            var jsonOptions = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            jsonOptions.Converters.Add(new NullToEmptyStringJsonConverter());
            SecurityReport? report = JsonSerializer.Deserialize<SecurityReport>(jsonResult, jsonOptions);
            if (report is null ||
                string.IsNullOrWhiteSpace(report.QuarantineId) ||
                string.IsNullOrWhiteSpace(report.StagedPath) ||
                report.Hashes is null ||
                report.Identity is null)
            {
                throw new InvalidOperationException("The successful scan report is missing required quarantine data.");
            }

            stagedPath = report.StagedPath;
            await _repository.RecordScanAsync(
                report,
                originalSource,
                report.Findings.Select(finding => new Core.Models.SecurityFindingModel
                {
                    Severity = finding.Severity,
                    Category = finding.Category,
                    Finding = finding.Finding,
                    Explanation = finding.Explanation
                }));

            Report = report;
            HumanAssessment = PlainLanguageAssessmentService.Create(
                report.Verdict,
                report.RiskScore,
                report.Identity.DetectedType,
                report.Findings.Select(finding => new Core.Models.SecurityFindingModel
                {
                    Severity = finding.Severity,
                    Category = finding.Category,
                    Finding = finding.Finding,
                    Explanation = finding.Explanation
                }),
                report.Recommendation);
            foreach (SecurityFinding finding in report.Findings)
            {
                Findings.Add(finding);
            }

            try
            {
                File.Delete(incomingFile);
                Directory.Delete(Path.GetDirectoryName(incomingFile)!);
            }
            catch (Exception cleanupException)
            {
                ErrorMessage = $"The scan was saved, but the temporary download copy could not be removed: {cleanupException.Message}";
            }

            Progress = 100;
            HasReport = true;
            Phase = $"Analysis complete: {report.Verdict} (risk {report.RiskScore}/100). Choose to delete or store the file.";
            if (guidedDemo)
            {
                UpdateGuidedDemoStages(3);
                GuidedDemoMessage = $"Analysis completed: {report.Verdict}, risk {report.RiskScore}/100, {report.FindingCount} finding(s). Review the evidence, then delete the synthetic sample.";
            }
        }
        catch (OperationCanceledException)
        {
            Phase = "Download canceled.";
            ErrorMessage = "The download was canceled. No partial file was retained.";
            string? cleanupError = CleanupFailedWorkflow(incomingFile, sessionDirectory, stagedPath);
            if (cleanupError is not null)
            {
                ErrorMessage += cleanupError;
            }

            if (guidedDemo)
            {
                GuidedDemoMessage = "The diagnostic sample operation was canceled.";
            }
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Quarantine and scan failed: {ex.Message}";
            Phase = "The file was not released.";
            string? cleanupError = CleanupFailedWorkflow(incomingFile, sessionDirectory, stagedPath);
            if (cleanupError is not null)
            {
                ErrorMessage += cleanupError;
            }

            if (guidedDemo)
            {
                GuidedDemoMessage = "The diagnostic sample operation could not continue. See the error details above.";
            }
        }
        finally
        {
            IsDownloading = false;
            IsProgressIndeterminate = false;
            _downloadCancellation?.Dispose();
            _downloadCancellation = null;
            IsRunning = false;
        }
    }

    private static string? CleanupFailedWorkflow(
        string? incomingFile,
        string? sessionDirectory,
        string? stagedPath)
    {
        var cleanupErrors = new List<string>();
        if (stagedPath is not null && File.Exists(stagedPath))
        {
            try
            {
                File.SetAttributes(stagedPath, FileAttributes.Normal);
                File.Delete(stagedPath);
            }
            catch (Exception ex)
            {
                cleanupErrors.Add($"staged quarantine file: {ex.Message}");
            }
        }

        if (sessionDirectory is not null && Directory.Exists(sessionDirectory))
        {
            try
            {
                Directory.Delete(sessionDirectory, recursive: true);
            }
            catch (Exception ex)
            {
                cleanupErrors.Add($"temporary download folder: {ex.Message}");
            }
        }
        else if (incomingFile is not null && File.Exists(incomingFile))
        {
            try
            {
                File.Delete(incomingFile);
            }
            catch (Exception ex)
            {
                cleanupErrors.Add($"temporary download file: {ex.Message}");
            }
        }

        return cleanupErrors.Count == 0
            ? null
            : $" Cleanup was incomplete ({string.Join("; ", cleanupErrors)}).";
    }

    private void UpdateGuidedDemoStages(int currentStep, bool completed = false)
    {
        string[] titles = ["Stage sample", "Analyze file", "Review findings", "Choose action"];
        string[] details =
        [
            "Copy the synthetic sample into temporary quarantine staging.",
            "Run applicable local static analysis checks.",
            "Inspect the verdict and explainable findings.",
            "Delete the flagged sample; release requires explicit confirmation."
        ];

        GuidedDemoStages.Clear();
        for (int index = 0; index < titles.Length; index++)
        {
            string status = completed || index + 1 < currentStep
                ? "Complete"
                : index + 1 == currentStep
                    ? "Current"
                    : "Upcoming";
            GuidedDemoStages.Add(new GuidedDemoStage($"0{index + 1}", titles[index], details[index], status));
        }
    }

    private void CompleteGuidedDemo()
    {
        if (!IsGuidedDemo)
        {
            return;
        }

        UpdateGuidedDemoStages(4, completed: true);
        GuidedDemoMessage = "Diagnostic sample processing is complete. The decision was recorded in the quarantine ledger.";
        IsGuidedDemo = false;
        GuidedDemoCommand.NotifyCanExecuteChanged();
    }

    private static async Task CopyWithProgressAsync(
        string sourcePath,
        string destinationPath,
        IProgress<DownloadProgress> progress,
        CancellationToken cancellationToken)
    {
        await using var source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, true);
        await using var destination = new FileStream(destinationPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, true);

        long totalBytes = source.Length;
        long copiedBytes = 0;
        byte[] buffer = new byte[65536];
        int bytesRead;
        while ((bytesRead = await source.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)) > 0)
        {
            await destination.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);
            copiedBytes += bytesRead;
            progress.Report(new DownloadProgress(copiedBytes, totalBytes));
        }

        await destination.FlushAsync(cancellationToken);
    }

    private bool CanReleaseFile() =>
        HasReport &&
        !IsRunning &&
        Report is not null &&
        File.Exists(Report.StagedPath);

    private void CancelDownload() => _downloadCancellation?.Cancel();

    private async Task ReleaseFileAsync()
    {
        if (!CanReleaseFile() || Report is null)
        {
            return;
        }

        if (Report.Verdict != "SAFE")
        {
            MessageBoxResult confirmation = MessageBox.Show(
                $"VaultSentry classified '{Report.FileName}' as {Report.Verdict} (risk {Report.RiskScore}/100).\n\nReleasing it may expose this device to harm. Release it anyway?",
                "Unsafe File Release",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);
            if (confirmation != MessageBoxResult.Yes)
            {
                return;
            }
        }

        try
        {
            string destination = await _releaseService.ReleaseAsync(
                Report.QuarantineId,
                Report.StagedPath,
                Report.FileName);
            HasReport = false;
            Phase = $"File authorized and released to Released-Files: {destination}";
            CompleteGuidedDemo();
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Could not release the file to Released-Files: {ex.Message}";
        }
    }

    private async Task DeleteQuarantinedFileAsync()
    {
        if (!HasReport || IsRunning || Report is null)
        {
            return;
        }

        MessageBoxResult confirmation = MessageBox.Show(
            $"Delete '{Report.FileName}' from quarantine?",
            "Confirm Delete",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (confirmation != MessageBoxResult.Yes)
        {
            return;
        }

        try
        {
            await QuarantineRepository.ShredFileAsync(Report.StagedPath);
            await _repository.UpdateQuarantineStatusAsync(Report.QuarantineId, "SHREDDED");
            HasReport = false;
            Phase = "Quarantined file deleted.";
            CompleteGuidedDemo();
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Could not delete the quarantined file: {ex.Message}";
        }
    }

}
