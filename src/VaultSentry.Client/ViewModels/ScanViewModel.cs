using System;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using VaultSentry.Client.Models;
using VaultSentry.Client.Services;
using VaultSentry.Client.Utils;
using VaultSentry.Core.Interfaces;
using VaultSentry.Core.Models;

namespace VaultSentry.Client.ViewModels
{
    public class ScanViewModel : ViewModelBase
    {
        private readonly IEngineProcessBridge _engineBridge;
        private readonly QuarantineRepository _repository;
        private readonly FileAnalysisViewModel _fileAnalysisViewModel;

        private string _targetFilePath = string.Empty;
        private bool _isScanning;

        public FileAnalysisViewModel AnalysisViewModel => _fileAnalysisViewModel;

        public IAsyncRelayCommand RunScanCommand { get; }
        public IRelayCommand BrowseCommand { get; }

        public ScanViewModel(IEngineProcessBridge engineBridge, QuarantineRepository repository)
        {
            _engineBridge = engineBridge ?? throw new ArgumentNullException(nameof(engineBridge));
            _repository = repository ?? throw new ArgumentNullException(nameof(repository));
            _fileAnalysisViewModel = new FileAnalysisViewModel();

            RunScanCommand = new AsyncRelayCommand(ExecuteScanAsync);
            BrowseCommand = new RelayCommand(ExecuteBrowse);
        }

        public string TargetFilePath
        {
            get => _targetFilePath;
            set => SetProperty(ref _targetFilePath, value ?? string.Empty);
        }

        public bool IsScanning
        {
            get => _isScanning;
            set => SetProperty(ref _isScanning, value);
        }

        private void ExecuteBrowse()
        {
            var dialog = new OpenFileDialog
            {
                Title = "Select File for VaultSentry Analysis",
                Filter = "All Files (*.*)|*.*",
                CheckFileExists = true,
                CheckPathExists = true,
                Multiselect = false
            };

            if (dialog.ShowDialog() == true)
            {
                TargetFilePath = dialog.FileName;
            }
        }

        public async Task ExecuteScanAsync()
        {
            if (string.IsNullOrWhiteSpace(TargetFilePath))
            {
                _fileAnalysisViewModel.ErrorMessage = "Please enter or select a valid target file path.";
                return;
            }

            IsScanning = true;
            
            // Clear previous state before new scan
            _fileAnalysisViewModel.ErrorMessage = string.Empty;
            _fileAnalysisViewModel.TargetFilePath = TargetFilePath;

            try
            {
                string jsonResult = await _engineBridge.RunScanAsync(TargetFilePath);
                _fileAnalysisViewModel.PopulateFromScanResultJson(jsonResult);

                if (!string.IsNullOrEmpty(_fileAnalysisViewModel.ErrorMessage))
                {
                    return;
                }

                using var document = JsonDocument.Parse(jsonResult);
                if (!document.RootElement.TryGetProperty("status", out var status) ||
                    status.ValueKind != JsonValueKind.String ||
                    status.GetString() != "SUCCESS")
                {
                    return;
                }

                var jsonOptions = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                };
                jsonOptions.Converters.Add(new NullToEmptyStringJsonConverter());

                SecurityReport? report = JsonSerializer.Deserialize<SecurityReport>(jsonResult, jsonOptions);
                if (report is null ||
                    string.IsNullOrWhiteSpace(report.QuarantineId) ||
                    string.IsNullOrWhiteSpace(report.StagedPath) ||
                    report.Hashes is null ||
                    report.Identity is null)
                {
                    throw new InvalidOperationException("The successful scan report is missing required persistence data.");
                }

                var findings = (report.Findings ?? [])
                    .Select(finding => new SecurityFindingModel
                    {
                        Severity = finding.Severity,
                        Category = finding.Category,
                        Finding = finding.Finding,
                        Explanation = finding.Explanation
                    });

                try
                {
                    await _repository.RecordScanAsync(report, TargetFilePath, findings);
                }
                catch (Exception ex)
                {
                    _fileAnalysisViewModel.ErrorMessage = $"Scan completed, but the report could not be saved: {ex.Message}";
                }
            }
            catch (Exception ex)
            {
                _fileAnalysisViewModel.ErrorMessage = $"Scan report processing error: {ex.Message}";
                _fileAnalysisViewModel.Verdict = "ERROR";
                _fileAnalysisViewModel.RiskScore = 0;
            }
            finally
            {
                IsScanning = false;
            }
        }
    }
}