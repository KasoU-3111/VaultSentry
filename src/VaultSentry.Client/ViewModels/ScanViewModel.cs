using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using VaultSentry.Client.Services;
using VaultSentry.Core.Interfaces;

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
            }
            catch (Exception ex)
            {
                // Push IPC dispatch errors into the unified dashboard state
                _fileAnalysisViewModel.ErrorMessage = $"IPC Dispatch Error: {ex.Message}";
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