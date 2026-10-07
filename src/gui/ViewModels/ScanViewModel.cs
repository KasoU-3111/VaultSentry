using System;
using System.IO;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using VaultSentry.Client.Models;
using VaultSentry.Client.Services;
using VaultSentry.Client.Services.Interfaces;

namespace VaultSentry.Client.ViewModels;

public partial class ScanViewModel : ViewModelBase
{
    private readonly IEngineProcessBridge _engineBridge;
    private readonly QuarantineRepository _repository;

    [ObservableProperty]
    private string _targetFilePath = string.Empty;

    [ObservableProperty]
    private bool _isScanning;

    [ObservableProperty]
    private string? _errorMessage;

    [ObservableProperty]
    private string? _actionMessage;

    [ObservableProperty]
    private SecurityReport? _scanResult;

    public ScanViewModel(IEngineProcessBridge engineBridge, QuarantineRepository repository)
    {
        _engineBridge = engineBridge;
        _repository = repository;
    }

    [RelayCommand]
    private void BrowseFile()
    {
        var openFileDialog = new OpenFileDialog
        {
            Title = "Select File for VaultSentry Quarantine & Analysis",
            Filter = "All Files (*.*)|*.*"
        };

        if (openFileDialog.ShowDialog() == true)
        {
            TargetFilePath = openFileDialog.FileName;
            ErrorMessage = null;
            ActionMessage = null;
        }
    }

    [RelayCommand]
    private async Task RunScanAsync()
    {
        if (string.IsNullOrWhiteSpace(TargetFilePath) || !File.Exists(TargetFilePath))
        {
            ErrorMessage = "Please specify a valid, existing file path for analysis.";
            ScanResult = null;
            return;
        }

        IsScanning = true;
        ErrorMessage = null;
        ActionMessage = null;
        ScanResult = null;

        try
        {
            ScanResult = await _engineBridge.ScanFileAsync(TargetFilePath);
            if (ScanResult == null || ScanResult.Status == "ERROR")
            {
                ErrorMessage = "The analysis engine returned an empty or error state report.";
            }
            else
            {
                // Persist scan history to SQLite database
                await _repository.RecordScanAsync(ScanResult, TargetFilePath);
            }
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Scan Execution Error: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
        }
    }

    [RelayCommand]
    private async Task ShredPayloadAsync()
    {
        if (ScanResult == null || string.IsNullOrWhiteSpace(ScanResult.StagedPath)) return;

        try
        {
            await QuarantineRepository.ShredFileAsync(ScanResult.StagedPath);
            ActionMessage = "File successfully destroyed via cryptographic pseudo-random shredding.";
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Shredding failed: {ex.Message}";
        }
    }
}