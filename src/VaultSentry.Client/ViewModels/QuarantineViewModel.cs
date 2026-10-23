using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using VaultSentry.Client.Models;
using VaultSentry.Client.Services;

namespace VaultSentry.Client.ViewModels;

public partial class QuarantineViewModel : ViewModelBase
{
    private readonly QuarantineRepository _repository;

    [ObservableProperty]
    private ObservableCollection<QuarantineItem> _quarantinedItems = new();

    [ObservableProperty]
    private QuarantineItem? _selectedItem;

    [ObservableProperty]
    private string? _statusMessage;

    [ObservableProperty]
    private bool _isLoading;

    public QuarantineViewModel(QuarantineRepository repository)
    {
        _repository = repository;
        // Eagerly populate quarantine audit ledger from SQLite on creation
        _ = LoadQuarantineDataAsync();
    }

    [RelayCommand]
    public async Task LoadQuarantineDataAsync()
    {
        IsLoading = true;
        try
        {
            var items = await _repository.GetQuarantinedItemsAsync();
            QuarantinedItems.Clear();
            foreach (var item in items)
            {
                QuarantinedItems.Add(item);
            }
            if (QuarantinedItems.Count == 0)
            {
                StatusMessage = "No quarantined files currently in the isolation vault.";
            }
            else
            {
                StatusMessage = $"Loaded {QuarantinedItems.Count} quarantine record(s).";
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Ledger Read Error: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    private async Task ShredSelectedPayloadAsync()
    {
        if (SelectedItem == null)
        {
            StatusMessage = "Please select a quarantined item from the list to shred.";
            return;
        }

        try
        {
            await QuarantineRepository.ShredFileAsync(SelectedItem.StagedPath);
            await _repository.UpdateQuarantineStatusAsync(SelectedItem.QuarantineId, "SHREDDED");
            StatusMessage = $"Payload '{Path.GetFileName(SelectedItem.OriginalPath)}' securely destroyed via 3-Pass DoD wipe.";
            await LoadQuarantineDataAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Disposal Error: {ex.Message}";
        }
    }

    [RelayCommand]
    private async Task ReleaseSelectedFileAsync()
    {
        if (SelectedItem == null)
        {
            StatusMessage = "Please select an item from the list to release.";
            return;
        }

        if (!File.Exists(SelectedItem.StagedPath))
        {
            StatusMessage = "Cannot release: Staged payload does not exist or was already shredded.";
            return;
        }

        var saveDialog = new SaveFileDialog
        {
            Title = "Select Destination for Released File",
            FileName = Path.GetFileName(SelectedItem.OriginalPath)
        };

        if (saveDialog.ShowDialog() == true)
        {
            try
            {
                File.SetAttributes(SelectedItem.StagedPath, FileAttributes.Normal);
                File.Copy(SelectedItem.StagedPath, saveDialog.FileName, overwrite: true);
                await _repository.UpdateQuarantineStatusAsync(SelectedItem.QuarantineId, "RELEASED");
                StatusMessage = $"File successfully released to: {saveDialog.FileName}";
                await LoadQuarantineDataAsync();
            }
            catch (Exception ex)
            {
                StatusMessage = $"Release Error: {ex.Message}";
            }
        }
    }
}