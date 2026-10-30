using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using CommunityToolkit.Mvvm.Input;
using VaultSentry.Client.Services;

namespace VaultSentry.Client.ViewModels
{
    /// <summary>
    /// State manager for the Quarantine Vault. 
    /// Handles the lifecycle of quarantined files (review, release, and deletion).
    /// </summary>
    public class QuarantineViewModel : ViewModelBase
    {
        private readonly QuarantineRepository _repository;
        private readonly QuarantineReleaseService _releaseService;
        private bool _isLoading;
        private bool _hasItems;
        private string _errorMessage = string.Empty;

        public ObservableCollection<QuarantineItem> QuarantinedItems { get; } = new();

        public IAsyncRelayCommand LoadItemsCommand { get; }
        public IAsyncRelayCommand<QuarantineItem> ReleaseFileCommand { get; }
        public IAsyncRelayCommand<QuarantineItem> ShredFileCommand { get; }

        public QuarantineViewModel(
            QuarantineRepository repository,
            QuarantineReleaseService releaseService)
        {
            _repository = repository ?? throw new ArgumentNullException(nameof(repository));
            _releaseService = releaseService ?? throw new ArgumentNullException(nameof(releaseService));

            LoadItemsCommand = new AsyncRelayCommand(LoadItemsAsync);
            ReleaseFileCommand = new AsyncRelayCommand<QuarantineItem>(ReleaseFileAsync, CanReleaseFile);
            ShredFileCommand = new AsyncRelayCommand<QuarantineItem>(ShredFileAsync, CanShredFile);
        }

        public bool IsLoading
        {
            get => _isLoading;
            set => SetProperty(ref _isLoading, value);
        }

        public bool HasItems
        {
            get => _hasItems;
            private set => SetProperty(ref _hasItems, value);
        }

        public string ErrorMessage
        {
            get => _errorMessage;
            private set => SetProperty(ref _errorMessage, value);
        }

        public async Task LoadItemsAsync()
        {
            IsLoading = true;
            ErrorMessage = string.Empty;
            try
            {
                QuarantinedItems.Clear();
                var items = await _repository.GetQuarantinedItemsAsync();
                
                foreach (var item in items)
                {
                    QuarantinedItems.Add(item);
                }

                HasItems = QuarantinedItems.Count > 0;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to load quarantine ledger: {ex.Message}");
                ErrorMessage = $"Could not load the quarantine vault: {ex.Message}";
            }
            finally
            {
                IsLoading = false;
            }
        }

        /// <summary>
        /// Adapter alias method to satisfy MainViewModel navigation hooks (Resolves CS1061).
        /// </summary>
        public async Task LoadQuarantineDataAsync()
        {
            await LoadItemsAsync();
        }

        private static bool CanReleaseFile(QuarantineItem? item) =>
            item is { Status: "STAGED" or "QUARANTINED", Verdict: "SAFE" or "SUSPICIOUS" or "MALICIOUS" }
            && File.Exists(item.StagedPath);

        private static bool CanShredFile(QuarantineItem? item) =>
            item is { Status: "STAGED" or "QUARANTINED" };

        private async Task ReleaseFileAsync(QuarantineItem? item)
        {
            if (item is null || !CanReleaseFile(item)) return;

            if (item.Verdict != "SAFE")
            {
                MessageBoxResult confirmation = MessageBox.Show(
                    $"VaultSentry classified '{Path.GetFileName(item.OriginalPath)}' as {item.Verdict}.\n\nReleasing it may expose this device to harm. Release it anyway?",
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
                if (!File.Exists(item.StagedPath))
                {
                    throw new FileNotFoundException("The staged safe file is no longer present.", item.StagedPath);
                }

                string destinationPath = await _releaseService.ReleaseAsync(
                    item.QuarantineId,
                    item.StagedPath,
                    Path.GetFileName(item.OriginalPath));
                ErrorMessage = string.Empty;
                System.Diagnostics.Debug.WriteLine($"Released '{item.QuarantineId}' to '{destinationPath}'.");
                await LoadItemsAsync();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to release file {item.QuarantineId}: {ex.Message}");
                ErrorMessage = $"Could not release '{Path.GetFileName(item.OriginalPath)}': {ex.Message}";
            }
        }

        private async Task ShredFileAsync(QuarantineItem? item)
        {
            if (item is null || item.Status is "SHREDDED" or "RELEASED")
            {
                return;
            }

            string stagedFileName = Path.GetFileName(item.StagedPath);
            MessageBoxResult confirmation = MessageBox.Show(
                File.Exists(item.StagedPath)
                    ? $"Delete '{Path.GetFileName(item.OriginalPath)}' from quarantine?"
                    : $"The quarantined file '{stagedFileName}' is already missing. Mark its ledger record as deleted?",
                "Delete from Quarantine",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);
            if (confirmation != MessageBoxResult.Yes)
            {
                return;
            }

            try
            {
                await QuarantineRepository.ShredFileAsync(item.StagedPath);
                await _repository.UpdateQuarantineStatusAsync(item.QuarantineId, "SHREDDED");
                ErrorMessage = string.Empty;
                await LoadItemsAsync();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to delete quarantined file {item.QuarantineId}: {ex.Message}");
                ErrorMessage = $"Could not delete '{Path.GetFileName(item.OriginalPath)}': {ex.Message}";
            }
        }
    }
}