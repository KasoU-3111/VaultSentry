using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.Input;
using VaultSentry.Client.Services;

namespace VaultSentry.Client.ViewModels
{
    /// <summary>
    /// State manager for the Quarantine Vault. 
    /// Handles the lifecycle of isolated files (Review, Release, Cryptographic Shred).
    /// </summary>
    public class QuarantineViewModel : ViewModelBase
    {
        private readonly QuarantineRepository _repository;
        private bool _isLoading;

        public ObservableCollection<QuarantineItem> QuarantinedItems { get; } = new();

        public IAsyncRelayCommand LoadItemsCommand { get; }
        public IAsyncRelayCommand<QuarantineItem> ReleaseFileCommand { get; }
        public IAsyncRelayCommand<QuarantineItem> ShredFileCommand { get; }

        public QuarantineViewModel(QuarantineRepository repository)
        {
            _repository = repository ?? throw new ArgumentNullException(nameof(repository));

            LoadItemsCommand = new AsyncRelayCommand(LoadItemsAsync);
            ReleaseFileCommand = new AsyncRelayCommand<QuarantineItem>(ReleaseFileAsync);
            ShredFileCommand = new AsyncRelayCommand<QuarantineItem>(ShredFileAsync);
        }

        public bool IsLoading
        {
            get => _isLoading;
            set => SetProperty(ref _isLoading, value);
        }

        public async Task LoadItemsAsync()
        {
            IsLoading = true;
            try
            {
                QuarantinedItems.Clear();
                var items = await _repository.GetQuarantinedItemsAsync();
                
                foreach (var item in items)
                {
                    QuarantinedItems.Add(item);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to load quarantine ledger: {ex.Message}");
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

        private async Task ReleaseFileAsync(QuarantineItem? item)
        {
            if (item == null || (item.Status != "QUARANTINED" && item.Status != "STAGED")) return;

            try
            {
                if (File.Exists(item.StagedPath))
                {
                    string userDownloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
                    string safeFileName = Path.GetFileName(item.OriginalPath);
                    string destinationPath = Path.Combine(userDownloads, safeFileName);

                    int counter = 1;
                    while (File.Exists(destinationPath))
                    {
                        string name = Path.GetFileNameWithoutExtension(safeFileName);
                        string ext = Path.GetExtension(safeFileName);
                        destinationPath = Path.Combine(userDownloads, $"{name} ({counter}){ext}");
                        counter++;
                    }

                    File.Move(item.StagedPath, destinationPath);
                }

                await _repository.UpdateQuarantineStatusAsync(item.QuarantineId, "RELEASED");
                await LoadItemsAsync();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to release file {item.QuarantineId}: {ex.Message}");
            }
        }

        private async Task ShredFileAsync(QuarantineItem? item)
        {
            if (item == null || item.Status == "SHREDDED") return;

            try
            {
                await QuarantineRepository.ShredFileAsync(item.StagedPath);
                await _repository.UpdateQuarantineStatusAsync(item.QuarantineId, "SHREDDED");
                await LoadItemsAsync();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to shred file {item.QuarantineId}: {ex.Message}");
            }
        }
    }
}