using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.Input;
using VaultSentry.Client.Services;

namespace VaultSentry.Client.ViewModels
{
    public class DashboardViewModel : ViewModelBase
    {
        private readonly QuarantineRepository _repository;
        private int _totalScans;
        private int _quarantinedThreats;
        private int _cleanFiles;

        public IAsyncRelayCommand LoadMetricsCommand { get; }

        public DashboardViewModel(QuarantineRepository repository)
        {
            _repository = repository ?? throw new ArgumentNullException(nameof(repository));
            LoadMetricsCommand = new AsyncRelayCommand(LoadMetricsAsync);
            
            // Automatically load on creation
            _ = LoadMetricsAsync();
        }

        public int TotalScans
        {
            get => _totalScans;
            set => SetProperty(ref _totalScans, value);
        }

        public int QuarantinedThreats
        {
            get => _quarantinedThreats;
            set => SetProperty(ref _quarantinedThreats, value);
        }

        public int CleanFiles
        {
            get => _cleanFiles;
            set => SetProperty(ref _cleanFiles, value);
        }

        public async Task LoadMetricsAsync()
        {
            try
            {
                var metrics = await _repository.GetDashboardMetricsAsync();
                TotalScans = metrics.TotalScans;
                QuarantinedThreats = metrics.QuarantinedCount;
                CleanFiles = metrics.CleanCount;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to load dashboard metrics: {ex.Message}");
            }
        }

        public async Task RefreshMetricsAsync() => await LoadMetricsAsync();
    }
}