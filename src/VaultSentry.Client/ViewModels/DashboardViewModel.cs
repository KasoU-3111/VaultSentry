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
        private bool _isRefreshing;
        private string _refreshMessage = string.Empty;
        private string _refreshError = string.Empty;

        public IAsyncRelayCommand LoadMetricsCommand { get; }
        public IRelayCommand OpenSecureIntakeCommand { get; private set; } = null!;
        public IRelayCommand OpenAnalysisCommand { get; private set; } = null!;
        public IRelayCommand OpenQuarantineCommand { get; private set; } = null!;
        public IAsyncRelayCommand StartGuidedDemoCommand { get; private set; } = null!;
        public string DropZonePath { get; }

        public DashboardViewModel(QuarantineRepository repository, DownloadIngressOptions ingressOptions)
        {
            _repository = repository ?? throw new ArgumentNullException(nameof(repository));
            DropZonePath = ingressOptions.DropZonePath;
            LoadMetricsCommand = new AsyncRelayCommand(LoadMetricsAsync);
            
            // Automatically load on creation
            _ = LoadMetricsAsync();
        }

        public void ConfigureNavigation(
            IRelayCommand openSecureIntakeCommand,
            IRelayCommand openAnalysisCommand,
            IRelayCommand openQuarantineCommand,
            IAsyncRelayCommand startGuidedDemoCommand)
        {
            OpenSecureIntakeCommand = openSecureIntakeCommand ?? throw new ArgumentNullException(nameof(openSecureIntakeCommand));
            OpenAnalysisCommand = openAnalysisCommand ?? throw new ArgumentNullException(nameof(openAnalysisCommand));
            OpenQuarantineCommand = openQuarantineCommand ?? throw new ArgumentNullException(nameof(openQuarantineCommand));
            StartGuidedDemoCommand = startGuidedDemoCommand ?? throw new ArgumentNullException(nameof(startGuidedDemoCommand));
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

        public bool IsRefreshing
        {
            get => _isRefreshing;
            private set => SetProperty(ref _isRefreshing, value);
        }

        public string RefreshMessage
        {
            get => _refreshMessage;
            private set => SetProperty(ref _refreshMessage, value);
        }

        public string RefreshError
        {
            get => _refreshError;
            private set => SetProperty(ref _refreshError, value);
        }

        public async Task LoadMetricsAsync()
        {
            IsRefreshing = true;
            RefreshMessage = string.Empty;
            RefreshError = string.Empty;

            try
            {
                var metrics = await _repository.GetDashboardMetricsAsync();
                TotalScans = metrics.TotalScans;
                QuarantinedThreats = metrics.QuarantinedCount;
                CleanFiles = metrics.CleanCount;
                RefreshMessage = $"Metrics refreshed at {DateTime.Now:T}.";
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to load dashboard metrics: {ex.Message}");
                RefreshError = $"Could not refresh dashboard metrics: {ex.Message}";
            }
            finally
            {
                IsRefreshing = false;
            }
        }

        public async Task RefreshMetricsAsync() => await LoadMetricsAsync();
    }
}