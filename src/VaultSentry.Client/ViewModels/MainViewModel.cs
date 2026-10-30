using CommunityToolkit.Mvvm.Input;

namespace VaultSentry.Client.ViewModels
{
    public class MainViewModel : ViewModelBase
    {
        private ViewModelBase _currentViewModel;
        private string _currentSection = "Overview";

        public DashboardViewModel DashboardVM { get; }
        public ScanViewModel ScanVM { get; }
        public QuarantineViewModel QuarantineVM { get; }
        public DownloadSimulationViewModel DownloadSimulationVM { get; }

        public IRelayCommand NavigateToDashboardCommand { get; }
        public IRelayCommand NavigateToScanCommand { get; }
        public IRelayCommand NavigateToQuarantineCommand { get; }
        public IRelayCommand NavigateToDownloadSimulationCommand { get; }
        public IAsyncRelayCommand StartGuidedDemoCommand { get; }

        public MainViewModel(
            DashboardViewModel dashboardViewModel,
            ScanViewModel scanViewModel,
            QuarantineViewModel quarantineViewModel,
            DownloadSimulationViewModel downloadSimulationViewModel)
        {
            DashboardVM = dashboardViewModel;
            ScanVM = scanViewModel;
            QuarantineVM = quarantineViewModel;
            DownloadSimulationVM = downloadSimulationViewModel;

            // Default startup view
            _currentViewModel = DashboardVM;

            NavigateToDashboardCommand = new AsyncRelayCommand(async () => 
            {
                CurrentViewModel = DashboardVM;
                await DashboardVM.RefreshMetricsAsync();
            });

            NavigateToScanCommand = new RelayCommand(() => 
            {
                CurrentViewModel = ScanVM;
            });

            NavigateToQuarantineCommand = new AsyncRelayCommand(async () => 
            {
                CurrentViewModel = QuarantineVM;
                await QuarantineVM.LoadQuarantineDataAsync(); // CRITICAL FIX: Loads SQLite ledger on tab click
            });

            NavigateToDownloadSimulationCommand = new RelayCommand(() =>
            {
                CurrentViewModel = DownloadSimulationVM;
            });

            StartGuidedDemoCommand = new AsyncRelayCommand(async () =>
            {
                CurrentViewModel = DownloadSimulationVM;
                await DownloadSimulationVM.GuidedDemoCommand.ExecuteAsync(null);
            });

            DashboardVM.ConfigureNavigation(
                NavigateToDownloadSimulationCommand,
                NavigateToScanCommand,
                NavigateToQuarantineCommand,
                StartGuidedDemoCommand);
        }

        public ViewModelBase CurrentViewModel
        {
            get => _currentViewModel;
            set
            {
                if (SetProperty(ref _currentViewModel, value))
                {
                    CurrentSection = value switch
                    {
                        DashboardViewModel => "Overview",
                        ScanViewModel => "File analysis",
                        QuarantineViewModel => "Quarantine vault",
                        DownloadSimulationViewModel => "VQS URL ingestion",
                        _ => "VaultSentry"
                    };
                }
            }
        }

        public string CurrentSection
        {
            get => _currentSection;
            private set => SetProperty(ref _currentSection, value);
        }
    }
}