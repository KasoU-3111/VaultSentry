using System.Threading.Tasks;
using CommunityToolkit.Mvvm.Input;
using VaultSentry.Client.Services;

namespace VaultSentry.Client.ViewModels
{
    public class MainViewModel : ViewModelBase
    {
        private readonly QuarantineRepository _repository;
        private ViewModelBase _currentViewModel;

        public DashboardViewModel DashboardVM { get; }
        public ScanViewModel ScanVM { get; }
        public QuarantineViewModel QuarantineVM { get; }

        public IRelayCommand NavigateToDashboardCommand { get; }
        public IRelayCommand NavigateToScanCommand { get; }
        public IRelayCommand NavigateToQuarantineCommand { get; }

        public MainViewModel(QuarantineRepository repository, EngineProcessBridge engineBridge)
        {
            _repository = repository;
            
            DashboardVM = new DashboardViewModel(_repository);
            ScanVM = new ScanViewModel(engineBridge, _repository);
            QuarantineVM = new QuarantineViewModel(_repository);

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
        }

        public ViewModelBase CurrentViewModel
        {
            get => _currentViewModel;
            set => SetProperty(ref _currentViewModel, value);
        }
    }
}