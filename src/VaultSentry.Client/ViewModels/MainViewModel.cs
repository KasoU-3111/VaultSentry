using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace VaultSentry.Client.ViewModels;

public partial class MainViewModel : ViewModelBase
{
    [ObservableProperty]
    private ViewModelBase _currentViewModel;

    public DashboardViewModel DashboardVM { get; }
    public ScanViewModel ScanVM { get; }
    public QuarantineViewModel QuarantineVM { get; }

    public MainViewModel(DashboardViewModel dashboardVM, ScanViewModel scanVM, QuarantineViewModel quarantineVM)
    {
        DashboardVM = dashboardVM;
        ScanVM = scanVM;
        QuarantineVM = quarantineVM;
        
        // Explicitly set default starting view
        _currentViewModel = dashboardVM;

        // Populate initial SQLite ledger counts
        _ = DashboardVM.RefreshMetricsAsync();
    }

    [RelayCommand]
    private async Task NavigateToDashboardAsync()
    {
        CurrentViewModel = DashboardVM;
        await DashboardVM.RefreshMetricsAsync();
    }

    [RelayCommand]
    private void NavigateToScan()
    {
        CurrentViewModel = ScanVM;
    }

    [RelayCommand]
    private async Task NavigateToQuarantineAsync()
    {
        CurrentViewModel = QuarantineVM;
        await QuarantineVM.LoadQuarantineDataAsync();
    }
}