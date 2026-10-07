using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using VaultSentry.Client.Services;

namespace VaultSentry.Client.ViewModels;

public partial class DashboardViewModel : ViewModelBase
{
    private readonly QuarantineRepository _repository;

    [ObservableProperty]
    private int _totalScannedFiles;

    [ObservableProperty]
    private int _quarantinedThreats;

    [ObservableProperty]
    private int _cleanFiles;

    [ObservableProperty]
    private string _systemStatus = "Virtual Quarantine Space Active";

    public DashboardViewModel(QuarantineRepository repository)
    {
        _repository = repository;
    }

    [RelayCommand]
    public async Task RefreshMetricsAsync()
    {
        try
        {
            var metrics = await _repository.GetDashboardMetricsAsync();
            TotalScannedFiles = metrics.TotalScans;
            QuarantinedThreats = metrics.QuarantinedCount;
            CleanFiles = metrics.CleanCount;
        }
        catch (Exception ex)
        {
            SystemStatus = $"Database Sync Error: {ex.Message}";
        }
    }
}