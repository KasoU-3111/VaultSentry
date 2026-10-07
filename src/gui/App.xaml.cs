using System;
using System.IO;
using System.Windows;
using VaultSentry.Client.Services;
using VaultSentry.Client.Services.Interfaces;
using VaultSentry.Client.ViewModels;
using VaultSentry.Client.Views;

namespace VaultSentry.Client;

/// <summary>
/// Application Composition Root and Lifecycle Coordinator.
/// </summary>
public partial class App : Application
{
    private IDownloadIngressWatcher? _ingressWatcher;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // 1. Resolve Application Boundaries
        var baseDir = AppDomain.CurrentDomain.BaseDirectory;
        var workspaceRoot = Path.GetFullPath(Path.Combine(baseDir, @"..\..\..\..\.."));

        var pythonExe = Path.Combine(workspaceRoot, @".venv\Scripts\python.exe");
        if (!File.Exists(pythonExe))
        {
            pythonExe = "python"; // Fallback to system PATH
        }

        var mainScript = Path.Combine(workspaceRoot, @"src\engine\main.py");
        var dbPath = Path.Combine(workspaceRoot, @"src\database\vaultsentry.db");
        var vqsDropZone = Path.Combine(workspaceRoot, @"quarantine_storage\VQS_DropZone");

        // 2. Initialize Infrastructure Services & Repository
        var engineBridge = new EngineProcessBridge(pythonExe, mainScript);
        var repository = new QuarantineRepository(dbPath);

        // 3. Initialize Presentation ViewModels
        var dashboardVM = new DashboardViewModel(repository);
        var scanVM = new ScanViewModel(engineBridge, repository);
        var quarantineVM = new QuarantineViewModel(repository);

        var mainVM = new MainViewModel(dashboardVM, scanVM, quarantineVM);

        // 4. Initialize & Start Real-time Ingress Watcher
        _ingressWatcher = new DownloadIngressWatcher(vqsDropZone, async (capturedFilePath) =>
        {
            await Dispatcher.InvokeAsync(async () =>
            {
                // Auto-switch navigation to File Analysis
                mainVM.CurrentViewModel = scanVM;
                scanVM.TargetFilePath = capturedFilePath;

                // Execute the static analysis pipeline automatically
                await scanVM.RunScanCommand.ExecuteAsync(null);
            });
        });

        _ingressWatcher.Start();

        // 5. Initialize Root Window
        var mainWindow = new MainWindow
        {
            DataContext = mainVM
        };

        mainWindow.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _ingressWatcher?.Dispose();
        base.OnExit(e);
    }
}