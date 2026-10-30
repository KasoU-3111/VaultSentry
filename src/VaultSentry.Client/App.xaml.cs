using System;
using System.IO;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using VaultSentry.Client.Models;
using VaultSentry.Client.Services;
using VaultSentry.Client.Services.Interfaces;
using VaultSentry.Client.ViewModels;
using VaultSentry.Client.Views;
using VaultSentry.Core.Interfaces;

namespace VaultSentry.Client
{
    /// <summary>
    /// Application Composition Root and Lifecycle Coordinator.
    /// Configures dependency injection, infrastructure services, and optional post-download folder monitoring.
    /// </summary>
    public partial class App : Application
    {
        private IServiceProvider? _serviceProvider;
        private IDownloadIngressWatcher? _ingressWatcher;

        public static IServiceProvider? ServiceProvider { get; private set; }

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            try
            {
                // 1. Resolve Workspace Root dynamically across all build/run configurations
                string workspaceRoot = ResolveWorkspaceRoot();
                VaultSentrySettings settings = VaultSentrySettings.Load(workspaceRoot);

                // 2. Build Dependency Injection Service Container
                var serviceCollection = new ServiceCollection();
                ConfigureServices(serviceCollection, workspaceRoot, settings);
                _serviceProvider = serviceCollection.BuildServiceProvider();
                ServiceProvider = _serviceProvider;

                // 3. Resolve ViewModels from Service Provider
                var mainVM = _serviceProvider.GetRequiredService<MainViewModel>();
                var scanVM = _serviceProvider.GetRequiredService<ScanViewModel>();
                var ingressOptions = _serviceProvider.GetRequiredService<DownloadIngressOptions>();

                // 4. Configure optional post-download monitoring for the VQS drop zone
                string vqsDropZone = ingressOptions.DropZonePath;
                Directory.CreateDirectory(vqsDropZone);
                if (!VqsSecurityDescriptor.InitializeAndHardenDirectory(vqsDropZone))
                {
                    MessageBox.Show(
                        "Windows could not apply the drop-zone execution restriction. Downloads can still be scanned, but files in this folder are not protected from being launched before scanning completes.",
                        "VaultSentry - Drop Zone Warning",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                }

                _ingressWatcher = new DownloadIngressWatcher(vqsDropZone, async (capturedFilePath) =>
                {
                    await Dispatcher.InvokeAsync(async () =>
                    {
                        try
                        {
                            // Navigate UI to File Analysis workspace
                            mainVM.CurrentViewModel = scanVM;

                            await scanVM.ScanIngressFileAsync(capturedFilePath);
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show($"Error processing ingested file: {ex.Message}", "VaultSentry Ingress Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                        }
                    }).Task.Unwrap();
                }, (failedPath, exception) =>
                {
                    Dispatcher.BeginInvoke(new Action(() =>
                        MessageBox.Show(
                            $"VaultSentry could not process the incoming file '{Path.GetFileName(failedPath)}': {exception.Message}",
                            "VaultSentry Ingress Error",
                            MessageBoxButton.OK,
                            MessageBoxImage.Warning)));
                });

                _ingressWatcher.Start();

                // 5. Launch MainWindow Shell
                var mainWindow = new MainWindow
                {
                    DataContext = mainVM
                };

                mainWindow.Show();
            }
            catch (Exception ex)
            {
                // Catch any fatal startup crash, log it, and present a clear diagnostic window
                LogFatalStartupError(ex);
                Shutdown(1);
            }
        }

        private static void ConfigureServices(
            IServiceCollection services,
            string workspaceRoot,
            VaultSentrySettings settings)
        {
            string dbDir = Path.Combine(workspaceRoot, "src", "database");
            Directory.CreateDirectory(dbDir);
            string dbPath = Path.Combine(dbDir, "vaultsentry.db");
            string quarantineStoragePath = settings.ResolveQuarantinePath(workspaceRoot);
            string dropZonePath = Path.Combine(quarantineStoragePath, "VQS_DropZone");

            // Infrastructure Services - Register both concrete type and interface mappings to prevent DI resolution failures
            services.AddSingleton<QuarantineRepository>(_ => new QuarantineRepository(dbPath));
            services.AddSingleton<QuarantineReleaseService>();
            services.AddSingleton<QuarantineDownloadService>();
            services.AddSingleton<EngineProcessBridge>(_ => new EngineProcessBridge(workspaceRoot, settings));
            services.AddSingleton<IEngineProcessBridge>(provider => provider.GetRequiredService<EngineProcessBridge>());
            services.AddSingleton(new DownloadIngressOptions(dropZonePath, quarantineStoragePath, workspaceRoot));

            // ViewModels
            services.AddSingleton<FileAnalysisViewModel>();
            services.AddSingleton<DashboardViewModel>();
            services.AddSingleton<ScanViewModel>();
            services.AddSingleton<QuarantineViewModel>();
            services.AddSingleton<DownloadSimulationViewModel>();
            services.AddSingleton<MainViewModel>();
        }

        private static string ResolveWorkspaceRoot()
        {
            string? currentDir = AppDomain.CurrentDomain.BaseDirectory;

            while (!string.IsNullOrEmpty(currentDir))
            {
                if (Directory.Exists(Path.Combine(currentDir, ".git")) ||
                    File.Exists(Path.Combine(currentDir, "requirements.txt")) ||
                    Directory.Exists(Path.Combine(currentDir, "src", "VaultSentry.Engine")))
                {
                    return currentDir;
                }

                var parent = Directory.GetParent(currentDir);
                if (parent == null) break;
                currentDir = parent.FullName;
            }

            return AppDomain.CurrentDomain.BaseDirectory;
        }

        private static void LogFatalStartupError(Exception ex)
        {
            try
            {
                string logDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
                Directory.CreateDirectory(logDir);
                string logPath = Path.Combine(logDir, "fatal_startup.log");

                File.WriteAllText(logPath, $"[{DateTime.UtcNow}] FATAL STARTUP ERROR:\n{ex.Message}\n\n{ex.StackTrace}");
                
                MessageBox.Show(
                    $"VaultSentry failed to start due to a critical exception:\n\n{ex.Message}\n\nDetails saved to logs\\fatal_startup.log",
                    "VaultSentry - Startup Critical Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
            catch
            {
                MessageBox.Show($"Critical Startup Error: {ex.Message}", "VaultSentry Crash", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        protected override void OnExit(ExitEventArgs e)
        {
            try
            {
                _ingressWatcher?.Dispose();

                if (_serviceProvider is IDisposable disposableProvider)
                {
                    disposableProvider.Dispose();
                }
            }
            catch
            {
                // Suppress disposal exceptions on exit
            }

            base.OnExit(e);
        }
    }
}