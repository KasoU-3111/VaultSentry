using System;
using System.IO;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using VaultSentry.Client.Services;
using VaultSentry.Client.Services.Interfaces;
using VaultSentry.Client.ViewModels;
using VaultSentry.Client.Views;
using VaultSentry.Core.Interfaces;

namespace VaultSentry.Client
{
    /// <summary>
    /// Application Composition Root and Lifecycle Coordinator.
    /// Configures Dependency Injection, Infrastructure Services, and Real-time VQS Ingress Monitoring safely.
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

                // 2. Build Dependency Injection Service Container
                var serviceCollection = new ServiceCollection();
                ConfigureServices(serviceCollection, workspaceRoot);
                _serviceProvider = serviceCollection.BuildServiceProvider();
                ServiceProvider = _serviceProvider;

                // 3. Resolve ViewModels from Service Provider
                var mainVM = _serviceProvider.GetRequiredService<MainViewModel>();
                var scanVM = _serviceProvider.GetRequiredService<ScanViewModel>();

                // 4. Configure Real-time VQS DropZone Ingress Watcher safely
                string vqsDropZone = Path.Combine(workspaceRoot, "quarantine_storage", "VQS_DropZone");
                Directory.CreateDirectory(vqsDropZone);

                _ingressWatcher = new DownloadIngressWatcher(vqsDropZone, async (capturedFilePath) =>
                {
                    await Dispatcher.InvokeAsync(async () =>
                    {
                        try
                        {
                            // Navigate UI to File Analysis workspace
                            mainVM.CurrentViewModel = scanVM;
                            scanVM.TargetFilePath = capturedFilePath;

                            // Execute scan workflow directly and asynchronously
                            await scanVM.ExecuteScanAsync();
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show($"Error processing ingested file: {ex.Message}", "VaultSentry Ingress Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                        }
                    });
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

        private static void ConfigureServices(IServiceCollection services, string workspaceRoot)
        {
            string dbDir = Path.Combine(workspaceRoot, "src", "database");
            Directory.CreateDirectory(dbDir);
            string dbPath = Path.Combine(dbDir, "vaultsentry.db");

            // Infrastructure Services - Register both concrete type and interface mappings to prevent DI resolution failures
            services.AddSingleton<QuarantineRepository>(_ => new QuarantineRepository(dbPath));
            services.AddSingleton<EngineProcessBridge>(_ => new EngineProcessBridge(workspaceRoot));
            services.AddSingleton<IEngineProcessBridge>(provider => provider.GetRequiredService<EngineProcessBridge>());
            services.AddSingleton<PipelineService>();

            // ViewModels
            services.AddSingleton<FileAnalysisViewModel>();
            services.AddSingleton<DashboardViewModel>();
            services.AddSingleton<ScanViewModel>();
            services.AddSingleton<QuarantineViewModel>();
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