using System;
using System.IO;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using VaultSentry.Client.Services;
using VaultSentry.Client.Services.Interfaces; // Fixes CS0246 & CS1061 for IDownloadIngressWatcher
using VaultSentry.Client.ViewModels;
using VaultSentry.Client.Views;
using VaultSentry.Core.Interfaces;

namespace VaultSentry.Client
{
    /// <summary>
    /// Application Composition Root and Lifecycle Coordinator.
    /// Configures Dependency Injection, Infrastructure Services, and Real-time VQS Ingress Monitoring.
    /// </summary>
    public partial class App : Application
    {
        private IServiceProvider? _serviceProvider;
        private IDownloadIngressWatcher? _ingressWatcher;

        public static IServiceProvider? ServiceProvider { get; private set; }

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

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

            // 4. Configure Real-time VQS DropZone Ingress Watcher
            string vqsDropZone = Path.Combine(workspaceRoot, "quarantine_storage", "VQS_DropZone");
            Directory.CreateDirectory(vqsDropZone);

            _ingressWatcher = new DownloadIngressWatcher(vqsDropZone, async (capturedFilePath) =>
            {
                await Dispatcher.InvokeAsync(async () =>
                {
                    // Navigate UI to File Analysis workspace
                    mainVM.CurrentViewModel = scanVM;
                    scanVM.TargetFilePath = capturedFilePath;

                    // Execute scan workflow directly and asynchronously
                    await scanVM.ExecuteScanAsync();
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

        /// <summary>
        /// Registers application services and ViewModels adhering to Inversion of Control (IoC).
        /// </summary>
        private static void ConfigureServices(IServiceCollection services, string workspaceRoot)
        {
            string dbPath = Path.Combine(workspaceRoot, "src", "database", "vaultsentry.db");

            // Infrastructure Services
            services.AddSingleton<QuarantineRepository>(_ => new QuarantineRepository(dbPath));
            services.AddSingleton<IEngineProcessBridge>(_ => new EngineProcessBridge(workspaceRoot));
            services.AddSingleton<PipelineService>();

            // ViewModels
            services.AddSingleton<FileAnalysisViewModel>();
            services.AddSingleton<DashboardViewModel>();
            services.AddSingleton<ScanViewModel>();
            services.AddSingleton<QuarantineViewModel>();
            services.AddSingleton<MainViewModel>();
        }

        /// <summary>
        /// Robustly detects workspace root directory by traversing upward until project markers are found.
        /// </summary>
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

        protected override void OnExit(ExitEventArgs e)
        {
            _ingressWatcher?.Dispose();

            if (_serviceProvider is IDisposable disposableProvider)
            {
                disposableProvider.Dispose();
            }

            base.OnExit(e);
        }
    }
}