using System;
using System.IO;
using VaultSentry.Client.Services.Interfaces;

namespace VaultSentry.Client.Services
{
    /// <summary>
    /// File System Ingress Watcher that intercepts files written to the VQS DropZone
    /// and dispatches them asynchronously to the scan pipeline.
    /// </summary>
    public class DownloadIngressWatcher : IDownloadIngressWatcher
    {
        private readonly FileSystemWatcher _watcher;
        private readonly Func<string, System.Threading.Tasks.Task> _onFileCapturedCallback;
        private bool _disposed;

        public DownloadIngressWatcher(string watchPath, Func<string, System.Threading.Tasks.Task> onFileCapturedCallback)
        {
            if (string.IsNullOrWhiteSpace(watchPath))
                throw new ArgumentNullException(nameof(watchPath));

            _onFileCapturedCallback = onFileCapturedCallback ?? throw new ArgumentNullException(nameof(onFileCapturedCallback));

            if (!Directory.Exists(watchPath))
            {
                Directory.CreateDirectory(watchPath);
            }

            _watcher = new FileSystemWatcher(watchPath)
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                Filter = "*.*",
                EnableRaisingEvents = false
            };

            _watcher.Created += OnFileCreated;
        }

        public void Start()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(DownloadIngressWatcher));
            _watcher.EnableRaisingEvents = true;
        }

        public void Stop()
        {
            if (_disposed) return;
            _watcher.EnableRaisingEvents = false;
        }

        private async void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            try
            {
                // Wait briefly to ensure file handle is released by writer process
                await System.Threading.Tasks.Task.Delay(500);

                if (File.Exists(e.FullPath))
                {
                    await _onFileCapturedCallback.Invoke(e.FullPath);
                }
            }
            catch (Exception)
            {
                // Catch unhandled thread exceptions from async void event handler
            }
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                Stop();
                _watcher.Created -= OnFileCreated;
                _watcher.Dispose();
                _disposed = true;
            }
            GC.SuppressFinalize(this);
        }
    }
}