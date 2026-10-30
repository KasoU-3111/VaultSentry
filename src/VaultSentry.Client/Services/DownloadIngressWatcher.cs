using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using VaultSentry.Client.Services.Interfaces;

namespace VaultSentry.Client.Services
{
    /// <summary>
    /// Monitors a configured folder and dispatches stable files for post-download scanning.
    /// </summary>
    public class DownloadIngressWatcher : IDownloadIngressWatcher
    {
        private static readonly TimeSpan FileStabilityTimeout = TimeSpan.FromMinutes(2);
        private static readonly TimeSpan FileStabilityInterval = TimeSpan.FromMilliseconds(500);
        private static readonly string[] TemporaryExtensions = { ".part", ".tmp", ".download" };

        private readonly FileSystemWatcher _watcher;
        private readonly Func<string, System.Threading.Tasks.Task> _onFileCapturedCallback;
        private readonly Action<string, Exception> _onProcessingErrorCallback;
        private readonly ConcurrentDictionary<string, byte> _processingPaths = new(StringComparer.OrdinalIgnoreCase);
        private bool _disposed;

        public DownloadIngressWatcher(
            string watchPath,
            Func<string, System.Threading.Tasks.Task> onFileCapturedCallback,
            Action<string, Exception> onProcessingErrorCallback)
        {
            if (string.IsNullOrWhiteSpace(watchPath))
                throw new ArgumentNullException(nameof(watchPath));

            _onFileCapturedCallback = onFileCapturedCallback ?? throw new ArgumentNullException(nameof(onFileCapturedCallback));
            _onProcessingErrorCallback = onProcessingErrorCallback ?? throw new ArgumentNullException(nameof(onProcessingErrorCallback));

            if (!Directory.Exists(watchPath))
            {
                Directory.CreateDirectory(watchPath);
            }

            _watcher = new FileSystemWatcher(watchPath)
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                Filter = "*",
                EnableRaisingEvents = false
            };

            _watcher.Created += OnFileCreated;
            _watcher.Changed += OnFileChanged;
            _watcher.Renamed += OnFileRenamed;
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

        private void OnFileCreated(object sender, FileSystemEventArgs e) => QueueCompletedFile(e.FullPath);

        private void OnFileChanged(object sender, FileSystemEventArgs e) => QueueCompletedFile(e.FullPath);

        private void OnFileRenamed(object sender, RenamedEventArgs e) => QueueCompletedFile(e.FullPath);

        private void QueueCompletedFile(string path)
        {
            if (IsTemporaryDownload(path) || !_processingPaths.TryAdd(path, 0))
            {
                return;
            }

            _ = ProcessCompletedFileAsync(path);
        }

        private static bool IsTemporaryDownload(string path)
        {
            string extension = Path.GetExtension(path);
            foreach (string temporaryExtension in TemporaryExtensions)
            {
                if (string.Equals(extension, temporaryExtension, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private async Task ProcessCompletedFileAsync(string path)
        {
            try
            {
                if (await WaitUntilFileIsStableAsync(path))
                {
                    await _onFileCapturedCallback(path);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Failed to process completed download '{path}': {ex}");
                _onProcessingErrorCallback(path, ex);
            }
            finally
            {
                _processingPaths.TryRemove(path, out _);
            }
        }

        private static async Task<bool> WaitUntilFileIsStableAsync(string path)
        {
            var stopwatch = Stopwatch.StartNew();
            long previousLength = -1;
            DateTime previousWriteTimeUtc = DateTime.MinValue;
            int stableChecks = 0;

            while (stopwatch.Elapsed < FileStabilityTimeout)
            {
                if (!File.Exists(path))
                {
                    return false;
                }

                try
                {
                    var fileInfo = new FileInfo(path);
                    long currentLength = fileInfo.Length;
                    DateTime currentWriteTimeUtc = fileInfo.LastWriteTimeUtc;

                    using (new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None))
                    {
                        if (currentLength == previousLength && currentWriteTimeUtc == previousWriteTimeUtc)
                        {
                            stableChecks++;
                            if (stableChecks >= 2)
                            {
                                return true;
                            }
                        }
                        else
                        {
                            stableChecks = 0;
                        }
                    }

                    previousLength = currentLength;
                    previousWriteTimeUtc = currentWriteTimeUtc;
                }
                catch (IOException)
                {
                    stableChecks = 0;
                }
                catch (UnauthorizedAccessException)
                {
                    stableChecks = 0;
                }

                await Task.Delay(FileStabilityInterval);
            }

            throw new TimeoutException($"Download did not become stable within {FileStabilityTimeout.TotalMinutes:0} minutes.");
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                Stop();
                _watcher.Created -= OnFileCreated;
                _watcher.Changed -= OnFileChanged;
                _watcher.Renamed -= OnFileRenamed;
                _watcher.Dispose();
                _disposed = true;
            }
            GC.SuppressFinalize(this);
        }
    }
}