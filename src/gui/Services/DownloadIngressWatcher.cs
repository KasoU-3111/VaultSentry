using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using VaultSentry.Client.Services.Interfaces;

namespace VaultSentry.Client.Services;

/// <summary>
/// Enterprise real-time ingress watcher that intercepts browser downloads in VQS,
/// debounces inflight chunk streams, verifies write completion, and dispatches analysis.
/// </summary>
public sealed class DownloadIngressWatcher : IDownloadIngressWatcher
{
    private readonly string _watchDirectory;
    private readonly Func<string, Task> _onPayloadCapturedAsync;
    private FileSystemWatcher? _fileWatcher;
    private readonly ConcurrentDictionary<string, byte> _activeProcessingRegistry = new(StringComparer.OrdinalIgnoreCase);
    private readonly CancellationTokenSource _lifecycleCts = new();
    private bool _isDisposed;

    // Temporary shadow extensions utilized by modern web browsers and download managers
    private static readonly string[] InflightExtensions =
    {
        ".crdownload",  // Chromium (Chrome, Edge, Brave, Opera)
        ".part",        // Mozilla Firefox
        ".download",    // Apple Safari / Generic Downloaders
        ".tmp",         // Generic Temporary Stream
        ".opdownload"   // Legacy Opera
    };

    public bool IsRunning => _fileWatcher?.EnableRaisingEvents ?? false;

    public DownloadIngressWatcher(string watchDirectory, Func<string, Task> onPayloadCapturedAsync)
    {
        if (string.IsNullOrWhiteSpace(watchDirectory))
            throw new ArgumentNullException(nameof(watchDirectory));

        _watchDirectory = Path.GetFullPath(watchDirectory);
        _onPayloadCapturedAsync = onPayloadCapturedAsync ?? throw new ArgumentNullException(nameof(onPayloadCapturedAsync));

        // Enforce physical directory initialization and execution-denial NT ACLs
        VqsSecurityDescriptor.InitializeAndHardenDirectory(_watchDirectory);
        InitializeWatcher();
    }

    private void InitializeWatcher()
    {
        _fileWatcher = new FileSystemWatcher(_watchDirectory)
        {
            NotifyFilter = NotifyFilters.FileName |
                           NotifyFilters.LastWrite |
                           NotifyFilters.Size |
                           NotifyFilters.CreationTime,
            IncludeSubdirectories = false,
            InternalBufferSize = 65536 // 64 KB buffer to prevent event dropping during bursts
        };

        _fileWatcher.Created += OnFileSystemMutation;
        _fileWatcher.Changed += OnFileSystemMutation;
        _fileWatcher.Renamed += OnFileSystemRenamed;
        _fileWatcher.Error += OnWatcherInternalError;
    }

    public void Start()
    {
        ThrowIfDisposed();
        if (_fileWatcher != null && !_fileWatcher.EnableRaisingEvents)
        {
            _fileWatcher.EnableRaisingEvents = true;
        }
    }

    public void Stop()
    {
        ThrowIfDisposed();
        if (_fileWatcher != null && _fileWatcher.EnableRaisingEvents)
        {
            _fileWatcher.EnableRaisingEvents = false;
        }
    }

    private void OnFileSystemMutation(object sender, FileSystemEventArgs e)
    {
        EvaluateAndScheduleIngress(e.FullPath);
    }

    private void OnFileSystemRenamed(object sender, RenamedEventArgs e)
    {
        // Occurs when browser completes download and strips .crdownload/.part extension
        EvaluateAndScheduleIngress(e.FullPath);
    }

    private void OnWatcherInternalError(object sender, ErrorEventArgs e)
    {
        // Recovers the FileSystemWatcher if the Windows OS buffer overflows
        Task.Run(async () =>
        {
            try
            {
                Stop();
                await Task.Delay(1000, _lifecycleCts.Token);
                Start();
            }
            catch (Exception)
            {
                // Suppress lifecycle recovery exceptions
            }
        });
    }

    private void EvaluateAndScheduleIngress(string fullFilePath)
    {
        if (string.IsNullOrWhiteSpace(fullFilePath) || _lifecycleCts.IsCancellationRequested)
            return;

        // 1. Filter out inflight temporary browser download streams
        if (IsInflightShadowExtension(fullFilePath))
            return;

        // 2. Prevent duplicate concurrency races on the same file
        if (!_activeProcessingRegistry.TryAdd(fullFilePath, 0))
            return;

        // 3. Dispatch to background thread pool for handle synchronization
        Task.Run(async () =>
        {
            try
            {
                bool isReady = await WaitForExclusiveHandleAsync(fullFilePath, _lifecycleCts.Token);
                if (isReady && File.Exists(fullFilePath))
                {
                    await _onPayloadCapturedAsync(fullFilePath);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[VQS Ingress Error] Processing failed for {fullFilePath}: {ex.Message}");
            }
            finally
            {
                _activeProcessingRegistry.TryRemove(fullFilePath, out _);
            }
        }, _lifecycleCts.Token);
    }

    /// <summary>
    /// Inspects whether the target file matches known browser inflight extension masks.
    /// </summary>
    private static bool IsInflightShadowExtension(string path)
    {
        string extension = Path.GetExtension(path).ToLowerInvariant();
        foreach (var shadowExt in InflightExtensions)
        {
            if (extension == shadowExt || path.EndsWith(shadowExt, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    /// <summary>
    /// Executes exponential backoff handle verification to guarantee the browser process
    /// has flushed all bytes and closed its write handle before static inspection begins.
    /// </summary>
    private static async Task<bool> WaitForExclusiveHandleAsync(
        string filePath, 
        CancellationToken ct, 
        int maxAttempts = 30, 
        int initialDelayMs = 250)
    {
        int delay = initialDelayMs;

        for (int attempt = 0; attempt < maxAttempts; attempt++)
        {
            if (ct.IsCancellationRequested) 
                return false;

            if (!File.Exists(filePath)) 
                return false;

            try
            {
                // Attempt to acquire an exclusive write lock to verify all external write streams are closed
                using var stream = new FileStream(
                    filePath, 
                    FileMode.Open, 
                    FileAccess.ReadWrite, 
                    FileShare.None, 
                    4096, 
                    FileOptions.None);

                if (stream.Length > 0)
                {
                    return true;
                }
            }
            catch (IOException)
            {
                // File is still locked by the web browser writing payload chunks
            }
            catch (UnauthorizedAccessException)
            {
                // Access restricted during active OS security descriptor assignment
            }

            await Task.Delay(delay, ct);
            delay = Math.Min(delay + 100, 1000); // Cap incremental polling delay at 1s
        }

        return false;
    }

    private void ThrowIfDisposed()
    {
        if (_isDisposed)
            throw new ObjectDisposedException(nameof(DownloadIngressWatcher));
    }

    public void Dispose()
    {
        if (_isDisposed) return;

        _lifecycleCts.Cancel();
        
        if (_fileWatcher != null)
        {
            _fileWatcher.EnableRaisingEvents = false;
            _fileWatcher.Created -= OnFileSystemMutation;
            _fileWatcher.Changed -= OnFileSystemMutation;
            _fileWatcher.Renamed -= OnFileSystemRenamed;
            _fileWatcher.Error -= OnWatcherInternalError;
            _fileWatcher.Dispose();
        }

        _lifecycleCts.Dispose();
        _isDisposed = true;
    }
}