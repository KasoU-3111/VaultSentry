using System;
using System.Threading.Tasks;

namespace VaultSentry.Client.Services.Interfaces;

/// <summary>
/// Defines the contract for real-time filesystem download ingress interception.
/// </summary>
public interface IDownloadIngressWatcher : IDisposable
{
    /// <summary>
    /// Starts real-time monitoring of the drop zone.
    /// </summary>
    void Start();

    /// <summary>
    /// Pauses or stops active directory monitoring.
    /// </summary>
    void Stop();

    /// <summary>
    /// Gets a value indicating whether the watcher is actively listening for ingress events.
    /// </summary>
    bool IsRunning { get; }
}