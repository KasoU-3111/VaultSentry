using System;

namespace VaultSentry.Client.Services.Interfaces
{
    /// <summary>
    /// Real-time ingress monitoring contract for Virtual Quarantine Space (VQS) DropZone.
    /// Encapsulates FileSystemWatcher event handling to ensure safe file staging.
    /// </summary>
    public interface IDownloadIngressWatcher : IDisposable
    {
        /// <summary>
        /// Begins monitoring the designated VQS DropZone directory for incoming files.
        /// </summary>
        void Start();

        /// <summary>
        /// Halts active file system monitoring.
        /// </summary>
        void Stop();
    }
}