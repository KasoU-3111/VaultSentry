using System;

namespace VaultSentry.Client.Services.Interfaces
{
    /// <summary>
    /// Contract for best-effort monitoring of a configured folder after files are written.
    /// </summary>
    public interface IDownloadIngressWatcher : IDisposable
    {
        /// <summary>
        /// Begins monitoring the designated folder for files to scan after they are written.
        /// </summary>
        void Start();

        /// <summary>
        /// Halts active file system monitoring.
        /// </summary>
        void Stop();
    }
}