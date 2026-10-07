using System.Threading;
using System.Threading.Tasks;
using VaultSentry.Client.Models;

namespace VaultSentry.Client.Services.Interfaces;

/// <summary>
/// Contract for launching and communicating with the VaultSentry Python static analysis engine.
/// </summary>
public interface IEngineProcessBridge
{
    /// <summary>
    /// Asynchronously dispatches an untrusted file to the Python backend process 
    /// for Virtual Quarantine Space staging, static analysis, and risk scoring.
    /// </summary>
    /// <param name="filePath">Absolute local filesystem path to the untrusted file.</param>
    /// <param name="cancellationToken">Token to monitor for scan cancellation requests.</param>
    /// <returns>A structured <see cref="SecurityReport"/> payload or null if analysis fails.</returns>
    Task<SecurityReport?> ScanFileAsync(string filePath, CancellationToken cancellationToken = default);
}