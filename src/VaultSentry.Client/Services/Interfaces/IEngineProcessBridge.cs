using System.Threading.Tasks;

namespace VaultSentry.Core.Interfaces
{
    /// <summary>
    /// Core contract for the C# to Python Subprocess Inter-Process Communication (IPC) Bridge.
    /// Abstracts local static security analysis execution through the VaultSentry engine.
    /// </summary>
    public interface IEngineProcessBridge
    {
        /// <summary>
        /// Asynchronously executes the Python security scan pipeline against a target file.
        /// </summary>
        /// <param name="filePath">Absolute path to the target file queued for static inspection.</param>
        /// <returns>A raw JSON string representing the complete security analysis state report.</returns>
        Task<string> RunScanAsync(string filePath);
    }
}