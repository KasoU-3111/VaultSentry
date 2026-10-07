using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using VaultSentry.Client.Models;
using VaultSentry.Client.Services.Interfaces;

namespace VaultSentry.Client.Services;

public class EngineProcessBridge : IEngineProcessBridge
{
    private readonly string _pythonExecutablePath;
    private readonly string _mainScriptPath;
    private readonly string _workingDirectory;

    public EngineProcessBridge(string pythonExecutablePath, string mainScriptPath)
    {
        _pythonExecutablePath = pythonExecutablePath;
        _mainScriptPath = mainScriptPath;

        // Resolve workspace root from main script path (src/engine/main.py -> root)
        var engineDir = Path.GetDirectoryName(Path.GetFullPath(_mainScriptPath));
        var srcDir = Path.GetDirectoryName(engineDir);
        _workingDirectory = Path.GetDirectoryName(srcDir) ?? AppDomain.CurrentDomain.BaseDirectory;
    }

    public async Task<SecurityReport?> ScanFileAsync(string filePath, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException($"Target file for scanning does not exist: {filePath}");

        if (!File.Exists(_mainScriptPath))
            throw new FileNotFoundException($"Engine entry point script not found: {_mainScriptPath}");

        var startInfo = new ProcessStartInfo
        {
            FileName = _pythonExecutablePath,
            Arguments = $"\"{_mainScriptPath}\" --file \"{filePath}\"",
            WorkingDirectory = _workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        // Ensure PYTHONPATH points to the project root
        startInfo.EnvironmentVariables["PYTHONPATH"] = _workingDirectory;

        using var process = new Process { StartInfo = startInfo };

        try
        {
            process.Start();

            Task<string> outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            Task<string> errorTask = process.StandardError.ReadToEndAsync(cancellationToken);

            await Task.WhenAll(outputTask, errorTask);
            await process.WaitForExitAsync(cancellationToken);

            string jsonOutput = outputTask.Result;
            string errorOutput = errorTask.Result;

            if (process.ExitCode != 0 && string.IsNullOrWhiteSpace(jsonOutput))
            {
                throw new InvalidOperationException($"Engine process exited with code {process.ExitCode}: {errorOutput}");
            }

            if (string.IsNullOrWhiteSpace(jsonOutput))
            {
                throw new InvalidDataException("Engine output stream returned empty response.");
            }

            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            };

            return JsonSerializer.Deserialize<SecurityReport>(jsonOutput, options);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[!] IPC Bridge Failure: {ex.Message}");
            throw;
        }
    }
}