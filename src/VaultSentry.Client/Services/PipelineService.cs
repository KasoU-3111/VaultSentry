using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace VaultSentry.Client.Services
{
    /// <summary>
    /// Robust IPC Subprocess Host that locates the Python Engine dynamically
    /// across Debug, Release, and Production directory layouts.
    /// </summary>
    public class PipelineService
    {
        private readonly string _pythonExecutable;
        private readonly string _engineMainScript;

        public PipelineService()
        {
            _pythonExecutable = "python.exe";
            _engineMainScript = ResolveEngineScriptPath();
        }

        private static string ResolveEngineScriptPath()
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            DirectoryInfo? dir = new DirectoryInfo(baseDir);

            // Dynamically probe upward through parent directories for src/VaultSentry.Engine/main.py or VaultSentry.Engine/main.py
            while (dir != null)
            {
                string pathCandidate1 = Path.Combine(dir.FullName, "src", "VaultSentry.Engine", "main.py");
                if (File.Exists(pathCandidate1))
                {
                    return pathCandidate1;
                }

                string pathCandidate2 = Path.Combine(dir.FullName, "VaultSentry.Engine", "main.py");
                if (File.Exists(pathCandidate2))
                {
                    return pathCandidate2;
                }

                dir = dir.Parent;
            }

            // Fallback default
            return Path.GetFullPath(Path.Combine(baseDir, @"..\..\..\..\SRC\VaultSentry.Engine\main.py"));
        }

        public async Task<string> RunScanAsync(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                return CreateErrorJson($"Target file does not exist on disk: {filePath}");
            }

            if (!File.Exists(_engineMainScript))
            {
                return CreateErrorJson($"VaultSentry Engine main.py script not found at probed path: {_engineMainScript}");
            }

            return await Task.Run(() =>
            {
                try
                {
                    var startInfo = new ProcessStartInfo
                    {
                        FileName = _pythonExecutable,
                        Arguments = $"\"{_engineMainScript}\" \"{filePath}\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true,
                        StandardOutputEncoding = Encoding.UTF8,
                        StandardErrorEncoding = Encoding.UTF8,
                        WorkingDirectory = Path.GetDirectoryName(_engineMainScript) ?? string.Empty
                    };

                    using var process = new Process { StartInfo = startInfo };
                    var outputBuilder = new StringBuilder();
                    var errorBuilder = new StringBuilder();

                    process.OutputDataReceived += (sender, e) =>
                    {
                        if (e.Data != null) outputBuilder.AppendLine(e.Data);
                    };

                    process.ErrorDataReceived += (sender, e) =>
                    {
                        if (e.Data != null) errorBuilder.AppendLine(e.Data);
                    };

                    process.Start();
                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();

                    bool exited = process.WaitForExit(30000); // 30-second timeout

                    if (!exited)
                    {
                        process.Kill(true);
                        return CreateErrorJson("Scan Execution Timeout: Engine exceeded 30 seconds limit.");
                    }

                    string stdout = outputBuilder.ToString().Trim();
                    string stderr = errorBuilder.ToString().Trim();

                    if (string.IsNullOrWhiteSpace(stdout))
                    {
                        string errDetail = string.IsNullOrWhiteSpace(stderr) ? "No output or stderr captured from Python process." : stderr;
                        return CreateErrorJson($"Engine returned empty stdout. Diagnostic StdErr: {errDetail}");
                    }

                    return stdout;
                }
                catch (Exception ex)
                {
                    return CreateErrorJson($"IPC Execution Exception: {ex.Message}");
                }
            });
        }

        private static string CreateErrorJson(string message)
        {
            string safeMsg = (message ?? "Unspecified IPC Error")
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\r", "")
                .Replace("\n", " ");

            return $"{{\"status\":\"ERROR\",\"message\":\"{safeMsg}\",\"verdict\":\"ERROR\",\"risk_score\":0,\"findings\":[]}}";
        }
    }
}