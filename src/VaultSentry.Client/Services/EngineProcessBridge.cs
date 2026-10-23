using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using VaultSentry.Core.Interfaces;

namespace VaultSentry.Client.Services
{
    /// <summary>
    /// Subprocess host that executes the VaultSentry Python engine via stdIn/stdOut IPC.
    /// Implements robust directory resolution and execution timeout guards.
    /// </summary>
    public class EngineProcessBridge : IEngineProcessBridge
    {
        private readonly string _workspaceRoot;
        private readonly string _pythonExecutable;
        private readonly string _engineMainScript;

        public EngineProcessBridge(string workspaceRoot)
        {
            _workspaceRoot = string.IsNullOrWhiteSpace(workspaceRoot) 
                ? AppDomain.CurrentDomain.BaseDirectory 
                : workspaceRoot;

            _pythonExecutable = "python.exe";
            _engineMainScript = ResolveEngineScriptPath(_workspaceRoot);
        }

        private static string ResolveEngineScriptPath(string root)
        {
            string candidate1 = Path.Combine(root, "src", "VaultSentry.Engine", "main.py");
            if (File.Exists(candidate1)) return candidate1;

            string candidate2 = Path.Combine(root, "VaultSentry.Engine", "main.py");
            if (File.Exists(candidate2)) return candidate2;

            return Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, @"..\..\..\..\SRC\VaultSentry.Engine\main.py"));
        }

        public async Task<string> RunScanAsync(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                return CreateErrorJson($"Target file does not exist on disk: {filePath}");
            }

            if (!File.Exists(_engineMainScript))
            {
                return CreateErrorJson($"VaultSentry Engine main.py script not found at: {_engineMainScript}");
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
                        string errDetail = string.IsNullOrWhiteSpace(stderr) ? "No stderr captured." : stderr;
                        return CreateErrorJson($"Engine output empty. StdErr: {errDetail}");
                    }

                    return stdout;
                }
                catch (Exception ex)
                {
                    return CreateErrorJson($"IPC Subprocess Exception: {ex.Message}");
                }
            });
        }

        private static string CreateErrorJson(string message)
        {
            string safeMsg = (message ?? "Unspecified Error")
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\r", "")
                .Replace("\n", " ");

            return $"{{\"status\":\"ERROR\",\"message\":\"{safeMsg}\",\"verdict\":\"ERROR\",\"risk_score\":0,\"findings\":[]}}";
        }
    }
}