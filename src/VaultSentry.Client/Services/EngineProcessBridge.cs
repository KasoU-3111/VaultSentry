using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using VaultSentry.Client.Models;
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
        private readonly int _timeoutMilliseconds;

        public EngineProcessBridge(string workspaceRoot)
            : this(workspaceRoot, VaultSentrySettings.Load(workspaceRoot))
        {
        }

        public EngineProcessBridge(string workspaceRoot, VaultSentrySettings settings)
        {
            _workspaceRoot = string.IsNullOrWhiteSpace(workspaceRoot) 
                ? AppDomain.CurrentDomain.BaseDirectory 
                : workspaceRoot;

            _pythonExecutable = "python.exe";
            _engineMainScript = settings.ResolveEnginePath(_workspaceRoot);
            _timeoutMilliseconds = checked(settings.Engine!.TimeoutSeconds * 1000);
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
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true,
                        StandardOutputEncoding = Encoding.UTF8,
                        StandardErrorEncoding = Encoding.UTF8,
                        WorkingDirectory = Path.GetDirectoryName(_engineMainScript) ?? string.Empty
                    };
                    startInfo.ArgumentList.Add(_engineMainScript);
                    startInfo.ArgumentList.Add(filePath);

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

                    bool exited = process.WaitForExit(_timeoutMilliseconds);

                    if (!exited)
                    {
                        process.Kill(true);
                        return CreateErrorJson($"Scan Execution Timeout: Engine exceeded {_timeoutMilliseconds / 1000} seconds.");
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