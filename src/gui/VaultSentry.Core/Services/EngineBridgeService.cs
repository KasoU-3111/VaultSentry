using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using Newtonsoft.Json;
using VaultSentry.Core.Models;

namespace VaultSentry.Core.Services
{
    /// <summary>
    /// Manages Inter-Process Communication (IPC) between C# WPF frontend and Python Static Scan Engine.
    /// </summary>
    public class EngineBridgeService
    {
        private readonly string _pythonExecutable;
        private readonly string _projectRoot;

        public EngineBridgeService(string? projectRoot = null, string? pythonExec = null)
        {
            _projectRoot = projectRoot ?? ResolveProjectRoot();
            _pythonExecutable = pythonExec ?? ResolvePythonExecutable(_projectRoot);
        }

        /// <summary>
        /// Recursively traverses directory tree upwards from output directory to locate repository root.
        /// </summary>
        private static string ResolveProjectRoot()
        {
            string? currentDir = AppDomain.CurrentDomain.BaseDirectory;

            while (!string.IsNullOrEmpty(currentDir))
            {
                // Check for repository root markers
                if (Directory.Exists(Path.Combine(currentDir, ".git")) ||
                    File.Exists(Path.Combine(currentDir, "requirements.txt")) ||
                    Directory.Exists(Path.Combine(currentDir, "src", "engine")))
                {
                    return currentDir;
                }

                var parent = Directory.GetParent(currentDir);
                if (parent == null) break;
                currentDir = parent.FullName;
            }

            // Fallback to base directory if root marker is missing
            return AppDomain.CurrentDomain.BaseDirectory;
        }

        /// <summary>
        /// Resolves the Python executable path using virtual environments or system PATH.
        /// </summary>
        private static string ResolvePythonExecutable(string projectRoot)
        {
            // Candidate relative paths
            string[] candidatePaths = new[]
            {
                Path.Combine(projectRoot, ".venv", "Scripts", "python.exe"),
                Path.Combine(projectRoot, "venv", "Scripts", "python.exe"),
                Path.Combine(projectRoot, "src", ".venv", "Scripts", "python.exe")
            };

            foreach (var path in candidatePaths)
            {
                if (File.Exists(path))
                {
                    return path;
                }
            }

            // Fallback: Check if python is on system PATH
            string? systemPython = FindPythonInPath();
            if (!string.IsNullOrEmpty(systemPython))
            {
                return systemPython;
            }

            throw new FileNotFoundException(
                $"Python environment not detected. Verified target paths:\n" +
                $"- {string.Join("\n- ", candidatePaths)}\n" +
                $"Ensure .venv is created at root ({projectRoot}) or Python is on system PATH."
            );
        }

        private static string? FindPythonInPath()
        {
            var pathEnv = Environment.GetEnvironmentVariable("PATH");
            if (string.IsNullOrEmpty(pathEnv)) return null;

            foreach (var dir in pathEnv.Split(Path.PathSeparator))
            {
                var fullPath = Path.Combine(dir.Trim(), "python.exe");
                if (File.Exists(fullPath)) return fullPath;
            }

            return null;
        }

        public async Task<ScanReportModel?> ExecuteScanAsync(string targetFilePath)
        {
            if (!File.Exists(targetFilePath))
                throw new FileNotFoundException($"Scan target does not exist: {targetFilePath}");

            if (!File.Exists(_pythonExecutable))
                throw new FileNotFoundException($"Python executable not found at: {_pythonExecutable}");

            var startInfo = new ProcessStartInfo
            {
                FileName = _pythonExecutable,
                Arguments = $"-m src.engine.main --file \"{targetFilePath}\"",
                WorkingDirectory = _projectRoot,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = new Process { StartInfo = startInfo };
            
            process.Start();
            
            string jsonOutput = await process.StandardOutput.ReadToEndAsync();
            string errorOutput = await process.StandardError.ReadToEndAsync();
            
            await process.WaitForExitAsync();

            if (process.ExitCode != 0 && string.IsNullOrWhiteSpace(jsonOutput))
            {
                throw new InvalidOperationException($"Engine Scan Failed (Exit Code {process.ExitCode}): {errorOutput}");
            }

            return JsonConvert.DeserializeObject<ScanReportModel>(jsonOutput);
        }
    }
}