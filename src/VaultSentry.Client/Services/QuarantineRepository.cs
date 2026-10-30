using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using VaultSentry.Client.Models;
using VaultSentry.Core.Models;

namespace VaultSentry.Client.Services
{
    public record DashboardMetrics(int TotalScans, int QuarantinedCount, int CleanCount);

    public record QuarantineItem(
        string QuarantineId,
        string OriginalPath,
        string StagedPath,
        string Status,
        string Sha256,
        string Verdict,
        string CreatedAt);

    /// <summary>
    /// Data Access Layer for VaultSentry SQLite persistence.
    /// Manages quarantine state, historical scan telemetry, granular security findings, and secure payload destruction.
    /// </summary>
    public class QuarantineRepository
    {
        private readonly string _connectionString;

        public QuarantineRepository(string dbPath)
        {
            var dbDir = Path.GetDirectoryName(Path.GetFullPath(dbPath));
            if (!string.IsNullOrEmpty(dbDir) && !Directory.Exists(dbDir))
            {
                Directory.CreateDirectory(dbDir);
            }

            _connectionString = $"Data Source={dbPath}";
            InitializeDatabase();
        }

        private void InitializeDatabase()
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var pragmaCmd = connection.CreateCommand();
            pragmaCmd.CommandText = "PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;";
            pragmaCmd.ExecuteNonQuery();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    quarantine_id TEXT NOT NULL UNIQUE,
                    file_name TEXT NOT NULL,
                    file_size_bytes INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    sha1 TEXT,
                    md5 TEXT,
                    detected_type TEXT,
                    verdict TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    scan_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS quarantine_ledger (
                    quarantine_id TEXT PRIMARY KEY,
                    original_path TEXT NOT NULL,
                    staged_path TEXT NOT NULL,
                    status TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS security_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    quarantine_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    finding TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    FOREIGN KEY(quarantine_id) REFERENCES quarantine_ledger(quarantine_id) ON DELETE CASCADE
                );
            ";
            cmd.ExecuteNonQuery();

            MigrateScanHistorySchema(connection);
        }

        private static void MigrateScanHistorySchema(SqliteConnection connection)
        {
            using var columnsCommand = connection.CreateCommand();
            columnsCommand.CommandText = "PRAGMA table_info(scan_history);";

            bool hasQuarantineId = false;
            using (var reader = columnsCommand.ExecuteReader())
            {
                while (reader.Read())
                {
                    if (string.Equals(reader.GetString(1), "quarantine_id", StringComparison.OrdinalIgnoreCase))
                    {
                        hasQuarantineId = true;
                        break;
                    }
                }
            }

            if (!hasQuarantineId)
            {
                using var alterCommand = connection.CreateCommand();
                alterCommand.CommandText = "ALTER TABLE scan_history ADD COLUMN quarantine_id TEXT;";
                alterCommand.ExecuteNonQuery();
            }

            using var indexCommand = connection.CreateCommand();
            indexCommand.CommandText = @"
                CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_history_quarantine_id
                ON scan_history (quarantine_id);

                UPDATE scan_history
                SET quarantine_id = (
                    SELECT quarantine_ledger.quarantine_id
                    FROM quarantine_ledger
                    WHERE quarantine_ledger.sha256 = scan_history.sha256
                      AND quarantine_ledger.created_at = scan_history.scan_timestamp
                      AND NOT EXISTS (
                          SELECT 1
                          FROM scan_history AS assigned
                          WHERE assigned.quarantine_id = quarantine_ledger.quarantine_id
                      )
                    LIMIT 1
                )
                WHERE quarantine_id IS NULL;
            ";
            indexCommand.ExecuteNonQuery();
        }

        public async Task RecordScanAsync(SecurityReport report, string originalPath, IEnumerable<SecurityFindingModel> findings)
        {
            using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync();

            using var transaction = connection.BeginTransaction();

            try
            {
                // 1. Insert into Ledger
                using (var cmd = connection.CreateCommand())
                {
                    cmd.Transaction = transaction;
                    cmd.CommandText = @"
                        INSERT OR REPLACE INTO quarantine_ledger (quarantine_id, original_path, staged_path, status, sha256)
                        VALUES ($qid, $orig, $staged, $status, $sha256);
                    ";
                    cmd.Parameters.AddWithValue("$qid", report.QuarantineId);
                    cmd.Parameters.AddWithValue("$orig", originalPath);
                    cmd.Parameters.AddWithValue("$staged", report.StagedPath);
                    cmd.Parameters.AddWithValue("$status", report.Verdict == "SAFE" ? "STAGED" : "QUARANTINED");
                    cmd.Parameters.AddWithValue("$sha256", report.Hashes.Sha256);
                    await cmd.ExecuteNonQueryAsync();
                }

                // 2. Insert into Scan History
                using (var cmd = connection.CreateCommand())
                {
                    cmd.Transaction = transaction;
                    cmd.CommandText = @"
                        INSERT OR REPLACE INTO scan_history (quarantine_id, file_name, file_size_bytes, sha256, sha1, md5, detected_type, verdict, risk_score)
                        VALUES ($qid, $name, $size, $sha256, $sha1, $md5, $type, $verdict, $score);
                    ";
                    cmd.Parameters.AddWithValue("$qid", report.QuarantineId);
                    cmd.Parameters.AddWithValue("$name", report.FileName);
                    cmd.Parameters.AddWithValue("$size", report.FileSizeBytes);
                    cmd.Parameters.AddWithValue("$sha256", report.Hashes.Sha256);
                    cmd.Parameters.AddWithValue("$sha1", report.Hashes.Sha1 ?? string.Empty);
                    cmd.Parameters.AddWithValue("$md5", report.Hashes.Md5 ?? string.Empty);
                    cmd.Parameters.AddWithValue("$type", report.Identity?.DetectedType ?? "Unknown");
                    cmd.Parameters.AddWithValue("$verdict", report.Verdict);
                    cmd.Parameters.AddWithValue("$score", report.RiskScore);
                    await cmd.ExecuteNonQueryAsync();
                }

                // 3. Clear existing findings (for rescans) and insert new ones
                using (var deleteCmd = connection.CreateCommand())
                {
                    deleteCmd.Transaction = transaction;
                    deleteCmd.CommandText = "DELETE FROM security_findings WHERE quarantine_id = $qid;";
                    deleteCmd.Parameters.AddWithValue("$qid", report.QuarantineId);
                    await deleteCmd.ExecuteNonQueryAsync();
                }

                foreach (var finding in findings)
                {
                    using var findingCmd = connection.CreateCommand();
                    findingCmd.Transaction = transaction;
                    findingCmd.CommandText = @"
                        INSERT INTO security_findings (quarantine_id, severity, category, finding, explanation)
                        VALUES ($qid, $severity, $category, $finding, $explanation);
                    ";
                    findingCmd.Parameters.AddWithValue("$qid", report.QuarantineId);
                    findingCmd.Parameters.AddWithValue("$severity", finding.Severity);
                    findingCmd.Parameters.AddWithValue("$category", finding.Category);
                    findingCmd.Parameters.AddWithValue("$finding", finding.Finding);
                    findingCmd.Parameters.AddWithValue("$explanation", finding.Explanation);
                    await findingCmd.ExecuteNonQueryAsync();
                }

                await transaction.CommitAsync();
            }
            catch
            {
                await transaction.RollbackAsync();
                throw;
            }
        }

        public async Task<DashboardMetrics> GetDashboardMetricsAsync()
        {
            using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                SELECT 
                    COUNT(*) AS total_scans,
                    SUM(CASE WHEN verdict = 'MALICIOUS' THEN 1 ELSE 0 END) AS quarantined_threats,
                    SUM(CASE WHEN verdict = 'SAFE' THEN 1 ELSE 0 END) AS clean_files
                FROM scan_history;
            ";

            using var reader = await cmd.ExecuteReaderAsync();
            if (await reader.ReadAsync())
            {
                int total = reader.IsDBNull(0) ? 0 : reader.GetInt32(0);
                int quarantined = reader.IsDBNull(1) ? 0 : reader.GetInt32(1);
                int clean = reader.IsDBNull(2) ? 0 : reader.GetInt32(2);
                return new DashboardMetrics(total, quarantined, clean);
            }

            return new DashboardMetrics(0, 0, 0);
        }

        public async Task<List<QuarantineItem>> GetQuarantinedItemsAsync()
        {
            var items = new List<QuarantineItem>();
            using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                SELECT q.quarantine_id, q.original_path, q.staged_path, q.status, q.sha256,
                       COALESCE(h.verdict, 'UNVERIFIED'), q.created_at
                FROM quarantine_ledger AS q
                LEFT JOIN scan_history AS h ON h.quarantine_id = q.quarantine_id
                ORDER BY q.created_at DESC;
            ";

            using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                items.Add(new QuarantineItem(
                    reader.GetString(0),
                    reader.GetString(1),
                    reader.GetString(2),
                    reader.GetString(3),
                    reader.GetString(4),
                    reader.GetString(5),
                    reader.GetString(6)
                ));
            }

            return items;
        }

        public async Task UpdateQuarantineStatusAsync(string quarantineId, string newStatus)
        {
            using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                UPDATE quarantine_ledger
                SET status = $status, updated_at = CURRENT_TIMESTAMP
                WHERE quarantine_id = $qid;
            ";
            cmd.Parameters.AddWithValue("$status", newStatus);
            cmd.Parameters.AddWithValue("$qid", quarantineId);
            int updatedRows = await cmd.ExecuteNonQueryAsync();
            if (updatedRows != 1)
            {
                throw new InvalidOperationException(
                    $"Could not update quarantine status: record '{quarantineId}' was not found.");
            }
        }

        public static async Task ShredFileAsync(string filePath)
        {
            if (!File.Exists(filePath)) return;

            File.SetAttributes(filePath, FileAttributes.Normal);
            var fileLength = new FileInfo(filePath).Length;
            byte[] buffer = new byte[65536];

            using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None))
            {
                long written = 0;
                while (written < fileLength)
                {
                    RandomNumberGenerator.Fill(buffer);
                    int count = (int)Math.Min(buffer.Length, fileLength - written);
                    await stream.WriteAsync(buffer.AsMemory(0, count));
                    written += count;
                }
                await stream.FlushAsync();
            }

            File.Delete(filePath);
        }
    }
}