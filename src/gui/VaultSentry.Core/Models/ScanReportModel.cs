using System;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace VaultSentry.Core.Models
{
    public class ScanReportModel
    {
        [JsonProperty("report_header")]
        public ReportHeader Header { get; set; } = new();

        [JsonProperty("assessment")]
        public RiskAssessment Assessment { get; set; } = new();

        [JsonProperty("detailed_scanner_outputs")]
        public DetailedOutputs DetailedOutputs { get; set; } = new();
    }

    public class ReportHeader
    {
        [JsonProperty("platform")]
        public string Platform { get; set; } = string.Empty;

        [JsonProperty("version")]
        public string Version { get; set; } = string.Empty;

        [JsonProperty("file_name")]
        public string FileName { get; set; } = string.Empty;

        [JsonProperty("staged_uuid")]
        public string StagedUuid { get; set; } = string.Empty;

        [JsonProperty("file_size_bytes")]
        public long FileSizeBytes { get; set; }
    }

    public class RiskAssessment
    {
        [JsonProperty("risk_score")]
        public int RiskScore { get; set; }

        [JsonProperty("verdict")]
        public string Verdict { get; set; } = string.Empty;

        [JsonProperty("recommendation")]
        public string Recommendation { get; set; } = string.Empty;

        [JsonProperty("finding_count")]
        public int FindingCount { get; set; }

        [JsonProperty("findings")]
        public List<FindingItem> Findings { get; set; } = new();
    }

    public class FindingItem
    {
        [JsonProperty("severity")]
        public string Severity { get; set; } = string.Empty;

        [JsonProperty("category")]
        public string Category { get; set; } = string.Empty;

        [JsonProperty("finding")]
        public string Title { get; set; } = string.Empty;

        [JsonProperty("explanation")]
        public string Explanation { get; set; } = string.Empty;
    }

    public class DetailedOutputs
    {
        [JsonProperty("identity_integrity")]
        public object? IdentityIntegrity { get; set; }

        [JsonProperty("pe")]
        public object? Pe { get; set; }

        [JsonProperty("document")]
        public object? Document { get; set; }

        [JsonProperty("archive")]
        public object? Archive { get; set; }

        [JsonProperty("malware")]
        public object? Malware { get; set; }

        [JsonProperty("heuristics")]
        public object? Heuristics { get; set; }
    }
}