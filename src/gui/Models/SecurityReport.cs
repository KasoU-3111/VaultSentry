using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VaultSentry.Client.Models;

public record SecurityFinding(
    [property: JsonPropertyName("severity")] string Severity,
    [property: JsonPropertyName("category")] string Category,
    [property: JsonPropertyName("finding")] string Finding,
    [property: JsonPropertyName("explanation")] string Explanation
);

public record FileHashes(
    [property: JsonPropertyName("sha256")] string Sha256,
    [property: JsonPropertyName("sha1")] string Sha1,
    [property: JsonPropertyName("md5")] string Md5
);

public record FileIdentity(
    [property: JsonPropertyName("detected_type")] string DetectedType,
    [property: JsonPropertyName("mime_type")] string MimeType,
    [property: JsonPropertyName("magic_hex")] string MagicHex,
    [property: JsonPropertyName("family")] string Family
);

public record SecurityReport(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("file_name")] string FileName,
    [property: JsonPropertyName("file_size_bytes")] long FileSizeBytes,
    [property: JsonPropertyName("quarantine_id")] string QuarantineId,
    [property: JsonPropertyName("staged_path")] string StagedPath,
    [property: JsonPropertyName("hashes")] FileHashes Hashes,
    [property: JsonPropertyName("identity")] FileIdentity Identity,
    [property: JsonPropertyName("verdict")] string Verdict,
    [property: JsonPropertyName("risk_score")] int RiskScore,
    [property: JsonPropertyName("recommendation")] string Recommendation,
    [property: JsonPropertyName("finding_count")] int FindingCount,
    [property: JsonPropertyName("findings")] List<SecurityFinding> Findings
);

public record QuarantineItem(
    string QuarantineId,
    string OriginalPath,
    string StagedPath,
    string Status,
    string Sha256,
    string CreatedAt
);