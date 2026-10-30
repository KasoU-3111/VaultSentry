using System;
using System.Collections.Generic;
using System.Linq;
using VaultSentry.Core.Models;

namespace VaultSentry.Client.Services;

public sealed record PlainLanguageAssessment(
    string Summary,
    string Recommendation,
    string Limitation,
    IReadOnlyList<string> Evidence);

public static class PlainLanguageAssessmentService
{
    private const string StaticAnalysisLimitation =
        "";

    public static PlainLanguageAssessment Create(
        string verdict,
        int riskScore,
        string detectedType,
        IEnumerable<SecurityFindingModel> findings,
        string? engineRecommendation = null)
    {
        ArgumentNullException.ThrowIfNull(findings);
        string normalizedVerdict = (verdict ?? string.Empty).Trim().ToUpperInvariant();
        List<SecurityFindingModel> evidence = findings.ToList();

        string summary = normalizedVerdict switch
        {
            "SAFE" => $"VaultSentry did not find enough concerning signals to flag this {DescribeType(detectedType)} (risk score {riskScore}/100). This means it passed the checks available in this scan—not that it is guaranteed safe.",
            "SUSPICIOUS" => $"VaultSentry found unusual or concerning signals in this {DescribeType(detectedType)} (risk score {riskScore}/100). Those signals are not proof of malware, but the file should stay in quarantine until you decide what to do.",
            "MALICIOUS" => $"VaultSentry found strong warning signs in this {DescribeType(detectedType)} and classified it as malicious (risk score {riskScore}/100). Do not open or run it; deletion is the safer choice.",
            "ERROR" => "VaultSentry could not complete a reliable assessment. Treat this file as unreviewed and keep it in quarantine until a scan succeeds.",
            _ => $"VaultSentry returned the verdict {normalizedVerdict} (risk score {riskScore}/100). Review the signals below before deciding what to do."
        };

        string recommendation = normalizedVerdict switch
        {
            "SAFE" => "If you choose to release it, continue to use normal operating-system protections and only open files you expected to receive.",
            "SUSPICIOUS" => "Keep it quarantined while you verify where it came from. Release it only if you understand and accept the risk.",
            "MALICIOUS" => "Keep it quarantined and delete it. Do not release or execute it.",
            "ERROR" => "Keep the file quarantined and try the scan again. Do not treat an incomplete scan as a safe result.",
            _ => string.IsNullOrWhiteSpace(engineRecommendation)
                ? "Review the detailed findings and keep the file quarantined if you are unsure."
                : engineRecommendation
        };

        List<string> explanations = evidence
            .Select(ExplainFinding)
            .Where(explanation => !string.IsNullOrWhiteSpace(explanation))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (explanations.Count == 0)
        {
            explanations.Add(normalizedVerdict == "SAFE"
                ? "No specific warning signals were reported by this scan."
                : "The engine did not provide specific finding details for this verdict.");
        }

        return new PlainLanguageAssessment(summary, recommendation, StaticAnalysisLimitation, explanations);
    }

    private static string DescribeType(string? detectedType) =>
        string.IsNullOrWhiteSpace(detectedType) || detectedType.Equals("Unknown", StringComparison.OrdinalIgnoreCase)
            ? "file"
            : detectedType.Trim();

    private static string ExplainFinding(SecurityFindingModel finding)
    {
        string title = finding.Finding ?? string.Empty;
        string combined = $"{title} {finding.Explanation}".ToLowerInvariant();

        string explanation = combined switch
        {
            var value when value.Contains("header vs extension mismatch") =>
                "The file's actual contents do not match the type suggested by its name. A mismatch can be used to disguise what a file really is.",
            var value when value.Contains("double extension") =>
                "The filename uses more than one extension (for example, a document-looking name ending in .exe), which can mislead someone about what will open.",
            var value when value.Contains("yara") || value.Contains("clamav") || value.Contains("signature detection") =>
                "A malware-signature scanner matched a known suspicious pattern in the file. A signature match is a strong reason to keep it isolated.",
            var value when value.Contains("macro auto-execution") =>
                "The document contains a macro trigger that may cause embedded code to run automatically when opened.",
            var value when value.Contains("executable/script embedded in pdf") =>
                "The PDF contains embedded executable or script content, which is not expected in an ordinary document and could perform actions when opened in a vulnerable reader.",
            var value when value.Contains("embedded file attachment") =>
                "The document contains embedded attachments. Those attachments may have their own risks and were identified as part of this scan.",
            var value when value.Contains("archive path traversal") || value.Contains("zip slip") =>
                "An archive entry appears to use a path that could escape the chosen extraction folder if unpacked by unsafe software.",
            var value when value.Contains("zip bomb") || value.Contains("file count exceeded") =>
                "The archive contains an unusually large number of entries or may expand excessively, which can overwhelm software or a device when unpacked.",
            var value when value.Contains("entropy") || value.Contains("packer") || value.Contains("packed") =>
                "Some file data looks unusually compressed, encrypted, or obscured. This can occur for legitimate reasons, but it can also hide what the file contains.",
            var value when value.Contains("malformed") || value.Contains("corrupted") || value.Contains("invalid structure") =>
                "The file's internal structure could not be read as expected. It may be damaged, unusual, or deliberately crafted to avoid inspection.",
            var value when value.Contains("right-to-left override") =>
                "The filename uses a text-direction trick that can make its extension appear different from what it really is.",
            var value when value.Contains("critical system binary impersonation") =>
                "The file appears to imitate the name or identity of an important system component. That can be used to make a suspicious file look trustworthy.",
            var value when value.Contains("obfuscated") || value.Contains("base64") =>
                "Part of the file contains concealed or encoded text. This can hide commands from a person reading the file.",
            var value when value.Contains("process injection") =>
                "The file contains indicators associated with techniques that place code inside another running program. This behavior is commonly treated as high risk.",
            var value when value.Contains("motw") =>
                "The file may avoid or remove a Windows downloaded-file warning marker, which can reduce a user's visible warning when opening it.",
            var value when value.Contains("autorun") =>
                "The file contains an AutoRun configuration that could trigger actions automatically on systems or software that honor it.",
            _ => BuildGeneralExplanation(finding)
        };

        string severity = (finding.Severity ?? string.Empty).Trim().ToUpperInvariant();
        return severity switch
        {
            "CRITICAL" or "HIGH" => $"High-priority signal: {explanation}",
            "MEDIUM" => $"Caution: {explanation}",
            "LOW" => $"Minor signal: {explanation}",
            _ => explanation
        };
    }

    private static string BuildGeneralExplanation(SecurityFindingModel finding)
    {
        string category = string.IsNullOrWhiteSpace(finding.Category) ? "file analysis" : finding.Category.Trim();
        string title = string.IsNullOrWhiteSpace(finding.Finding) ? "an unusual condition" : finding.Finding.Trim();
        return $"The {category} check reported “{title}”. This signal contributed to the overall assessment; the technical details are available in the findings table.";
    }
}
