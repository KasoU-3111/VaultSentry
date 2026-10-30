using System;
using System.Collections.ObjectModel;
using System.Text.Json;
using VaultSentry.Client.Services;
using VaultSentry.Client.Utils;
using VaultSentry.Core.Models; // Resolves CS0246 for SecurityFindingModel

namespace VaultSentry.Client.ViewModels
{
    /// <summary>
    /// ViewModel managing the File Analysis dashboard view.
    /// Binds security verdict badges, risk scores, cryptographic hashes, and findings DataGrid.
    /// </summary>
    public class FileAnalysisViewModel : ViewModelBase
    {
        private string _targetFilePath = string.Empty;
        private string _errorMessage = string.Empty;
        private bool _hasError;
        private bool _isScanning;

        private string _identifiedType = "Unknown File Type";
        private string _sha256Hash = "N/A";
        private string _verdict = "SAFE";
        private int _riskScore = 0;
        private string _securityRecommendation = "No scan performed.";
        private PlainLanguageAssessment? _humanAssessment;

        public ObservableCollection<SecurityFindingModel> Findings { get; } = new ObservableCollection<SecurityFindingModel>();

        public PlainLanguageAssessment? HumanAssessment
        {
            get => _humanAssessment;
            private set => SetProperty(ref _humanAssessment, value);
        }

        public string TargetFilePath
        {
            get => _targetFilePath;
            set => SetProperty(ref _targetFilePath, value ?? string.Empty);
        }

        public string ErrorMessage
        {
            get => _errorMessage;
            set
            {
                if (SetProperty(ref _errorMessage, value ?? string.Empty))
                {
                    HasError = !string.IsNullOrWhiteSpace(_errorMessage);
                }
            }
        }

        public bool HasError
        {
            get => _hasError;
            private set => SetProperty(ref _hasError, value);
        }

        public bool IsScanning
        {
            get => _isScanning;
            set => SetProperty(ref _isScanning, value);
        }

        public string IdentifiedType
        {
            get => _identifiedType;
            set => SetProperty(ref _identifiedType, string.IsNullOrWhiteSpace(value) ? "Unknown File Type" : value);
        }

        public string Sha256Hash
        {
            get => _sha256Hash;
            set => SetProperty(ref _sha256Hash, string.IsNullOrWhiteSpace(value) ? "N/A" : value);
        }

        public string Verdict
        {
            get => _verdict;
            set => SetProperty(ref _verdict, string.IsNullOrWhiteSpace(value) ? "SAFE" : value);
        }

        public int RiskScore
        {
            get => _riskScore;
            set => SetProperty(ref _riskScore, Math.Clamp(value, 0, 100));
        }

        public string SecurityRecommendation
        {
            get => _securityRecommendation;
            set => SetProperty(ref _securityRecommendation, string.IsNullOrWhiteSpace(value) ? "No recommendation provided." : value);
        }

        /// <summary>
        /// Safely parses engine JSON output into strongly-typed WPF ViewModel properties.
        /// Evaluates both explicit 'status' envelope and payload completeness.
        /// </summary>
        public void PopulateFromScanResultJson(string jsonResponse)
        {
            try
            {
                ErrorMessage = string.Empty;
                Findings.Clear();
                HumanAssessment = null;

                if (string.IsNullOrWhiteSpace(jsonResponse))
                {
                    ErrorMessage = "Scan Engine Failure: Empty response received from analysis engine.";
                    return;
                }

                var jsonOptions = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                };
                jsonOptions.Converters.Add(new NullToEmptyStringJsonConverter());

                using var doc = JsonDocument.Parse(jsonResponse);
                var root = doc.RootElement;

                if (root.ValueKind != JsonValueKind.Object)
                {
                    ErrorMessage = "Invalid Response Format: Expected JSON object from engine.";
                    return;
                }

                // Check for Explicit Engine Error Response
                if (root.TryGetProperty("status", out var statusProp) && 
                    statusProp.ValueKind == JsonValueKind.String && 
                    statusProp.GetString() == "ERROR")
                {
                    ErrorMessage = root.TryGetProperty("message", out var msgProp) && msgProp.ValueKind == JsonValueKind.String
                        ? msgProp.GetString() ?? "Engine execution failure."
                        : "Engine execution failure.";
                    Verdict = "ERROR";
                    RiskScore = 0;
                    return;
                }

                // Robust Validation: Ensure valid scan result payload is present
                bool hasVerdict = root.TryGetProperty("verdict", out var vProp) && vProp.ValueKind == JsonValueKind.String;
                bool hasRiskScore = root.TryGetProperty("risk_score", out var rsProp) && rsProp.ValueKind == JsonValueKind.Number;

                if (!hasVerdict || !hasRiskScore)
                {
                    ErrorMessage = "The analysis engine returned an incomplete report payload.";
                    Verdict = "ERROR";
                    RiskScore = 0;
                    return;
                }

                // 1. Identity Verification
                if (root.TryGetProperty("identity", out var identityProp) && identityProp.ValueKind == JsonValueKind.Object)
                {
                    IdentifiedType = identityProp.TryGetProperty("detected_type", out var dt) && dt.ValueKind == JsonValueKind.String
                        ? dt.GetString() ?? "Unknown File Type"
                        : "Unknown File Type";
                }
                else
                {
                    IdentifiedType = "Unknown File Type";
                }

                // 2. Cryptographic Hashes
                if (root.TryGetProperty("hashes", out var hashesProp) && hashesProp.ValueKind == JsonValueKind.Object)
                {
                    Sha256Hash = hashesProp.TryGetProperty("sha256", out var hash) && hash.ValueKind == JsonValueKind.String
                        ? hash.GetString() ?? "N/A"
                        : "N/A";
                }
                else
                {
                    Sha256Hash = "N/A";
                }

                // 3. Risk Assessment & Verdict
                Verdict = vProp.GetString() ?? "SAFE";
                RiskScore = rsProp.GetInt32();

                SecurityRecommendation = root.TryGetProperty("recommendation", out var rec) && rec.ValueKind == JsonValueKind.String
                    ? rec.GetString() ?? "No recommendation provided."
                    : "No recommendation provided.";

                // 4. Populate Explainable Security Findings Grid
                if (root.TryGetProperty("findings", out var findingsProp) && findingsProp.ValueKind == JsonValueKind.Array)
                {
                    foreach (var elem in findingsProp.EnumerateArray())
                    {
                        if (elem.ValueKind != JsonValueKind.Object) continue;

                        var severity = elem.TryGetProperty("severity", out var s) && s.ValueKind == JsonValueKind.String
                            ? s.GetString() ?? "INFO"
                            : "INFO";

                        var category = elem.TryGetProperty("category", out var c) && c.ValueKind == JsonValueKind.String
                            ? c.GetString() ?? "General"
                            : "General";

                        var finding = elem.TryGetProperty("finding", out var f) && f.ValueKind == JsonValueKind.String
                            ? f.GetString() ?? "Finding"
                            : "Finding";

                        var explanation = elem.TryGetProperty("explanation", out var exp) && exp.ValueKind == JsonValueKind.String
                            ? exp.GetString() ?? string.Empty
                            : string.Empty;

                        Findings.Add(new SecurityFindingModel
                        {
                            Severity = severity,
                            Category = category,
                            Finding = finding,
                            Explanation = explanation
                        });
                    }
                }

                HumanAssessment = PlainLanguageAssessmentService.Create(
                    Verdict,
                    RiskScore,
                    IdentifiedType,
                    Findings,
                    SecurityRecommendation);
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Scan Response Parsing Error: {ex.Message}";
                Verdict = "ERROR";
                RiskScore = 0;
            }
        }
    }
}