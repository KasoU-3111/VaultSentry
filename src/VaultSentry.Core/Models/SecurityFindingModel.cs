namespace VaultSentry.Core.Models
{
    /// <summary>
    /// Represents an explainable security finding emitted by the VaultSentry engine.
    /// Shared DTO across Engine IPC, Core Services, and WPF Presentation layers.
    /// </summary>
    public class SecurityFindingModel
    {
        public string Severity { get; set; } = "INFO";
        public string Category { get; set; } = "General";
        public string Finding { get; set; } = "Unspecified Finding";
        public string Explanation { get; set; } = string.Empty;
    }
}