using System;
using System.IO;
using System.Text.Json;

namespace VaultSentry.Client.Models;

public sealed class VaultSentrySettings
{
    public string? Environment { get; init; }
    public EngineSettings? Engine { get; init; }
    public QuarantineSettings? Quarantine { get; init; }

    public static VaultSentrySettings Load(string workspaceRoot)
    {
        string settingsPath = Path.Combine(workspaceRoot, "config", "settings.json");
        if (!File.Exists(settingsPath))
        {
            throw new FileNotFoundException("VaultSentry settings file was not found.", settingsPath);
        }

        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(settingsPath));
        if (document.RootElement.ValueKind != JsonValueKind.Object ||
            !document.RootElement.TryGetProperty("VaultSentry", out JsonElement settingsSection) ||
            settingsSection.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException($"The 'VaultSentry' settings section is missing or invalid in '{settingsPath}'.");
        }

        var settings = JsonSerializer.Deserialize<VaultSentrySettings>(
            settingsSection.GetRawText(),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

        if (settings?.Engine is null ||
            string.IsNullOrWhiteSpace(settings.Engine.RelativePath) ||
            settings.Engine.TimeoutSeconds <= 0)
        {
            throw new InvalidDataException($"Engine settings in '{settingsPath}' are incomplete or invalid.");
        }

        if (settings.Quarantine is null ||
            string.IsNullOrWhiteSpace(settings.Quarantine.StoragePath) ||
            settings.Quarantine.AutoPurgeDays <= 0)
        {
            throw new InvalidDataException($"Quarantine settings in '{settingsPath}' are incomplete or invalid.");
        }

        return settings;
    }

    public string ResolveEnginePath(string workspaceRoot) =>
        ResolveConfiguredPath(workspaceRoot, Engine!.RelativePath!);

    public string ResolveQuarantinePath(string workspaceRoot) =>
        ResolveConfiguredPath(workspaceRoot, Quarantine!.StoragePath!);

    private static string ResolveConfiguredPath(string workspaceRoot, string configuredPath)
    {
        string path = Path.IsPathRooted(configuredPath)
            ? configuredPath
            : Path.Combine(workspaceRoot, configuredPath);

        return Path.GetFullPath(path);
    }

    public sealed class EngineSettings
    {
        public string? RelativePath { get; init; }
        public string? ModuleName { get; init; }
        public int TimeoutSeconds { get; init; }
    }

    public sealed class QuarantineSettings
    {
        public string? StoragePath { get; init; }
        public int AutoPurgeDays { get; init; }
    }
}
