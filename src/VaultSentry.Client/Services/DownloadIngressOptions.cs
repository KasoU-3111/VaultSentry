namespace VaultSentry.Client.Services;

public sealed record DownloadIngressOptions(
    string DropZonePath,
    string QuarantineStoragePath,
    string WorkspaceRoot);
