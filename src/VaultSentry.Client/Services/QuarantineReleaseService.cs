using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace VaultSentry.Client.Services;

public sealed class QuarantineReleaseService
{
    private readonly string _releasedFilesDirectory;
    private readonly QuarantineRepository _repository;

    public QuarantineReleaseService(
        DownloadIngressOptions ingressOptions,
        QuarantineRepository repository)
    {
        ArgumentNullException.ThrowIfNull(ingressOptions);
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _releasedFilesDirectory = Path.Combine(ingressOptions.QuarantineStoragePath, "Released-Files");
        Directory.CreateDirectory(_releasedFilesDirectory);
    }

    public string ReleasedFilesDirectory => _releasedFilesDirectory;

    public async Task<string> ReleaseAsync(
        string quarantineId,
        string stagedPath,
        string fileName)
    {
        if (string.IsNullOrWhiteSpace(quarantineId))
        {
            throw new ArgumentException("A quarantine ID is required to release a file.", nameof(quarantineId));
        }

        if (string.IsNullOrWhiteSpace(stagedPath))
        {
            throw new ArgumentException("A staged file path is required to release a file.", nameof(stagedPath));
        }

        if (!File.Exists(stagedPath))
        {
            throw new FileNotFoundException("The staged quarantine file is missing; nothing was released.", stagedPath);
        }

        Directory.CreateDirectory(_releasedFilesDirectory);
        string safeFileName = GetSafeFileName(fileName);
        string destinationPath = GetNonConflictingPath(_releasedFilesDirectory, safeFileName);

        File.Copy(stagedPath, destinationPath, overwrite: false);
        try
        {
            File.SetAttributes(destinationPath, FileAttributes.Normal);
            File.SetAttributes(stagedPath, FileAttributes.Normal);
            File.Delete(stagedPath);
            await _repository.UpdateQuarantineStatusAsync(quarantineId, "RELEASED");
            return destinationPath;
        }
        catch (Exception releaseException)
        {
            try
            {
                if (!File.Exists(stagedPath) && File.Exists(destinationPath))
                {
                    File.Copy(destinationPath, stagedPath, overwrite: false);
                }

                if (File.Exists(destinationPath))
                {
                    File.Delete(destinationPath);
                }
            }
            catch (Exception rollbackException)
            {
                throw new IOException(
                    $"Release failed and rollback was incomplete. The staged file is '{stagedPath}' and the release copy is '{destinationPath}'.",
                    new AggregateException(releaseException, rollbackException));
            }

            throw;
        }
    }

    private static string GetSafeFileName(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName))
        {
            throw new ArgumentException("The report does not contain a valid file name.", nameof(fileName));
        }

        string candidate = Path.GetFileName(fileName);
        char[] invalidCharacters = Path.GetInvalidFileNameChars();
        candidate = new string(candidate.Select(character =>
            invalidCharacters.Contains(character) || char.IsControl(character) ? '_' : character).ToArray()).Trim();

        if (string.IsNullOrWhiteSpace(candidate) || candidate is "." or "..")
        {
            throw new ArgumentException("The report does not contain a valid file name.", nameof(fileName));
        }

        return candidate;
    }

    private static string GetNonConflictingPath(string directory, string fileName)
    {
        string destination = Path.Combine(directory, fileName);
        int counter = 1;
        while (File.Exists(destination))
        {
            string name = Path.GetFileNameWithoutExtension(fileName);
            string extension = Path.GetExtension(fileName);
            destination = Path.Combine(directory, $"{name} ({counter}){extension}");
            counter++;
        }

        return destination;
    }
}
