using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace VaultSentry.Client.Services;

public sealed record DownloadProgress(long BytesReceived, long? TotalBytes);

public sealed record QuarantineDownloadResult(string FilePath, string FileName, Uri FinalUri);

public sealed class QuarantineDownloadService : IDisposable
{
    public const long MaximumDownloadBytes = 250L * 1024 * 1024;
    private const int MaximumRedirects = 10;
    private readonly HttpClient _httpClient;

    public QuarantineDownloadService()
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = System.Net.DecompressionMethods.None,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5)
        };
        _httpClient = new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
    }

    public async Task<QuarantineDownloadResult> DownloadToQuarantineAsync(
        string sourceUrl,
        string destinationDirectory,
        IProgress<DownloadProgress> progress,
        CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(sourceUrl, UriKind.Absolute, out Uri? uri) ||
            uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException("Enter a complete HTTPS URL. Non-encrypted HTTP downloads are not accepted.", nameof(sourceUrl));
        }

        var responseAndUri = await SendHttpsRequestAsync(uri, cancellationToken);
        using HttpResponseMessage response = responseAndUri.Response;
        Uri finalUri = responseAndUri.FinalUri;
        response.EnsureSuccessStatusCode();

        long? totalBytes = response.Content.Headers.ContentLength;
        if (totalBytes > MaximumDownloadBytes)
        {
            throw new InvalidOperationException(
                $"The file exceeds VaultSentry's {MaximumDownloadBytes / (1024 * 1024)} MB download limit.");
        }

        string fileName = GetSafeFileName(response, finalUri);
        Directory.CreateDirectory(destinationDirectory);
        string destinationPath = Path.Combine(destinationDirectory, fileName);

        try
        {
            await using Stream input = await response.Content.ReadAsStreamAsync(cancellationToken);
            await using var output = new FileStream(
                destinationPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                65536,
                FileOptions.Asynchronous | FileOptions.SequentialScan);

            var buffer = new byte[65536];
            long bytesReceived = 0;
            int bytesRead;
            while ((bytesRead = await input.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)) > 0)
            {
                bytesReceived += bytesRead;
                if (bytesReceived > MaximumDownloadBytes)
                {
                    throw new InvalidOperationException(
                        $"The download exceeded VaultSentry's {MaximumDownloadBytes / (1024 * 1024)} MB limit.");
                }

                await output.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);
                progress.Report(new DownloadProgress(bytesReceived, totalBytes));
            }

            await output.FlushAsync(cancellationToken);
            return new QuarantineDownloadResult(destinationPath, fileName, finalUri);
        }
        catch (Exception downloadException)
        {
            try
            {
                if (File.Exists(destinationPath))
                {
                    File.Delete(destinationPath);
                }
            }
            catch (Exception cleanupException)
            {
                throw new IOException(
                    $"Download failed and its partial quarantine file could not be removed: {cleanupException.Message}",
                    new AggregateException(downloadException, cleanupException));
            }
            throw;
        }
    }

    private async Task<(HttpResponseMessage Response, Uri FinalUri)> SendHttpsRequestAsync(
        Uri initialUri,
        CancellationToken cancellationToken)
    {
        Uri currentUri = initialUri;
        for (int redirectCount = 0; ; redirectCount++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, currentUri);
            HttpResponseMessage response = await _httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);

            if (!IsRedirect(response.StatusCode))
            {
                return (response, currentUri);
            }

            Uri? location = response.Headers.Location;
            response.Dispose();
            if (location is null)
            {
                throw new InvalidOperationException("The HTTPS server returned a redirect without a destination.");
            }

            Uri nextUri = location.IsAbsoluteUri ? location : new Uri(currentUri, location);
            if (nextUri.Scheme != Uri.UriSchemeHttps)
            {
                throw new InvalidOperationException("The HTTPS download attempted to redirect to a non-HTTPS URL; the request was blocked.");
            }

            if (redirectCount >= MaximumRedirects)
            {
                throw new InvalidOperationException($"The HTTPS download exceeded the {MaximumRedirects}-redirect limit.");
            }

            currentUri = nextUri;
        }
    }

    private static bool IsRedirect(System.Net.HttpStatusCode statusCode) =>
        statusCode is System.Net.HttpStatusCode.MovedPermanently
            or System.Net.HttpStatusCode.Redirect
            or System.Net.HttpStatusCode.RedirectMethod
            or System.Net.HttpStatusCode.TemporaryRedirect
            or System.Net.HttpStatusCode.PermanentRedirect;

    private static string GetSafeFileName(HttpResponseMessage response, Uri finalUri)
    {
        string? candidate = response.Content.Headers.ContentDisposition?.FileNameStar
            ?? response.Content.Headers.ContentDisposition?.FileName;
        candidate = candidate?.Trim().Trim('"');

        if (string.IsNullOrWhiteSpace(candidate))
        {
            candidate = Path.GetFileName(Uri.UnescapeDataString(finalUri.AbsolutePath));
        }

        string fileName = Path.GetFileName(candidate);
        char[] invalidCharacters = Path.GetInvalidFileNameChars();
        fileName = new string(fileName.Select(character =>
            invalidCharacters.Contains(character) || char.IsControl(character) ? '_' : character).ToArray()).Trim();

        if (string.IsNullOrWhiteSpace(fileName) || fileName is "." or "..")
        {
            return "downloaded-file";
        }

        return fileName;
    }

    public void Dispose() => _httpClient.Dispose();
}
