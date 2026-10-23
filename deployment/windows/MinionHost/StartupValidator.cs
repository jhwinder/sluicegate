using System.Text.Json;

namespace SluiceGate.Minion;

public static class StartupValidator
{
    public const string RuntimeScriptName = "PatchingMinion.ps1";

    private static readonly string[] RuntimeFiles =
    {
        RuntimeScriptName,
        "PatchingCatalog.psm1",
        "PatchingEngine.psm1",
        "SluiceGate.Minion.Core.psm1",
    };

    private static readonly string[] RequiredSettings =
    {
        "MissionControlUrl", "MinionId", "ApiKeyPath", "SluiceGatePublicKeyPath",
        "MinionPrivateKeyPath", "CatalogPath", "NessusMappingPath", "NonceStorePath",
    };

    private static readonly string[] RequiredFileSettings = { "ApiKeyPath", "SluiceGatePublicKeyPath", "MinionPrivateKeyPath" };

    /// <summary>Returns every problem that would stop the worker from running; empty means the installation is usable.</summary>
    public static IReadOnlyList<string> Validate(string? configPath, string runtimeDirectory)
    {
        var errors = new List<string>();
        foreach (var file in RuntimeFiles)
        {
            var path = Path.Combine(runtimeDirectory, file);
            if (!File.Exists(path))
            {
                errors.Add($"Minion runtime file is missing: {path}");
            }
        }

        if (string.IsNullOrWhiteSpace(configPath))
        {
            errors.Add("No configuration file was supplied; the service must start with --config <path>.");
            return errors;
        }
        if (!File.Exists(configPath))
        {
            errors.Add($"Configuration file is missing: {configPath}");
            return errors;
        }

        Dictionary<string, JsonElement> settings;
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(configPath));
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                errors.Add($"Configuration file must contain a JSON object: {configPath}");
                return errors;
            }
            settings = document.RootElement.EnumerateObject()
                .ToDictionary(property => property.Name, property => property.Value.Clone(), StringComparer.OrdinalIgnoreCase);
        }
        catch (JsonException ex)
        {
            errors.Add($"Configuration file is not valid JSON ({configPath}): {ex.Message}");
            return errors;
        }

        if (settings.ContainsKey("ApiKey"))
        {
            errors.Add("An inline ApiKey is not supported. Set ApiKeyPath to a protected key file.");
        }

        foreach (var name in RequiredSettings)
        {
            if (TextOf(settings, name) is null)
            {
                errors.Add($"Configuration setting '{name}' is required.");
            }
        }

        var url = TextOf(settings, "MissionControlUrl");
        if (url is not null)
        {
            var allowInsecure = settings.TryGetValue("AllowInsecureHttp", out var flag) && flag.ValueKind == JsonValueKind.True;
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                errors.Add("MissionControlUrl is not a valid absolute URL.");
            }
            else if (uri.Scheme != Uri.UriSchemeHttps && !(uri.Scheme == Uri.UriSchemeHttp && allowInsecure && uri.IsLoopback))
            {
                errors.Add("MissionControlUrl must use https. Plain http is allowed only for a loopback development endpoint with AllowInsecureHttp enabled.");
            }
        }

        foreach (var name in RequiredFileSettings)
        {
            var path = TextOf(settings, name);
            if (path is not null && !File.Exists(path))
            {
                errors.Add($"The file named by '{name}' does not exist: {path}");
            }
        }
        var apiKeyPath = TextOf(settings, "ApiKeyPath");
        if (apiKeyPath is not null && File.Exists(apiKeyPath) && new FileInfo(apiKeyPath).Length == 0)
        {
            errors.Add($"The API key file is empty: {apiKeyPath}");
        }

        var trustedCertificate = TextOf(settings, "TrustedServerCertificatePath");
        if (trustedCertificate is not null && !File.Exists(trustedCertificate))
        {
            errors.Add($"The file named by 'TrustedServerCertificatePath' does not exist: {trustedCertificate}");
        }

        return errors;
    }

    private static string? TextOf(Dictionary<string, JsonElement> settings, string name)
    {
        if (settings.TryGetValue(name, out var value) && value.ValueKind == JsonValueKind.String)
        {
            var text = value.GetString();
            return string.IsNullOrWhiteSpace(text) ? null : text;
        }
        return null;
    }
}
