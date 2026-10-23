using System.Text.Json;
using SluiceGate.Minion;
using Xunit;

namespace SluiceGate.Minion.Tests;

public sealed class StartupValidatorTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("minion-host-tests").FullName;

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private string Runtime(bool complete = true)
    {
        var runtime = Path.Combine(_root, "runtime");
        Directory.CreateDirectory(runtime);
        foreach (var name in new[] { "PatchingMinion.ps1", "PatchingCatalog.psm1", "PatchingEngine.psm1", "SluiceGate.Minion.Core.psm1" })
        {
            if (complete || name != "PatchingEngine.psm1")
            {
                File.WriteAllText(Path.Combine(runtime, name), "# test");
            }
        }
        return runtime;
    }

    private string File_(string name, string content = "x")
    {
        var path = Path.Combine(_root, name);
        File.WriteAllText(path, content);
        return path;
    }

    private string Config(Action<Dictionary<string, object?>>? change = null)
    {
        var settings = new Dictionary<string, object?>
        {
            ["MissionControlUrl"] = "https://sluicegate.example.internal",
            ["MinionId"] = "PATCH-01",
            ["ApiKeyPath"] = File_("api-key.txt", "secret"),
            ["SluiceGatePublicKeyPath"] = File_("sg-public.pem"),
            ["MinionPrivateKeyPath"] = File_("minion-private.pem"),
            ["CatalogPath"] = @"\\fileserver\patchrepo\patch_catalog.csv",
            ["NessusMappingPath"] = @"\\fileserver\patchrepo\nessus_mapping.csv",
            ["NonceStorePath"] = Path.Combine(_root, "nonces.txt"),
        };
        change?.Invoke(settings);
        return File_("minion.config.json", JsonSerializer.Serialize(settings));
    }

    [Fact]
    public void A_complete_installation_has_no_problems()
    {
        Assert.Empty(StartupValidator.Validate(Config(), Runtime()));
    }

    [Fact]
    public void A_missing_runtime_file_is_reported()
    {
        var problems = StartupValidator.Validate(Config(), Runtime(complete: false));
        Assert.Contains(problems, p => p.Contains("PatchingEngine.psm1"));
    }

    [Fact]
    public void A_missing_or_unsupplied_configuration_is_reported()
    {
        Assert.Contains(StartupValidator.Validate(null, Runtime()), p => p.Contains("--config"));
        Assert.Contains(StartupValidator.Validate(Path.Combine(_root, "nope.json"), Runtime()), p => p.Contains("missing"));
    }

    [Fact]
    public void Invalid_json_is_reported()
    {
        var problems = StartupValidator.Validate(File_("bad.json", "{ not json"), Runtime());
        Assert.Contains(problems, p => p.Contains("not valid JSON"));
    }

    [Fact]
    public void Required_settings_are_enforced_case_insensitively()
    {
        var path = Config(settings => { settings.Remove("MinionId"); settings["catalogpath"] = settings["CatalogPath"]; settings.Remove("CatalogPath"); });
        var problems = StartupValidator.Validate(path, Runtime());
        Assert.Contains(problems, p => p.Contains("'MinionId'"));
        Assert.DoesNotContain(problems, p => p.Contains("'CatalogPath'"));
    }

    [Fact]
    public void An_inline_api_key_is_rejected()
    {
        var problems = StartupValidator.Validate(Config(s => s["ApiKey"] = "inline-secret"), Runtime());
        Assert.Contains(problems, p => p.Contains("inline ApiKey"));
        Assert.DoesNotContain(problems, p => p.Contains("inline-secret"));
    }

    [Fact]
    public void Key_files_must_exist_and_the_api_key_file_must_not_be_empty()
    {
        var missing = StartupValidator.Validate(Config(s => s["MinionPrivateKeyPath"] = Path.Combine(_root, "absent.pem")), Runtime());
        Assert.Contains(missing, p => p.Contains("MinionPrivateKeyPath"));

        var empty = StartupValidator.Validate(Config(s => s["ApiKeyPath"] = File_("empty-key.txt", "")), Runtime());
        Assert.Contains(empty, p => p.Contains("empty"));
    }

    [Theory]
    [InlineData("http://sluicegate.example.internal", false, true)]
    [InlineData("http://127.0.0.1:8443", false, true)]
    [InlineData("http://sluicegate.example.internal", true, true)]
    [InlineData("http://127.0.0.1:8443", true, false)]
    [InlineData("https://sluicegate.example.internal", false, false)]
    [InlineData("ftp://sluicegate.example.internal", true, true)]
    [InlineData("not a url", false, true)]
    public void Only_https_or_an_explicitly_allowed_loopback_http_url_is_accepted(string url, bool allowInsecure, bool expectProblem)
    {
        var path = Config(s => { s["MissionControlUrl"] = url; s["AllowInsecureHttp"] = allowInsecure; });
        var problems = StartupValidator.Validate(path, Runtime());
        Assert.Equal(expectProblem, problems.Any(p => p.Contains("MissionControlUrl")));
    }

    [Fact]
    public void A_configured_trusted_certificate_must_exist()
    {
        var problems = StartupValidator.Validate(Config(s => s["TrustedServerCertificatePath"] = Path.Combine(_root, "absent-cert.pem")), Runtime());
        Assert.Contains(problems, p => p.Contains("TrustedServerCertificatePath"));
        Assert.Empty(StartupValidator.Validate(Config(s => s["TrustedServerCertificatePath"] = File_("server.pem")), Runtime()));
    }
}

public class CrashLoopTrackerTests
{
    [Fact]
    public void Five_rapid_exits_in_a_row_trip_the_tracker()
    {
        var tracker = new CrashLoopTracker();
        for (var i = 0; i < 4; i++)
        {
            Assert.False(tracker.RecordExit(TimeSpan.FromSeconds(3)));
        }
        Assert.True(tracker.RecordExit(TimeSpan.FromSeconds(3)));
    }

    [Fact]
    public void A_worker_that_ran_for_a_while_resets_the_count()
    {
        var tracker = new CrashLoopTracker();
        for (var i = 0; i < 4; i++)
        {
            tracker.RecordExit(TimeSpan.FromSeconds(3));
        }
        Assert.False(tracker.RecordExit(TimeSpan.FromMinutes(10)));
        Assert.Equal(0, tracker.ConsecutiveRapidExits);
        Assert.False(tracker.RecordExit(TimeSpan.FromSeconds(3)));
    }
}
