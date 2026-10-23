using System.Diagnostics;
using System.ServiceProcess;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace SluiceGate.Minion;

public class Program
{
    public static async Task Main(string[] args)
    {
        var builder = Host.CreateDefaultBuilder(args)
            .UseWindowsService(options =>
            {
                options.ServiceName = "SluiceGateMinion";
            })
            .ConfigureServices((hostContext, services) =>
            {
                services.AddHostedService<MinionWorkerService>();
            });

        await builder.Build().RunAsync();
    }
}

public class MinionWorkerService : BackgroundService
{
    private static readonly TimeSpan RestartDelay = TimeSpan.FromSeconds(30);

    private readonly ILogger<MinionWorkerService> _logger;
    private readonly IConfiguration _configuration;
    private readonly IHostLifetime _lifetime;
    private readonly IHostApplicationLifetime _applicationLifetime;

    public MinionWorkerService(
        ILogger<MinionWorkerService> logger,
        IConfiguration configuration,
        IHostLifetime lifetime,
        IHostApplicationLifetime applicationLifetime)
    {
        _logger = logger;
        _configuration = configuration;
        _lifetime = lifetime;
        _applicationLifetime = applicationLifetime;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("SluiceGate Minion Windows Service is starting...");

        var runtimeDirectory = Path.Combine(AppContext.BaseDirectory, "runtime");
        var configPath = _configuration["config"];

        var problems = StartupValidator.Validate(configPath, runtimeDirectory);
        if (problems.Count > 0)
        {
            foreach (var problem in problems)
            {
                _logger.LogCritical("Minion startup check failed: {Problem}", problem);
            }
            Fail();
            return;
        }

        var script = Path.Combine(runtimeDirectory, StartupValidator.RuntimeScriptName);
        var tracker = new CrashLoopTracker();
        while (!stoppingToken.IsCancellationRequested)
        {
            Process? process = null;
            var startedAt = DateTime.UtcNow;
            try
            {
                _logger.LogInformation("Starting the Minion worker via PowerShell...");

                var psi = new ProcessStartInfo
                {
                    FileName = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
                    Arguments = $"-NoProfile -ExecutionPolicy Bypass -File \"{script}\" -ConfigPath \"{configPath}\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    WorkingDirectory = runtimeDirectory
                };

                process = new Process { StartInfo = psi };
                process.OutputDataReceived += (s, e) => { if (e.Data != null) _logger.LogInformation("[Minion] {Msg}", e.Data); };
                process.ErrorDataReceived += (s, e) => { if (e.Data != null) _logger.LogWarning("[Minion Error] {Msg}", e.Data); };

                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                await process.WaitForExitAsync(stoppingToken);
                _logger.LogWarning("The Minion worker exited with code {Code}.", process.ExitCode);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                try
                {
                    if (process is { HasExited: false })
                    {
                        process.Kill(entireProcessTree: true);
                        await process.WaitForExitAsync(CancellationToken.None);
                    }
                }
                catch (InvalidOperationException)
                {
                }
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unhandled exception while running the Minion worker.");
            }
            finally
            {
                process?.Dispose();
            }

            if (tracker.RecordExit(DateTime.UtcNow - startedAt))
            {
                _logger.LogCritical(
                    "The Minion worker exited {Count} times in a row within a minute of starting. Stopping the service so the failure is visible; check the log above and the configuration.",
                    tracker.ConsecutiveRapidExits);
                Fail();
                return;
            }

            try
            {
                await Task.Delay(RestartDelay, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        _logger.LogInformation("SluiceGate Minion Windows Service has stopped.");
    }

    // A non-zero service exit code makes the Service Control Manager report a failure and apply its recovery actions.
    private void Fail()
    {
        Environment.ExitCode = 1;
        if (OperatingSystem.IsWindows() && _lifetime is ServiceBase serviceBase)
        {
            serviceBase.ExitCode = 1;
        }
        _applicationLifetime.StopApplication();
    }
}
