using System.Diagnostics;
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
    private readonly ILogger<MinionWorkerService> _logger;
    private readonly IHostEnvironment _env;

    public MinionWorkerService(ILogger<MinionWorkerService> logger, IHostEnvironment env)
    {
        _logger = logger;
        _env = env;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("SluiceGate Minion Windows Service is starting...");

        var baseDir = AppContext.BaseDirectory;
        var psScript = Path.Combine(baseDir, "PatchingMinion.ps1");
        var configPath = Path.Combine(baseDir, "minion.config.json");

        if (!File.Exists(psScript))
        {
            _logger.LogWarning("PowerShell worker script not found at {Path}. Running in standby loop.", psScript);
            while (!stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(10000, stoppingToken);
            }
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                _logger.LogInformation("Invoking Minion execution pass via PowerShell...");

                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -ExecutionPolicy Bypass -File \"{psScript}\" -ConfigPath \"{configPath}\" -SinglePass",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    WorkingDirectory = baseDir
                };

                using var process = new Process { StartInfo = psi };
                process.OutputDataReceived += (s, e) => { if (e.Data != null) _logger.LogInformation("[Minion] {Msg}", e.Data); };
                process.ErrorDataReceived += (s, e) => { if (e.Data != null) _logger.LogWarning("[Minion Error] {Msg}", e.Data); };

                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                await process.WaitForExitAsync(stoppingToken);
                _logger.LogInformation("Minion pass completed with exit code {Code}.", process.ExitCode);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unhandled exception during Minion pass.");
            }

            // Sleep between cycles (default 1 hour or configured in config)
            await Task.Delay(TimeSpan.FromMinutes(60), stoppingToken);
        }

        _logger.LogInformation("SluiceGate Minion Windows Service has stopped.");
    }
}
