$ErrorActionPreference = "Stop"

if ($env:GITHUB_ACTIONS -ne "true" -or $env:RUNNER_ENVIRONMENT -ne "github-hosted" -or $env:RUNNER_OS -ne "Windows") {
    throw "This test registers a Windows service and is restricted to disposable GitHub-hosted Windows runners."
}
if (Get-Service -Name "SluiceGateMinion" -ErrorAction SilentlyContinue) {
    throw "SluiceGateMinion already exists; refusing to alter it."
}

$directory = Join-Path $env:SystemRoot "Temp\sg-service-test-$([guid]::NewGuid().ToString('N'))"
$runtime = Join-Path $directory "runtime"
$serviceCreated = $false
New-Item -ItemType Directory -Path $runtime -Force | Out-Null
try {
    $hostPath = Join-Path $directory "SluiceGate.Minion.Service.exe"
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot "..\Minion\SluiceGate.Minion.Service.exe") -Destination $hostPath
    foreach ($name in @("PatchingCatalog.psm1", "PatchingEngine.psm1", "SluiceGate.Minion.Core.psm1")) {
        [System.IO.File]::WriteAllText((Join-Path $runtime $name), "")
    }
    $marker = Join-Path $directory "worker.pid"
    $markerLiteral = $marker.Replace("'", "''")
    $worker = @"
param([string]`$ConfigPath)
[System.IO.File]::WriteAllText('$markerLiteral', [string]`$PID)
while (`$true) { Start-Sleep -Seconds 1 }
"@
    [System.IO.File]::WriteAllText((Join-Path $runtime "PatchingMinion.ps1"), $worker)
    foreach ($name in @("api-key.txt", "public.pem", "private.pem")) {
        [System.IO.File]::WriteAllText((Join-Path $directory $name), "test")
    }
    $config = @{
        MissionControlUrl = "http://127.0.0.1:12345"
        AllowInsecureHttp = $true
        MinionId = "SERVICE-TEST"
        ApiKeyPath = Join-Path $directory "api-key.txt"
        SluiceGatePublicKeyPath = Join-Path $directory "public.pem"
        MinionPrivateKeyPath = Join-Path $directory "private.pem"
        CatalogPath = Join-Path $directory "catalog.csv"
        NessusMappingPath = Join-Path $directory "mapping.csv"
        NonceStorePath = Join-Path $directory "nonces.txt"
    }
    $configPath = Join-Path $directory "config.json"
    [System.IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json))

    $binaryPath = "`"$hostPath`" --config `"$configPath`""
    & sc.exe create SluiceGateMinion binPath= $binaryPath start= demand
    if ($LASTEXITCODE -ne 0) { throw "Failed to create test Windows service ($LASTEXITCODE)." }
    $serviceCreated = $true
    Start-Service -Name SluiceGateMinion
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while (-not (Test-Path -LiteralPath $marker) -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 250
    }
    if (-not (Test-Path -LiteralPath $marker)) { throw "Service did not start its PowerShell worker." }
    $workerId = [int][System.IO.File]::ReadAllText($marker)
    if (-not (Get-Process -Id $workerId -ErrorAction SilentlyContinue)) { throw "Service worker exited unexpectedly." }
    Stop-Service -Name SluiceGateMinion
    (Get-Service -Name SluiceGateMinion).WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
    if (Get-Process -Id $workerId -ErrorAction SilentlyContinue) { throw "Stopping the service left its worker running." }
    Write-Host "Service Control Manager start, worker launch and stop passed."
}
finally {
    if ($serviceCreated) {
        $service = Get-Service -Name SluiceGateMinion -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne "Stopped") {
            Stop-Service -Name SluiceGateMinion
            $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
        }
        & sc.exe delete SluiceGateMinion
        if ($LASTEXITCODE -ne 0) { throw "Failed to delete test Windows service ($LASTEXITCODE)." }
    }
    if (Test-Path -LiteralPath $directory) { Remove-Item -LiteralPath $directory -Recurse -Force }
}
