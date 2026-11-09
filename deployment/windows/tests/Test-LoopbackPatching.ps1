$ErrorActionPreference = "Stop"

if ($env:GITHUB_ACTIONS -ne "true" -or $env:RUNNER_ENVIRONMENT -ne "github-hosted" -or $env:RUNNER_OS -ne "Windows") {
    throw "This test changes WinRM configuration and is restricted to disposable GitHub-hosted Windows runners."
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Loopback patching test requires an elevated administrator."
}

$engine = Join-Path $PSScriptRoot "..\..\..\minion-registry\minions\patching\PatchingEngine.psm1"
Import-Module $engine -Force

$id = "sgtest$([guid]::NewGuid().ToString('N'))"
$testDirectory = Join-Path $env:SystemRoot "Temp\$id"
$targetDirectory = Join-Path $env:ProgramData "SluiceGate\Minion\TargetDiary\$id"
$stagingDirectory = Join-Path $env:SystemRoot "Temp\SluiceGate\Staging\$id"
$target = $env:COMPUTERNAME
New-Item -ItemType Directory -Path $testDirectory | Out-Null

try {
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command 'Enable-PSRemoting -Force -SkipNetworkProfileCheck'
    if ($LASTEXITCODE -ne 0) { throw "Failed to enable loopback PowerShell remoting." }
    Invoke-Command -ComputerName $target -ScriptBlock { "WinRM loopback ready" } -ErrorAction Stop | Write-Host
    if (-not (Test-Path -LiteralPath "\\$target\C$")) { throw "Loopback administrative share is unavailable." }

    $marker = Join-Path $testDirectory "marker.txt"
    $patch = Join-Path $testDirectory "test-patch.cmd"
    [System.IO.File]::WriteAllText($patch, "@echo off`r`necho executed>>`"$marker`"`r`nexit /b 0`r`n")
    $diaryPath = Join-Path $testDirectory "mission.json"
    [System.IO.File]::WriteAllText($diaryPath, '{"mission_id":"test","target_processes":[]}')
    $row = [pscustomobject]@{
        patch_path = $patch
        patch_sha256 = (Get-FileHash -LiteralPath $patch -Algorithm SHA256).Hash
        install_command = 'cmd.exe /c ""%PATCHPATH%""'
        plugin_id = "test-plugin"
        patch_id = "test-patch"
    }
    $arguments = @{
        TargetServer = $target
        PatchRow = $row
        MissionId = $id
        Attempt = 1
        ClaimGeneration = 1
        MissionDiaryPath = $diaryPath
        AllowedExecutables = @("cmd.exe")
        TimeoutSeconds = 60
    }

    $result = Invoke-TargetPatchInstall @arguments
    if ($result.status -ne "SUCCESS" -or $result.exit_code -ne 0) {
        throw "Loopback installer failed: $($result | ConvertTo-Json -Depth 8 -Compress)"
    }
    if (@(Get-Content -LiteralPath $marker).Count -ne 1) { throw "Expected one test installer execution." }
    $targetDiary = Get-Content -LiteralPath $result.operation_diary -Raw | ConvertFrom-Json
    if ($targetDiary.status -ne "SUCCEEDED" -or $targetDiary.exit_code -ne 0) { throw "Target diary did not record successful execution." }
    $missionDiary = Get-Content -LiteralPath $diaryPath -Raw | ConvertFrom-Json
    if ($missionDiary.target_processes.Count -ne 1 -or $missionDiary.target_processes[0].status -ne "SUCCEEDED") {
        throw "Mission diary did not record the successful target operation."
    }

    $arguments.Attempt = 2
    $arguments.ClaimGeneration = 2
    $repeated = Invoke-TargetPatchInstall @arguments
    if ($repeated.status -ne "SUCCESS" -or @(Get-Content -LiteralPath $marker).Count -ne 1) {
        throw "Replayed operation did not reuse the completed result: $($repeated | ConvertTo-Json -Depth 8 -Compress)"
    }

    $failurePatch = Join-Path $testDirectory "failure-patch.cmd"
    [System.IO.File]::WriteAllText($failurePatch, "@echo off`r`nexit /b 42`r`n")
    $failureRow = [pscustomobject]@{
        patch_path = $failurePatch
        patch_sha256 = (Get-FileHash -LiteralPath $failurePatch -Algorithm SHA256).Hash
        install_command = 'cmd.exe /c ""%PATCHPATH%""'
        plugin_id = "failure-plugin"
        patch_id = "failure-patch"
    }
    $arguments.PatchRow = $failureRow
    $arguments.Attempt = 1
    $arguments.ClaimGeneration = 1
    $failure = Invoke-TargetPatchInstall @arguments
    if ($failure.status -ne "FAILED" -or $failure.exit_code -ne 42) {
        throw "Installer failure was not reported correctly: $($failure | ConvertTo-Json -Depth 8 -Compress)"
    }
    $failureDiary = Get-Content -LiteralPath $diaryPath -Raw | ConvertFrom-Json
    $failureTarget = @($failureDiary.target_processes | Where-Object { $_.plugin_id -eq "failure-plugin" })
    if ($failureTarget.Count -ne 1 -or $failureTarget[0].status -ne "FAILED" -or $failureTarget[0].error -notmatch "42") {
        throw "Mission diary did not record the installer failure."
    }
    Write-Host "Loopback staging, execution, failure and duplicate prevention passed."
}
finally {
    foreach ($path in @($testDirectory, $targetDirectory, $stagingDirectory)) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
    }
}
