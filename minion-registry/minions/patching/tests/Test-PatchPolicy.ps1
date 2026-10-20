$ErrorActionPreference = "Stop"

$enginePath = Join-Path $PSScriptRoot "..\PatchingEngine.psm1"
Import-Module $enginePath -Force

function Assert-Equal {
    param(
        [object]$Actual,
        [object]$Expected,
        [string]$Message
    )
    if ($Actual -ne $Expected) {
        throw "$Message (expected '$Expected', got '$Actual')"
    }
}

$obligation = [pscustomobject]@{
    type = "allowed_patch_executables"
    data = [pscustomobject]@{ executables = @("msiexec") }
}
$allowed = @(Get-AllowedPatchExecutables -Obligations @($obligation))
Assert-Equal $allowed.Count 1 "Expected one policy-authorized executable"
Assert-Equal $allowed[0] "msiexec.exe" "Expected extension normalization"

$parts = Get-PatchCommandParts -Command '"msiexec.exe" /i "%PATCHPATH%" /qn'
Assert-Equal $parts.Executable "msiexec.exe" "Expected quoted executable parsing"
if ($parts.Arguments -notmatch "%PATCHPATH%") {
    throw "Expected the patch path token to remain in the arguments"
}

$pathRejected = $false
try {
    Get-PatchCommandParts -Command 'C:\Temp\msiexec.exe /i package.msi' | Out-Null
}
catch {
    $pathRejected = $true
}
Assert-Equal $pathRejected $true "Expected executable paths to be rejected"

$securityUpdate = [pscustomobject]@{
    Categories = @(
        [pscustomobject]@{ CategoryID = "11111111-1111-1111-1111-111111111111"; Type = 2 },
        [pscustomobject]@{ CategoryID = "0FA1201D-4330-4FA8-8AE9-B877473B6441"; Type = 3 }
    )
    InstallationBehavior = [pscustomobject]@{ RebootBehavior = 0 }
}
$otherUpdate = [pscustomobject]@{
    Categories = @([pscustomobject]@{ CategoryID = "11111111-1111-1111-1111-111111111111"; Type = 3 })
    InstallationBehavior = [pscustomobject]@{ RebootBehavior = 2 }
}
$featureUpdate = [pscustomobject]@{
    Categories = @([pscustomobject]@{ CategoryID = "B54E7D24-7ADD-428F-8B75-90A396FA584F"; Type = 3 })
    InstallationBehavior = [pscustomobject]@{ RebootBehavior = 0 }
}
$driverUpdate = [pscustomobject]@{
    Categories = @([pscustomobject]@{ CategoryID = "EBFC1FC5-71A4-4F7B-9ACA-3B9A503104A0"; Type = 3 })
    InstallationBehavior = [pscustomobject]@{ RebootBehavior = 0 }
}
$unknownUpdate = [pscustomobject]@{
    Categories = @()
    InstallationBehavior = [pscustomobject]@{}
}
Assert-Equal (Test-WuaSecurityUpdate $securityUpdate) $true "Expected Security Updates classification"
Assert-Equal (Test-WuaSecurityUpdate $otherUpdate) $false "Expected non-security classification rejection"
Assert-Equal (Get-WuaPatchType $featureUpdate) "FEATURE" "Expected Feature Packs mapping"
Assert-Equal (Get-WuaPatchType $driverUpdate) "DRIVER" "Expected driver mapping"
Assert-Equal (Get-WuaPatchType $otherUpdate) "UNKNOWN" "Expected unmapped classification to be unknown"
Assert-Equal (Test-WuaPatchTypeAllowed $featureUpdate @("FEATURE")) $true "Expected policy to allow mapped feature updates"
Assert-Equal (Test-WuaPatchTypeAllowed $featureUpdate @("SECURITY")) $false "Expected policy to filter disallowed feature updates"
Assert-Equal (Test-WuaPatchTypeAllowed $otherUpdate @("UNKNOWN")) $false "Expected unknown metadata to fail closed"
Assert-Equal (Get-WuaRebootBehavior $securityUpdate) 0 "Expected no-reboot metadata"
Assert-Equal (Get-WuaRebootBehavior $otherUpdate) 2 "Expected always-reboot metadata"
Assert-Equal (Get-WuaRebootBehavior $unknownUpdate) $null "Expected unknown reboot metadata to fail closed"
Assert-Equal (Test-MissionMaintenanceWindow $null) $true "Expected no interval to be unrestricted by time"
Assert-Equal (Test-MissionMaintenanceWindow ([pscustomobject]@{ start_utc = "2999-01-01T00:00:00Z"; end_utc = "3000-01-01T00:00:00Z" })) $false "Expected future interval to be closed"
Assert-Equal (Test-MissionMaintenanceWindow ([pscustomobject]@{ start_utc = "invalid"; end_utc = "3000-01-01T00:00:00Z" })) $false "Expected invalid interval to fail closed"
Assert-Equal (Test-MissionMaintenanceWindow ([pscustomobject]@{ start_utc = "2999-01-01T00:00:00-07:00"; end_utc = "3000-01-01T00:00:00Z" })) $false "Expected non-UTC interval to fail closed"

$missionDiaryPath = Join-Path ([System.IO.Path]::GetTempPath()) "sluice-mission-diary-$([guid]::NewGuid().ToString('N')).json"
$targetDiaryPath = Join-Path ([System.IO.Path]::GetTempPath()) "sluice-target-diary-$([guid]::NewGuid().ToString('N')).json"
try {
    [System.IO.File]::WriteAllText($missionDiaryPath, (@{ mission_id = "MISSION-TEST"; target_processes = @() } | ConvertTo-Json -Depth 8))
    Set-MissionDiaryTarget -MissionDiaryPath $missionDiaryPath -TargetServer "server.example.gov" -PluginId "plugin-1" -Attempt 1 -ClaimGeneration 1 -Status "SUCCEEDED" -OperationDiaryPath "target-attempt-1.json" -TargetProcessId 123 -TargetProcessStartedAt "2026-10-19T12:00:00Z"
    Set-MissionDiaryTarget -MissionDiaryPath $missionDiaryPath -TargetServer "server.example.gov" -PluginId "plugin-1" -Attempt 1 -ClaimGeneration 2 -Status "RUNNING" -OperationDiaryPath "target-attempt-1.json" -TargetProcessId 456 -TargetProcessStartedAt "2026-10-19T12:01:00Z"
    $storedDiary = Get-Content -LiteralPath $missionDiaryPath -Raw | ConvertFrom-Json
    Assert-Equal $storedDiary.target_processes.Count 2 "Expected distinct Diary entries for successive claim generations"
    [System.IO.File]::WriteAllText($targetDiaryPath, (@{ status = "SUCCEEDED"; exit_code = 0 } | ConvertTo-Json -Depth 4))
    Assert-Equal (Wait-TargetOperationDiary -TargetServer "unused" -DiaryPath $targetDiaryPath -TimeoutSeconds 1).status "SUCCEEDED" "Expected terminal target diary read"
}
finally {
    Remove-Item -LiteralPath $missionDiaryPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $targetDiaryPath -Force -ErrorAction SilentlyContinue
}

$tokenRejected = $false
try {
    Get-PatchCommandParts -Command 'msiexec.exe /i "%PATCHPATH%" /log "%TEMP%\patch.log"' | Out-Null
}
catch {
    $tokenRejected = $true
}
Assert-Equal $tokenRejected $true "Expected unsupported substitutions to be rejected"

$temporaryPatch = [System.IO.Path]::GetTempFileName()
try {
    [System.IO.File]::WriteAllText($temporaryPatch, "test patch")
    $hash = (Get-FileHash -LiteralPath $temporaryPatch -Algorithm SHA256).Hash
    $patchRow = [pscustomobject]@{
        patch_path = $temporaryPatch
        patch_sha256 = $hash
        install_command = 'msiexec.exe /i "%PATCHPATH%" /qn'
        plugin_id = "test-plugin"
        patch_id = "test-patch"
    }

    $dryRun = Invoke-TargetPatchInstall -TargetServer "unused" -PatchRow $patchRow -AllowedExecutables $allowed -DryRun $true
    Assert-Equal $dryRun.status "SUCCESS" "Expected authorized hash-valid dry run to succeed"

    $unauthorized = Invoke-TargetPatchInstall -TargetServer "unused" -PatchRow $patchRow -AllowedExecutables @("other.exe") -DryRun $true
    Assert-Equal $unauthorized.status "FAILED" "Expected unlisted executable to fail closed"
    if ($unauthorized.error -notmatch "does not authorize") {
        throw "Expected an explicit policy authorization failure"
    }
}
finally {
    Remove-Item -LiteralPath $temporaryPatch -Force -ErrorAction SilentlyContinue
}

Write-Host "Patch executable policy smoke tests passed."