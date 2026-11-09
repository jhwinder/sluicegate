$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "..\PatchingEngine.psm1") -Force
$workerPath = Join-Path $PSScriptRoot "..\PatchingMinion.ps1"
$tokens = $null
$parseErrors = $null
$workerAst = [System.Management.Automation.Language.Parser]::ParseFile($workerPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw "Cannot parse PatchingMinion.ps1: $parseErrors" }
$writer = $workerAst.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq "Write-MissionDiary"
}, $true)
if (-not $writer) { throw "Write-MissionDiary was not found" }
Invoke-Expression $writer.Extent.Text

$directory = Join-Path ([System.IO.Path]::GetTempPath()) "sluice-diary-test-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $directory | Out-Null
$path = Join-Path $directory "diary.json"
try {
    if ($env:OS -eq "Windows_NT") {
        $probe = Join-Path $directory "probe.json"
        $replacement = Join-Path $directory "replacement.json"
        [System.IO.File]::WriteAllText($probe, "old")
        [System.IO.File]::WriteAllText($replacement, "new")
        try {
            Move-Item -LiteralPath $replacement -Destination $probe -Force
            Write-Host "Move-Item replacement without a reader succeeded."
        }
        catch {
            Write-Host "Move-Item replacement without a reader failed: $($_.Exception.Message)"
        }
        [System.IO.File]::WriteAllText($replacement, "newer")
        $lockedProbe = [System.IO.File]::Open($probe, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        try {
            try {
                Move-Item -LiteralPath $replacement -Destination $probe -Force
                Write-Host "Move-Item replacement with a non-delete-sharing reader succeeded."
            }
            catch {
                Write-Host "Move-Item replacement with a non-delete-sharing reader failed: $($_.Exception.Message)"
            }
        }
        finally { $lockedProbe.Dispose() }
    }

    $diary = @{ mission_id = "MISSION-TEST"; status = "CLAIMED"; target_processes = @() }
    Write-MissionDiary -Path $path -Diary $diary
    $sharedReader = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
    try {
        Set-MissionDiaryTarget -MissionDiaryPath $path -TargetServer "server" -PluginId "plugin" -Attempt 1 -ClaimGeneration 1 -Status "RUNNING"
        $diary.status = "COMPLETE"
        Write-MissionDiary -Path $path -Diary $diary
        $stored = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if ($stored.status -ne "COMPLETE" -or $stored.target_processes.Count -ne 1 -or $stored.target_processes[0].target -ne "server") {
            throw "Diary replacement lost mission status or target data"
        }
        $reader = [System.IO.StreamReader]::new($sharedReader)
        try {
            $old = $reader.ReadToEnd() | ConvertFrom-Json
            if ($old.status -ne "CLAIMED") { throw "An open reader did not retain the complete previous diary" }
        }
        finally { $reader.Dispose() }
    }
    finally { $sharedReader.Dispose() }

    $resumed = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $resumed.status = "RESUMED"
    Write-MissionDiary -Path $path -Diary $resumed
    $stored = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ($stored.status -ne "RESUMED" -or $stored.target_processes.Count -ne 1) {
        throw "Resumed diary replacement lost mission status or target data"
    }

    if ($env:OS -eq "Windows_NT") {
        $before = [System.IO.File]::ReadAllText($path)
        $locked = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        try {
            $failed = $false
            try { Write-MissionDiaryFile -Path $path -Content '{"status":"SHOULD-NOT-WRITE"}' }
            catch [System.IO.IOException] { $failed = $true }
            if (-not $failed) { throw "A reader denying delete sharing should block replacement on Windows" }
            if ([System.IO.File]::ReadAllText($path) -ne $before) { throw "Failed replacement modified the previous diary" }
            if (@(Get-ChildItem -LiteralPath $directory -Filter "diary.json.*.tmp").Count -ne 0) { throw "Failed replacement left a temporary file" }
        }
        finally { $locked.Dispose() }
        Write-MissionDiaryFile -Path $path -Content $before
    }
    Write-Host "Mission Diary replacement tests passed."
}
finally {
    Remove-Item -LiteralPath $directory -Recurse -Force
}
