<#
.SYNOPSIS
    SluiceGate Patching Execution Engine Module
.DESCRIPTION
    Implements SHA-256 preflight verification, target file staging,
    constrained remote process invocation with %PATCHPATH% substitution,
    exit code analysis, reboot detection, and WSUS OS-update integration.
#>

$WuaClassificationPatchTypes = @{
    "0fa1201d-4330-4fa8-8ae9-b877473b6441" = "SECURITY"
    "b54e7d24-7add-428f-8b75-90a396fa584f" = "FEATURE"
    "68c5b0a3-d1a6-4553-ae49-01d3a7827828" = "SERVICE_PACK"
    "ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0" = "DRIVER"
    "e6cf1350-c01b-414d-a61f-263d14d133b4" = "BUGFIX"
    "cd5ffd1e-e932-4e3a-bf74-18bf0b1bbd83" = "OTHER"
    "e0789628-ce08-4437-be74-2495b842f43b" = "OTHER"
    "b4832bd8-e735-4761-8daf-37f882276dab" = "OTHER"
    "28bc880e-0592-4cbf-8f95-c79b17911d5f" = "OTHER"
}

function Get-WuaPatchType {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Update
    )

    $mappedTypes = @()
    $unknownClassification = $false
    foreach ($category in @($Update.Categories)) {
        try {
            if ([int]$category.Type -ne 3) {
                continue
            }
        }
        catch {
            $unknownClassification = $true
            continue
        }
        $categoryId = ([string]$category.CategoryID).Trim("{}").ToLowerInvariant()
        if ($WuaClassificationPatchTypes.ContainsKey($categoryId)) {
            $mappedType = [string]$WuaClassificationPatchTypes[$categoryId]
            if ($mappedTypes -notcontains $mappedType) {
                $mappedTypes += $mappedType
            }
        }
        else {
            $unknownClassification = $true
        }
    }

    if ($unknownClassification -or $mappedTypes.Count -ne 1) {
        return "UNKNOWN"
    }
    return $mappedTypes[0]
}

function Test-WuaSecurityUpdate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Update
    )

    return (Get-WuaPatchType -Update $Update) -eq "SECURITY"
}

function Test-WuaPatchTypeAllowed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Update,

        [string[]]$AllowedPatchTypes = @()
    )

    $patchType = Get-WuaPatchType -Update $Update
    if ($patchType -eq "UNKNOWN") {
        return $false
    }
    $normalizedAllowed = @($AllowedPatchTypes | ForEach-Object { ([string]$_).Trim().ToUpperInvariant() })
    return $normalizedAllowed -contains $patchType
}

function Get-WuaRebootBehavior {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Update
    )

    $behavior = $Update.InstallationBehavior.RebootBehavior
    if ($null -eq $behavior) {
        return $null
    }
    $value = [int]$behavior
    if ($value -lt 0 -or $value -gt 2) {
        return $null
    }
    return $value
}

function Test-MissionMaintenanceWindow {
    [CmdletBinding()]
    param(
        [object]$Window
    )

    if ($null -eq $Window) {
        return $true
    }

    if ([string]$Window.start_utc -notmatch '(Z|\+00:00)$' -or [string]$Window.end_utc -notmatch '(Z|\+00:00)$') {
        return $false
    }

    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    $start = [DateTimeOffset]::MinValue
    $end = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse([string]$Window.start_utc, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$start)) {
        return $false
    }
    if (-not [DateTimeOffset]::TryParse([string]$Window.end_utc, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$end)) {
        return $false
    }
    if ($end -le $start) {
        return $false
    }

    $now = [DateTimeOffset]::UtcNow
    return ($now -ge $start.ToUniversalTime() -and $now -lt $end.ToUniversalTime())
}

function Set-MissionDiaryTarget {
    [CmdletBinding()]
    param(
        [string]$MissionDiaryPath,
        [string]$TargetServer,
        [string]$PluginId,
        [int]$Attempt,
        [int]$ClaimGeneration,
        [string]$Status,
        [string]$OperationDiaryPath,
        [string]$TargetBootTime,
        [Nullable[int]]$TargetProcessId,
        [string]$TargetProcessStartedAt,
        [string]$ErrorMessage
    )

    if (-not $MissionDiaryPath -or -not (Test-Path -LiteralPath $MissionDiaryPath -PathType Leaf)) {
        return
    }
    $diary = Get-Content -LiteralPath $MissionDiaryPath -Raw | ConvertFrom-Json
    $targets = @($diary.target_processes | Where-Object { -not ($_.target -eq $TargetServer -and $_.plugin_id -eq $PluginId -and $_.attempt -eq $Attempt -and $_.claim_generation -eq $ClaimGeneration) })
    $targets += [pscustomobject]@{
        target = $TargetServer
        plugin_id = $PluginId
        attempt = $Attempt
        claim_generation = $ClaimGeneration
        status = $Status
        operation_diary_path = $OperationDiaryPath
        target_boot_time = $TargetBootTime
        target_process_id = $TargetProcessId
        target_process_started_at = $TargetProcessStartedAt
        error = $ErrorMessage
        updated_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
    }
    $diary.target_processes = $targets
    $temporaryPath = "$MissionDiaryPath.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        [System.IO.File]::WriteAllText($temporaryPath, ($diary | ConvertTo-Json -Depth 12), [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporaryPath -Destination $MissionDiaryPath -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue }
    }
}

function Wait-TargetOperationDiary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetServer,
        [Parameter(Mandatory = $true)]
        [string]$DiaryPath,
        [int]$TimeoutSeconds = 300
    )

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $missingProcessPolls = 0
    $lastEntry = $null
    while ($watch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        if (-not (Test-Path -LiteralPath $DiaryPath -PathType Leaf)) {
            Start-Sleep -Seconds 2
            continue
        }

        try { $lastEntry = Get-Content -LiteralPath $DiaryPath -Raw | ConvertFrom-Json }
        catch { return [pscustomobject]@{ status = "OUTCOME_UNKNOWN"; error = "Target operation diary became unreadable." } }
        if ($lastEntry.status -eq "TIMED_OUT") {
            return [pscustomobject]@{ status = "OUTCOME_UNKNOWN"; process_id = $lastEntry.process_id; process_started_at = $lastEntry.process_started_at; error = "Installer timed out; target state must be reconciled before retry." }
        }
        if ($lastEntry.status -in @("SUCCEEDED", "FAILED", "HASH_MISMATCH", "NOT_STARTED")) {
            return $lastEntry
        }
        if ($lastEntry.status -eq "RUNNING" -and $lastEntry.process_id -and $lastEntry.process_started_at) {
            try {
                $processState = Invoke-Command -ComputerName $TargetServer -ArgumentList @([int]$lastEntry.process_id, [string]$lastEntry.process_started_at) -ScriptBlock {
                    param($ProcessId, $ExpectedStartedAt)
                    $process = Get-Process -Id $ProcessId -ErrorAction Stop
                    $startedAt = [DateTimeOffset]::new($process.StartTime.ToUniversalTime()).ToString("o")
                    return @{ running = ($startedAt -eq $ExpectedStartedAt); started_at = $startedAt }
                } -ErrorAction Stop
                if ($processState.running) {
                    $missingProcessPolls = 0
                }
                else {
                    $missingProcessPolls++
                }
            }
            catch {
                $missingProcessPolls++
            }
            if ($missingProcessPolls -ge 3) {
                return [pscustomobject]@{ status = "OUTCOME_UNKNOWN"; process_id = $lastEntry.process_id; process_started_at = $lastEntry.process_started_at; error = "Target process exited but its operation diary has no terminal result." }
            }
        }
        Start-Sleep -Seconds 2
    }

    return [pscustomobject]@{
        status = "IN_PROGRESS"
        process_id = $lastEntry.process_id
        process_started_at = $lastEntry.process_started_at
        error = "Target operation remains active; no duplicate launch was attempted."
    }
}

function Invoke-TargetReboot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetServer,
        [object]$MaintenanceWindow,
        [int]$TimeoutSeconds = 900
    )

    if (-not (Test-MissionMaintenanceWindow -Window $MaintenanceWindow)) {
        return [pscustomobject]@{ success = $false; error = "Mission maintenance window is invalid or inactive; reboot was not started." }
    }

    try {
        Restart-Computer -ComputerName $TargetServer -Force -Wait -For PowerShell -Delay 5 -Timeout $TimeoutSeconds -ErrorAction Stop
        return [pscustomobject]@{ success = $true; rebooted_at = [DateTimeOffset]::UtcNow.ToString("o"); error = $null }
    }
    catch {
        return [pscustomobject]@{ success = $false; rebooted_at = $null; error = $_.ToString() }
    }
}

function Get-TargetBootTime {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$TargetServer)
    return Invoke-Command -ComputerName $TargetServer -ScriptBlock {
        (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime().ToString("o")
    } -ErrorAction Stop
}

function Get-MissionTargetRebootRecord {
    param(
        [string]$MissionDiaryPath,
        [string]$TargetServer
    )
    if (-not $MissionDiaryPath -or -not (Test-Path -LiteralPath $MissionDiaryPath -PathType Leaf)) {
        return $null
    }
    $diary = Get-Content -LiteralPath $MissionDiaryPath -Raw | ConvertFrom-Json
    $records = @($diary.target_processes) + @($diary.previous_attempt.target_processes)
    $rebootRecord = @($records | Where-Object { $_.target -eq $TargetServer -and $_.plugin_id -eq "__target_reboot__" } | Sort-Object claim_generation | Select-Object -Last 1)
    if (-not $rebootRecord) { return $null }
    return $rebootRecord[0]
}

function Test-MissionTargetRebooted {
    param(
        [string]$MissionDiaryPath,
        [string]$TargetServer
    )
    $rebootRecord = Get-MissionTargetRebootRecord -MissionDiaryPath $MissionDiaryPath -TargetServer $TargetServer
    if (-not $rebootRecord) { return $false }
    if ($rebootRecord.status -eq "REBOOTED") { return $true }
    if ($rebootRecord.status -ne "REBOOTING" -or -not $rebootRecord.target_boot_time) { return $false }
    try {
        $currentBootTime = Get-TargetBootTime -TargetServer $TargetServer
        return ([DateTimeOffset]::Parse($currentBootTime).ToUniversalTime() -gt [DateTimeOffset]::Parse([string]$rebootRecord.target_boot_time).ToUniversalTime())
    }
    catch {
        return $false
    }
}

function Test-PatchFileHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedHash
    )

    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        Write-Warning "Patch file not found: $FilePath"
        return $false
    }

    $actualHash = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256).Hash
    return ($actualHash.ToLowerInvariant() -eq $ExpectedHash.Trim().ToLowerInvariant())
}

function Get-AllowedPatchExecutables {
    [CmdletBinding()]
    param(
        [object[]]$Obligations = @()
    )

    $allowed = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($obligation in $Obligations) {
        if ($obligation.type -ne "allowed_patch_executables") {
            continue
        }
        foreach ($name in @($obligation.data.executables)) {
            $normalized = ([string]$name).Trim()
            if (-not $normalized -or $normalized -match '[\\/:\s]') {
                throw "Policy contains an invalid patch executable name."
            }
            if ([System.IO.Path]::GetExtension($normalized) -and [System.IO.Path]::GetExtension($normalized) -ne ".exe") {
                throw "Policy patch executable names must be executable basenames."
            }
            if (-not [System.IO.Path]::GetExtension($normalized)) {
                $normalized += ".exe"
            }
            [void]$allowed.Add($normalized)
        }
    }
    return @($allowed)
}

function Get-PatchCommandParts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    $match = [System.Text.RegularExpressions.Regex]::Match(
        $Command.Trim(),
        '^(?:"([^"\r\n]+)"|(\S+))(?:\s+(.*))?$'
    )
    if (-not $match.Success) {
        throw "Patch command must start with one executable name."
    }
    $unsupportedTokens = [System.Text.RegularExpressions.Regex]::Matches($Command, '%[^%]+%') |
        Where-Object { $_.Value -ine "%PATCHPATH%" }
    if ($unsupportedTokens.Count -gt 0) {
        throw "Patch command contains an unsupported substitution token."
    }

    $executable = if ($match.Groups[1].Success) { $match.Groups[1].Value } else { $match.Groups[2].Value }
    if ($executable -match '[\\/:]') {
        throw "Patch executable must be a bare name resolved from the target PATH."
    }
    if ([System.IO.Path]::GetExtension($executable) -and [System.IO.Path]::GetExtension($executable) -ne ".exe") {
        throw "Patch executable must be an .exe file."
    }
    if (-not [System.IO.Path]::GetExtension($executable)) {
        $executable += ".exe"
    }

    return [pscustomobject]@{
        Executable = $executable
        Arguments = $match.Groups[3].Value
    }
}

function Invoke-TargetPatchInstall {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetServer,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$PatchRow,

        [string]$MissionId = "LOCAL-TEST",
        [int]$Attempt = 1,
        [int]$ClaimGeneration = 1,
        [string]$MissionDiaryPath,

        [string[]]$AllowedExecutables = @(),

        [object]$MaintenanceWindow,

        [int]$TimeoutSeconds = 300,

        [bool]$AllowReboot = $false,

        [string]$StagingDirectory = "C$\Windows\Temp\SluiceGate\Staging",

        [bool]$DryRun = $false
    )

    $patchPath     = $PatchRow.patch_path
    $expectedSha   = $PatchRow.patch_sha256
    $installCmdTpl = $PatchRow.install_command
    $pluginId      = $PatchRow.plugin_id
    $patchId       = $PatchRow.patch_id
    $destinationFile = $null

    $result = [ordered]@{
        target          = $TargetServer
        plugin_id       = $pluginId
        patch_id        = $patchId
        status          = "FAILED"
        exit_code       = $null
        reboot_required = $false
        reboot_performed= $false
        error           = $null
        duration_sec    = 0
    }

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        if (-not (Test-MissionMaintenanceWindow -Window $MaintenanceWindow)) {
            $result.error = "Mission maintenance window is invalid or inactive."
            return $result
        }

        $commandParts = Get-PatchCommandParts -Command $installCmdTpl
        if ($AllowedExecutables -notcontains $commandParts.Executable) {
            $result.error = "Policy does not authorize patch executable '$($commandParts.Executable)'."
            return $result
        }

        # 1. Pre-flight SHA-256 hash check on the share
        Write-Host "Verifying SHA-256 hash for patch '$patchId' ($patchPath)..."
        if (-not (Test-PatchFileHash -FilePath $patchPath -ExpectedHash $expectedSha)) {
            $result.error = "SHA-256 hash check failed for source file: $patchPath"
            return $result
        }

        if ($DryRun) {
            $result.status = "SUCCESS"
            $result.exit_code = 0
            $result.error = "DryRun: Verification succeeded."
            return $result
        }

        # 2. Use an attempt-specific staging path so a resume cannot overwrite an active installer's file.
        $fileName = [System.IO.Path]::GetFileName($patchPath)
        $safeMissionId = $MissionId -replace '[^A-Za-z0-9_-]', '_'
        $safePluginId = ([string]$pluginId) -replace '[^A-Za-z0-9_-]', '_'
        $safeTarget = ([string]$TargetServer).Trim().TrimEnd('.').ToLowerInvariant() -replace '[^A-Za-z0-9_-]', '_'
        $targetDiaryDirectory = "\\$TargetServer\C$\ProgramData\SluiceGate\Minion\TargetDiary\$safeMissionId"
        $targetDiaryPath = Join-Path $targetDiaryDirectory ("target-{0}-patch-{1}-attempt-{2:D2}.json" -f $safeTarget, $safePluginId, $Attempt)
        $targetLockPath = Join-Path $targetDiaryDirectory "target-$safeTarget-patch-$safePluginId.lock"

        if (Test-Path -LiteralPath $targetLockPath -PathType Leaf) {
            $preflightLock = $null
            try {
                $preflightLock = [System.IO.File]::Open($targetLockPath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            }
            catch [System.IO.IOException] {
                $activeDiary = Get-ChildItem -LiteralPath $targetDiaryDirectory -Filter "target-$safeTarget-patch-$safePluginId-attempt-*.json" -File |
                    Sort-Object LastWriteTimeUtc -Descending |
                    Select-Object -First 1
                if (-not $activeDiary) {
                    $result.status = "FAILED"
                    $result.error = "Target operation lock is held but its Mission Diary is missing; refusing to stage or execute."
                    return $result
                }
                $priorResult = Wait-TargetOperationDiary -TargetServer $TargetServer -DiaryPath $activeDiary.FullName -TimeoutSeconds $TimeoutSeconds
                if ($priorResult.status -eq "SUCCEEDED") {
                    $result.status = "SUCCESS"
                    $result.exit_code = $priorResult.exit_code
                    $result.reboot_required = ([int]$priorResult.exit_code -eq 3010)
                    $result.target_process_id = $priorResult.process_id
                    $result.target_process_started_at = $priorResult.process_started_at
                    $result.operation_diary = $activeDiary.FullName
                    Set-MissionDiaryTarget -MissionDiaryPath $MissionDiaryPath -TargetServer $TargetServer -PluginId $pluginId -Attempt $Attempt -ClaimGeneration $ClaimGeneration -Status "SUCCEEDED" -OperationDiaryPath $activeDiary.FullName -TargetProcessId $priorResult.process_id -TargetProcessStartedAt $priorResult.process_started_at
                    return $result
                }
                if ($priorResult.status -eq "IN_PROGRESS") {
                    $result.status = "IN_PROGRESS"
                    $result.error = $priorResult.error
                    $result.target_process_id = $priorResult.process_id
                    $result.target_process_started_at = $priorResult.process_started_at
                    $result.operation_diary = $activeDiary.FullName
                    Set-MissionDiaryTarget -MissionDiaryPath $MissionDiaryPath -TargetServer $TargetServer -PluginId $pluginId -Attempt $Attempt -ClaimGeneration $ClaimGeneration -Status "RUNNING" -OperationDiaryPath $activeDiary.FullName -TargetProcessId $priorResult.process_id -TargetProcessStartedAt $priorResult.process_started_at
                    return $result
                }
                $result.status = "FAILED"
                $result.error = if ($priorResult.error) { $priorResult.error } else { "Target operation outcome is unknown; no duplicate execution was started." }
                $result.operation_diary = $activeDiary.FullName
                return $result
            }
            finally {
                if ($preflightLock) { $preflightLock.Dispose() }
            }
        }

        $remoteStageSuffix = "Windows\Temp\SluiceGate\Staging\$safeMissionId\attempt-$Attempt"
        $remoteSharePath = "\\$TargetServer\C$\$remoteStageSuffix"
        if (-not (Test-Path -LiteralPath $remoteSharePath)) {
            New-Item -ItemType Directory -Path $remoteSharePath -Force | Out-Null
        }
        $destinationFile = Join-Path $remoteSharePath $fileName

        Write-Host "Staging patch to $destinationFile..."
        Copy-Item -LiteralPath $patchPath -Destination $destinationFile -Force

        # Local path on the target server
        $localStagedPath = "C:\$remoteStageSuffix\$fileName"
        Set-MissionDiaryTarget `
            -MissionDiaryPath $MissionDiaryPath `
            -TargetServer $TargetServer `
            -PluginId $pluginId `
            -Attempt $Attempt `
            -ClaimGeneration $ClaimGeneration `
            -Status "PREPARING" `
            -OperationDiaryPath $targetDiaryPath

        # 3. Substitute only the authorized patch-path token and invoke directly.
        $effectiveArguments = $commandParts.Arguments.Replace("%PATCHPATH%", $localStagedPath)
        Write-Host "Executing installer on ${TargetServer}: $($commandParts.Executable)"
        $processResult = Invoke-Command -ComputerName $TargetServer -ArgumentList @(
            $commandParts.Executable,
            $effectiveArguments,
            $TimeoutSeconds,
            $expectedSha,
            $localStagedPath,
            $MaintenanceWindow,
            $MissionId,
            $Attempt,
            $ClaimGeneration,
            $pluginId,
            $patchId,
            $TargetServer
        ) -ScriptBlock {
            param($Executable, $Arguments, $Timeout, $ExpectedHash, $StagedPath, $Window, $OperationMissionId, $OperationAttempt, $OperationGeneration, $PluginId, $PatchId, $TargetServerName)

            $safeMissionId = [regex]::Replace([string]$OperationMissionId, '[^A-Za-z0-9_-]', '_')

        if ($processResult.status -eq "IN_PROGRESS") {
            $waited = Wait-TargetOperationDiary -TargetServer $TargetServer -DiaryPath $targetDiaryPath -TimeoutSeconds $TimeoutSeconds
            if ($waited.status -in @("SUCCEEDED", "FAILED", "TIMED_OUT", "HASH_MISMATCH", "NOT_STARTED")) {
                $processResult = [pscustomobject]@{
                    status = "EXITED"
                    exit_code = $waited.exit_code
                    stdout = $waited.stdout
                    stderr = $waited.stderr
                    target_process_id = $waited.process_id
                    target_process_started_at = $waited.process_started_at
                    diary_path = $targetDiaryPath
                }
            }
            elseif ($waited.status -eq "OUTCOME_UNKNOWN") {
                $processResult = [pscustomobject]@{
                    status = "OUTCOME_UNKNOWN"
                    exit_code = $waited.exit_code
                    stdout = $waited.stdout
                    stderr = $waited.error
                    target_process_id = $waited.process_id
                    target_process_started_at = $waited.process_started_at
                    diary_path = $targetDiaryPath
                }
            }
            else {
                $processResult = [pscustomobject]@{
                    status = "IN_PROGRESS"
                    exit_code = $null
                    stdout = ""
                    stderr = $waited.error
                    target_process_id = $waited.process_id
                    target_process_started_at = $waited.process_started_at
                    diary_path = $targetDiaryPath
                }
            }
        }
            $safePluginId = [regex]::Replace([string]$PluginId, '[^A-Za-z0-9_-]', '_')
            $safeTarget = ([string]$TargetServerName).Trim().TrimEnd('.').ToLowerInvariant() -replace '[^A-Za-z0-9_-]', '_'
            $diaryDirectory = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) "SluiceGate\Minion\TargetDiary\$safeMissionId"
            New-Item -ItemType Directory -Path $diaryDirectory -Force | Out-Null
            $diaryPath = Join-Path $diaryDirectory ("target-{0}-patch-{1}-attempt-{2:D2}.json" -f $safeTarget, $safePluginId, [int]$OperationAttempt)
            $lockPath = Join-Path $diaryDirectory "target-$safeTarget-patch-$safePluginId.lock"
            $lockHandle = $null

            function Write-TargetOperationDiary([string]$Path, [hashtable]$Entry) {
                $tempPath = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
                try {
                    [System.IO.File]::WriteAllText($tempPath, ($Entry | ConvertTo-Json -Depth 8), [System.Text.UTF8Encoding]::new($false))
                    Move-Item -LiteralPath $tempPath -Destination $Path -Force
                }
                finally {
                    if (Test-Path -LiteralPath $tempPath) { Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue }
                }
            }

            try {
                try {
                    $lockHandle = [System.IO.File]::Open($lockPath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
                }
                catch [System.IO.IOException] {
                    $activeDiaryFile = Get-ChildItem -LiteralPath $diaryDirectory -Filter "target-$safeTarget-patch-$safePluginId-attempt-*.json" -File | Sort-Object Name -Descending | Select-Object -First 1
                    if ($activeDiaryFile) {
                        try {
                            $activeDiary = Get-Content -LiteralPath $activeDiaryFile.FullName -Raw | ConvertFrom-Json
                            return [pscustomobject]@{ status = "IN_PROGRESS"; exit_code = $null; stdout = ""; stderr = "Another Mission worker holds the target operation lock."; target_process_id = $activeDiary.process_id; target_process_started_at = $activeDiary.process_started_at; diary_path = $activeDiaryFile.FullName }
                        }
                        catch { }
                    }
                    return [pscustomobject]@{ status = "OUTCOME_UNKNOWN"; exit_code = $null; stdout = ""; stderr = "Target operation lock is held but its diary cannot be read."; target_process_id = $null; target_process_started_at = $null; diary_path = $diaryPath }
                }

                $priorDiaries = Get-ChildItem -LiteralPath $diaryDirectory -Filter "target-$safeTarget-patch-$safePluginId-attempt-*.json" -File | Sort-Object Name -Descending
                foreach ($priorFile in $priorDiaries) {
                    try { $prior = Get-Content -LiteralPath $priorFile.FullName -Raw | ConvertFrom-Json }
                    catch { return [pscustomobject]@{ status = "OUTCOME_UNKNOWN"; exit_code = $null; stdout = ""; stderr = "Target operation diary is unreadable; refusing duplicate execution."; diary_path = $priorFile.FullName } }

                    if ($prior.patch_sha256 -ne $ExpectedHash) {
                        return [pscustomobject]@{ status = "OUTCOME_UNKNOWN"; exit_code = $null; stdout = ""; stderr = "Target diary hash does not match this Mission; refusing execution."; diary_path = $priorFile.FullName }
                    }
                    if ($prior.status -eq "SUCCEEDED") {
                        return [pscustomobject]@{ status = "ALREADY_COMPLETED"; exit_code = $prior.exit_code; stdout = $prior.stdout; stderr = $prior.stderr; target_process_id = $prior.process_id; target_process_started_at = $prior.process_started_at; diary_path = $priorFile.FullName }
                    }
                    if ($prior.status -eq "TIMED_OUT") {
                        return [pscustomobject]@{ status = "OUTCOME_UNKNOWN"; exit_code = $prior.exit_code; stdout = $prior.stdout; stderr = "Prior installer timed out; refusing automatic re-execution until target state is reconciled."; target_process_id = $prior.process_id; target_process_started_at = $prior.process_started_at; diary_path = $priorFile.FullName }
                    }
                    if ($prior.status -eq "RETRYABLE_BUSY") {
                        $activeInstaller = Get-Process -Name "msiexec" -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($activeInstaller) {
                            $busyStartedAt = [DateTimeOffset]::new($activeInstaller.StartTime.ToUniversalTime()).ToString("o")
                            return [pscustomobject]@{ status = "IN_PROGRESS"; exit_code = 1618; stdout = $prior.stdout; stderr = "Windows Installer is busy with another operation."; target_process_id = $activeInstaller.Id; target_process_started_at = $busyStartedAt; diary_path = $priorFile.FullName }
                        }
                        Remove-Item -LiteralPath $priorFile.FullName -Force
                        continue
                    }
                    if ($prior.status -eq "RUNNING" -and $prior.process_id -and $prior.process_started_at) {
                        try {
                            $existingProcess = Get-Process -Id ([int]$prior.process_id) -ErrorAction Stop
                            $existingStart = [DateTimeOffset]::new($existingProcess.StartTime.ToUniversalTime()).ToString("o")
                            if ($existingStart -eq [string]$prior.process_started_at) {
                                return [pscustomobject]@{ status = "IN_PROGRESS"; exit_code = $null; stdout = ""; stderr = "Recorded target installer is still running."; target_process_id = [int]$prior.process_id; target_process_started_at = $existingStart; diary_path = $priorFile.FullName }
                            }
                        }
                        catch [Microsoft.PowerShell.Commands.ProcessCommandException] { }
                        catch [System.ArgumentException] { }
                        return [pscustomobject]@{ status = "OUTCOME_UNKNOWN"; exit_code = $null; stdout = ""; stderr = "Target diary records a prior process whose final outcome is unknown; refusing duplicate execution."; target_process_id = [int]$prior.process_id; target_process_started_at = [string]$prior.process_started_at; diary_path = $priorFile.FullName }
                    }
                    if ($prior.status -in @("PREPARING", "OUTCOME_UNKNOWN")) {
                        return [pscustomobject]@{ status = "OUTCOME_UNKNOWN"; exit_code = $null; stdout = ""; stderr = "Prior target operation state is uncertain; refusing duplicate execution."; diary_path = $priorFile.FullName }
                    }
                    if ([int]$prior.attempt -ge [int]$OperationAttempt) {
                        if ($prior.status -in @("FAILED", "HASH_MISMATCH", "NOT_STARTED")) {
                            return [pscustomobject]@{ status = "EXITED"; exit_code = $prior.exit_code; stdout = $prior.stdout; stderr = $prior.stderr; target_process_id = $prior.process_id; target_process_started_at = $prior.process_started_at; diary_path = $priorFile.FullName }
                        }
                        return [pscustomobject]@{ status = "OUTCOME_UNKNOWN"; exit_code = $null; stdout = ""; stderr = "Attempt diary cannot be safely resumed; refusing duplicate execution."; diary_path = $priorFile.FullName }
                    }
                    if ($prior.status -notin @("FAILED", "HASH_MISMATCH", "NOT_STARTED")) {
                        return [pscustomobject]@{ status = "OUTCOME_UNKNOWN"; exit_code = $null; stdout = ""; stderr = "Previous attempt has no safe terminal outcome; refusing duplicate execution."; diary_path = $priorFile.FullName }
                    }
                }

                $entry = @{
                    mission_id = $OperationMissionId
                    attempt = [int]$OperationAttempt
                    claim_generation = [int]$OperationGeneration
                    plugin_id = $PluginId
                    patch_id = $PatchId
                    target = $TargetServerName
                    patch_sha256 = $ExpectedHash
                    executable = $Executable
                    status = "PREPARING"
                    process_id = $null
                    process_started_at = $null
                    started_at = [DateTimeOffset]::UtcNow.ToString("o")
                    completed_at = $null
                    exit_code = $null
                    stdout = ""
                    stderr = ""
                }
                Write-TargetOperationDiary -Path $diaryPath -Entry $entry

                if ($null -ne $Window) {
                    $windowStart = [DateTimeOffset]::Parse([string]$Window.start_utc).ToUniversalTime()
                    $windowEnd = [DateTimeOffset]::Parse([string]$Window.end_utc).ToUniversalTime()
                    $now = [DateTimeOffset]::UtcNow
                    if ($now -lt $windowStart -or $now -ge $windowEnd) {
                        $entry.status = "NOT_STARTED"
                        $entry.completed_at = [DateTimeOffset]::UtcNow.ToString("o")
                        $entry.stderr = "Maintenance window is not active."
                        Write-TargetOperationDiary -Path $diaryPath -Entry $entry
                        return [pscustomobject]@{ status = "OUTSIDE_WINDOW"; exit_code = $null; stdout = ""; stderr = $entry.stderr; diary_path = $diaryPath }
                    }
                }

                $actualHash = (Get-FileHash -LiteralPath $StagedPath -Algorithm SHA256).Hash
                if ($actualHash -ine $ExpectedHash.Trim()) {
                    $entry.status = "HASH_MISMATCH"
                    $entry.completed_at = [DateTimeOffset]::UtcNow.ToString("o")
                    $entry.stderr = "Staged file SHA-256 mismatch."
                    Write-TargetOperationDiary -Path $diaryPath -Entry $entry
                    return [pscustomobject]@{ status = "HASH_MISMATCH"; exit_code = $null; stdout = ""; stderr = $entry.stderr; diary_path = $diaryPath }
                }

                $processInfo = [System.Diagnostics.ProcessStartInfo]::new()
                $processInfo.FileName = $Executable
                $processInfo.Arguments = $Arguments
                $processInfo.UseShellExecute = $false
                $processInfo.RedirectStandardOutput = $true
                $processInfo.RedirectStandardError = $true
                $processInfo.CreateNoWindow = $true

                $process = [System.Diagnostics.Process]::new()
                $process.StartInfo = $processInfo
                [void]$process.Start()
                $entry.status = "RUNNING"
                $entry.process_id = $process.Id
                $entry.process_started_at = [DateTimeOffset]::new($process.StartTime.ToUniversalTime()).ToString("o")
                Write-TargetOperationDiary -Path $diaryPath -Entry $entry

                $stdoutTask = $process.StandardOutput.ReadToEndAsync()
                $stderrTask = $process.StandardError.ReadToEndAsync()
                if (-not $process.WaitForExit($Timeout * 1000)) {
                    $process.Kill()
                    $process.WaitForExit()
                    $entry.status = "TIMED_OUT"
                    $entry.completed_at = [DateTimeOffset]::UtcNow.ToString("o")
                    $entry.stderr = "Installer exceeded the configured timeout."
                    Write-TargetOperationDiary -Path $diaryPath -Entry $entry
                    return [pscustomobject]@{ status = "TIMED_OUT"; exit_code = $null; stdout = ""; stderr = $entry.stderr; target_process_id = $entry.process_id; target_process_started_at = $entry.process_started_at; diary_path = $diaryPath }
                }

                $stdout = $stdoutTask.GetAwaiter().GetResult()
                $stderr = $stderrTask.GetAwaiter().GetResult()
                if ($stdout.Length -gt 8192) { $stdout = $stdout.Substring(0, 8192) + " [truncated]" }
                if ($stderr.Length -gt 8192) { $stderr = $stderr.Substring(0, 8192) + " [truncated]" }
                if ($Executable -ieq "msiexec.exe" -and $process.ExitCode -eq 1618) {
                    $entry.status = "RETRYABLE_BUSY"
                    $entry.completed_at = [DateTimeOffset]::UtcNow.ToString("o")
                    $entry.exit_code = $process.ExitCode
                    $entry.stdout = $stdout
                    $entry.stderr = $stderr
                    Write-TargetOperationDiary -Path $diaryPath -Entry $entry
                    return [pscustomobject]@{ status = "RETRYABLE_BUSY"; exit_code = 1618; stdout = $stdout; stderr = "Windows Installer is busy with another operation."; target_process_id = $null; target_process_started_at = $null; diary_path = $diaryPath }
                }
                $entry.status = if ($process.ExitCode -in @(0, 3010)) { "SUCCEEDED" } else { "FAILED" }
                $entry.completed_at = [DateTimeOffset]::UtcNow.ToString("o")
                $entry.exit_code = $process.ExitCode
                $entry.stdout = $stdout
                $entry.stderr = $stderr
                Write-TargetOperationDiary -Path $diaryPath -Entry $entry
                return [pscustomobject]@{ status = "EXITED"; exit_code = $process.ExitCode; stdout = $stdout; stderr = $stderr; target_process_id = $entry.process_id; target_process_started_at = $entry.process_started_at; diary_path = $diaryPath }
            }
            finally {
                if ($lockHandle) { $lockHandle.Dispose() }
            }
        } -ErrorAction Stop

        if ($processResult.status -eq "IN_PROGRESS") {
            $diaryName = Split-Path -Leaf ([string]$processResult.diary_path)
            $diaryToWatch = Join-Path (Split-Path -Parent $targetDiaryPath) $diaryName
            $processResult = Wait-TargetOperationDiary -TargetServer $TargetServer -DiaryPath $diaryToWatch -TimeoutSeconds $TimeoutSeconds
            if ($processResult.status -eq "IN_PROGRESS") {
                $result.status = "IN_PROGRESS"
                $result.error = $processResult.error
                $result.target_process_id = $processResult.process_id
                $result.target_process_started_at = $processResult.process_started_at
                $result.operation_diary = $diaryToWatch
                Set-MissionDiaryTarget -MissionDiaryPath $MissionDiaryPath -TargetServer $TargetServer -PluginId $pluginId -Attempt $Attempt -ClaimGeneration $ClaimGeneration -Status "RUNNING" -OperationDiaryPath $diaryToWatch -TargetProcessId $processResult.process_id -TargetProcessStartedAt $processResult.process_started_at
                return $result
            }
            if ($processResult.status -eq "OUTCOME_UNKNOWN") {
                $result.error = $processResult.error
                $result.target_process_id = $processResult.process_id
                $result.target_process_started_at = $processResult.process_started_at
                $result.operation_diary = $diaryToWatch
                Set-MissionDiaryTarget -MissionDiaryPath $MissionDiaryPath -TargetServer $TargetServer -PluginId $pluginId -Attempt $Attempt -ClaimGeneration $ClaimGeneration -Status "OUTCOME_UNKNOWN" -OperationDiaryPath $diaryToWatch -TargetProcessId $processResult.process_id -TargetProcessStartedAt $processResult.process_started_at -ErrorMessage $result.error
                return $result
            }
            if ($processResult.status -eq "TIMED_OUT") {
                $processResult = [pscustomobject]@{ status = "OUTCOME_UNKNOWN"; exit_code = $processResult.exit_code; stdout = $processResult.stdout; stderr = "Prior installer timed out; target state must be reconciled before retry."; target_process_id = $processResult.process_id; target_process_started_at = $processResult.process_started_at; diary_path = $diaryToWatch }
            }
            elseif ($processResult.status -in @("SUCCEEDED", "FAILED", "HASH_MISMATCH", "NOT_STARTED")) {
                $processResult = [pscustomobject]@{
                    status = "EXITED"
                    exit_code = $processResult.exit_code
                    stdout = $processResult.stdout
                    stderr = $processResult.stderr
                    target_process_id = $processResult.process_id
                    target_process_started_at = $processResult.process_started_at
                    diary_path = $diaryToWatch
                }
            }
        }

        if ($processResult.status -eq "HASH_MISMATCH") {
            $result.error = $processResult.stderr
            Set-MissionDiaryTarget -MissionDiaryPath $MissionDiaryPath -TargetServer $TargetServer -PluginId $pluginId -Attempt $Attempt -ClaimGeneration $ClaimGeneration -Status "HASH_MISMATCH" -OperationDiaryPath $targetDiaryPath -ErrorMessage $result.error
            return $result
        }
        if ($processResult.status -eq "RETRYABLE_BUSY") {
            $result.status = "IN_PROGRESS"
            $result.exit_code = 1618
            $result.error = $processResult.stderr
            $result.stdout = $processResult.stdout
            $result.stderr = $processResult.stderr
            $result.target_process_id = $processResult.target_process_id
            $result.target_process_started_at = $processResult.target_process_started_at
            $result.operation_diary = $processResult.diary_path
            Set-MissionDiaryTarget -MissionDiaryPath $MissionDiaryPath -TargetServer $TargetServer -PluginId $pluginId -Attempt $Attempt -ClaimGeneration $ClaimGeneration -Status "RETRYABLE_BUSY" -OperationDiaryPath $processResult.diary_path -TargetProcessId $processResult.target_process_id -TargetProcessStartedAt $processResult.target_process_started_at -ErrorMessage $result.error
            return $result
        }
        if ($processResult.status -eq "OUTSIDE_WINDOW") {
            $result.error = $processResult.stderr
            Set-MissionDiaryTarget -MissionDiaryPath $MissionDiaryPath -TargetServer $TargetServer -PluginId $pluginId -Attempt $Attempt -ClaimGeneration $ClaimGeneration -Status "NOT_STARTED" -OperationDiaryPath $targetDiaryPath -ErrorMessage $result.error
            return $result
        }
        if ($processResult.status -eq "IN_PROGRESS") {
            $result.status = "IN_PROGRESS"
            $result.target_process_id = $processResult.target_process_id
            $result.target_process_started_at = $processResult.target_process_started_at
            $result.operation_diary = $processResult.diary_path
            Set-MissionDiaryTarget -MissionDiaryPath $MissionDiaryPath -TargetServer $TargetServer -PluginId $pluginId -Attempt $Attempt -ClaimGeneration $ClaimGeneration -Status "RUNNING" -OperationDiaryPath $targetDiaryPath -TargetProcessId $processResult.target_process_id -TargetProcessStartedAt $processResult.target_process_started_at
            return $result
        }
        if ($processResult.status -eq "OUTCOME_UNKNOWN") {
            $result.status = "FAILED"
            $result.error = $processResult.stderr
            $result.target_process_id = $processResult.target_process_id
            $result.target_process_started_at = $processResult.target_process_started_at
            $result.operation_diary = $processResult.diary_path
            Set-MissionDiaryTarget -MissionDiaryPath $MissionDiaryPath -TargetServer $TargetServer -PluginId $pluginId -Attempt $Attempt -ClaimGeneration $ClaimGeneration -Status "OUTCOME_UNKNOWN" -OperationDiaryPath $targetDiaryPath -TargetProcessId $processResult.target_process_id -TargetProcessStartedAt $processResult.target_process_started_at -ErrorMessage $result.error
            return $result
        }
        if ($processResult.status -eq "ALREADY_COMPLETED") {
            $result.status = if ([int]$processResult.exit_code -eq 0 -or [int]$processResult.exit_code -eq 3010) { "SUCCESS" } else { "FAILED" }
            $result.exit_code = $processResult.exit_code
            $result.reboot_required = ([int]$processResult.exit_code -eq 3010)
            $result.stdout = $processResult.stdout
            $result.stderr = $processResult.stderr
            $result.target_process_id = $processResult.target_process_id
            $result.target_process_started_at = $processResult.target_process_started_at
            $result.operation_diary = $processResult.diary_path
            Set-MissionDiaryTarget -MissionDiaryPath $MissionDiaryPath -TargetServer $TargetServer -PluginId $pluginId -Attempt $Attempt -ClaimGeneration $ClaimGeneration -Status "SUCCEEDED" -OperationDiaryPath $targetDiaryPath -TargetProcessId $processResult.target_process_id -TargetProcessStartedAt $processResult.target_process_started_at
            return $result
        }
        if ($processResult.status -eq "TIMED_OUT") {
            $result.status = "TIMED_OUT"
            $result.error = $processResult.stderr
            $result.stdout = $processResult.stdout
            $result.stderr = $processResult.stderr
            Set-MissionDiaryTarget -MissionDiaryPath $MissionDiaryPath -TargetServer $TargetServer -PluginId $pluginId -Attempt $Attempt -ClaimGeneration $ClaimGeneration -Status "TIMED_OUT" -OperationDiaryPath $targetDiaryPath -TargetProcessId $processResult.target_process_id -TargetProcessStartedAt $processResult.target_process_started_at -ErrorMessage $result.error
            return $result
        }

        $exitCode = [int]$processResult.exit_code
        $result.exit_code = $exitCode
        $result.stdout = $processResult.stdout
        $result.stderr = $processResult.stderr
        $result.target_process_id = $processResult.target_process_id
        $result.target_process_started_at = $processResult.target_process_started_at
        $result.operation_diary = $processResult.diary_path
        Set-MissionDiaryTarget -MissionDiaryPath $MissionDiaryPath -TargetServer $TargetServer -PluginId $pluginId -Attempt $Attempt -ClaimGeneration $ClaimGeneration -Status $(if ($result.status -eq "SUCCESS") { "SUCCEEDED" } else { "FAILED" }) -OperationDiaryPath $targetDiaryPath -TargetProcessId $processResult.target_process_id -TargetProcessStartedAt $processResult.target_process_started_at -ErrorMessage $result.error

        # 5. Determine success / reboot requirement
        # Standard Windows installer return codes: 0 = Success, 3010 = Success (Reboot required)
        if ($exitCode -eq 0) {
            $result.status = "SUCCESS"
        }
        elseif ($exitCode -eq 3010) {
            $result.reboot_required = $true
            if ($AllowReboot) {
                $result.status = "SUCCESS"
            }
            else {
                $result.status = "FAILED"
                $result.error = "Installer required a reboot, but the signed Mission does not permit reboot."
            }
        }
        else {
            $result.status = "FAILED"
            $result.error = "Installer exited with non-zero code: $exitCode"
        }

    }
    catch {
        $result.status = "FAILED"
        $result.error = $_.ToString()
        Write-Error "Error executing patch ${patchId} on ${TargetServer}: $_"
    }
    finally {
        if ($destinationFile -and (Test-Path -LiteralPath $destinationFile)) {
            Remove-Item -LiteralPath $destinationFile -Force -ErrorAction SilentlyContinue
        }
        $stopwatch.Stop()
        $result.duration_sec = [math]::Round($stopwatch.Elapsed.TotalSeconds, 2)
    }

    return $result
}

function Invoke-TargetWsusUpdate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetServer,

        [object]$MaintenanceWindow,

        [string[]]$AllowedPatchTypes = @(),

        [bool]$AllowReboot = $false,

        [bool]$DryRun = $false
    )

    $result = [ordered]@{
        target          = $TargetServer
        source          = "wsus"
        status          = "SUCCESS"
        updates_applied = @()
        reboot_required = $false
        no_op_reason    = $null
        error           = $null
    }

    if ($DryRun) {
        $result.no_op_reason = "DryRun: WSUS update execution was skipped."
        return $result
    }
    if (-not (Test-MissionMaintenanceWindow -Window $MaintenanceWindow)) {
        $result.status = "FAILED"
        $result.error = "Mission maintenance window is invalid or inactive."
        return $result
    }

    try {
        # Remote execution to trigger Windows Update Agent scan and installation
        $wsusScript = {
            param($Window, $MissionAllowsReboot, $MissionAllowedPatchTypes, $ClassificationMap)

            if ($null -ne $Window) {
                $windowStart = [DateTimeOffset]::Parse([string]$Window.start_utc).ToUniversalTime()
                $windowEnd = [DateTimeOffset]::Parse([string]$Window.end_utc).ToUniversalTime()
                $now = [DateTimeOffset]::UtcNow
                if ($now -lt $windowStart -or $now -ge $windowEnd) {
                    return @{ Success = $false; RebootRequired = $false; Applied = @(); Error = "Maintenance window is not active." }
                }
            }

            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
            $applied = @()
            $skipped_policy = 0
            $skipped_reboot = 0
            $skipped_unknown = 0

            if ($searchResult.Updates.Count -gt 0) {
                $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
                foreach ($update in $searchResult.Updates) {
                    $mappedTypes = @()
                    $unknownClassification = $false
                    foreach ($category in $update.Categories) {
                        try {
                            if ([int]$category.Type -ne 3) {
                                continue
                            }
                        }
                        catch {
                            $unknownClassification = $true
                            continue
                        }
                        $categoryId = ([string]$category.CategoryID).Trim("{}").ToLowerInvariant()
                        if ($ClassificationMap.ContainsKey($categoryId)) {
                            $mappedType = [string]$ClassificationMap[$categoryId]
                            if ($mappedTypes -notcontains $mappedType) {
                                $mappedTypes += $mappedType
                            }
                        }
                        else {
                            $unknownClassification = $true
                        }
                    }
                    if ($unknownClassification -or $mappedTypes.Count -ne 1 -or $mappedTypes[0] -eq "UNKNOWN") {
                        $skipped_unknown++
                        continue
                    }
                    if ($MissionAllowedPatchTypes -notcontains $mappedTypes[0]) {
                        $skipped_policy++
                        continue
                    }

                    $rebootBehavior = $update.InstallationBehavior.RebootBehavior
                    if ($null -eq $rebootBehavior -or [int]$rebootBehavior -lt 0 -or [int]$rebootBehavior -gt 2) {
                        $skipped_unknown++
                        continue
                    }
                    if (-not $MissionAllowsReboot -and [int]$rebootBehavior -ne 0) {
                        $skipped_reboot++
                        continue
                    }
                    if ($update.IsDownloaded) {
                        $updatesToInstall.Add($update) | Out-Null
                        $applied += $update.Title
                    } else {
                        $skipped_unknown++
                    }
                }
                if ($updatesToInstall.Count -gt 0) {
                    if ($null -ne $Window) {
                        $now = [DateTimeOffset]::UtcNow
                        if ($now -lt $windowStart -or $now -ge $windowEnd) {
                            return @{ Success = $false; RebootRequired = $false; Applied = @(); Error = "Maintenance window closed before installation." }
                        }
                    }
                    $installer = $updateSession.CreateUpdateInstaller()
                    $installer.Updates = $updatesToInstall
                    $installationResult = $installer.Install()
                    return @{
                        Success = ($installationResult.ResultCode -eq 2)
                        RebootRequired = $installationResult.RebootRequired
                        Applied = $applied
                        SkippedPolicy = $skipped_policy
                        SkippedReboot = $skipped_reboot
                        SkippedUnknown = $skipped_unknown
                    }
                }
            }
            return @{
                Success = $true
                RebootRequired = $false
                Applied = @()
                SkippedPolicy = $skipped_policy
                SkippedReboot = $skipped_reboot
                SkippedUnknown = $skipped_unknown
            }
        }

        $normalizedAllowedTypes = @($AllowedPatchTypes | ForEach-Object { ([string]$_).Trim().ToUpperInvariant() })
        $res = Invoke-Command -ComputerName $TargetServer -ArgumentList @($MaintenanceWindow, $AllowReboot, $normalizedAllowedTypes, $WuaClassificationPatchTypes) -ScriptBlock $wsusScript -ErrorAction Stop
        if ($res) {
            $result.updates_applied = @($res.Applied)
            $result.reboot_required = [bool]$res.RebootRequired
            if ($res.Applied.Count -eq 0) {
                $result.no_op_reason = "No downloaded WUA updates matched Mission policy constraints. Skipped by policy: $($res.SkippedPolicy); reboot-required: $($res.SkippedReboot); unknown metadata: $($res.SkippedUnknown)."
            }
            if (-not [bool]$res.Success) {
                $result.status = "FAILED"
                $result.error = if ($res.Error) { [string]$res.Error } else { "Windows Update Agent did not report successful installation." }
            }
        }
        else {
            $result.status = "FAILED"
            $result.error = "Windows Update Agent returned no installation result."
        }
    }
    catch {
        $result.status = "FAILED"
        $result.error = $_.ToString()
    }

    return $result
}

function Invoke-PatchReconcile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Envelope,

        [Parameter(Mandatory = $true)]
        [string]$CatalogPath,

        [Parameter(Mandatory = $true)]
        [string]$NessusMappingPath,

        [string]$MissionDiaryPath,

        [int]$Attempt = 1,

        [int]$ClaimGeneration = 1,

        [int]$TimeoutSeconds = 300,

        [scriptblock]$StatusReporter,

        [hashtable]$StatusContext,

        [bool]$DryRun = $false
    )

    $targets          = @($Envelope.target.servers)
    $parameters       = $Envelope.parameters
    $patchSources     = @($parameters.patch_sources)
    $patchConstraints = $parameters.patch_constraints
    $allowedTypes     = if ($patchConstraints.allowed_patch_types) { @($patchConstraints.allowed_patch_types) } else { @("SECURITY") }
    $allowReboot      = if ($patchConstraints.allow_reboot) { [bool]$patchConstraints.allow_reboot } else { $false }
    $maintenanceWindow = $parameters.maintenance_window
    $allowedExecutables = @(Get-AllowedPatchExecutables -Obligations @($Envelope.obligations))

    if (-not (Test-MissionMaintenanceWindow -Window $maintenanceWindow)) {
        return @{
            Status = "MISSION_COMPLETE_FAILED"
            Result = @{
                capability = "windows.patch.reconcile"
                success = $false
                error = "Mission maintenance window is invalid or inactive."
            }
        }
    }

    Write-Host "Starting patch reconciliation for $($targets.Count) target(s)..."
    Write-Host "Sources: $($patchSources -join ', ')"
    Write-Host "Allowed Types: $($allowedTypes -join ', ')"
    Write-Host "Allow Reboot: $allowReboot"

    $catalogRows = Import-PatchCatalog -Path $CatalogPath
    $mappingRows = Import-NessusMapping -Path $NessusMappingPath

    $resolvedPatches = Resolve-TargetPatches `
        -MappingRows $mappingRows `
        -ApprovedCatalogRows $catalogRows `
        -TargetServers $targets `
        -AllowedPatchTypes $allowedTypes `
        -AllowReboot $allowReboot

    $targetResults = [System.Collections.Generic.List[object]]::new()
    $anyFailure = $false
    $anySuccess = $false
    $anyInProgress = $false
    $anyWaitingForReboot = $false

    foreach ($server in $targets) {
        $normalizedServer = $server.Trim().ToLowerInvariant()
        $serverPatches = $resolvedPatches[$normalizedServer]
        $installedForServer = [System.Collections.Generic.List[object]]::new()
        $wsusResult = $null

        # 1. WSUS OS update reconciliation if enabled
        if ($patchSources -contains "wsus") {
            Write-Host "Running WSUS update reconciliation on $server..."
            $wsusResult = Invoke-TargetWsusUpdate -TargetServer $server -MaintenanceWindow $maintenanceWindow -AllowedPatchTypes $allowedTypes -AllowReboot $allowReboot -DryRun $DryRun
            if ($wsusResult.status -eq "FAILED") {
                $anyFailure = $true
            }
            else {
                $anySuccess = $true
            }
        }

        # 2. Non-OS Nessus IAVM patch installation if enabled
        if ($patchSources -contains "nessus_catalog") {
            if ($null -ne $serverPatches -and $serverPatches.Count -gt 0) {
                Write-Host "Applying $($serverPatches.Count) qualifying patch(es) to $server..."
                foreach ($patchRow in $serverPatches) {
                    $installOutcome = Invoke-TargetPatchInstall `
                        -TargetServer $server `
                        -PatchRow $patchRow `
                        -MissionId $Envelope.mission_id `
                        -Attempt $Attempt `
                        -ClaimGeneration $ClaimGeneration `
                        -MissionDiaryPath $MissionDiaryPath `
                        -AllowedExecutables $allowedExecutables `
                        -MaintenanceWindow $maintenanceWindow `
                        -TimeoutSeconds $TimeoutSeconds `
                        -DryRun $DryRun

                    $installedForServer.Add($installOutcome)

                    if ($installOutcome.status -eq "SUCCESS") {
                        $anySuccess = $true
                    }
                    elseif ($installOutcome.status -eq "IN_PROGRESS") {
                        $anyInProgress = $true
                        break
                    }
                    else {
                        $anyFailure = $true
                    }
                }
            }
            else {
                Write-Host "No qualifying non-OS catalog patches for $server."
            }
        }

        $targetResult = [ordered]@{
            server          = $server
            catalog_patches = $installedForServer
            wsus_result     = $wsusResult
            reboot_required = [bool]($wsusResult.reboot_required -or @($installedForServer | Where-Object { $_.reboot_required }).Count -gt 0)
            reboot_performed = $false
        }
        if (($patchSources -contains "nessus_catalog") -and $installedForServer.Count -eq 0) {
            $targetResult.catalog_no_op_reason = "No approved catalog patches matched this target and the Mission constraints."
        }

        if ($targetResult.reboot_required) {
            if (-not $allowReboot) {
                $targetResult.reboot_error = "Work reported that reboot is required, but the signed Mission does not permit reboot."
                $anyFailure = $true
            }
            elseif (Test-MissionTargetRebooted -MissionDiaryPath $MissionDiaryPath -TargetServer $server) {
                $targetResult.reboot_performed = $true
                $rebootRecord = Get-MissionTargetRebootRecord -MissionDiaryPath $MissionDiaryPath -TargetServer $server
                Set-MissionDiaryTarget -MissionDiaryPath $MissionDiaryPath -TargetServer $server -PluginId "__target_reboot__" -Attempt $Attempt -ClaimGeneration $ClaimGeneration -Status "REBOOTED" -OperationDiaryPath "" -TargetBootTime $rebootRecord.target_boot_time
            }
            elseif ((Get-MissionTargetRebootRecord -MissionDiaryPath $MissionDiaryPath -TargetServer $server).status -eq "REBOOTING") {
                $targetResult.reboot_pending = $true
                $targetResult.reboot_error = "Target reboot is still pending or its completion is not yet observable."
                $anyWaitingForReboot = $true
            }
            elseif ((Get-MissionTargetRebootRecord -MissionDiaryPath $MissionDiaryPath -TargetServer $server).status -eq "REBOOT_FAILED") {
                $targetResult.reboot_error = "Previous reboot attempt failed; operator intervention is required."
                $anyFailure = $true
            }
            elseif (-not (Test-MissionMaintenanceWindow -Window $maintenanceWindow)) {
                $targetResult.reboot_error = "Maintenance window closed before the required reboot; target was not rebooted."
                $anyFailure = $true
            }
            else {
                $priorBootTime = Get-TargetBootTime -TargetServer $server
                Set-MissionDiaryTarget -MissionDiaryPath $MissionDiaryPath -TargetServer $server -PluginId "__target_reboot__" -Attempt $Attempt -ClaimGeneration $ClaimGeneration -Status "REBOOTING" -OperationDiaryPath "" -TargetBootTime $priorBootTime
                if ($StatusReporter) {
                    & $StatusReporter "MISSION_WAITING_FOR_REBOOT" @{ target = $server; reason = "PATCH_REBOOT_REQUIRED"; attempt = $Attempt } $StatusContext
                }
                $rebootOutcome = Invoke-TargetReboot -TargetServer $server -MaintenanceWindow $maintenanceWindow -TimeoutSeconds $TimeoutSeconds
                if ($rebootOutcome.success -and (Test-MissionTargetRebooted -MissionDiaryPath $MissionDiaryPath -TargetServer $server)) {
                    $targetResult.reboot_performed = $true
                    Set-MissionDiaryTarget -MissionDiaryPath $MissionDiaryPath -TargetServer $server -PluginId "__target_reboot__" -Attempt $Attempt -ClaimGeneration $ClaimGeneration -Status "REBOOTED" -OperationDiaryPath "" -TargetBootTime $priorBootTime -ErrorMessage $null
                    if ($StatusReporter) {
                        & $StatusReporter "MISSION_IN_PROGRESS" @{ target = $server; phase = "REBOOT_RESUMED"; rebooted_at = $rebootOutcome.rebooted_at } $StatusContext
                    }
                }
                elseif ($rebootOutcome.success) {
                    $targetResult.reboot_pending = $true
                    $targetResult.reboot_error = "Reboot command returned but the target boot time has not changed yet."
                    $anyInProgress = $true
                }
                else {
                    $targetResult.reboot_error = $rebootOutcome.error
                    Set-MissionDiaryTarget -MissionDiaryPath $MissionDiaryPath -TargetServer $server -PluginId "__target_reboot__" -Attempt $Attempt -ClaimGeneration $ClaimGeneration -Status "REBOOT_FAILED" -OperationDiaryPath "" -ErrorMessage $rebootOutcome.error
                    $anyFailure = $true
                }
            }
        }
        $targetResults.Add($targetResult)
        if ($anyInProgress) {
            break
        }
    }

    # Determine aggregate mission status
    $terminalStatus = "MISSION_COMPLETE_SUCCEEDED"
    if ($anyWaitingForReboot) {
        $terminalStatus = "MISSION_WAITING_FOR_REBOOT"
    }
    elseif ($anyInProgress) {
        $terminalStatus = "MISSION_IN_PROGRESS"
    }
    elseif ($anyFailure -and $anySuccess) {
        $terminalStatus = "MISSION_COMPLETE_PARTIAL"
    }
    elseif ($anyFailure -and (-not $anySuccess)) {
        $terminalStatus = "MISSION_COMPLETE_FAILED"
    }

    return @{
        Status = $terminalStatus
        Result = [ordered]@{
            capability       = "windows.patch.reconcile"
            targets_count    = $targets.Count
            target_results   = $targetResults
            executed_at      = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        }
    }
}

Export-ModuleMember -Function `
    Get-WuaPatchType, `
    Test-WuaSecurityUpdate, `
    Test-WuaPatchTypeAllowed, `
    Get-WuaRebootBehavior, `
    Test-MissionMaintenanceWindow, `
    Set-MissionDiaryTarget, `
    Wait-TargetOperationDiary, `
    Test-PatchFileHash, `
    Get-AllowedPatchExecutables, `
    Get-PatchCommandParts, `
    Invoke-TargetPatchInstall, `
    Invoke-TargetWsusUpdate, `
    Invoke-PatchReconcile
