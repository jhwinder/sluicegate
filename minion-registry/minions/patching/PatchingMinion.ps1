<#
.SYNOPSIS
    SluiceGate Windows Patching Minion
.DESCRIPTION
    Non-autonomous Minion runtime for Windows OS and non-OS IAVM patching.
    Polls SluiceGate Minion Mission Control, claims authorized missions,
    intersects Nessus findings with target servers, verifies package hashes,
    and executes policy-constrained patching on target servers.
#>

[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot "minion.config.json"),
    [switch]$SinglePass
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Configuration file not found: $ConfigPath"
}

$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json

# Import Core Template Module
$coreModulePath = Join-Path $PSScriptRoot "..\..\templates\powershell\SluiceGate.Minion.Core.psm1"
if (-not (Test-Path -LiteralPath $coreModulePath)) {
    # Check alternate relative location if deployed
    $coreModulePath = Join-Path $PSScriptRoot "SluiceGate.Minion.Core.psm1"
}
Import-Module $coreModulePath -Force

# Import Patching Modules
$catalogModulePath = Join-Path $PSScriptRoot "PatchingCatalog.psm1"
$engineModulePath  = Join-Path $PSScriptRoot "PatchingEngine.psm1"
Import-Module $catalogModulePath -Force
Import-Module $engineModulePath -Force

$MissionControlUrl       = if ($config.MissionControlUrl) { $config.MissionControlUrl } else { $config.CentralCommandUrl }
$MinionId                = if ($config.MinionId) { $config.MinionId } else { "PATCH-01" }
$ApiKey                  = $config.ApiKey
$SluiceGatePublicKeyPath = $config.SluiceGatePublicKeyPath
$MinionPrivateKeyPath    = $config.MinionPrivateKeyPath
$CatalogPath             = $config.CatalogPath
$NessusMappingPath       = $config.NessusMappingPath
$NonceStorePath          = if ($config.NonceStorePath) { $config.NonceStorePath } else { Join-Path $PSScriptRoot "nonces.txt" }
$PollIntervalSeconds     = if ($config.PollIntervalSeconds) { [int]$config.PollIntervalSeconds } else { 3600 }
$MissionDiaryDirectory   = if ($config.MissionDiaryDirectory) { $config.MissionDiaryDirectory } else { Join-Path $env:ProgramData "SluiceGate\Minion\MissionDiary" }
$DryRun                  = if ($config.DryRun) { [bool]$config.DryRun } else { $false }
$TrustedCertificatePath  = $config.TrustedServerCertificatePath
$TrustedCertificateSha256 = @($config.TrustedServerCertificateSha256)
$AllowInsecureHttp       = ($config.AllowInsecureHttp -eq $true)
$SupportedCapabilities   = @(
    "windows.patch.reconcile",
    "windows.patch.discover",
    "windows.patch.status"
)
$script:ActiveMission = $null
$script:ActiveHeartbeatJob = $null
$script:RetryDelaySeconds = $null

New-Item -ItemType Directory -Path $MissionDiaryDirectory -Force | Out-Null

Set-MinionTransportSecurity `
    -MissionControlUrl $MissionControlUrl `
    -TrustedCertificatePath $TrustedCertificatePath `
    -TrustedCertificateSha256 $TrustedCertificateSha256 `
    -AllowInsecureHttp $AllowInsecureHttp

function Get-MissionDiaryPath {
    param(
        [string]$MissionId,
        [int]$Attempt,
        [int]$ClaimGeneration
    )
    $safeMissionId = $MissionId -replace '[^A-Za-z0-9_-]', '_'
    $missionDirectory = Join-Path $MissionDiaryDirectory $safeMissionId
    New-Item -ItemType Directory -Path $missionDirectory -Force | Out-Null
    return Join-Path $missionDirectory ("attempt-{0:D2}-generation-{1:D4}.json" -f $Attempt, $ClaimGeneration)
}

function Write-MissionDiary {
    param(
        [string]$Path,
        [hashtable]$Diary
    )
    $Diary.updated_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
    $temporaryPath = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        [System.IO.File]::WriteAllText($temporaryPath, ($Diary | ConvertTo-Json -Depth 12), [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Read-PreviousMissionDiary {
    param(
        [string]$MissionId,
        [int]$ClaimGeneration
    )
    $safeMissionId = $MissionId -replace '[^A-Za-z0-9_-]', '_'
    $missionDirectory = Join-Path $MissionDiaryDirectory $safeMissionId
    if (-not (Test-Path -LiteralPath $missionDirectory -PathType Container)) {
        return $null
    }
    $previous = Get-ChildItem -LiteralPath $missionDirectory -Filter 'attempt-*.json' -File |
        Where-Object { $_.BaseName -match 'generation-(\d+)$' -and [int]$Matches[1] -lt $ClaimGeneration } |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if (-not $previous) {
        return $null
    }
    $record = Get-Content -LiteralPath $previous.FullName -Raw | ConvertFrom-Json
    $record | Add-Member -NotePropertyName diary_path -NotePropertyValue $previous.FullName -Force
    return $record
}

function Remove-MissionTargetDiaries {
    param(
        [string]$MissionId,
        [object]$Result
    )

    foreach ($targetResult in @($Result.target_results)) {
        $safeMissionId = $MissionId -replace '[^A-Za-z0-9_-]', '_'
        $targetDiaryDirectory = "\\$($targetResult.server)\C$\ProgramData\SluiceGate\Minion\TargetDiary\$safeMissionId"
        try {
            if (Test-Path -LiteralPath $targetDiaryDirectory -PathType Container) {
                Remove-Item -LiteralPath $targetDiaryDirectory -Recurse -Force
            }
        }
        catch {
            Write-Warning "Could not remove completed target Mission Diary for $($targetResult.server): $_"
        }
    }
}

function Start-MissionHeartbeat {
    param(
        [string]$MissionId,
        [string]$ClaimToken,
        [string]$DiaryPath,
        [int]$IntervalSeconds,
        [int]$WorkerProcessId,
        [double]$WorkerStartedAt
    )

    return Start-Job -ArgumentList @(
        $MissionControlUrl, $MinionId, $ApiKey, $MissionId, $ClaimToken,
        $DiaryPath, $IntervalSeconds, $WorkerProcessId, $WorkerStartedAt,
        $coreModulePath, $TrustedCertificatePath, $TrustedCertificateSha256, $AllowInsecureHttp
    ) -ScriptBlock {
        param($ServiceUrl, $RegisteredMinionId, $MinionApiKey, $ActiveMissionId, $ActiveClaimToken, $ActiveDiaryPath, $HeartbeatSeconds, $WorkerId, $WorkerStart, $CoreModule, $TrustedCertificate, $TrustedFingerprints, $AllowHttp)
        Import-Module $CoreModule -Force
        Set-MinionTransportSecurity -MissionControlUrl $ServiceUrl -TrustedCertificatePath $TrustedCertificate -TrustedCertificateSha256 $TrustedFingerprints -AllowInsecureHttp $AllowHttp
        $headers = @{ Authorization = "Bearer $MinionApiKey"; "Content-Type" = "application/json" }
        while ($true) {
            $diaryState = @{}
            if (Test-Path -LiteralPath $ActiveDiaryPath -PathType Leaf) {
                try { $diaryState = Get-Content -LiteralPath $ActiveDiaryPath -Raw | ConvertFrom-Json } catch { $diaryState = @{} }
            }
            $targetProcesses = @(
                foreach ($target in @($diaryState.target_processes)) {
                    $targetState = $null
                    if ($target.operation_diary_path -and (Test-Path -LiteralPath $target.operation_diary_path -PathType Leaf)) {
                        try { $targetState = Get-Content -LiteralPath $target.operation_diary_path -Raw | ConvertFrom-Json } catch { $targetState = $null }
                    }
                    if ($targetState) {
                        [pscustomobject]@{
                            target = $target.target
                            plugin_id = $target.plugin_id
                            attempt = $target.attempt
                            status = $targetState.status
                            process_id = $targetState.process_id
                            process_started_at = $targetState.process_started_at
                            exit_code = $targetState.exit_code
                        }
                    }
                    else { $target }
                }
            )
            $detail = @{
                attempt = $diaryState.attempt
                claim_generation = $diaryState.claim_generation
                diary_status = $diaryState.status
                target_processes = @($targetProcesses | Select-Object -Last 16)
            }
            $body = @{
                claim_token = $ActiveClaimToken
                process_id = $WorkerId
                process_started_at = $WorkerStart
                detail = $detail
            } | ConvertTo-Json -Depth 8
            try {
                Invoke-MinionHttp -Method Post -Uri "$($ServiceUrl.TrimEnd('/'))/internal/v1/minions/$RegisteredMinionId/missions/$ActiveMissionId/heartbeat" -Headers $headers -Body $body -TimeoutSec 15 | Out-Null
            }
            catch {
                if ((Get-MinionHttpStatusCode -ErrorRecord $_) -eq 409) { break }
            }
            Start-Sleep -Seconds $HeartbeatSeconds
        }
    }
}

Write-Host "=========================================================="
Write-Host " SluiceGate Windows Patching Minion: $MinionId"
Write-Host " Mission Control: $MissionControlUrl"
Write-Host " Catalog Path:    $CatalogPath"
Write-Host " Mapping Path:    $NessusMappingPath"
Write-Host " DryRun Mode:     $DryRun"
Write-Host "=========================================================="

# Define the capability handler scriptblock
$capabilityHandler = {
    param([pscustomobject]$MissionEnvelope, [scriptblock]$StatusReporter, [hashtable]$StatusContext)

    $capability = $MissionEnvelope.capability

    switch ($capability) {
        "windows.patch.reconcile" {
            return Invoke-PatchReconcile `
                -Envelope $MissionEnvelope `
                -CatalogPath $CatalogPath `
                -NessusMappingPath $NessusMappingPath `
                -MissionDiaryPath $script:CurrentDiaryPath `
                -Attempt $script:CurrentAttempt `
                -ClaimGeneration $script:CurrentClaimGeneration `
                -TimeoutSeconds ([int]$MissionEnvelope.execution.attempt_timeout_seconds) `
                -StatusReporter $StatusReporter `
                -StatusContext $StatusContext `
                -DryRun $DryRun
        }
        "windows.patch.discover" {
            $cat = Import-PatchCatalog -Path $CatalogPath
            $map = Import-NessusMapping -Path $NessusMappingPath
            return @{
                Status = "MISSION_COMPLETE_SUCCEEDED"
                Result = [ordered]@{
                    capability        = "windows.patch.discover"
                    approved_patches  = $cat.Count
                    mapping_records   = $map.Count
                }
            }
        }
        "windows.patch.status" {
            return @{
                Status = "MISSION_COMPLETE_SUCCEEDED"
                Result = [ordered]@{
                    capability = "windows.patch.status"
                    minion_id  = $MinionId
                    healthy    = $true
                    timestamp  = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                }
            }
        }
        default {
            throw "Unhandled capability: $capability"
        }
    }
}

function Run-MissionPass {
    if ($script:ActiveMission -and $script:ActiveHeartbeatJob -and $script:ActiveHeartbeatJob.State -ne "Running") {
        Remove-Job $script:ActiveHeartbeatJob -Force -ErrorAction SilentlyContinue
        $script:ActiveHeartbeatJob = $null
        $script:ActiveMission = $null
    }

    # 1. Check in with Minion Mission Control
    $checkIn = Invoke-MinionCheckIn -MissionControlUrl $MissionControlUrl -MinionId $MinionId -ApiKey $ApiKey
    if ($null -eq $checkIn) {
        Write-Warning "Check-in failed with Minion Mission Control. Retrying next cycle..."
        return
    }

    # 2. Claim queued mission
    $continuingMission = $null -ne $script:ActiveMission
    $claimResponse = if ($continuingMission) {
        $script:ActiveMission
    }
    else {
        Get-MinionMissionClaim -MissionControlUrl $MissionControlUrl -MinionId $MinionId -ApiKey $ApiKey
    }
    if ($null -eq $claimResponse -or $null -eq $claimResponse.mission_id) {
        if ($claimResponse -and $claimResponse.retry_after_seconds) {
            $script:RetryDelaySeconds = [int]$claimResponse.retry_after_seconds
        }
        # No queued missions
        return
    }
    $script:RetryDelaySeconds = $null

    $missionId = $claimResponse.mission_id
    $envelope  = $claimResponse.envelope
    $claimToken = $claimResponse.claim_token
    if ($continuingMission) {
        $script:CurrentAttempt = [int]$claimResponse.attempt
        $script:CurrentClaimGeneration = [int]$claimResponse.claim_generation
        $script:CurrentDiaryPath = [string]$claimResponse.diary_path
        $previousDiary = $null
        $diary = Get-Content -LiteralPath $script:CurrentDiaryPath -Raw | ConvertFrom-Json
        $workerStartedAt = [double]$diary.worker_process_started_at
    }
    else {
        $script:CurrentAttempt = [int]$claimResponse.attempt
        $script:CurrentClaimGeneration = [int]$claimResponse.claim_generation
        $script:CurrentDiaryPath = Get-MissionDiaryPath -MissionId $missionId -Attempt $script:CurrentAttempt -ClaimGeneration $script:CurrentClaimGeneration
        $previousDiary = if ($script:CurrentClaimGeneration -gt 1) { Read-PreviousMissionDiary -MissionId $missionId -ClaimGeneration $script:CurrentClaimGeneration } else { $null }
        $workerProcess = Get-Process -Id $PID
        $workerStartedAt = [DateTimeOffset]::new($workerProcess.StartTime.ToUniversalTime()).ToUnixTimeSeconds()
        $diary = @{
            mission_id = $missionId
            minion_id = $MinionId
            attempt = $script:CurrentAttempt
            claim_generation = $script:CurrentClaimGeneration
            envelope_signature = $envelope.signature
            resumed = [bool]($claimResponse.resume -or $script:CurrentAttempt -gt 1)
            previous_attempt = if ($previousDiary) { @{ attempt = $previousDiary.attempt; claim_generation = $previousDiary.claim_generation; status = $previousDiary.status; target_processes = $previousDiary.target_processes } } else { $null }
            worker_process_id = $PID
            worker_process_started_at = $workerStartedAt
            status = "CLAIMED"
            target_processes = @()
            result = $null
        }
        Write-MissionDiary -Path $script:CurrentDiaryPath -Diary $diary
    }
    Write-Host "Claimed Mission: $missionId (Capability: $($envelope.capability))"

    $resumeEvidenceValid = $false
    $requiresDiaryResume = ($claimResponse.resume -or $script:CurrentAttempt -gt 1)
    if ($continuingMission) {
        $resumeEvidenceValid = ($diary.mission_id -eq $missionId -and $diary.envelope_signature -eq $envelope.signature)
    }
    elseif ($requiresDiaryResume -and $previousDiary) {
        $resumeEvidenceValid = ($previousDiary.mission_id -eq $missionId -and $previousDiary.envelope_signature -eq $envelope.signature)
    }
    if ($requiresDiaryResume -and -not $resumeEvidenceValid) {
        $rejectionSubmission = Send-MinionStatus `
            -MissionControlUrl $MissionControlUrl `
            -MinionId $MinionId `
            -MissionId $missionId `
            -ApiKey $ApiKey `
            -ClaimToken $claimToken `
            -Status "MISSION_REJECTED" `
            -Detail @{ reason = "RESUME_DIARY_MISMATCH"; message = "No local Mission Diary matches this Mission and signed envelope." }
        if ($rejectionSubmission.status -in @("RECORDED", "ALREADY_RECORDED")) {
            Remove-Item -LiteralPath (Split-Path -Parent $script:CurrentDiaryPath) -Recurse -Force -ErrorAction SilentlyContinue
        }
        return
    }

    # 3. Validate Task Envelope
    $validation = Test-MissionEnvelope `
        -Envelope $envelope `
        -ExpectedMinionId $MinionId `
        -SluiceGatePublicKeyPath $SluiceGatePublicKeyPath `
        -NonceStorePath $NonceStorePath `
        -SupportedCapabilities $SupportedCapabilities `
        -AllowConsumedNonce:([bool]$resumeEvidenceValid)

    if (-not $validation.IsValid) {
        Write-Warning "Mission $missionId validation failed: $($validation.Reason) - $($validation.Message)"
        $rejectionSubmission = Send-MinionStatus `
            -MissionControlUrl $MissionControlUrl `
            -MinionId $MinionId `
            -MissionId $missionId `
            -ApiKey $ApiKey `
            -ClaimToken $claimToken `
            -Status "MISSION_REJECTED" `
            -Detail @{ reason = $validation.Reason; message = $validation.Message; worker_process_id = $PID; worker_process_started_at = $workerStartedAt }
        $diary.status = "REJECTED"
        Write-MissionDiary -Path $script:CurrentDiaryPath -Diary $diary
        if ($rejectionSubmission.status -in @("RECORDED", "ALREADY_RECORDED")) {
            Remove-Item -LiteralPath (Split-Path -Parent $script:CurrentDiaryPath) -Recurse -Force -ErrorAction SilentlyContinue
        }
        return
    }

    if (-not $continuingMission -and $previousDiary -and $previousDiary.diary_path -and (Test-Path -LiteralPath $previousDiary.diary_path)) {
        Remove-Item -LiteralPath $previousDiary.diary_path -Force -ErrorAction SilentlyContinue
    }

    $execution = $envelope.execution
    $heartbeatInterval = [int]$execution.heartbeat_interval_seconds
    if (-not $script:ActiveHeartbeatJob -or $script:ActiveHeartbeatJob.State -ne "Running") {
        $script:ActiveHeartbeatJob = Start-MissionHeartbeat `
            -MissionId $missionId `
            -ClaimToken $claimToken `
            -DiaryPath $script:CurrentDiaryPath `
            -IntervalSeconds $heartbeatInterval `
            -WorkerProcessId $PID `
            -WorkerStartedAt $workerStartedAt
    }
    if (-not $continuingMission) {
        $script:ActiveMission = @{
            mission_id = $missionId
            envelope = $envelope
            claim_token = $claimToken
            attempt = $script:CurrentAttempt
            claim_generation = $script:CurrentClaimGeneration
            resume = [bool]$claimResponse.resume
            resume_status = $claimResponse.resume_status
            diary_path = $script:CurrentDiaryPath
        }
    }

    # Record nonce
    if (-not $resumeEvidenceValid) {
        Add-MinionNonce -Nonce $envelope.nonce -NonceStorePath $NonceStorePath
    }

    # 4. Acknowledge only fresh claims; resumed work keeps its current state.
    if (-not $continuingMission -and (-not $claimResponse.resume -or $claimResponse.resume_status -eq "CLAIMED")) {
        $null = Send-MinionStatus `
            -MissionControlUrl $MissionControlUrl `
            -MinionId $MinionId `
            -MissionId $missionId `
            -ApiKey $ApiKey `
            -ClaimToken $claimToken `
            -Status "MISSION_ACKNOWLEDGED" `
            -Detail @{ worker_process_id = $PID; worker_process_started_at = $workerStartedAt; process_detail = @{ diary_path = $script:CurrentDiaryPath; attempt = $script:CurrentAttempt; claim_generation = $script:CurrentClaimGeneration; resumed = [bool]$claimResponse.resume } }
    }

    # 5. Report In-Progress
    $null = Send-MinionStatus `
        -MissionControlUrl $MissionControlUrl `
        -MinionId $MinionId `
        -MissionId $missionId `
        -ApiKey $ApiKey `
        -ClaimToken $claimToken `
        -Status "MISSION_IN_PROGRESS" `
        -Detail @{ worker_process_id = $PID; worker_process_started_at = $workerStartedAt; process_detail = @{ diary_path = $script:CurrentDiaryPath; phase = "STARTING" } }
    $diary.status = "IN_PROGRESS"
    Write-MissionDiary -Path $script:CurrentDiaryPath -Diary $diary

    # 6. Execute Capability Handler
    $terminalStatus = "MISSION_COMPLETE_SUCCEEDED"
    $outcome = $null
    $statusContext = @{
        MissionControlUrl = $MissionControlUrl
        MinionId = $MinionId
        MissionId = $missionId
        ApiKey = $ApiKey
        ClaimToken = $claimToken
        WorkerProcessId = $PID
        WorkerStartedAt = $workerStartedAt
    }
    $statusReporter = {
        param([string]$Status, [hashtable]$Detail, [hashtable]$Context)
        Send-MinionStatus `
            -MissionControlUrl $Context.MissionControlUrl `
            -MinionId $Context.MinionId `
            -MissionId $Context.MissionId `
            -ApiKey $Context.ApiKey `
            -ClaimToken $Context.ClaimToken `
            -Status $Status `
            -Detail (@{
                worker_process_id = $Context.WorkerProcessId
                worker_process_started_at = $Context.WorkerStartedAt
                process_detail = $Detail
            }) | Out-Null
    }

    try {
        $outcome = & $capabilityHandler $envelope $statusReporter $statusContext
        if ($outcome -is [hashtable] -and $outcome.ContainsKey("Status")) {
            $terminalStatus = $outcome["Status"]
        }
    }
    catch {
        Write-Error "Execution error for Mission ${missionId}: $_"
        $terminalStatus = "MISSION_COMPLETE_FAILED"
        $outcome = @{
            Status = $terminalStatus
            Result = @{
                capability = $envelope.capability
                success    = $false
                error      = $_.ToString()
            }
        }
    }

    # 7. Submit signed result
    Write-Host "Submitting signed result for $missionId ($terminalStatus)..."
    $diary.status = $terminalStatus
    $diary.result = $outcome.Result
    Write-MissionDiary -Path $script:CurrentDiaryPath -Diary $diary

    if ($terminalStatus -in @("MISSION_IN_PROGRESS", "MISSION_WAITING_FOR_REBOOT")) {
        $null = Send-MinionStatus `
            -MissionControlUrl $MissionControlUrl `
            -MinionId $MinionId `
            -MissionId $missionId `
            -ApiKey $ApiKey `
            -ClaimToken $claimToken `
            -Status $terminalStatus `
            -Detail @{ worker_process_id = $PID; worker_process_started_at = $workerStartedAt; process_detail = $outcome.Result }
        $script:ActiveMission = @{
            mission_id = $missionId
            envelope = $envelope
            claim_token = $claimToken
            attempt = $script:CurrentAttempt
            claim_generation = $script:CurrentClaimGeneration
            resume = $true
            resume_status = $terminalStatus
            diary_path = $script:CurrentDiaryPath
        }
        return
    }

    $resultSubmission = Send-MinionResult `
        -MissionControlUrl $MissionControlUrl `
        -MinionId $MinionId `
        -MissionId $missionId `
        -ApiKey $ApiKey `
        -ClaimToken $claimToken `
        -PrivateKeyPath $MinionPrivateKeyPath `
        -Status $terminalStatus `
        -Result ($outcome.Result -as [hashtable])
    $terminalStatus = $resultSubmission.mission_status

    if ($resultSubmission.response.status -in @("RECORDED", "ALREADY_RECORDED")) {
        Remove-MissionTargetDiaries -MissionId $missionId -Result $outcome.Result
        Remove-Item -LiteralPath (Split-Path -Parent $script:CurrentDiaryPath) -Recurse -Force -ErrorAction SilentlyContinue
        $script:ActiveMission = $null
    }
    if ($script:ActiveHeartbeatJob) { Stop-Job $script:ActiveHeartbeatJob -ErrorAction SilentlyContinue; Remove-Job $script:ActiveHeartbeatJob -Force -ErrorAction SilentlyContinue; $script:ActiveHeartbeatJob = $null }

    Write-Host "Mission $missionId completed with status $terminalStatus."
}

# Execution loop
if ($SinglePass) {
    Run-MissionPass
}
else {
    while ($true) {
        try {
            Run-MissionPass
        }
        catch {
            Write-Warning "Error in Minion pass: $_"
            if ($script:ActiveHeartbeatJob) { Stop-Job $script:ActiveHeartbeatJob -ErrorAction SilentlyContinue; Remove-Job $script:ActiveHeartbeatJob -Force -ErrorAction SilentlyContinue; $script:ActiveHeartbeatJob = $null }
        }
        $nextPollSeconds = if ($script:ActiveMission) { [int]$script:ActiveMission.envelope.execution.retry_interval_seconds } elseif ($script:RetryDelaySeconds) { $script:RetryDelaySeconds } else { $PollIntervalSeconds }
        Start-Sleep -Seconds $nextPollSeconds
    }
}
