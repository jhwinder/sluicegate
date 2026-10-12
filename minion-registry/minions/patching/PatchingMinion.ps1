<#
.SYNOPSIS
    SluiceGate Windows Patching Minion
.DESCRIPTION
    Non-autonomous Minion runtime for Windows OS and non-OS IAVM patching.
    Polls SluiceGate Minion Central Command, claims authorized missions,
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

$CentralCommandUrl       = $config.CentralCommandUrl
$MinionId                = if ($config.MinionId) { $config.MinionId } else { "PATCH-01" }
$ApiKey                  = $config.ApiKey
$SluiceGatePublicKeyPath = $config.SluiceGatePublicKeyPath
$MinionPrivateKeyPath    = $config.MinionPrivateKeyPath
$CatalogPath             = $config.CatalogPath
$NessusMappingPath       = $config.NessusMappingPath
$NonceStorePath          = if ($config.NonceStorePath) { $config.NonceStorePath } else { Join-Path $PSScriptRoot "nonces.txt" }
$PollIntervalSeconds     = if ($config.PollIntervalSeconds) { [int]$config.PollIntervalSeconds } else { 3600 }
$DryRun                  = if ($config.DryRun) { [bool]$config.DryRun } else { $false }
$SupportedCapabilities   = @(
    "windows.patch.reconcile",
    "windows.patch.discover",
    "windows.patch.inspect",
    "windows.patch.install",
    "windows.patch.status"
)

Write-Host "=========================================================="
Write-Host " SluiceGate Windows Patching Minion: $MinionId"
Write-Host " Central Command: $CentralCommandUrl"
Write-Host " Catalog Path:    $CatalogPath"
Write-Host " Mapping Path:    $NessusMappingPath"
Write-Host " DryRun Mode:     $DryRun"
Write-Host "=========================================================="

# Define the capability handler scriptblock
$capabilityHandler = {
    param([pscustomobject]$MissionEnvelope)

    $capability = $MissionEnvelope.capability

    switch ($capability) {
        "windows.patch.reconcile" {
            return Invoke-PatchReconcile `
                -Envelope $MissionEnvelope `
                -CatalogPath $CatalogPath `
                -NessusMappingPath $NessusMappingPath `
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
    # 1. Check in with Minion Central Command
    $checkIn = Invoke-MinionCheckIn -CentralCommandUrl $CentralCommandUrl -MinionId $MinionId -ApiKey $ApiKey
    if ($null -eq $checkIn) {
        Write-Warning "Check-in failed with Minion Central Command. Retrying next cycle..."
        return
    }

    # 2. Claim queued mission
    $claimResponse = Get-MinionMissionClaim -CentralCommandUrl $CentralCommandUrl -MinionId $MinionId -ApiKey $ApiKey
    if ($null -eq $claimResponse -or $null -eq $claimResponse.mission_id) {
        # No queued missions
        return
    }

    $missionId = $claimResponse.mission_id
    $envelope  = $claimResponse.envelope
    Write-Host "Claimed Mission: $missionId (Capability: $($envelope.capability))"

    # 3. Validate Task Envelope
    $validation = Test-MissionEnvelope `
        -Envelope $envelope `
        -ExpectedMinionId $MinionId `
        -SluiceGatePublicKeyPath $SluiceGatePublicKeyPath `
        -NonceStorePath $NonceStorePath `
        -SupportedCapabilities $SupportedCapabilities

    if (-not $validation.IsValid) {
        Write-Warning "Mission $missionId validation failed: $($validation.Reason) - $($validation.Message)"
        $null = Send-MinionStatus `
            -CentralCommandUrl $CentralCommandUrl `
            -MinionId $MinionId `
            -MissionId $missionId `
            -ApiKey $ApiKey `
            -Status "MISSION_REJECTED" `
            -Detail @{ reason = $validation.Reason; message = $validation.Message }
        return
    }

    # Record nonce
    Add-MinionNonce -Nonce $envelope.nonce -NonceStorePath $NonceStorePath

    # 4. Acknowledge Mission
    $null = Send-MinionStatus `
        -CentralCommandUrl $CentralCommandUrl `
        -MinionId $MinionId `
        -MissionId $missionId `
        -ApiKey $ApiKey `
        -Status "MISSION_ACKNOWLEDGED"

    # 5. Report In-Progress
    $null = Send-MinionStatus `
        -CentralCommandUrl $CentralCommandUrl `
        -MinionId $MinionId `
        -MissionId $missionId `
        -ApiKey $ApiKey `
        -Status "MISSION_IN_PROGRESS"

    # 6. Execute Capability Handler
    $terminalStatus = "MISSION_COMPLETE_SUCCEEDED"
    $outcome = $null

    try {
        $outcome = & $capabilityHandler $envelope
        if ($outcome -is [hashtable] -and $outcome.ContainsKey("Status")) {
            $terminalStatus = $outcome["Status"]
        }
    }
    catch {
        Write-Error "Execution error for Mission $missionId: $_"
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
    $null = Send-MinionResult `
        -CentralCommandUrl $CentralCommandUrl `
        -MinionId $MinionId `
        -MissionId $missionId `
        -ApiKey $ApiKey `
        -PrivateKeyPath $MinionPrivateKeyPath `
        -Status $terminalStatus `
        -Result ($outcome.Result -as [hashtable])

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
        }
        Start-Sleep -Seconds $PollIntervalSeconds
    }
}
