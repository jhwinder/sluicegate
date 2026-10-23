<#
.SYNOPSIS
    SluiceGate Generic PowerShell Minion Worker Loop Template
.DESCRIPTION
    Reusable template for instantiating non-autonomous PowerShell Minions.
    Handles Mission Control polling, envelope authentication, nonce replay protection,
    status transition reporting, and signed result return.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

    [scriptblock]$CapabilityHandler = $null
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Configuration file not found: $ConfigPath"
}

$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$modulePath = Join-Path $PSScriptRoot "SluiceGate.Minion.Core.psm1"
Import-Module $modulePath -Force

$MissionControlUrl       = if ($config.MissionControlUrl) { $config.MissionControlUrl } else { $config.CentralCommandUrl }
$MinionId                = $config.MinionId
$ApiKey                  = Get-MinionApiKey -Config $config
$SluiceGatePublicKeyPath = $config.SluiceGatePublicKeyPath
$MinionPrivateKeyPath    = $config.MinionPrivateKeyPath
$NonceStorePath          = if ($config.NonceStorePath) { $config.NonceStorePath } else { Join-Path $PSScriptRoot "nonces.txt" }
$PollIntervalSeconds     = if ($config.PollIntervalSeconds) { [int]$config.PollIntervalSeconds } else { 60 }
$SupportedCapabilities   = @($config.SupportedCapabilities)

Set-MinionTransportSecurity `
    -MissionControlUrl $MissionControlUrl `
    -TrustedCertificatePath $config.TrustedServerCertificatePath `
    -TrustedCertificateSha256 @($config.TrustedServerCertificateSha256) `
    -AllowInsecureHttp ($config.AllowInsecureHttp -eq $true)

Write-Host "Starting SluiceGate Minion '$MinionId'..."
Write-Host "Mission Control URL: $MissionControlUrl"
Write-Host "Supported Capabilities: $($SupportedCapabilities -join ', ')"

while ($true) {
    try {
        # 1. Check in with Minion Mission Control
        $checkIn = Invoke-MinionCheckIn -MissionControlUrl $MissionControlUrl -MinionId $MinionId -ApiKey $ApiKey
        if ($null -ne $checkIn) {
            # 2. Check for assigned missions
            $claimResponse = Get-MinionMissionClaim -MissionControlUrl $MissionControlUrl -MinionId $MinionId -ApiKey $ApiKey
            if ($null -ne $claimResponse -and $null -ne $claimResponse.mission_id) {
                $missionId = $claimResponse.mission_id
                $envelope  = $claimResponse.envelope
                $claimToken = $claimResponse.claim_token
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
                        -MissionControlUrl $MissionControlUrl `
                        -MinionId $MinionId `
                        -MissionId $missionId `
                        -ApiKey $ApiKey `
                        -ClaimToken $claimToken `
                        -Status "MISSION_REJECTED" `
                        -Detail @{ reason = $validation.Reason; message = $validation.Message }
                    continue
                }

                # Record consumed nonce
                Add-MinionNonce -Nonce $envelope.nonce -NonceStorePath $NonceStorePath

                # 4. Acknowledge Mission
                $null = Send-MinionStatus `
                    -MissionControlUrl $MissionControlUrl `
                    -MinionId $MinionId `
                    -MissionId $missionId `
                    -ApiKey $ApiKey `
                    -ClaimToken $claimToken `
                    -Status "MISSION_ACKNOWLEDGED"

                # 5. Report Execution Started
                $null = Send-MinionStatus `
                    -MissionControlUrl $MissionControlUrl `
                    -MinionId $MinionId `
                    -MissionId $missionId `
                    -ApiKey $ApiKey `
                    -ClaimToken $claimToken `
                    -Status "MISSION_IN_PROGRESS"

                # 6. Execute capability handler
                $executionResult = $null
                $terminalStatus = "MISSION_COMPLETE_SUCCEEDED"

                try {
                    if ($null -ne $CapabilityHandler) {
                        $executionResult = & $CapabilityHandler $envelope
                        if ($executionResult -is [hashtable] -and $executionResult.ContainsKey("Status")) {
                            $terminalStatus = $executionResult["Status"]
                        }
                    }
                    else {
                        $executionResult = @{
                            success = $true
                            message = "Template no-op handler executed."
                        }
                    }
                }
                catch {
                    Write-Error "Handler execution error: $_"
                    $terminalStatus = "MISSION_COMPLETE_FAILED"
                    $executionResult = @{
                        success = $false
                        error = $_.ToString()
                    }
                }

                # 7. Submit signed result
                Write-Host "Sending final Mission Result for $missionId ($terminalStatus)..."
                $null = Send-MinionResult `
                    -MissionControlUrl $MissionControlUrl `
                    -MinionId $MinionId `
                    -MissionId $missionId `
                    -ApiKey $ApiKey `
                    -ClaimToken $claimToken `
                    -PrivateKeyPath $MinionPrivateKeyPath `
                    -Status $terminalStatus `
                    -Result ($executionResult -as [hashtable])
                
                Write-Host "Mission $missionId completed with status $terminalStatus."
            }
        }
    }
    catch {
        Write-Warning "Minion worker loop error: $_"
    }

    Start-Sleep -Seconds $PollIntervalSeconds
}
