<#
.SYNOPSIS
    SluiceGate Minion Core PowerShell Module
.DESCRIPTION
    Provides reusable functions for Minion Mission Control communication,
    cryptographic signature verification and signing, nonce replay protection,
    canonical JSON formatting, and envelope validation.
#>

function ConvertTo-CanonicalJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject
    )

    function Sort-ObjectKeys([object]$obj) {
        if ($null -eq $obj) {
            return $null
        }
        if ($obj -is [System.Collections.IDictionary]) {
            $sorted = [ordered]@{}
            foreach ($key in ($obj.Keys | Sort-Object)) {
                $sorted[$key] = Sort-ObjectKeys $obj[$key]
            }
            return $sorted
        }
        if ($obj -is [System.Collections.IEnumerable] -and $obj -isnot [string]) {
            $list = [System.Collections.Generic.List[object]]::new()
            foreach ($item in $obj) {
                $list.Add((Sort-ObjectKeys $item))
            }
            return $list
        }
        if ($obj -is [PSCustomObject]) {
            $sorted = [ordered]@{}
            foreach ($prop in ($obj.PSObject.Properties.Name | Sort-Object)) {
                $sorted[$prop] = Sort-ObjectKeys $obj.$prop
            }
            return $sorted
        }
        return $obj
    }

    $sortedObject = Sort-ObjectKeys $InputObject
    # Compress without whitespace
    $json = ConvertTo-Json -InputObject $sortedObject -Compress -Depth 10
    return $json
}

function Test-MinionSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CanonicalJson,

        [Parameter(Mandatory = $true)]
        [string]$SignatureHex,

        [Parameter(Mandatory = $true)]
        [string]$PublicKeyPath
    )

    if (-not (Test-Path -LiteralPath $PublicKeyPath -PathType Leaf)) {
        Write-Error "SluiceGate public key not found at: $PublicKeyPath"
        return $false
    }

    # OpenSSL verification approach
    $tempData = [System.IO.Path]::GetTempFileName()
    $tempSig = [System.IO.Path]::GetTempFileName()

    try {
        [System.IO.File]::WriteAllBytes($tempData, [System.Text.Encoding]::UTF8.GetBytes($CanonicalJson))
        $sigBytes = [byte[]]::new($SignatureHex.Length / 2)
        for ($i = 0; $i -lt $SignatureHex.Length; $i += 2) {
            $sigBytes[$i / 2] = [Convert]::ToByte($SignatureHex.Substring($i, 2), 16)
        }
        [System.IO.File]::WriteAllBytes($tempSig, $sigBytes)

        $null = & openssl pkeyutl -verify -pubin -inkey $PublicKeyPath -rawin -in $tempData -sigfile $tempSig 2>&1
        return ($LASTEXITCODE -eq 0)
    }
    catch {
        Write-Warning "Signature verification failed: $_"
        return $false
    }
    finally {
        if (Test-Path -LiteralPath $tempData) { Remove-Item -LiteralPath $tempData -Force -ErrorAction SilentlyContinue }
        if (Test-Path -LiteralPath $tempSig) { Remove-Item -LiteralPath $tempSig -Force -ErrorAction SilentlyContinue }
    }
}

function New-MinionSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CanonicalJson,

        [Parameter(Mandatory = $true)]
        [string]$PrivateKeyPath
    )

    if (-not (Test-Path -LiteralPath $PrivateKeyPath -PathType Leaf)) {
        throw "Minion private key not found at: $PrivateKeyPath"
    }

    $tempData = [System.IO.Path]::GetTempFileName()
    $tempSig = [System.IO.Path]::GetTempFileName()

    try {
        [System.IO.File]::WriteAllBytes($tempData, [System.Text.Encoding]::UTF8.GetBytes($CanonicalJson))
        $null = & openssl pkeyutl -sign -inkey $PrivateKeyPath -rawin -in $tempData -out $tempSig 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "OpenSSL signing failed with exit code $LASTEXITCODE"
        }
        $sigBytes = [System.IO.File]::ReadAllBytes($tempSig)
        $hex = [System.BitConverter]::ToString($sigBytes).Replace("-", "").ToLowerInvariant()
        return $hex
    }
    finally {
        if (Test-Path -LiteralPath $tempData) { Remove-Item -LiteralPath $tempData -Force -ErrorAction SilentlyContinue }
        if (Test-Path -LiteralPath $tempSig) { Remove-Item -LiteralPath $tempSig -Force -ErrorAction SilentlyContinue }
    }
}

function Test-MinionNonce {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Nonce,

        [Parameter(Mandatory = $true)]
        [string]$NonceStorePath
    )

    if (-not (Test-Path -LiteralPath $NonceStorePath)) {
        return $true
    }

    $seen = Get-Content -LiteralPath $NonceStorePath -ErrorAction SilentlyContinue
    if ($seen -contains $Nonce) {
        return $false
    }
    return $true
}

function Add-MinionNonce {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Nonce,

        [Parameter(Mandatory = $true)]
        [string]$NonceStorePath,

        [int]$MaxEntries = 10000
    )

    $parent = [System.IO.Path]::GetDirectoryName($NonceStorePath)
    if ($parent -and (-not (Test-Path -LiteralPath $parent))) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    Add-Content -LiteralPath $NonceStorePath -Value $Nonce -Encoding UTF8

    # Trim if exceeds max
    $lines = Get-Content -LiteralPath $NonceStorePath -ErrorAction SilentlyContinue
    if ($lines.Count -gt $MaxEntries) {
        $trimmed = $lines | Select-Object -Last ($MaxEntries / 2)
        Set-Content -LiteralPath $NonceStorePath -Value $trimmed -Encoding UTF8
    }
}

function Test-MissionEnvelope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Envelope,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedMinionId,

        [Parameter(Mandatory = $true)]
        [string]$SluiceGatePublicKeyPath,

        [Parameter(Mandatory = $true)]
        [string]$NonceStorePath,

        [Parameter(Mandatory = $true)]
        [string[]]$SupportedCapabilities
    )

    $rejectionReason = $null

    # 1. Protocol version validation
    if ($Envelope.protocol_version -ne "1.0") {
        return @{ IsValid = $false; Reason = "UNSUPPORTED_PROTOCOL_VERSION"; Message = "Protocol version '$($Envelope.protocol_version)' is unsupported." }
    }

    # 2. Intended Minion ID validation
    if ($Envelope.minion_id -ne $ExpectedMinionId) {
        return @{ IsValid = $false; Reason = "MINION_ID_MISMATCH"; Message = "Mission addressed to '$($Envelope.minion_id)', expected '$ExpectedMinionId'." }
    }

    # 3. Capability validation
    if ($SupportedCapabilities -notcontains $Envelope.capability) {
        return @{ IsValid = $false; Reason = "UNSUPPORTED_CAPABILITY"; Message = "Capability '$($Envelope.capability)' not supported by this Minion." }
    }

    # 4. Expiration validation
    $nowEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if ($Envelope.expires_at -and ($Envelope.expires_at -lt $nowEpoch)) {
        return @{ IsValid = $false; Reason = "MISSION_EXPIRED"; Message = "Mission expired at $($Envelope.expires_at), current time is $nowEpoch." }
    }

    # 5. Nonce / replay validation
    if (-not (Test-MinionNonce -Nonce $Envelope.nonce -NonceStorePath $NonceStorePath)) {
        return @{ IsValid = $false; Reason = "REPLAY_DETECTED"; Message = "Nonce '$($Envelope.nonce)' has already been consumed." }
    }

    # 6. SluiceGate signature verification
    $signature = $Envelope.signature
    if (-not $signature) {
        return @{ IsValid = $false; Reason = "MISSING_SIGNATURE"; Message = "Mission envelope does not contain a signature." }
    }

    # Construct payload without signature for verification
    $payload = [ordered]@{}
    foreach ($prop in $Envelope.PSObject.Properties) {
        if ($prop.Name -ne "signature") {
            $payload[$prop.Name] = $prop.Value
        }
    }
    $canonicalJson = ConvertTo-CanonicalJson -InputObject $payload
    $sigValid = Test-MinionSignature -CanonicalJson $canonicalJson -SignatureHex $signature -PublicKeyPath $SluiceGatePublicKeyPath

    if (-not $sigValid) {
        return @{ IsValid = $false; Reason = "INVALID_SIGNATURE"; Message = "Cryptographic signature verification failed." }
    }

    return @{ IsValid = $true; Reason = $null; Message = "Mission envelope is valid." }
}

function Invoke-MinionCheckIn {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MissionControlUrl,

        [Parameter(Mandatory = $true)]
        [string]$MinionId,

        [Parameter(Mandatory = $true)]
        [string]$ApiKey
    )

    $url = "$($MissionControlUrl.TrimEnd('/'))/internal/v1/minions/$MinionId/check-in"
    $headers = @{
        "Authorization" = "Bearer $ApiKey"
        "Content-Type"  = "application/json"
    }

    try {
        $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -TimeoutSec 15
        return $response
    }
    catch {
        Write-Warning "Check-in failed: $_"
        return $null
    }
}

function Get-MinionMissionClaim {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MissionControlUrl,

        [Parameter(Mandatory = $true)]
        [string]$MinionId,

        [Parameter(Mandatory = $true)]
        [string]$ApiKey
    )

    $url = "$($MissionControlUrl.TrimEnd('/'))/internal/v1/minions/$MinionId/missions/claim"
    $headers = @{
        "Authorization" = "Bearer $ApiKey"
        "Content-Type"  = "application/json"
    }

    try {
        $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -TimeoutSec 15
        return $response
    }
    catch {
        Write-Warning "Mission claim request failed: $_"
        return $null
    }
}

function Send-MinionStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MissionControlUrl,

        [Parameter(Mandatory = $true)]
        [string]$MinionId,

        [Parameter(Mandatory = $true)]
        [string]$MissionId,

        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$Status,

        [hashtable]$Detail = @{}
    )

    $url = "$($MissionControlUrl.TrimEnd('/'))/internal/v1/minions/$MinionId/missions/$MissionId/status"
    $headers = @{
        "Authorization" = "Bearer $ApiKey"
        "Content-Type"  = "application/json"
    }

    $eventId = "evt-" + [System.Guid]::NewGuid().ToString("N")
    $body = @{
        event_id    = $eventId
        status      = $Status
        detail      = $Detail
        occurred_at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    } | ConvertTo-Json -Depth 6

    $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body -TimeoutSec 15
    return $response
}

function Send-MinionResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MissionControlUrl,

        [Parameter(Mandatory = $true)]
        [string]$MinionId,

        [Parameter(Mandatory = $true)]
        [string]$MissionId,

        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$PrivateKeyPath,

        [Parameter(Mandatory = $true)]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [hashtable]$Result
    )

    $url = "$($MissionControlUrl.TrimEnd('/'))/internal/v1/minions/$MinionId/missions/$MissionId/result"
    $headers = @{
        "Authorization" = "Bearer $ApiKey"
        "Content-Type"  = "application/json"
    }

    $eventId = "evt-" + [System.Guid]::NewGuid().ToString("N")
    $signedPayload = [ordered]@{
        event_id   = $eventId
        mission_id = $MissionId
        minion_id  = $MinionId
        result     = $Result
        status     = $Status
    }

    $canonicalJson = ConvertTo-CanonicalJson -InputObject $signedPayload
    $signature = New-MinionSignature -CanonicalJson $canonicalJson -PrivateKeyPath $PrivateKeyPath

    $body = @{
        event_id  = $eventId
        status    = $Status
        result    = $Result
        signature = $signature
    } | ConvertTo-Json -Depth 10

    $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body -TimeoutSec 20
    return $response
}

Export-ModuleMember -Function `
    ConvertTo-CanonicalJson, `
    Test-MinionSignature, `
    New-MinionSignature, `
    Test-MinionNonce, `
    Add-MinionNonce, `
    Test-MissionEnvelope, `
    Invoke-MinionCheckIn, `
    Get-MinionMissionClaim, `
    Send-MinionStatus, `
    Send-MinionResult
