# Shared helpers for Install-SluiceGate.ps1 and Set-MinionApiKey.ps1. Compatible with Windows PowerShell 5.1.

$script:AdministratorsSid = '*S-1-5-32-544'
$script:SystemSid = '*S-1-5-18'

function Get-PemCertificateFingerprints {
    <# Returns the uppercase SHA-256 fingerprint of every certificate in a PEM file. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $text = Get-Content -LiteralPath $Path -Raw
    $blocks = [regex]::Matches($text, '-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if ($blocks.Count -eq 0) {
        throw "No PEM-encoded certificate found in $Path."
    }
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        foreach ($block in $blocks) {
            $der = [Convert]::FromBase64String(($block.Groups[1].Value -replace '\s', ''))
            ([BitConverter]::ToString($sha256.ComputeHash($der))) -replace '-', ''
        }
    }
    finally {
        $sha256.Dispose()
    }
}

function New-MinionConfigurationJson {
    <#
    .SYNOPSIS
        Builds minion.config.json from the packaged template. A setting whose value is $null is removed from the result.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TemplatePath,
        [Parameter(Mandatory = $true)][hashtable]$Settings
    )

    $template = Get-Content -LiteralPath $TemplatePath -Raw | ConvertFrom-Json
    $result = [ordered]@{}
    foreach ($property in $template.PSObject.Properties) {
        $result[$property.Name] = $property.Value
    }
    foreach ($name in $Settings.Keys) {
        if ($null -eq $Settings[$name]) {
            $result.Remove($name)
        }
        else {
            $result[$name] = $Settings[$name]
        }
    }
    $result.Remove('ApiKey')
    return ($result | ConvertTo-Json -Depth 5)
}

function Resolve-ServiceAccountSid {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Account)

    try {
        return ([System.Security.Principal.NTAccount]$Account).Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        throw "Service account '$Account' could not be resolved. Use DOMAIN\name (or DOMAIN\name$ for a gMSA)."
    }
}

function Invoke-Icacls {
    param([string[]]$Arguments)
    $output = & icacls.exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "icacls failed for '$($Arguments -join ' ')': $output"
    }
}

function Set-MinionRestrictedAcl {
    <#
    .SYNOPSIS
        Removes inherited access and grants only Administrators and SYSTEM full control, plus optional read/modify access.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$AccountSid,
        [ValidateSet('Read', 'Modify')][string]$AccountAccess = 'Read'
    )

    $inherit = if (Test-Path -LiteralPath $Path -PathType Container) { '(OI)(CI)' } else { '' }
    $grants = @("$($script:AdministratorsSid):${inherit}F", "$($script:SystemSid):${inherit}F")
    if ($AccountSid) {
        $right = if ($AccountAccess -eq 'Modify') { 'M' } else { 'R' }
        $grants += "*${AccountSid}:${inherit}${right}"
    }
    Invoke-Icacls -Arguments (@($Path, '/inheritance:r', '/grant:r') + $grants)
}

function Set-MinionDataAcl {
    <# Protects the Minion data root: config and keys are read-only to the service account; data and the Mission Diary are writable. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$DataRoot,
        [Parameter(Mandatory = $true)][string]$AccountSid
    )

    Invoke-Icacls -Arguments @($DataRoot, '/inheritance:r', '/grant:r', "$($script:AdministratorsSid):(OI)(CI)F", "$($script:SystemSid):(OI)(CI)F", "*${AccountSid}:(RX)")
    foreach ($child in Get-ChildItem -LiteralPath $DataRoot -Recurse -Force) {
        Invoke-Icacls -Arguments @($child.FullName, '/reset')
    }
    foreach ($name in 'config', 'keys') {
        Invoke-Icacls -Arguments @((Join-Path $DataRoot $name), '/grant:r', "*${AccountSid}:(OI)(CI)R")
    }
    foreach ($name in 'data', 'MissionDiary') {
        Invoke-Icacls -Arguments @((Join-Path $DataRoot $name), '/grant:r', "*${AccountSid}:(OI)(CI)M")
    }
}
