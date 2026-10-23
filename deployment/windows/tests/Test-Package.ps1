[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$WorkDir
)

# Exercises the installer helpers and API-key loading, then prints one JSON object for the caller to check.
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "../MinionInstallHelpers.ps1")
Import-Module (Join-Path $PSScriptRoot "../../../minion-registry/templates/powershell/SluiceGate.Minion.Core.psm1") -Force
$template = Join-Path $PSScriptRoot "../../../minion-registry/minions/patching/minion.config.example.json"

function Invoke-Case([scriptblock]$Block) {
    try { return @{ ok = $true; value = (& $Block); message = "" } }
    catch { return @{ ok = $false; value = $null; message = $_.Exception.Message } }
}

$results = [ordered]@{}

$results.fingerprints = Invoke-Case { @(Get-PemCertificateFingerprints -Path (Join-Path $WorkDir "bundle.pem")) }
$results.fingerprint_of_garbage = Invoke-Case { Get-PemCertificateFingerprints -Path (Join-Path $WorkDir "garbage.pem") }

$settings = @{
    MissionControlUrl = "https://sluicegate.example.internal"
    MinionId = "PATCH-02"
    ApiKeyPath = "C:\ProgramData\SluiceGate\Minion\keys\minion-api-key.txt"
    DryRun = $true
    TrustedServerCertificatePath = $null
    TrustedServerCertificateSha256 = $null
}
$results.config_without_certificate = Invoke-Case { New-MinionConfigurationJson -TemplatePath $template -Settings $settings | ConvertFrom-Json }

$withCertificate = $settings.Clone()
$withCertificate.TrustedServerCertificatePath = "C:\ProgramData\SluiceGate\Minion\keys\sg-server-cert.pem"
$withCertificate.TrustedServerCertificateSha256 = @("AA11", "BB22")
$results.config_with_certificate = Invoke-Case { New-MinionConfigurationJson -TemplatePath $template -Settings $withCertificate | ConvertFrom-Json }

$withInlineKey = Join-Path $WorkDir "template-with-inline-key.json"
@{ ApiKey = "inline-secret"; MinionId = "X" } | ConvertTo-Json | Set-Content -LiteralPath $withInlineKey
$results.config_drops_inline_api_key = Invoke-Case { (New-MinionConfigurationJson -TemplatePath $withInlineKey -Settings @{}) -match "inline-secret" }

$results.api_key = Invoke-Case { Get-MinionApiKey -Config ([pscustomobject]@{ ApiKeyPath = (Join-Path $WorkDir "api-key.txt") }) }
$results.api_key_inline = Invoke-Case { Get-MinionApiKey -Config ([pscustomobject]@{ ApiKey = "inline-secret"; ApiKeyPath = (Join-Path $WorkDir "api-key.txt") }) }
$results.api_key_unset = Invoke-Case { Get-MinionApiKey -Config ([pscustomobject]@{ MinionId = "X" }) }
$results.api_key_missing_file = Invoke-Case { Get-MinionApiKey -Config ([pscustomobject]@{ ApiKeyPath = (Join-Path $WorkDir "absent.txt") }) }
$results.api_key_empty_file = Invoke-Case { Get-MinionApiKey -Config ([pscustomobject]@{ ApiKeyPath = (Join-Path $WorkDir "empty-key.txt") }) }

ConvertTo-Json -InputObject $results -Depth 6 -Compress
