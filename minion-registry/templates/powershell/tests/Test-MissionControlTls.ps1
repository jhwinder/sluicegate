[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScenarioFile
)

# Runs Mission Control TLS scenarios and prints one JSON array of results; the caller decides pass/fail.
$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "..\SluiceGate.Minion.Core.psm1") -Force

$scenarios = Get-Content -LiteralPath $ScenarioFile -Raw | ConvertFrom-Json
$results = foreach ($scenario in $scenarios) {
    $outcome = "success"
    $detail = ""
    try {
        $setup = @{
            MissionControlUrl = $scenario.url
            AllowInsecureHttp = ($scenario.allowInsecureHttp -eq $true)
        }
        if ($scenario.trustedCertificatePath) { $setup.TrustedCertificatePath = $scenario.trustedCertificatePath }
        if ($scenario.trustedCertificateSha256) { $setup.TrustedCertificateSha256 = @($scenario.trustedCertificateSha256) }
        Set-MinionTransportSecurity @setup -WarningAction SilentlyContinue
        if (-not $scenario.configOnly) {
            $response = Invoke-MinionHttp -Method Get -Uri ("{0}/health" -f $scenario.url.TrimEnd('/')) -Headers @{ Authorization = "Bearer test-key" } -TimeoutSec 15
            if ($response.status -ne "ok") { throw "Unexpected response from the test server." }
        }
    }
    catch {
        $outcome = "failure"
        $detail = $_.Exception.Message
        for ($inner = $_.Exception.InnerException; $null -ne $inner; $inner = $inner.InnerException) {
            if ($inner -is [SluiceGate.MissionControlHttpException]) { $detail = $inner.Message; break }
        }
    }
    [pscustomobject]@{ name = $scenario.name; outcome = $outcome; detail = $detail }
}
ConvertTo-Json -InputObject @($results) -Depth 4 -Compress
