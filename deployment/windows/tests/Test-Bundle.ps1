[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$WorkDir
)

# Builds a Minion-only bundle from the repository and reports its layout. Get-AuthenticodeSignature does not exist outside Windows.
$ErrorActionPreference = "Stop"
function Get-AuthenticodeSignature { param($FilePath) [pscustomobject]@{ Status = "NotSigned" } }

$executable = Join-Path $WorkDir "SluiceGate.Minion.Service.exe"
Set-Content -LiteralPath $executable -Value "stub executable"
$bundle = Join-Path $WorkDir "bundle"
& (Join-Path $PSScriptRoot "../Build-DeploymentBundle.ps1") -MinionExecutable $executable -Version "9.9.9" -OutputDirectory $bundle -SkipSignatureCheck 6>$null 3>$null

$secondRun = try { & (Join-Path $PSScriptRoot "../Build-DeploymentBundle.ps1") -MinionExecutable $executable -Version "9.9.9" -OutputDirectory $bundle -SkipSignatureCheck 6>$null 3>$null; "no error" } catch { $_.Exception.Message }

ConvertTo-Json -Compress -InputObject @{ secondRun = $secondRun }
