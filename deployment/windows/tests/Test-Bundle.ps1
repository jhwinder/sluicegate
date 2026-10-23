[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$WorkDir
)

# Builds a bundle from the repository and reports the result. Get-AuthenticodeSignature and docker are stubbed.
$ErrorActionPreference = "Stop"
function Get-AuthenticodeSignature { param($FilePath) [pscustomobject]@{ Status = "NotSigned" } }
function docker {
    $global:LASTEXITCODE = 0
    if ($args[0] -eq "save") { Set-Content -LiteralPath $args[2] -Value "stub image archive" }
}

$executable = Join-Path $WorkDir "SluiceGate.Minion.Service.exe"
Set-Content -LiteralPath $executable -Value "stub executable"
$bundle = Join-Path $WorkDir "bundle"
$builder = Join-Path $PSScriptRoot "../Build-DeploymentBundle.ps1"
& $builder -MinionExecutable $executable -ServiceImage "sluicegate/sg-service:9.9.9" -Version "9.9.9" -OutputDirectory $bundle 6>$null 3>$null

$secondRun = try { & $builder -MinionExecutable $executable -ServiceImage "sluicegate/sg-service:9.9.9" -Version "9.9.9" -OutputDirectory $bundle 6>$null 3>$null; "no error" } catch { $_.Exception.Message }

ConvertTo-Json -Compress -InputObject @{ secondRun = $secondRun }
