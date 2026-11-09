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

$executable = Join-Path $PSScriptRoot "../Minion/SluiceGate.Minion.Service.exe"
$bundle = Join-Path $WorkDir "bundle"
$builder = Join-Path $PSScriptRoot "../Build-DeploymentBundle.ps1"
$version = (Get-Content -LiteralPath (Join-Path $PSScriptRoot "../../../minion-registry/minions/patching/minion-release.json") -Raw | ConvertFrom-Json).version
& $builder -MinionExecutable $executable -ServiceImage "sluicegate/sg-service:9.9.9" -Version $version -OutputDirectory $bundle 6>$null 3>$null

$secondRun = try { & $builder -MinionExecutable $executable -ServiceImage "sluicegate/sg-service:9.9.9" -Version $version -OutputDirectory $bundle 6>$null 3>$null; "no error" } catch { $_.Exception.Message }

$runtime = Join-Path $bundle "Minion/runtime"
$worker = Join-Path $runtime "PatchingMinion.ps1"
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($worker, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw "Patching Minion has syntax errors: $errors" }
$function = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq "Get-ReleaseReport" }, $true)
if (-not $function) { throw "Release report function not found" }
$probe = Join-Path $runtime "release-probe.ps1"
$original = [System.IO.File]::ReadAllBytes($worker)
try {
    [System.IO.File]::WriteAllText($probe, $function.Extent.Text + "`nGet-ReleaseReport | ConvertTo-Json -Compress`n")
    $report = & $probe | ConvertFrom-Json
    Add-Content -LiteralPath $worker -Value "# tampered"
    $changed = & $probe | ConvertFrom-Json
    Remove-Item -LiteralPath $worker
    $missing = try { & $probe; "no error" } catch { $_.Exception.Message }
}
finally {
    [System.IO.File]::WriteAllBytes($worker, $original)
    Remove-Item -LiteralPath $probe -Force
}

ConvertTo-Json -Compress -InputObject @{ secondRun = $secondRun; report = $report; changed = $changed; missing = $missing }
