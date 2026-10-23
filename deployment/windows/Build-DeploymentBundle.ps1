[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$MinionExecutable,

    # Omit for a Minion-only bundle whose Mission Control runs on another host.
    [string]$ServiceImage,

    # Release identifier recorded in the bundle, for example 1.0.0.
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path,

    [string]$OutputDirectory = (Join-Path $PSScriptRoot "out"),

    [switch]$SkipSignatureCheck
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $MinionExecutable -PathType Leaf)) {
    throw "Minion executable not found: $MinionExecutable"
}
$signature = Get-AuthenticodeSignature -FilePath $MinionExecutable
if ($signature.Status -ne "Valid") {
    if ($SkipSignatureCheck) {
        Write-Warning "Minion executable is not Authenticode-signed (Status: $($signature.Status)). Proceeding because -SkipSignatureCheck was specified."
    } else {
        throw "Minion executable must be Authenticode-signed before bundling (Status: $($signature.Status)). Use -SkipSignatureCheck to bypass for testing/development."
    }
}

# Files the Minion needs at run time, relative to the repository root, and where they go under Minion/runtime.
$runtimeFiles = @(
    @{ Source = "minion-registry/minions/patching/PatchingMinion.ps1"; Target = "" },
    @{ Source = "minion-registry/minions/patching/PatchingCatalog.psm1"; Target = "" },
    @{ Source = "minion-registry/minions/patching/PatchingEngine.psm1"; Target = "" },
    @{ Source = "minion-registry/templates/powershell/SluiceGate.Minion.Core.psm1"; Target = "" },
    @{ Source = "minion-registry/protocol/mission-envelope.schema.json"; Target = "protocol" }
)
$configTemplate = Join-Path $RepositoryRoot "minion-registry/minions/patching/minion.config.example.json"
foreach ($path in @($configTemplate) + ($runtimeFiles | ForEach-Object { Join-Path $RepositoryRoot $_.Source })) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required runtime file not found: $path"
    }
}

if ((Test-Path -LiteralPath $OutputDirectory) -and (Get-ChildItem -LiteralPath $OutputDirectory -Force | Select-Object -First 1)) {
    throw "Output directory is not empty: $OutputDirectory. Choose a new directory or empty it first so stale files are not bundled."
}
$runtimeDirectory = Join-Path $OutputDirectory "Minion/runtime"
New-Item -ItemType Directory -Path $runtimeDirectory -Force | Out-Null

Copy-Item -LiteralPath $MinionExecutable -Destination (Join-Path $OutputDirectory "Minion/SluiceGate.Minion.Service.exe") -Force
foreach ($file in $runtimeFiles) {
    $destination = if ($file.Target) { Join-Path $runtimeDirectory $file.Target } else { $runtimeDirectory }
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $RepositoryRoot $file.Source) -Destination $destination -Force
}
@{ version = $Version; builtAtUtc = [DateTime]::UtcNow.ToString("o"); serviceImage = $ServiceImage } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runtimeDirectory "version.json") -Encoding UTF8

Copy-Item -LiteralPath $configTemplate -Destination (Join-Path $OutputDirectory "minion.config.template.json") -Force
foreach ($script in "Install-SluiceGate.ps1", "Uninstall-SluiceGate.ps1", "Set-MinionApiKey.ps1", "MinionInstallHelpers.ps1", "service.env.example", "README.md") {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $script) -Destination $OutputDirectory -Force
}

if ($ServiceImage) {
    docker image inspect $ServiceImage *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Service image not found locally: $ServiceImage"
    }
    New-Item -ItemType Directory -Path (Join-Path $OutputDirectory "images") -Force | Out-Null
    docker save --output (Join-Path $OutputDirectory "images/sg-service-image.tar") $ServiceImage
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to export service image"
    }
}

# One record per file, in the format used by sha256sum, so the whole bundle can be checked.
$root = (Resolve-Path $OutputDirectory).Path.TrimEnd('\', '/')
$manifest = Join-Path $root "SHA256SUMS.txt"
Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object { $_.FullName -ne $manifest } | Sort-Object FullName | ForEach-Object {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
    "{0}  {1}" -f $hash, $_.FullName.Substring($root.Length + 1).Replace('\', '/')
} | Set-Content -LiteralPath $manifest -Encoding ASCII
Write-Host "Deployment bundle $Version written to $root"
