[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$MinionExecutable,

    [Parameter(Mandatory = $true)]
    [string]$ServiceImage,

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

New-Item -ItemType Directory -Path (Join-Path $OutputDirectory "Minion") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $OutputDirectory "images") -Force | Out-Null
Copy-Item -LiteralPath $MinionExecutable -Destination (Join-Path $OutputDirectory "Minion\SluiceGate.Minion.Service.exe") -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "Install-SluiceGate.ps1") -Destination $OutputDirectory -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "Uninstall-SluiceGate.ps1") -Destination $OutputDirectory -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "service.env.example") -Destination $OutputDirectory -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "README.md") -Destination $OutputDirectory -Force

docker image inspect $ServiceImage *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Service image not found locally: $ServiceImage"
}
docker save --output (Join-Path $OutputDirectory "images\sg-service-image.tar") $ServiceImage
if ($LASTEXITCODE -ne 0) {
    throw "Failed to export service image"
}

Get-FileHash -Algorithm SHA256 -Path (Join-Path $OutputDirectory "Minion\SluiceGate.Minion.Service.exe") | Format-List | Out-File (Join-Path $OutputDirectory "SHA256SUMS.txt")
Get-FileHash -Algorithm SHA256 -Path (Join-Path $OutputDirectory "images\sg-service-image.tar") | Format-List | Out-File (Join-Path $OutputDirectory "SHA256SUMS.txt") -Append
Write-Host "Deployment bundle written to $OutputDirectory"
