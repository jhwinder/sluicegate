[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot "secrets")
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$privateKeyPath = Join-Path $OutputDirectory "demo-minion-key.pem"
$publicKeyPath = Join-Path $OutputDirectory "demo-minion-public.pem"
openssl genpkey -algorithm ED25519 -out $privateKeyPath
if ($LASTEXITCODE -ne 0) { throw "Failed to create development Minion private key" }
openssl pkey -in $privateKeyPath -pubout -out $publicKeyPath
if ($LASTEXITCODE -ne 0) { throw "Failed to create development Minion public key" }
Write-Host "Created development-only demo signing keys under $OutputDirectory"
Write-Warning "Do not use these keys outside local demo development. Protect and delete the private key when finished."
