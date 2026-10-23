[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageRoot,

    [Parameter(Mandatory = $true)]
    [string]$ServiceImage,

    [Parameter(Mandatory = $true)]
    [string]$MissionControlUrl,

    [Parameter(Mandatory = $true)]
    [string]$MinionId,

    [string]$InstallRoot = "$env:ProgramFiles\SluiceGate\Minion",
    [string]$ContainerName = "sluicegate-service",
    [switch]$SkipSignatureCheck
)

$ErrorActionPreference = "Stop"
$serviceName = "SluiceGateMinion"
$serviceExecutable = Join-Path $InstallRoot "SluiceGate.Minion.Service.exe"
$databaseVolume = "sluicegate-service-data"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker CLI is not installed or is not available on PATH. Install the latest stable Docker release supported on Windows Server 2022 first."
}

$dockerVersion = docker version --format '{{.Server.Version}}' 2>$null
if ($LASTEXITCODE -ne 0 -or -not $dockerVersion) {
    throw "Docker Engine is unavailable. Start and validate Docker before installing SluiceGate."
}

if (-not (Test-Path -LiteralPath $PackageRoot)) {
    throw "Package root not found: $PackageRoot"
}

$requiredArtifacts = @(
    (Join-Path $PackageRoot "Minion\SluiceGate.Minion.Service.exe"),
    (Join-Path $PackageRoot "service.env.example"),
    (Join-Path $PackageRoot "images\sg-service-image.tar")
)
foreach ($artifact in $requiredArtifacts) {
    if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
        throw "Required deployment artifact is missing: $artifact"
    }
}

$minionSignature = Get-AuthenticodeSignature -FilePath $requiredArtifacts[0]
if ($minionSignature.Status -ne "Valid") {
    if ($SkipSignatureCheck) {
        Write-Warning "The SG Minion executable is not Authenticode-signed (Status: $($minionSignature.Status)). Proceeding because -SkipSignatureCheck was specified."
    } else {
        throw "The SG Minion executable must have a valid Authenticode signature (Status: $($minionSignature.Status)). Use -SkipSignatureCheck to bypass for testing/development."
    }
}

$serviceEnvPath = Join-Path $InstallRoot "service.env"
$signingKeyPath = Join-Path $InstallRoot "sg-signing-key.pem"
$tlsDirectory = Join-Path $InstallRoot "tls"
$tlsCertificatePath = Join-Path $tlsDirectory "server-cert.pem"
$tlsKeyPath = Join-Path $tlsDirectory "server-key.pem"
$policyDirectory = Join-Path $InstallRoot "policy"
$policyPath = Join-Path $policyDirectory "production-policy.yml"
if (-not $MissionControlUrl.StartsWith("https://", [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "MissionControlUrl must use https. Plain HTTP Mission Control is supported only for local development."
}
if (-not (Test-Path -LiteralPath $serviceEnvPath -PathType Leaf)) {
    throw "Provision service.env using approved secret management before installation."
}
if (-not (Test-Path -LiteralPath $signingKeyPath -PathType Leaf)) {
    throw "Provision the SluiceGate Ed25519 signing key at $signingKeyPath using approved key management before installation."
}
foreach ($tlsFile in @($tlsCertificatePath, $tlsKeyPath)) {
    if (-not (Test-Path -LiteralPath $tlsFile -PathType Leaf)) {
        throw "Provision the Mission Control TLS certificate and private key at $tlsFile before installation (see docs/Installation_Guide.md)."
    }
}
if (-not (Test-Path -LiteralPath $policyPath -PathType Leaf)) {
    throw "Provision the approved SluiceGate policy at $policyPath before installation."
}

if ($PSCmdlet.ShouldProcess($InstallRoot, "Install SluiceGate Minion service and container")) {
    New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
    Copy-Item -Path (Join-Path $PackageRoot "Minion\*") -Destination $InstallRoot -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $PackageRoot "service.env.example") -Destination (Join-Path $InstallRoot "service.env.example") -Force
    docker load --input (Join-Path $PackageRoot "images\sg-service-image.tar")
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to load the SluiceGate service image bundle"
    }

    docker rm -f $ContainerName 2>$null | Out-Null
    docker volume create $databaseVolume | Out-Null
    docker run -d --restart unless-stopped --name $ContainerName `
        -p 127.0.0.1:8443:8443 `
        -v "${databaseVolume}:/data" `
        -v ("{0}:/run/secrets/sg-signing-key.pem:ro" -f $signingKeyPath) `
        -v ("{0}:/run/tls:ro" -f $tlsDirectory) `
        -e SG_TLS_CERT_FILE=/run/tls/server-cert.pem `
        -e SG_TLS_KEY_FILE=/run/tls/server-key.pem `
        -v ("{0}:/config:rw" -f $policyDirectory) `
        --env-file $serviceEnvPath `
        $ServiceImage
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to start SluiceGate service container"
    }

    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        Stop-Service -Name $serviceName -Force
        sc.exe delete $serviceName | Out-Null
    }
    New-Service -Name $serviceName -BinaryPathName ('"{0}" --config "{1}" --minion-id "{2}" --mission-control-url "{3}"' -f $serviceExecutable, (Join-Path $InstallRoot "minion.config.json"), $MinionId, $MissionControlUrl) `
        -DisplayName "SluiceGate Minion" -Description "SluiceGate Minion Mission Control client and execution runtime" `
        -StartupType Automatic | Out-Null
    Start-Service -Name $serviceName
}

Write-Host "SluiceGate deployment configured. Docker Engine version: $dockerVersion"
Write-Host "Configure the service logon identity and target/share permissions through your approved Windows administration process."
