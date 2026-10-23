[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageRoot,

    # Required unless -SkipServiceContainer is used.
    [string]$ServiceImage,

    [Parameter(Mandatory = $true)]
    [string]$MissionControlUrl,

    [Parameter(Mandatory = $true)]
    [string]$MinionId,

    [Parameter(Mandatory = $true)]
    [string]$CatalogPath,

    [Parameter(Mandatory = $true)]
    [string]$NessusMappingPath,

    # DOMAIN\name for a domain account, or DOMAIN\name$ for a gMSA.
    [Parameter(Mandatory = $true)]
    [string]$ServiceAccount,

    [securestring]$ServiceAccountPassword,

    # PEM certificate the Minion should trust (self-signed server certificate or private CA).
    [string]$TrustedServerCertificate,

    [string]$InstallRoot = "$env:ProgramFiles\SluiceGate\Minion",
    [string]$DataRoot = "$env:ProgramData\SluiceGate\Minion",
    [string]$ContainerName = "sluicegate-service",
    [switch]$ReplaceConfig,
    [switch]$DisableDryRun,
    # Install only the Minion; Mission Control runs on another host.
    [switch]$SkipServiceContainer,
    [switch]$SkipSignatureCheck
)

$ErrorActionPreference = "Stop"
$serviceName = "SluiceGateMinion"
$serviceExecutable = Join-Path $InstallRoot "SluiceGate.Minion.Service.exe"
$databaseVolume = "sluicegate-service-data"

. (Join-Path $PSScriptRoot "MinionInstallHelpers.ps1")

$dockerVersion = $null
if (-not $SkipServiceContainer) {
    if (-not $ServiceImage) {
        throw "ServiceImage is required unless -SkipServiceContainer is used."
    }
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw "Docker CLI is not installed or is not available on PATH. Install the latest stable Docker release supported on Windows Server 2022 first."
    }

    $dockerVersion = docker version --format '{{.Server.Version}}' 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $dockerVersion) {
        throw "Docker Engine is unavailable. Start and validate Docker before installing SluiceGate."
    }
}

if (-not (Test-Path -LiteralPath $PackageRoot)) {
    throw "Package root not found: $PackageRoot"
}

$requiredArtifacts = @(
    (Join-Path $PackageRoot "Minion\SluiceGate.Minion.Service.exe"),
    (Join-Path $PackageRoot "Minion\runtime\PatchingMinion.ps1"),
    (Join-Path $PackageRoot "Minion\runtime\PatchingCatalog.psm1"),
    (Join-Path $PackageRoot "Minion\runtime\PatchingEngine.psm1"),
    (Join-Path $PackageRoot "Minion\runtime\SluiceGate.Minion.Core.psm1"),
    (Join-Path $PackageRoot "minion.config.template.json")
)
if (-not $SkipServiceContainer) {
    $requiredArtifacts += (Join-Path $PackageRoot "service.env.example")
    $requiredArtifacts += (Join-Path $PackageRoot "images\sg-service-image.tar")
}
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
if (-not $SkipServiceContainer) {
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
}

# Keys are provisioned before installation so they never sit in a package or a command line.
$keysDirectory = Join-Path $DataRoot "keys"
$apiKeyFile = Join-Path $keysDirectory "minion-api-key.txt"
$minionPrivateKeyFile = Join-Path $keysDirectory "minion-private-key.pem"
$sluiceGatePublicKeyFile = Join-Path $keysDirectory "sg-public-key.pem"
$serverCertificateFile = Join-Path $keysDirectory "sg-server-cert.pem"
foreach ($keyFile in @($apiKeyFile, $minionPrivateKeyFile, $sluiceGatePublicKeyFile)) {
    if (-not (Test-Path -LiteralPath $keyFile -PathType Leaf)) {
        throw "Provision $keyFile before installation. Use Set-MinionApiKey.ps1 for the API key; see the Installation Guide for the key pair and the SluiceGate public key."
    }
}

$trustedFingerprints = $null
if ($TrustedServerCertificate) {
    if (-not (Test-Path -LiteralPath $TrustedServerCertificate -PathType Leaf)) {
        throw "Trusted server certificate file not found: $TrustedServerCertificate"
    }
    $trustedFingerprints = @(Get-PemCertificateFingerprints -Path $TrustedServerCertificate)
}

$accountSid = Resolve-ServiceAccountSid -Account $ServiceAccount
$isManagedAccount = $ServiceAccount.EndsWith('$')
if (-not $isManagedAccount -and -not $ServiceAccountPassword) {
    $ServiceAccountPassword = Read-Host -Prompt "Password for $ServiceAccount" -AsSecureString
}

if ($PSCmdlet.ShouldProcess($InstallRoot, "Install SluiceGate Minion service and container")) {
    $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($existingService) {
        if ($existingService.Status -ne "Stopped") {
            Stop-Service -Name $serviceName -Force
        }
        sc.exe delete $serviceName | Out-Null
        for ($wait = 0; $wait -lt 20 -and (Get-Service -Name $serviceName -ErrorAction SilentlyContinue); $wait++) {
            Start-Sleep -Milliseconds 500
        }
    }

    New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
    foreach ($directory in 'config', 'keys', 'data', 'MissionDiary') {
        New-Item -ItemType Directory -Path (Join-Path $DataRoot $directory) -Force | Out-Null
    }
    Copy-Item -Path (Join-Path $PackageRoot "Minion\*") -Destination $InstallRoot -Recurse -Force
    if (-not $SkipServiceContainer) {
        Copy-Item -LiteralPath (Join-Path $PackageRoot "service.env.example") -Destination (Join-Path $InstallRoot "service.env.example") -Force
    }

    # The configuration holds no secrets; an existing file is kept on upgrade unless -ReplaceConfig is given.
    $configPath = Join-Path $DataRoot "config\minion.config.json"
    if ((Test-Path -LiteralPath $configPath -PathType Leaf) -and -not $ReplaceConfig) {
        Write-Host "Keeping the existing configuration at $configPath (use -ReplaceConfig to regenerate it)."
    } else {
        if ($TrustedServerCertificate) {
            Copy-Item -LiteralPath $TrustedServerCertificate -Destination $serverCertificateFile -Force
        }
        $settings = @{
            MissionControlUrl = $MissionControlUrl
            MinionId = $MinionId
            ApiKeyPath = $apiKeyFile
            SluiceGatePublicKeyPath = $sluiceGatePublicKeyFile
            MinionPrivateKeyPath = $minionPrivateKeyFile
            CatalogPath = $CatalogPath
            NessusMappingPath = $NessusMappingPath
            NonceStorePath = (Join-Path $DataRoot "data\nonces.txt")
            MissionDiaryDirectory = (Join-Path $DataRoot "MissionDiary")
            DryRun = (-not $DisableDryRun)
            TrustedServerCertificatePath = $null
            TrustedServerCertificateSha256 = $null
        }
        if ($TrustedServerCertificate) {
            $settings.TrustedServerCertificatePath = $serverCertificateFile
            $settings.TrustedServerCertificateSha256 = $trustedFingerprints
        }
        $json = New-MinionConfigurationJson -TemplatePath (Join-Path $PackageRoot "minion.config.template.json") -Settings $settings
        [System.IO.File]::WriteAllText($configPath, $json, [System.Text.UTF8Encoding]::new($false))
    }
    Set-MinionDataAcl -DataRoot $DataRoot -AccountSid $accountSid

    if (-not $SkipServiceContainer) {
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
    }

    # The service logs startup problems to the Application event log under this source.
    if (-not [System.Diagnostics.EventLog]::SourceExists($serviceName)) {
        [System.Diagnostics.EventLog]::CreateEventSource($serviceName, "Application")
    }

    $binaryPath = '"{0}" --config "{1}"' -f $serviceExecutable, $configPath
    $serviceParameters = @{
        Name = $serviceName
        BinaryPathName = $binaryPath
        DisplayName = "SluiceGate Minion"
        Description = "SluiceGate Minion Mission Control client and execution runtime"
        StartupType = "Automatic"
    }
    if (-not $isManagedAccount) {
        $serviceParameters.Credential = New-Object System.Management.Automation.PSCredential($ServiceAccount, $ServiceAccountPassword)
    }
    New-Service @serviceParameters | Out-Null
    if ($isManagedAccount) {
        # A gMSA has no password; the account name alone is passed to the Service Control Manager.
        sc.exe config $serviceName obj= $ServiceAccount | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Could not configure $serviceName to run as $ServiceAccount."
        }
    }
    # Restart twice after a failure, then stay stopped so the failure is visible.
    sc.exe failure $serviceName reset= 86400 actions= restart/60000/restart/60000//0 | Out-Null
    sc.exe failureflag $serviceName 1 | Out-Null

    Start-Service -Name $serviceName
    for ($second = 0; $second -lt 10; $second++) {
        Start-Sleep -Seconds 1
        if ((Get-Service -Name $serviceName).Status -ne "Running") {
            throw "The $serviceName service stopped right after starting. Read the Application event log (source $serviceName) for the startup check that failed."
        }
    }
}

Write-Host "SluiceGate Minion installed$(if ($dockerVersion) { " with the local service container (Docker Engine $dockerVersion)" })."
Write-Host "Minion configuration: $DataRoot\config\minion.config.json (DryRun is $(-not $DisableDryRun))."
Write-Host "Grant $ServiceAccount read access to the catalog, mapping, and patch share, and the remote execution rights it needs on its authorized targets."
