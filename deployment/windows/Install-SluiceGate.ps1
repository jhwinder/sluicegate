[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageRoot,

    # Tag of the sg-service image inside the bundle's images\sg-service-image.tar.
    [Parameter(Mandatory = $true)]
    [string]$ServiceImage,

    # Where the Minion on this server connects. https://127.0.0.1:8443 works with -SelfSignedCertificate.
    [Parameter(Mandatory = $true)]
    [string]$MissionControlUrl,

    # Address Agents and administrators use from other machines (also used in email links and the certificate's names).
    # Defaults to MissionControlUrl.
    [string]$PublicUrl,

    # Must match the Minion ID you register in the Admin Console.
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

    [string]$WslDistribution = "Ubuntu",

    # TLS for the service: generate a self-signed certificate, or supply a certificate and key you already have.
    [switch]$SelfSignedCertificate,
    [string]$TlsCertificate,
    [string]$TlsKey,
    [switch]$ReplaceCertificate,

    # PEM file the Minion should trust when Windows does not already trust the certificate (a private CA root).
    # Not needed with -SelfSignedCertificate, which the installer trusts automatically.
    [string]$TrustedServerCertificate,

    # Policy to install on first install; the starter policy blocks everything.
    [string]$PolicyFile,

    [string]$InstallRoot = "$env:ProgramFiles\SluiceGate\Minion",
    [string]$DataRoot = "$env:ProgramData\SluiceGate\Minion",
    [string]$ContainerName = "sluicegate-service",
    [switch]$ReplaceConfig,
    [switch]$DisableDryRun,
    [switch]$SkipStartupTask,
    # Fail instead of warning when the Minion executable is not Authenticode-signed.
    [switch]$RequireSignature
)

$ErrorActionPreference = "Stop"
$serviceName = "SluiceGateMinion"
$serviceExecutable = Join-Path $InstallRoot "SluiceGate.Minion.Service.exe"

. (Join-Path $PSScriptRoot "MinionInstallHelpers.ps1")
. (Join-Path $PSScriptRoot "WslServiceContainer.ps1")

if (-not (Test-Path -LiteralPath $PackageRoot)) {
    throw "Package root not found: $PackageRoot"
}

$requiredArtifacts = @(
    (Join-Path $PackageRoot "Minion\SluiceGate.Minion.Service.exe"),
    (Join-Path $PackageRoot "Minion\runtime\PatchingMinion.ps1"),
    (Join-Path $PackageRoot "Minion\runtime\PatchingCatalog.psm1"),
    (Join-Path $PackageRoot "Minion\runtime\PatchingEngine.psm1"),
    (Join-Path $PackageRoot "Minion\runtime\SluiceGate.Minion.Core.psm1"),
    (Join-Path $PackageRoot "minion.config.template.json"),
    (Join-Path $PackageRoot "service.env.example"),
    (Join-Path $PackageRoot "policy.starter.yml"),
    (Join-Path $PackageRoot "new-selfsigned-certificate.sh"),
    (Join-Path $PackageRoot "images\sg-service-image.tar")
)
foreach ($artifact in $requiredArtifacts) {
    if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
        throw "Required deployment artifact is missing: $artifact"
    }
}

$minionSignature = Get-AuthenticodeSignature -FilePath $requiredArtifacts[0]
if ($minionSignature.Status -ne "Valid") {
    if ($RequireSignature) {
        throw "The SG Minion executable must have a valid Authenticode signature (Status: $($minionSignature.Status))."
    }
    Write-Warning "The SG Minion executable is not Authenticode-signed (Status: $($minionSignature.Status)). Installing anyway; use -RequireSignature to enforce signing."
}

if (-not $MissionControlUrl.StartsWith("https://", [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "MissionControlUrl must use https. Plain HTTP Mission Control is supported only for local development."
}
if ($PublicUrl -and -not $PublicUrl.StartsWith("https://", [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "PublicUrl must use https."
}
if ($SelfSignedCertificate -and ($TlsCertificate -or $TlsKey)) {
    throw "Use either -SelfSignedCertificate or -TlsCertificate with -TlsKey, not both."
}
foreach ($optionalFile in @($TlsCertificate, $TlsKey, $TrustedServerCertificate, $PolicyFile)) {
    if ($optionalFile -and -not (Test-Path -LiteralPath $optionalFile -PathType Leaf)) {
        throw "File not found: $optionalFile"
    }
}
# The Minion runtime calls openssl.exe for signing and verification, and the installer uses it to create the Minion key pair.
if (-not (Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
    throw "openssl.exe is not on PATH. Install OpenSSL for Windows (Installation Guide, section 3) and open a new PowerShell window."
}

$keysDirectory = Join-Path $DataRoot "keys"
$apiKeyFile = Join-Path $keysDirectory "minion-api-key.txt"
$minionPrivateKeyFile = Join-Path $keysDirectory "minion-private-key.pem"
$minionPublicKeyFile = Join-Path $keysDirectory "minion-public-key.pem"
$sluiceGatePublicKeyFile = Join-Path $keysDirectory "sg-public-key.pem"
$serverCertificateFile = Join-Path $keysDirectory "sg-server-cert.pem"

$accountSid = Resolve-ServiceAccountSid -Account $ServiceAccount
$isManagedAccount = $ServiceAccount.EndsWith('$')
if (-not $isManagedAccount -and -not $ServiceAccountPassword) {
    $ServiceAccountPassword = Read-Host -Prompt "Password for $ServiceAccount" -AsSecureString
}
$startupTaskCredential = $null
if (-not $SkipStartupTask) {
    $installingUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $startupTaskCredential = New-Object System.Management.Automation.PSCredential($installingUser, (Read-Host -Prompt "Password for $installingUser (registers the startup task that keeps WSL running)" -AsSecureString))
}

if ($PSCmdlet.ShouldProcess($InstallRoot, "Install the SluiceGate service container and Minion")) {
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
    Set-MinionRestrictedAcl -Path $keysDirectory
    Copy-Item -Path (Join-Path $PackageRoot "Minion\*") -Destination $InstallRoot -Recurse -Force

    # sg-service runs in Docker Engine inside WSL; its secrets live only under /opt/sluicegate in WSL.
    $container = Install-SluiceGateServiceContainer -PackageRoot $PackageRoot -Distribution $WslDistribution -ServiceImage $ServiceImage `
        -ContainerName $ContainerName -MissionControlUrl $MissionControlUrl -PublicUrl $PublicUrl -MinionId $MinionId `
        -TlsCertificate $TlsCertificate -TlsKey $TlsKey -SelfSignedCertificate:$SelfSignedCertificate -ReplaceCertificate:$ReplaceCertificate -PolicyFile $PolicyFile

    $utf8 = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($sluiceGatePublicKeyFile, $container.SluiceGatePublicKeyPem, $utf8)
    if ($SelfSignedCertificate) {
        [System.IO.File]::WriteAllText($serverCertificateFile, $container.ServerCertificatePem, $utf8)
    } elseif ($TrustedServerCertificate) {
        Copy-Item -LiteralPath $TrustedServerCertificate -Destination $serverCertificateFile -Force
    }

    if (-not (Test-Path -LiteralPath $minionPrivateKeyFile -PathType Leaf)) {
        & openssl.exe genpkey -algorithm ED25519 -out $minionPrivateKeyFile
        if ($LASTEXITCODE -ne 0) { throw "openssl could not create the Minion private key." }
        & openssl.exe pkey -in $minionPrivateKeyFile -pubout -out $minionPublicKeyFile
        if ($LASTEXITCODE -ne 0) { throw "openssl could not derive the Minion public key." }
        Write-Host "Created the Minion key pair in $keysDirectory."
    }

    # The configuration holds no secrets; an existing file is kept on upgrade unless -ReplaceConfig is given.
    $configPath = Join-Path $DataRoot "config\minion.config.json"
    if ((Test-Path -LiteralPath $configPath -PathType Leaf) -and -not $ReplaceConfig) {
        Write-Host "Keeping the existing configuration at $configPath (use -ReplaceConfig to regenerate it)."
    } else {
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
        if ($SelfSignedCertificate -or $TrustedServerCertificate) {
            $settings.TrustedServerCertificatePath = $serverCertificateFile
            $settings.TrustedServerCertificateSha256 = @(Get-PemCertificateFingerprints -Path $serverCertificateFile)
        }
        $json = New-MinionConfigurationJson -TemplatePath (Join-Path $PackageRoot "minion.config.template.json") -Settings $settings
        [System.IO.File]::WriteAllText($configPath, $json, $utf8)
    }
    Set-MinionDataAcl -DataRoot $DataRoot -AccountSid $accountSid

    if (-not $SkipStartupTask) {
        Register-WslKeepAliveTask -Distribution $WslDistribution -Credential $startupTaskCredential
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

    # The API key is issued by the Admin Console, which only exists now, so a first install stops here.
    if (-not (Test-Path -LiteralPath $apiKeyFile -PathType Leaf)) {
        Write-Warning "The Minion service is installed but not started: $apiKeyFile does not exist yet."
        Write-Host "Next: sign in to the Admin Console, register the Minion with $minionPublicKeyFile, run .\Set-MinionApiKey.ps1, then Start-Service $serviceName."
    } else {
        Start-Service -Name $serviceName
        for ($second = 0; $second -lt 10; $second++) {
            Start-Sleep -Seconds 1
            if ((Get-Service -Name $serviceName).Status -ne "Running") {
                throw "The $serviceName service stopped right after starting. Read the Application event log (source $serviceName) for the startup check that failed."
            }
        }
    }
}

Write-Host "SluiceGate installed: the service runs in Docker inside WSL ($WslDistribution) and listens on 127.0.0.1:8443."
Write-Host "Minion configuration: $DataRoot\config\minion.config.json (DryRun is $(-not $DisableDryRun))."
Write-Host "Grant $ServiceAccount read access to the catalog, mapping, and patch share, and the remote execution rights it needs on its authorized targets."
