# Runs sg-service in a Docker Engine installed inside a WSL 2 distribution. Compatible with Windows PowerShell 5.1.
# Every WSL interaction goes through Invoke-Wsl so tests can replace it.

function ConvertTo-WindowsArgument {
    param([string]$Argument)
    if ($Argument.Length -gt 0 -and $Argument -notmatch '[\s"]') {
        return $Argument
    }
    $escaped = [regex]::Replace($Argument, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

function Invoke-Wsl {
    <#
    .SYNOPSIS
        Runs a command as root inside the WSL distribution without a shell. File content is streamed through standard input,
        so secrets never appear on a command line.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Distribution,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$InputFile,
        [byte[]]$InputBytes,
        [switch]$AllowFailure
    )

    $commandLine = '-d {0} -u root --exec {1}' -f (ConvertTo-WindowsArgument $Distribution), (($Arguments | ForEach-Object { ConvertTo-WindowsArgument $_ }) -join ' ')
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = 'wsl.exe'
    $startInfo.Arguments = $commandLine
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.RedirectStandardInput = [bool]($InputFile -or $InputBytes)
    $startInfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $startInfo.StandardErrorEncoding = [System.Text.Encoding]::UTF8

    $process = [System.Diagnostics.Process]::Start($startInfo)
    try {
        $outputTask = $process.StandardOutput.ReadToEndAsync()
        $errorTask = $process.StandardError.ReadToEndAsync()
        if ($startInfo.RedirectStandardInput) {
            try {
                if ($InputFile) {
                    $stream = [System.IO.File]::OpenRead($InputFile)
                    try { $stream.CopyTo($process.StandardInput.BaseStream) } finally { $stream.Dispose() }
                }
                else {
                    $process.StandardInput.BaseStream.Write($InputBytes, 0, $InputBytes.Length)
                }
            }
            finally {
                $process.StandardInput.Close()
            }
        }
        $process.WaitForExit()
        # wsl.exe's own messages are UTF-16, which arrive here with embedded NUL characters.
        $result = [pscustomobject]@{
            ExitCode = $process.ExitCode
            Output = ($outputTask.Result -replace "`0", '')
            Error = ($errorTask.Result -replace "`0", '')
        }
    }
    finally {
        $process.Dispose()
    }
    if ($result.ExitCode -ne 0 -and -not $AllowFailure) {
        $detail = ($result.Error + $result.Output).Trim()
        if ($detail.Length -gt 2000) { $detail = $detail.Substring(0, 2000) }
        throw "WSL command failed (exit $($result.ExitCode)): $($Arguments[0..([Math]::Min(2, $Arguments.Count - 1))] -join ' ') ... $detail"
    }
    return $result
}

function New-RandomHexSecret {
    param([int]$Bytes = 32)
    $buffer = New-Object byte[] $Bytes
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($buffer) } finally { $generator.Dispose() }
    return (($buffer | ForEach-Object { $_.ToString('x2') }) -join '')
}

function New-ServiceEnvText {
    <# Fills the installer-controlled values of service.env.example. Lines are joined with LF because the file is read on Linux. #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string[]]$TemplateLines,
        [Parameter(Mandatory = $true)][string]$BootstrapKey,
        [Parameter(Mandatory = $true)][string]$MinionId,
        [Parameter(Mandatory = $true)][string]$PublicUrl
    )

    $lines = foreach ($line in $TemplateLines) {
        if ($line -match '^SG_BOOTSTRAP_ADMIN_KEY=') { "SG_BOOTSTRAP_ADMIN_KEY=$BootstrapKey" }
        elseif ($line -match '^SG_PATCH_MINION_ID=') { "SG_PATCH_MINION_ID=$MinionId" }
        elseif ($line -match '^SG_PUBLIC_URL=') { "SG_PUBLIC_URL=$PublicUrl" }
        else { $line }
    }
    return (($lines -join "`n") + "`n")
}

function Send-TextToWsl {
    param([string]$Distribution, [string]$Text, [string]$Destination, [string]$Mode = '0600')
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Text)
    Invoke-Wsl -Distribution $Distribution -Arguments @('sh', '-c', 'umask 077; cat > "$1" && chmod "$2" "$1"', 'sh', $Destination, $Mode) -InputBytes $bytes | Out-Null
}

function Send-FileToWsl {
    param([string]$Distribution, [string]$Path, [string]$Destination, [string]$Mode = '0600')
    Invoke-Wsl -Distribution $Distribution -Arguments @('sh', '-c', 'umask 077; cat > "$1" && chmod "$2" "$1"', 'sh', $Destination, $Mode) -InputFile $Path | Out-Null
}

function Test-WslPath {
    param([string]$Distribution, [string]$Path)
    return ((Invoke-Wsl -Distribution $Distribution -Arguments @('test', '-e', $Path) -AllowFailure).ExitCode -eq 0)
}

function Install-SluiceGateServiceContainer {
    <#
    .SYNOPSIS
        Creates the service's files under /opt/sluicegate inside WSL and starts the sg-service container.
    .DESCRIPTION
        Existing service.env, signing key, policy, and TLS files are kept so an upgrade never replaces them.
        Returns the public values the Windows side needs: the SluiceGate public key and the server certificate.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$PackageRoot,
        [Parameter(Mandatory = $true)][string]$Distribution,
        [Parameter(Mandatory = $true)][string]$ServiceImage,
        [Parameter(Mandatory = $true)][string]$MissionControlUrl,
        [string]$PublicUrl,
        [Parameter(Mandatory = $true)][string]$MinionId,
        [string]$ContainerName = 'sluicegate-service',
        [string]$VolumeName = 'sluicegate-service-data',
        [string]$ServiceRoot = '/opt/sluicegate',
        [string]$TlsCertificate,
        [string]$TlsKey,
        [switch]$SelfSignedCertificate,
        [switch]$ReplaceCertificate,
        [string]$PolicyFile
    )

    $engine = Invoke-Wsl -Distribution $Distribution -Arguments @('docker', 'version', '--format', '{{.Server.Version}}') -AllowFailure
    if ($engine.ExitCode -ne 0) {
        throw "Docker Engine is not reachable inside the WSL distribution '$Distribution'. Install and start it first (Installation Guide, section 3). Detail: $(($engine.Error + $engine.Output).Trim())"
    }

    $secretsDir = "$ServiceRoot/secrets"
    $tlsDir = "$ServiceRoot/tls"
    $policyDir = "$ServiceRoot/policy"
    $envFile = "$ServiceRoot/service.env"
    if (-not $PublicUrl) { $PublicUrl = $MissionControlUrl }
    $signingKey = "$secretsDir/sg-signing-key.pem"
    $policyPath = "$policyDir/production-policy.yml"
    $certPath = "$tlsDir/server-cert.pem"
    $keyPath = "$tlsDir/server-key.pem"

    Invoke-Wsl -Distribution $Distribution -Arguments (@('install', '-d', '-m', '0700') + @($ServiceRoot, $secretsDir, $tlsDir, $policyDir)) | Out-Null

    if (-not (Test-WslPath -Distribution $Distribution -Path $envFile)) {
        $template = Get-Content -LiteralPath (Join-Path $PackageRoot 'service.env.example')
        $text = New-ServiceEnvText -TemplateLines $template -BootstrapKey (New-RandomHexSecret) -MinionId $MinionId -PublicUrl $PublicUrl
        Send-TextToWsl -Distribution $Distribution -Text $text -Destination $envFile
        Write-Host "Created $envFile with a new one-time bootstrap admin key."
    }
    else {
        Write-Host "Keeping the existing $envFile."
    }

    if (-not (Test-WslPath -Distribution $Distribution -Path $signingKey)) {
        Invoke-Wsl -Distribution $Distribution -Arguments @('sh', '-c', 'umask 077; openssl genpkey -algorithm ED25519 -out "$1"', 'sh', $signingKey) | Out-Null
        Write-Host "Generated the SluiceGate signing key inside WSL (it never leaves $secretsDir)."
    }

    if (-not (Test-WslPath -Distribution $Distribution -Path $policyPath)) {
        $source = if ($PolicyFile) { $PolicyFile } else { Join-Path $PackageRoot 'policy.starter.yml' }
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "Policy file not found: $source"
        }
        Send-FileToWsl -Distribution $Distribution -Path $source -Destination $policyPath -Mode '0640'
        Write-Host "Installed the initial policy from $source."
    }

    $haveCertificate = Test-WslPath -Distribution $Distribution -Path $certPath
    if ($TlsCertificate -or $TlsKey) {
        if (-not ($TlsCertificate -and $TlsKey)) {
            throw "-TlsCertificate and -TlsKey must be given together."
        }
        if (-not $haveCertificate -or $ReplaceCertificate) {
            Send-FileToWsl -Distribution $Distribution -Path $TlsCertificate -Destination $certPath -Mode '0644'
            Send-FileToWsl -Distribution $Distribution -Path $TlsKey -Destination $keyPath -Mode '0600'
        }
    }
    elseif ($SelfSignedCertificate) {
        if (-not $haveCertificate -or $ReplaceCertificate) {
            $names = @(([Uri]$PublicUrl).Host, ([Uri]$MissionControlUrl).Host, 'localhost', '127.0.0.1') | Select-Object -Unique
            Invoke-Wsl -Distribution $Distribution -Arguments (@('env', "OUTPUT_DIR=$tlsDir", 'sh', '-s', '--') + $names) -InputFile (Join-Path $PackageRoot 'new-selfsigned-certificate.sh') | Out-Null
            Invoke-Wsl -Distribution $Distribution -Arguments @('sh', '-c', 'mv -f "$1/sluicegate-server.pem" "$1/server-cert.pem" && mv -f "$1/sluicegate-server.key" "$1/server-key.pem"', 'sh', $tlsDir) | Out-Null
            Write-Host "Generated a self-signed certificate for $($names -join ', ')."
        }
    }
    elseif (-not $haveCertificate) {
        throw "No TLS certificate exists yet. Pass -SelfSignedCertificate, or -TlsCertificate and -TlsKey."
    }

    Invoke-Wsl -Distribution $Distribution -Arguments @('docker', 'load') -InputFile (Join-Path $PackageRoot 'images/sg-service-image.tar') | Out-Null

    Invoke-Wsl -Distribution $Distribution -Arguments @('docker', 'rm', '-f', $ContainerName) -AllowFailure | Out-Null
    Invoke-Wsl -Distribution $Distribution -Arguments @('docker', 'volume', 'create', $VolumeName) | Out-Null
    Invoke-Wsl -Distribution $Distribution -Arguments @(
        'docker', 'run', '-d', '--restart', 'unless-stopped', '--name', $ContainerName,
        '-p', '127.0.0.1:8443:8443',
        '-v', "${VolumeName}:/data",
        '-v', "${signingKey}:/run/secrets/sg-signing-key.pem:ro",
        '-v', "${tlsDir}:/run/tls:ro",
        '-v', "${policyDir}:/config:rw",
        '-e', 'SG_TLS_CERT_FILE=/run/tls/server-cert.pem',
        '-e', 'SG_TLS_KEY_FILE=/run/tls/server-key.pem',
        '--env-file', $envFile,
        $ServiceImage
    ) | Out-Null

    # Readiness probe only: it does not verify the certificate, which clients and the Minion do.
    $probe = 'import ssl,urllib.request as u;print(u.urlopen("https://127.0.0.1:8443/health",context=ssl._create_unverified_context(),timeout=5).status)'
    $ready = $false
    for ($attempt = 0; $attempt -lt 30 -and -not $ready; $attempt++) {
        $ready = ((Invoke-Wsl -Distribution $Distribution -Arguments @('docker', 'exec', $ContainerName, 'python', '-c', $probe) -AllowFailure).ExitCode -eq 0)
        if (-not $ready) { Start-Sleep -Seconds 2 }
    }
    if (-not $ready) {
        $logs = (Invoke-Wsl -Distribution $Distribution -Arguments @('docker', 'logs', '--tail', '40', $ContainerName) -AllowFailure)
        throw "The sg-service container did not become healthy. Recent log output:`n$(($logs.Output + $logs.Error).Trim())"
    }

    return [pscustomobject]@{
        SluiceGatePublicKeyPem = (Invoke-Wsl -Distribution $Distribution -Arguments @('openssl', 'pkey', '-in', $signingKey, '-pubout')).Output
        ServerCertificatePem = (Invoke-Wsl -Distribution $Distribution -Arguments @('cat', $certPath)).Output
    }
}

function Remove-SluiceGateServiceContainer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Distribution,
        [string]$ContainerName = 'sluicegate-service',
        [string]$VolumeName = 'sluicegate-service-data',
        [string]$ServiceRoot = '/opt/sluicegate',
        [switch]$RemoveData
    )

    Invoke-Wsl -Distribution $Distribution -Arguments @('docker', 'rm', '-f', $ContainerName) -AllowFailure | Out-Null
    if ($RemoveData) {
        Invoke-Wsl -Distribution $Distribution -Arguments @('docker', 'volume', 'rm', '-f', $VolumeName) -AllowFailure | Out-Null
        Invoke-Wsl -Distribution $Distribution -Arguments @('rm', '-rf', $ServiceRoot) -AllowFailure | Out-Null
    }
}

function Register-WslKeepAliveTask {
    <# WSL stops an idle distribution; this task keeps it (and the container's Docker Engine) running from boot. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Distribution,
        [Parameter(Mandatory = $true)][pscredential]$Credential,
        [string]$TaskName = 'SluiceGateWsl'
    )

    $action = New-ScheduledTaskAction -Execute 'wsl.exe' -Argument ("-d {0} -u root --exec sleep infinity" -f (ConvertTo-WindowsArgument $Distribution))
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
        -User $Credential.UserName -Password $Credential.GetNetworkCredential().Password -RunLevel Highest -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName
}
