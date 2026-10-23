[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$WorkDir
)

# Runs the WSL container installation against a fake WSL (an in-memory file system and a log of commands) and prints
# one JSON object for the caller to check.
$ErrorActionPreference = "Stop"
$windowsDir = Join-Path $PSScriptRoot ".."
. (Join-Path $windowsDir "WslServiceContainer.ps1")

$script:Files = @{}
$script:Modes = @{}
$script:Calls = New-Object System.Collections.ArrayList
$script:DockerAvailable = $true

function Invoke-Wsl {
    param([string]$Distribution, [string[]]$Arguments, [string]$InputFile, [byte[]]$InputBytes, [switch]$AllowFailure)
    [void]$script:Calls.Add(@{ Distribution = $Distribution; Arguments = @($Arguments); InputFile = $InputFile })
    $success = { param($text) [pscustomobject]@{ ExitCode = 0; Output = $text; Error = "" } }
    $failure = [pscustomobject]@{ ExitCode = 1; Output = ""; Error = "simulated failure" }
    $received = $null
    if ($InputBytes) { $received = [System.Text.Encoding]::UTF8.GetString($InputBytes) }
    elseif ($InputFile) { $received = "FILE:" + (Split-Path -Leaf $InputFile) }

    switch ($Arguments[0]) {
        "docker" {
            if ($Arguments[1] -eq "version" -and -not $script:DockerAvailable) {
                if ($AllowFailure) { return $failure }
                throw "docker unavailable"
            }
            return (& $success "27.0.1")
        }
        "test" { if ($script:Files.ContainsKey($Arguments[2])) { return (& $success "") } else { return $failure } }
        "sh" {
            $body = $Arguments[2]
            if ($body -like "*cat >*") { $script:Files[$Arguments[4]] = $received; $script:Modes[$Arguments[4]] = $Arguments[5] }
            elseif ($body -like "*openssl genpkey*") { $script:Files[$Arguments[4]] = "SIGNING-KEY-" + [guid]::NewGuid().ToString("N") }
            elseif ($body -like "*mv -f*") {
                $directory = $Arguments[4]
                $script:Files["$directory/server-cert.pem"] = $script:Files["$directory/sluicegate-server.pem"]
                $script:Files["$directory/server-key.pem"] = $script:Files["$directory/sluicegate-server.key"]
                $script:Files.Remove("$directory/sluicegate-server.pem")
                $script:Files.Remove("$directory/sluicegate-server.key")
            }
            return (& $success "")
        }
        "env" {
            $directory = $Arguments[1] -replace "^OUTPUT_DIR=", ""
            $names = $Arguments[5..($Arguments.Count - 1)]
            $script:Files["$directory/sluicegate-server.pem"] = "-----BEGIN CERTIFICATE-----`nCERT-FOR-" + ($names -join ",") + "`n-----END CERTIFICATE-----"
            $script:Files["$directory/sluicegate-server.key"] = "SERVER-KEY"
            return (& $success "")
        }
        "openssl" { return (& $success ("PUBLIC-OF-" + $script:Files[$Arguments[3]])) }
        "cat" { return (& $success $script:Files[$Arguments[1]]) }
        default { return (& $success "") }
    }
}

function Invoke-Case([scriptblock]$Block) {
    try { return @{ ok = $true; value = (& $Block); message = "" } }
    catch { return @{ ok = $false; value = $null; message = $_.Exception.Message } }
}

function Install-Fake([hashtable]$Extra = @{}) {
    $script:Calls.Clear()
    $parameters = @{
        PackageRoot = $windowsDir
        Distribution = "Ubuntu"
        ServiceImage = "sluicegate/sg-service:1.0.0"
        MissionControlUrl = "https://127.0.0.1:8443"
        PublicUrl = "https://sluicegate.example.internal:8443"
        MinionId = "PATCH-07"
    }
    foreach ($name in $Extra.Keys) { $parameters[$name] = $Extra[$name] }
    return Install-SluiceGateServiceContainer @parameters
}

# The package root needs the image archive and certificate script the installer streams into WSL.
$package = Join-Path $WorkDir "package"
New-Item -ItemType Directory -Path (Join-Path $package "images") -Force | Out-Null
foreach ($name in "service.env.example", "policy.starter.yml") { Copy-Item -LiteralPath (Join-Path $windowsDir $name) -Destination $package }
Set-Content -LiteralPath (Join-Path $package "new-selfsigned-certificate.sh") -Value "# stub"
Set-Content -LiteralPath (Join-Path $package "images/sg-service-image.tar") -Value "stub image"
$windowsDir = $package

function Summarize {
    $docker = @($script:Calls | Where-Object { $_.Arguments[0] -eq "docker" } | ForEach-Object { , @($_.Arguments) })
    return @{
        files = @($script:Files.Keys | Sort-Object)
        env = $script:Files["/opt/sluicegate/service.env"]
        env_mode = $script:Modes["/opt/sluicegate/service.env"]
        policy = $script:Files["/opt/sluicegate/policy/production-policy.yml"]
        policy_mode = $script:Modes["/opt/sluicegate/policy/production-policy.yml"]
        signing_key = $script:Files["/opt/sluicegate/secrets/sg-signing-key.pem"]
        tls_key_mode = $script:Modes["/opt/sluicegate/tls/server-key.pem"]
        certificate = $script:Files["/opt/sluicegate/tls/server-cert.pem"]
        docker = $docker
        generator_calls = @($script:Calls | Where-Object { $_.Arguments[0] -eq "env" }).Count
        all_arguments = @($script:Calls | ForEach-Object { $_.Arguments } | ForEach-Object { $_ })
    }
}

$results = [ordered]@{}

$first = Install-Fake @{ SelfSignedCertificate = $true }
$results.first = Summarize
$results.first.returned_public_key = $first.SluiceGatePublicKeyPem
$results.first.returned_certificate = $first.ServerCertificatePem

$envBefore = $script:Files["/opt/sluicegate/service.env"]
$keyBefore = $script:Files["/opt/sluicegate/secrets/sg-signing-key.pem"]
$certBefore = $script:Files["/opt/sluicegate/tls/server-cert.pem"]
$script:Files["/opt/sluicegate/policy/production-policy.yml"] = "edited in the Admin Console"
$null = Install-Fake @{ SelfSignedCertificate = $true }
$results.second = Summarize
$results.second.env_unchanged = ($script:Files["/opt/sluicegate/service.env"] -ceq $envBefore)
$results.second.key_unchanged = ($script:Files["/opt/sluicegate/secrets/sg-signing-key.pem"] -ceq $keyBefore)
$results.second.certificate_unchanged = ($script:Files["/opt/sluicegate/tls/server-cert.pem"] -ceq $certBefore)

$null = Install-Fake @{ SelfSignedCertificate = $true; ReplaceCertificate = $true }
$results.replaced = Summarize

$caCertificate = Join-Path $WorkDir "ca-cert.pem"
$caKey = Join-Path $WorkDir "ca-key.pem"
Set-Content -LiteralPath $caCertificate -Value "CA-CERT"
Set-Content -LiteralPath $caKey -Value "CA-KEY"
$script:Files.Clear(); $script:Modes.Clear()
$null = Install-Fake @{ TlsCertificate = $caCertificate; TlsKey = $caKey; PolicyFile = $caCertificate }
$results.ca = Summarize

$script:Files.Clear(); $script:Modes.Clear()
$results.no_tls = Invoke-Case { Install-Fake }
$results.cert_without_key = Invoke-Case { Install-Fake @{ TlsCertificate = $caCertificate } }
$script:DockerAvailable = $false
$results.no_docker = Invoke-Case { Install-Fake @{ SelfSignedCertificate = $true } }
$script:DockerAvailable = $true

$results.argument_quoting = @(
    (ConvertTo-WindowsArgument "plain"),
    (ConvertTo-WindowsArgument "has space"),
    (ConvertTo-WindowsArgument 'say "hi"'),
    (ConvertTo-WindowsArgument 'C:\path with space\'),
    (ConvertTo-WindowsArgument "")
)

$template = Get-Content -LiteralPath (Join-Path $package "service.env.example")
$envText = New-ServiceEnvText -TemplateLines $template -BootstrapKey "abc123" -MinionId "M-1" -PublicUrl "https://x.example"
$results.env_text = $envText
$results.random_secret = New-RandomHexSecret

ConvertTo-Json -InputObject $results -Depth 8 -Compress
