<#
.SYNOPSIS
    SluiceGate Minion Core PowerShell Module
.DESCRIPTION
    Provides reusable functions for Minion Mission Control communication,
    cryptographic signature verification and signing, nonce replay protection,
    canonical JSON formatting, and envelope validation.
#>

$script:MinionTrustedCertificates = $null
$script:MinionAllowInsecureHttp = $false

# C# 5 syntax only: Windows PowerShell 5.1 compiles this with its built-in compiler.
$script:MissionControlHttpSource = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SluiceGate
{
    public class MissionControlHttpException : Exception
    {
        public int StatusCode { get; private set; }

        public MissionControlHttpException(string message, int statusCode, Exception inner) : base(message, inner)
        {
            StatusCode = statusCode;
        }
    }

    public static class MissionControlHttp
    {
        public static X509Certificate2[] LoadCertificates(string path)
        {
            string text = System.IO.File.ReadAllText(path);
            List<X509Certificate2> certificates = new List<X509Certificate2>();
            string begin = "-----BEGIN CERTIFICATE-----";
            string end = "-----END CERTIFICATE-----";
            int index = 0;
            while (true)
            {
                int start = text.IndexOf(begin, index, StringComparison.Ordinal);
                if (start < 0)
                {
                    break;
                }
                int stop = text.IndexOf(end, start, StringComparison.Ordinal);
                if (stop < 0)
                {
                    throw new FormatException("The certificate file contains an unterminated PEM block.");
                }
                string base64 = text.Substring(start + begin.Length, stop - start - begin.Length);
                certificates.Add(new X509Certificate2(Convert.FromBase64String(base64)));
                index = stop + end.Length;
            }
            if (certificates.Count == 0)
            {
                throw new FormatException("The certificate file contains no PEM-encoded certificate.");
            }
            return certificates.ToArray();
        }

        public static string Sha256(X509Certificate2 certificate)
        {
            using (SHA256 hash = SHA256.Create())
            {
                return BitConverter.ToString(hash.ComputeHash(certificate.RawData)).Replace("-", "");
            }
        }

        private static bool SameCertificate(X509Certificate2 left, X509Certificate2 right)
        {
            byte[] a = left.RawData;
            byte[] b = right.RawData;
            if (a.Length != b.Length)
            {
                return false;
            }
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                {
                    return false;
                }
            }
            return true;
        }

        private static bool Contains(X509Certificate2[] pinned, X509Certificate2 candidate)
        {
            foreach (X509Certificate2 item in pinned)
            {
                if (SameCertificate(item, candidate))
                {
                    return true;
                }
            }
            return false;
        }

        // Returns null when the server certificate is acceptable, otherwise the reason it was rejected.
        private static string Reject(X509Certificate2[] pinned, X509Certificate2 server, SslPolicyErrors errors)
        {
            if (server == null || (errors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0)
            {
                return "no server certificate was presented";
            }
            if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
            {
                return "the certificate does not match the Mission Control host name";
            }
            if (pinned == null || pinned.Length == 0)
            {
                return errors == SslPolicyErrors.None ? null : "the certificate is not trusted by this computer";
            }

            DateTime now = DateTime.UtcNow;
            if (now < server.NotBefore.ToUniversalTime() || now > server.NotAfter.ToUniversalTime())
            {
                return "the certificate is expired or not yet valid";
            }
            using (X509Chain chain = new X509Chain())
            {
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                chain.ChainPolicy.ApplicationPolicy.Add(new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1"));
                foreach (X509Certificate2 item in pinned)
                {
                    chain.ChainPolicy.ExtraStore.Add(item);
                }
                chain.Build(server);
                bool leafPinned = Contains(pinned, server);
                foreach (X509ChainStatus status in chain.ChainStatus)
                {
                    if (status.Status == X509ChainStatusFlags.NoError || status.Status == X509ChainStatusFlags.UntrustedRoot)
                    {
                        continue;
                    }
                    if (status.Status == X509ChainStatusFlags.PartialChain && leafPinned)
                    {
                        continue;
                    }
                    return "the certificate chain is invalid (" + status.Status.ToString() + ")";
                }
                foreach (X509ChainElement element in chain.ChainElements)
                {
                    if (Contains(pinned, element.Certificate))
                    {
                        return null;
                    }
                }
            }
            return "the certificate is not the provisioned trusted certificate or issued by it";
        }

        private static bool IsTlsFailure(Exception exception)
        {
            for (Exception current = exception; current != null; current = current.InnerException)
            {
                WebException web = current as WebException;
                if (current is AuthenticationException ||
                    (web != null && (web.Status == WebExceptionStatus.TrustFailure || web.Status == WebExceptionStatus.SecureChannelFailure)))
                {
                    return true;
                }
            }
            return false;
        }

        public static string Send(string method, string url, IDictionary headers, string body, int timeoutSeconds, X509Certificate2[] pinned)
        {
            try
            {
                ServicePointManager.SecurityProtocol = ServicePointManager.SecurityProtocol | (SecurityProtocolType)3072;
            }
            catch (Exception)
            {
            }

            string[] rejection = new string[1];
            HttpClientHandler handler = new HttpClientHandler();
            handler.AllowAutoRedirect = false;
            handler.ServerCertificateCustomValidationCallback = delegate (HttpRequestMessage request, X509Certificate2 certificate, X509Chain chain, SslPolicyErrors errors)
            {
                rejection[0] = Reject(pinned, certificate, errors);
                return rejection[0] == null;
            };

            string host = new Uri(url).Host;
            using (HttpClient client = new HttpClient(handler))
            {
                client.Timeout = TimeSpan.FromSeconds(timeoutSeconds);
                using (HttpRequestMessage message = new HttpRequestMessage(new HttpMethod(method), url))
                {
                    string contentType = "application/json";
                    foreach (DictionaryEntry header in headers)
                    {
                        string name = Convert.ToString(header.Key);
                        string value = Convert.ToString(header.Value);
                        if (string.Equals(name, "Content-Type", StringComparison.OrdinalIgnoreCase))
                        {
                            contentType = value;
                        }
                        else
                        {
                            message.Headers.TryAddWithoutValidation(name, value);
                        }
                    }
                    if (body != null)
                    {
                        message.Content = new StringContent(body, Encoding.UTF8, contentType);
                    }
                    else if (string.Equals(method, "POST", StringComparison.OrdinalIgnoreCase))
                    {
                        message.Content = new ByteArrayContent(new byte[0]);
                    }

                    HttpResponseMessage response;
                    try
                    {
                        response = client.SendAsync(message).GetAwaiter().GetResult();
                    }
                    catch (Exception ex)
                    {
                        if (rejection[0] != null || IsTlsFailure(ex))
                        {
                            throw new MissionControlHttpException("Mission Control TLS validation failed for " + host + ": " + (rejection[0] ?? "the TLS handshake was rejected"), 0, ex);
                        }
                        throw new MissionControlHttpException("Mission Control request to " + host + " failed (" + ex.GetType().Name + ")", 0, ex);
                    }
                    using (response)
                    {
                        string text = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                        int status = (int)response.StatusCode;
                        if (status < 200 || status > 299)
                        {
                            throw new MissionControlHttpException("Mission Control returned HTTP " + status.ToString(), status, null);
                        }
                        return text;
                    }
                }
            }
        }
    }
}
'@


function ConvertTo-CanonicalJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject
    )

    function Sort-ObjectKeys([object]$obj) {
        if ($null -eq $obj) {
            return $null
        }
        if ($obj -is [System.Collections.IDictionary]) {
            $sorted = [ordered]@{}
            foreach ($key in ($obj.Keys | Sort-Object)) {
                $sorted[$key] = Sort-ObjectKeys $obj[$key]
            }
            return $sorted
        }
        if ($obj -is [System.Collections.IEnumerable] -and $obj -isnot [string]) {
            $list = [System.Collections.Generic.List[object]]::new()
            foreach ($item in $obj) {
                $list.Add((Sort-ObjectKeys $item))
            }
            return $list
        }
        if ($obj -is [PSCustomObject]) {
            $sorted = [ordered]@{}
            foreach ($prop in ($obj.PSObject.Properties.Name | Sort-Object)) {
                $sorted[$prop] = Sort-ObjectKeys $obj.$prop
            }
            return $sorted
        }
        return $obj
    }

    $sortedObject = Sort-ObjectKeys $InputObject
    # Compress without whitespace
    $json = ConvertTo-Json -InputObject $sortedObject -Compress -Depth 10
    return $json
}

function Test-MinionSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CanonicalJson,

        [Parameter(Mandatory = $true)]
        [string]$SignatureHex,

        [Parameter(Mandatory = $true)]
        [string]$PublicKeyPath
    )

    if (-not (Test-Path -LiteralPath $PublicKeyPath -PathType Leaf)) {
        Write-Error "SluiceGate public key not found at: $PublicKeyPath"
        return $false
    }

    # OpenSSL verification approach
    $tempData = [System.IO.Path]::GetTempFileName()
    $tempSig = [System.IO.Path]::GetTempFileName()

    try {
        [System.IO.File]::WriteAllBytes($tempData, [System.Text.Encoding]::UTF8.GetBytes($CanonicalJson))
        $sigBytes = [byte[]]::new($SignatureHex.Length / 2)
        for ($i = 0; $i -lt $SignatureHex.Length; $i += 2) {
            $sigBytes[$i / 2] = [Convert]::ToByte($SignatureHex.Substring($i, 2), 16)
        }
        [System.IO.File]::WriteAllBytes($tempSig, $sigBytes)

        $null = & openssl pkeyutl -verify -pubin -inkey $PublicKeyPath -rawin -in $tempData -sigfile $tempSig 2>&1
        return ($LASTEXITCODE -eq 0)
    }
    catch {
        Write-Warning "Signature verification failed: $_"
        return $false
    }
    finally {
        if (Test-Path -LiteralPath $tempData) { Remove-Item -LiteralPath $tempData -Force -ErrorAction SilentlyContinue }
        if (Test-Path -LiteralPath $tempSig) { Remove-Item -LiteralPath $tempSig -Force -ErrorAction SilentlyContinue }
    }
}

function New-MinionSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CanonicalJson,

        [Parameter(Mandatory = $true)]
        [string]$PrivateKeyPath
    )

    if (-not (Test-Path -LiteralPath $PrivateKeyPath -PathType Leaf)) {
        throw "Minion private key not found at: $PrivateKeyPath"
    }

    $tempData = [System.IO.Path]::GetTempFileName()
    $tempSig = [System.IO.Path]::GetTempFileName()

    try {
        [System.IO.File]::WriteAllBytes($tempData, [System.Text.Encoding]::UTF8.GetBytes($CanonicalJson))
        $null = & openssl pkeyutl -sign -inkey $PrivateKeyPath -rawin -in $tempData -out $tempSig 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "OpenSSL signing failed with exit code $LASTEXITCODE"
        }
        $sigBytes = [System.IO.File]::ReadAllBytes($tempSig)
        $hex = [System.BitConverter]::ToString($sigBytes).Replace("-", "").ToLowerInvariant()
        return $hex
    }
    finally {
        if (Test-Path -LiteralPath $tempData) { Remove-Item -LiteralPath $tempData -Force -ErrorAction SilentlyContinue }
        if (Test-Path -LiteralPath $tempSig) { Remove-Item -LiteralPath $tempSig -Force -ErrorAction SilentlyContinue }
    }
}

function Test-MinionNonce {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Nonce,

        [Parameter(Mandatory = $true)]
        [string]$NonceStorePath
    )

    if (-not (Test-Path -LiteralPath $NonceStorePath)) {
        return $true
    }

    $seen = Get-Content -LiteralPath $NonceStorePath -ErrorAction SilentlyContinue
    if ($seen -contains $Nonce) {
        return $false
    }
    return $true
}

function Add-MinionNonce {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Nonce,

        [Parameter(Mandatory = $true)]
        [string]$NonceStorePath,

        [int]$MaxEntries = 10000
    )

    $parent = [System.IO.Path]::GetDirectoryName($NonceStorePath)
    if ($parent -and (-not (Test-Path -LiteralPath $parent))) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    Add-Content -LiteralPath $NonceStorePath -Value $Nonce -Encoding UTF8

    # Trim if exceeds max
    $lines = Get-Content -LiteralPath $NonceStorePath -ErrorAction SilentlyContinue
    if ($lines.Count -gt $MaxEntries) {
        $trimmed = $lines | Select-Object -Last ($MaxEntries / 2)
        Set-Content -LiteralPath $NonceStorePath -Value $trimmed -Encoding UTF8
    }
}

function Test-MissionEnvelope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Envelope,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedMinionId,

        [Parameter(Mandatory = $true)]
        [string]$SluiceGatePublicKeyPath,

        [Parameter(Mandatory = $true)]
        [string]$NonceStorePath,

        [Parameter(Mandatory = $true)]
        [string[]]$SupportedCapabilities,

        [switch]$AllowConsumedNonce
    )

    $rejectionReason = $null

    # 1. Protocol version validation
    if ($Envelope.protocol_version -ne "1.0") {
        return @{ IsValid = $false; Reason = "UNSUPPORTED_PROTOCOL_VERSION"; Message = "Protocol version '$($Envelope.protocol_version)' is unsupported." }
    }

    # 2. Intended Minion ID validation
    if ($Envelope.minion_id -ne $ExpectedMinionId) {
        return @{ IsValid = $false; Reason = "MINION_ID_MISMATCH"; Message = "Mission addressed to '$($Envelope.minion_id)', expected '$ExpectedMinionId'." }
    }

    # 3. Capability validation
    if ($SupportedCapabilities -notcontains $Envelope.capability) {
        return @{ IsValid = $false; Reason = "UNSUPPORTED_CAPABILITY"; Message = "Capability '$($Envelope.capability)' not supported by this Minion." }
    }

    # 4. Expiration validation
    $nowEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if ($Envelope.expires_at -and ($Envelope.expires_at -lt $nowEpoch)) {
        return @{ IsValid = $false; Reason = "MISSION_EXPIRED"; Message = "Mission expired at $($Envelope.expires_at), current time is $nowEpoch." }
    }

    # 5. Nonce / replay validation
    if (-not $AllowConsumedNonce -and -not (Test-MinionNonce -Nonce $Envelope.nonce -NonceStorePath $NonceStorePath)) {
        return @{ IsValid = $false; Reason = "REPLAY_DETECTED"; Message = "Nonce '$($Envelope.nonce)' has already been consumed." }
    }

    # 6. SluiceGate signature verification
    $signature = $Envelope.signature
    if (-not $signature) {
        return @{ IsValid = $false; Reason = "MISSING_SIGNATURE"; Message = "Mission envelope does not contain a signature." }
    }

    # Construct payload without signature for verification
    $payload = [ordered]@{}
    foreach ($prop in $Envelope.PSObject.Properties) {
        if ($prop.Name -ne "signature") {
            $payload[$prop.Name] = $prop.Value
        }
    }
    $canonicalJson = ConvertTo-CanonicalJson -InputObject $payload
    $sigValid = Test-MinionSignature -CanonicalJson $canonicalJson -SignatureHex $signature -PublicKeyPath $SluiceGatePublicKeyPath

    if (-not $sigValid) {
        return @{ IsValid = $false; Reason = "INVALID_SIGNATURE"; Message = "Cryptographic signature verification failed." }
    }

    return @{ IsValid = $true; Reason = $null; Message = "Mission envelope is valid." }
}

function Initialize-MinionHttpType {
    if ('SluiceGate.MissionControlHttp' -as [type]) {
        return
    }
    # Windows PowerShell 5.1 (.NET Framework) needs only System.Net.Http; PowerShell 7 splits these types across assemblies.
    $references = @('System.Net.Http')
    if ($PSVersionTable.PSEdition -eq 'Core') {
        $references += @(
            'System.Net.Primitives', 'System.Net.Security', 'System.Net.Requests', 'System.Net.ServicePoint', 'System.Collections', 'System.Collections.NonGeneric',
            'System.Security.Cryptography', 'System.Security.Cryptography.X509Certificates', 'System.Security.Cryptography.Algorithms',
            'System.Security.Cryptography.Primitives', 'System.Security.Cryptography.Encoding', 'System.Runtime'
        )
    }
    Add-Type -TypeDefinition $script:MissionControlHttpSource -ReferencedAssemblies $references -ErrorAction Stop
}

function Set-MinionTransportSecurity {
    <#
    .SYNOPSIS
        Configures how the Minion trusts Mission Control. Without this call the Minion requires https and the Windows trust store.
    .DESCRIPTION
        TrustedCertificatePath is a PEM file with the provisioned self-signed server certificate (or the private CA that issues it).
        When set, only that certificate chain is trusted; the host name and validity period are still enforced and no bypass exists.
        TrustedCertificateSha256 optionally lists the only certificate fingerprints allowed in that file.
        Plain http is accepted only for a loopback URL when AllowInsecureHttp is true, for local development.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MissionControlUrl,

        [string]$TrustedCertificatePath,

        [string[]]$TrustedCertificateSha256 = @(),

        [bool]$AllowInsecureHttp = $false
    )

    $uri = $null
    if (-not [Uri]::TryCreate($MissionControlUrl, [UriKind]::Absolute, [ref]$uri)) {
        throw "Mission Control URL is not a valid absolute URL."
    }
    if ($uri.Scheme -eq 'http') {
        if (-not ($AllowInsecureHttp -and $uri.IsLoopback)) {
            throw "Mission Control URL must use https. Plain http is allowed only for a loopback development endpoint with AllowInsecureHttp enabled."
        }
        if ($TrustedCertificatePath) {
            throw "TrustedServerCertificatePath requires an https Mission Control URL."
        }
        Write-Warning "Using plain http for Mission Control. This is for local development only; API keys are not protected."
    }
    elseif ($uri.Scheme -ne 'https') {
        throw "Unsupported Mission Control URL scheme '$($uri.Scheme)'."
    }

    $allowedFingerprints = @($TrustedCertificateSha256 | ForEach-Object { ([string]$_ -replace '[\s:]', '').ToUpperInvariant() } | Where-Object { $_ })
    $certificates = $null
    if ($TrustedCertificatePath) {
        if (-not (Test-Path -LiteralPath $TrustedCertificatePath -PathType Leaf)) {
            throw "Trusted server certificate file not found: $TrustedCertificatePath"
        }
        Initialize-MinionHttpType
        $certificates = [SluiceGate.MissionControlHttp]::LoadCertificates($TrustedCertificatePath)
        if ($allowedFingerprints.Count -gt 0) {
            foreach ($certificate in $certificates) {
                $fingerprint = [SluiceGate.MissionControlHttp]::Sha256($certificate)
                if ($allowedFingerprints -notcontains $fingerprint) {
                    throw "Trusted certificate file contains a certificate with unexpected SHA-256 fingerprint $fingerprint."
                }
            }
        }
    }
    elseif ($allowedFingerprints.Count -gt 0) {
        throw "TrustedServerCertificateSha256 requires TrustedServerCertificatePath."
    }

    $script:MinionTrustedCertificates = $certificates
    $script:MinionAllowInsecureHttp = [bool]$AllowInsecureHttp
}

function Invoke-MinionHttp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [string]$Body,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSec
    )

    $target = [Uri]$Uri
    if ($target.Scheme -ne 'https' -and -not ($target.Scheme -eq 'http' -and $script:MinionAllowInsecureHttp -and $target.IsLoopback)) {
        throw "Refusing to send Mission Control credentials over '$($target.Scheme)'. Mission Control must use https."
    }
    Initialize-MinionHttpType
    $text = [SluiceGate.MissionControlHttp]::Send($Method, $Uri, $Headers, $Body, $TimeoutSec, $script:MinionTrustedCertificates)
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }
    return ($text | ConvertFrom-Json)
}

function Get-MinionHttpStatusCode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    for ($inner = $ErrorRecord.Exception; $null -ne $inner; $inner = $inner.InnerException) {
        if ($inner -is [SluiceGate.MissionControlHttpException]) {
            return $inner.StatusCode
        }
    }
    return 0
}

function Invoke-MinionCheckIn {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MissionControlUrl,

        [Parameter(Mandatory = $true)]
        [string]$MinionId,

        [Parameter(Mandatory = $true)]
        [string]$ApiKey
    )

    $url = "$($MissionControlUrl.TrimEnd('/'))/internal/v1/minions/$MinionId/check-in"
    $headers = @{
        "Authorization" = "Bearer $ApiKey"
        "Content-Type"  = "application/json"
    }

    try {
        $response = Invoke-MinionHttp -Method Post -Uri $url -Headers $headers -TimeoutSec 15
        return $response
    }
    catch {
        Write-Warning "Check-in failed: $_"
        return $null
    }
}

function Get-MinionMissionClaim {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MissionControlUrl,

        [Parameter(Mandatory = $true)]
        [string]$MinionId,

        [Parameter(Mandatory = $true)]
        [string]$ApiKey
    )

    $url = "$($MissionControlUrl.TrimEnd('/'))/internal/v1/minions/$MinionId/missions/claim"
    $headers = @{
        "Authorization" = "Bearer $ApiKey"
        "Content-Type"  = "application/json"
    }

    try {
        $response = Invoke-MinionHttp -Method Post -Uri $url -Headers $headers -TimeoutSec 15
        return $response
    }
    catch {
        Write-Warning "Mission claim request failed: $_"
        return $null
    }
}

function Invoke-MinionPostWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [string]$Body,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSec
    )

    $maxAttempts = 3
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            return Invoke-MinionHttp -Method Post -Uri $Uri -Headers $Headers -Body $Body -TimeoutSec $TimeoutSec
        }
        catch {
            if ($attempt -eq $maxAttempts) {
                throw
            }
            Start-Sleep -Milliseconds (250 * [math]::Pow(2, $attempt - 1))
        }
    }
}

function Send-MinionStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MissionControlUrl,

        [Parameter(Mandatory = $true)]
        [string]$MinionId,

        [Parameter(Mandatory = $true)]
        [string]$MissionId,

        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$ClaimToken,

        [Parameter(Mandatory = $true)]
        [string]$Status,

        [hashtable]$Detail = @{}
    )

    $url = "$($MissionControlUrl.TrimEnd('/'))/internal/v1/minions/$MinionId/missions/$MissionId/status"
    $headers = @{
        "Authorization" = "Bearer $ApiKey"
        "Content-Type"  = "application/json"
    }

    $eventId = "evt-" + [System.Guid]::NewGuid().ToString("N")
    $body = @{
        event_id    = $eventId
        claim_token = $ClaimToken
        status      = $Status
        detail      = $Detail
        occurred_at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    } | ConvertTo-Json -Depth 6

    $response = Invoke-MinionPostWithRetry -Uri $url -Headers $headers -Body $body -TimeoutSec 15
    return $response
}

function Send-MinionHeartbeat {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MissionControlUrl,
        [Parameter(Mandatory = $true)]
        [string]$MinionId,
        [Parameter(Mandatory = $true)]
        [string]$MissionId,
        [Parameter(Mandatory = $true)]
        [string]$ApiKey,
        [Parameter(Mandatory = $true)]
        [string]$ClaimToken,
        [Parameter(Mandatory = $true)]
        [int]$ProcessId,
        [Parameter(Mandatory = $true)]
        [double]$ProcessStartedAt,
        [hashtable]$Detail = @{}
    )

    $url = "$($MissionControlUrl.TrimEnd('/'))/internal/v1/minions/$MinionId/missions/$MissionId/heartbeat"
    $headers = @{
        "Authorization" = "Bearer $ApiKey"
        "Content-Type" = "application/json"
    }
    $body = @{
        claim_token = $ClaimToken
        process_id = $ProcessId
        process_started_at = $ProcessStartedAt
        detail = $Detail
    } | ConvertTo-Json -Depth 8

    return Invoke-MinionPostWithRetry -Uri $url -Headers $headers -Body $body -TimeoutSec 15
}

function Send-MinionResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MissionControlUrl,

        [Parameter(Mandatory = $true)]
        [string]$MinionId,

        [Parameter(Mandatory = $true)]
        [string]$MissionId,

        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$ClaimToken,

        [Parameter(Mandatory = $true)]
        [string]$PrivateKeyPath,

        [Parameter(Mandatory = $true)]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [hashtable]$Result
    )

    $resultJson = ConvertTo-Json -InputObject $Result -Depth 10 -Compress
    if ([System.Text.Encoding]::UTF8.GetByteCount($resultJson) -gt (256 * 1024)) {
        $Status = "MISSION_COMPLETE_FAILED"
        $Result = @{
            capability = $Result.capability
            error = "Mission result exceeded the 256 KiB limit; detailed output was omitted."
        }
    }

    $url = "$($MissionControlUrl.TrimEnd('/'))/internal/v1/minions/$MinionId/missions/$MissionId/result"
    $headers = @{
        "Authorization" = "Bearer $ApiKey"
        "Content-Type"  = "application/json"
    }

    $eventId = "evt-" + [System.Guid]::NewGuid().ToString("N")
    $signedPayload = [ordered]@{
        event_id   = $eventId
        mission_id = $MissionId
        minion_id  = $MinionId
        result     = $Result
        status     = $Status
    }

    $canonicalJson = ConvertTo-CanonicalJson -InputObject $signedPayload
    $signature = New-MinionSignature -CanonicalJson $canonicalJson -PrivateKeyPath $PrivateKeyPath

    $body = @{
        event_id  = $eventId
        claim_token = $ClaimToken
        status    = $Status
        result    = $Result
        signature = $signature
    } | ConvertTo-Json -Depth 10

    $response = Invoke-MinionPostWithRetry -Uri $url -Headers $headers -Body $body -TimeoutSec 20
    return @{
        mission_status = $Status
        response = $response
    }
}

Export-ModuleMember -Function `
    ConvertTo-CanonicalJson, `
    Test-MinionSignature, `
    New-MinionSignature, `
    Test-MinionNonce, `
    Add-MinionNonce, `
    Test-MissionEnvelope, `
    Set-MinionTransportSecurity, `
    Invoke-MinionHttp, `
    Get-MinionHttpStatusCode, `
    Invoke-MinionCheckIn, `
    Get-MinionMissionClaim, `
    Send-MinionHeartbeat, `
    Send-MinionStatus, `
    Send-MinionResult
