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
                // DER certificate only; retain compatibility with Windows PowerShell 5.1.
#pragma warning disable SYSLIB0057
                certificates.Add(new X509Certificate2(Convert.FromBase64String(base64)));
#pragma warning restore SYSLIB0057
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
#pragma warning disable SYSLIB0014
                ServicePointManager.SecurityProtocol = ServicePointManager.SecurityProtocol | (SecurityProtocolType)3072;
#pragma warning restore SYSLIB0014
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


function ConvertTo-CanonicalStringLiteral {
    param([string]$Value)

    # ASCII-only output with lowercase \u escapes, identical to Python's json.dumps(ensure_ascii=True).
    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('"')
    foreach ($character in $Value.ToCharArray()) {
        $code = [int]$character
        switch ($code) {
            34 { [void]$builder.Append('\"') }
            92 { [void]$builder.Append('\\') }
            8 { [void]$builder.Append('\b') }
            9 { [void]$builder.Append('\t') }
            10 { [void]$builder.Append('\n') }
            12 { [void]$builder.Append('\f') }
            13 { [void]$builder.Append('\r') }
            default {
                if ($code -lt 32 -or $code -gt 126) {
                    [void]$builder.Append('\u').Append($code.ToString('x4', [System.Globalization.CultureInfo]::InvariantCulture))
                }
                else {
                    [void]$builder.Append($character)
                }
            }
        }
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function ConvertTo-CanonicalNumber {
    param([object]$Value)

    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    if ($Value -is [double] -or $Value -is [single]) {
        $number = [double]$Value
        if ([double]::IsNaN($number) -or [double]::IsInfinity($number)) {
            throw "NaN and infinity cannot be signed."
        }
    }
    elseif ($Value -is [decimal]) {
        $number = [double]$Value
    }
    else {
        return ([System.Convert]::ToString($Value, $invariant))
    }

    if ($number -eq [math]::Floor($number) -and [math]::Abs($number) -lt 9007199254740992) {
        return ([int64]$number).ToString($invariant)
    }

    # Shortest digits that round-trip, written positionally so no exponent form has to match Python.
    $text = $null
    for ($precision = 1; $precision -le 17; $precision++) {
        $text = $number.ToString("G$precision", $invariant)
        if ([double]::Parse($text, $invariant) -eq $number) { break }
    }
    $match = [regex]::Match($text, '^(-?)(\d)(?:\.(\d+))?E([+-]\d+)$')
    if (-not $match.Success) { return $text }

    $digits = $match.Groups[2].Value + $match.Groups[3].Value
    $position = 1 + [int]$match.Groups[4].Value
    if ($position -le 0) { $body = '0.' + ('0' * (-$position)) + $digits }
    elseif ($position -ge $digits.Length) { $body = $digits + ('0' * ($position - $digits.Length)) }
    else { $body = $digits.Insert($position, '.') }
    return $match.Groups[1].Value + $body
}

function ConvertTo-CanonicalValue {
    param([object]$Value)

    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { return $(if ($Value) { 'true' } else { 'false' }) }
    if ($Value -is [string]) { return (ConvertTo-CanonicalStringLiteral -Value $Value) }
    if ($Value -is [char]) { return (ConvertTo-CanonicalStringLiteral -Value ([string]$Value)) }
    if ($Value -is [datetime] -or $Value -is [datetimeoffset]) {
        throw "A date value cannot be canonicalized; keep timestamps as strings or Unix seconds."
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $keys = [string[]]@($Value.Keys | ForEach-Object { [string]$_ })
        [System.Array]::Sort($keys, [System.StringComparer]::Ordinal)
        $pairs = foreach ($key in $keys) {
            (ConvertTo-CanonicalStringLiteral -Value $key) + ':' + (ConvertTo-CanonicalValue -Value $Value[$key])
        }
        return '{' + (@($pairs) -join ',') + '}'
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = foreach ($item in $Value) { ConvertTo-CanonicalValue -Value $item }
        return '[' + (@($items) -join ',') + ']'
    }
    if ($Value -is [pscustomobject]) {
        $table = @{}
        foreach ($property in $Value.PSObject.Properties) { $table[$property.Name] = $property.Value }
        return (ConvertTo-CanonicalValue -Value $table)
    }
    if ($Value -is [System.ValueType] -and $Value.GetType().IsPrimitive -or $Value -is [decimal]) {
        return (ConvertTo-CanonicalNumber -Value $Value)
    }
    throw "Cannot canonicalize a value of type $($Value.GetType().FullName)."
}

function ConvertTo-CanonicalJson {
    <#
    .SYNOPSIS
        Canonical JSON used for every signed payload; byte-identical to sg_service.protocol.canonical_json.
        Sorted keys (ordinal), no whitespace, ASCII-only strings, integral numbers written without a fraction.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$InputObject
    )

    return (ConvertTo-CanonicalValue -Value $InputObject)
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

    $seen = foreach ($line in [System.IO.File]::ReadAllLines($NonceStorePath)) { $line.Split("`t")[0] }
    if ($seen -ccontains $Nonce) {
        return $false
    }
    return $true
}

function Register-MinionNonce {
    <#
    .SYNOPSIS
        Atomically records a Mission nonce. Returns $false when the nonce was already consumed (a replay).
    .DESCRIPTION
        The store holds one "<nonce><TAB><retain-until epoch seconds>" line per consumed nonce. A nonce is
        pruned only after its retain-until time, so a still-valid Mission can never be replayed because older
        entries were evicted. A lock file serializes concurrent workers around the check-and-add.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Nonce,

        [Parameter(Mandatory = $true)]
        [string]$NonceStorePath,

        # Epoch seconds until which the nonce must be remembered (Mission expiry plus clock skew).
        [Parameter(Mandatory = $true)]
        [long]$RetainUntil
    )

    $parent = [System.IO.Path]::GetDirectoryName($NonceStorePath)
    if ($parent -and (-not (Test-Path -LiteralPath $parent))) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $lock = $null
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while ($null -eq $lock) {
        try {
            $lock = [System.IO.File]::Open("$NonceStorePath.lock", [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        }
        catch [System.IO.IOException] {
            if ([DateTime]::UtcNow -gt $deadline) { throw "Timed out waiting for the nonce store lock." }
            Start-Sleep -Milliseconds 50
        }
    }

    try {
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $kept = [System.Collections.Generic.List[string]]::new()
        $pruned = $false
        $replay = $false
        if (Test-Path -LiteralPath $NonceStorePath) {
            foreach ($line in [System.IO.File]::ReadAllLines($NonceStorePath)) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                $fields = $line.Split("`t")
                # Entries from older versions have no expiry; keep them for a full Mission lifetime from now.
                $retain = if ($fields.Count -ge 2) { [long]$fields[1] } else { $now + 90000 }
                if ($retain -lt $now) { $pruned = $true; continue }
                if ($fields[0] -ceq $Nonce) { $replay = $true }
                $kept.Add("$($fields[0])`t$retain")
            }
        }
        if ($replay) { return $false }

        $kept.Add("$Nonce`t$RetainUntil")
        $temporary = "$NonceStorePath.$([guid]::NewGuid().ToString('N')).tmp"
        try {
            [System.IO.File]::WriteAllLines($temporary, $kept.ToArray(), (New-Object System.Text.UTF8Encoding($false)))
            Move-Item -LiteralPath $temporary -Destination $NonceStorePath -Force
        }
        finally {
            if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
        }
        return $true
    }
    finally {
        $lock.Dispose()
    }
}

function Test-JsonObject {
    param([object]$Value)
    return ($Value -is [pscustomobject] -or $Value -is [System.Collections.IDictionary])
}

function Get-JsonMemberNames {
    param([object]$Value)
    if ($Value -is [System.Collections.IDictionary]) { return @($Value.Keys | ForEach-Object { [string]$_ }) }
    return @($Value.PSObject.Properties.Name)
}

function Get-JsonMember {
    param([object]$Value, [string]$Name)
    if ($Value -is [System.Collections.IDictionary]) { $member = $Value[$Name] }
    else {
        # Assigned outside an if-expression: an expression result would unroll a one-element array.
        $member = $null
        $property = $Value.PSObject.Properties[$Name]
        if ($property) { $member = $property.Value }
    }
    # The leading comma keeps a one-element array from being unrolled into a scalar.
    if ($member -is [System.Collections.IEnumerable] -and $member -isnot [string] -and $member -isnot [System.Collections.IDictionary]) { return , $member }
    return $member
}

function Test-JsonNumber {
    param([object]$Value)
    return ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal] -or $Value -is [single] -or $Value -is [int16] -or $Value -is [byte] -or $Value -is [uint32] -or $Value -is [uint64])
}

function Test-JsonInteger {
    param([object]$Value, [long]$Minimum)
    return ((Test-JsonNumber $Value) -and ([double]$Value -eq [math]::Floor([double]$Value)) -and ([double]$Value -ge $Minimum))
}

function Test-JsonArray {
    param([object]$Value)
    return ($null -ne $Value -and $Value -is [System.Collections.IEnumerable] -and $Value -isnot [string] -and -not (Test-JsonObject $Value))
}

function Test-JsonDateTimeText {
    param([object]$Value)
    # Windows PowerShell 7.4 turns ISO date strings into DateTime on parse; both forms are acceptable.
    if ($Value -is [datetime]) { return $true }
    return ($Value -is [string] -and $Value -cmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$')
}

function Test-NonEmptyText {
    param([object]$Value, [int]$MinimumLength = 1)
    return ($Value -is [string] -and $Value.Length -ge $MinimumLength)
}

function Get-MissionEnvelopeSchemaErrors {
    <#
    .SYNOPSIS
        Hand-written mirror of minion-registry/protocol/mission-envelope.schema.json (Windows PowerShell 5.1 has
        no JSON Schema validator). Shared fixtures keep it in step with the schema; see Test-Protocol.ps1.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowNull()][object]$Envelope)

    $errors = [System.Collections.Generic.List[string]]::new()

    function Test-Members([object]$Object, [string]$Path, [string[]]$Required, [string[]]$Allowed) {
        if (-not (Test-JsonObject $Object)) { $errors.Add("${Path}: must be an object"); return $false }
        $names = Get-JsonMemberNames $Object
        foreach ($name in $Required) { if ($names -cnotcontains $name) { $errors.Add("${Path}: missing required member '$name'") } }
        foreach ($name in $names) { if ($Allowed -cnotcontains $name) { $errors.Add("${Path}: unknown member '$name'") } }
        return $true
    }

    $required = @("protocol_version", "request_id", "mission_id", "minion_id", "capability", "target", "parameters", "execution", "issued_at", "expires_at", "nonce", "requested_by", "policy_hash", "policy_decision", "obligations", "signing_key_id", "signature")
    if (-not (Test-Members $Envelope "<root>" $required ($required + "approval_evidence"))) { return $errors.ToArray() }
    $names = Get-JsonMemberNames $Envelope
    $value = { param($name) Get-JsonMember $Envelope $name }

    if ($names -ccontains "protocol_version" -and ((& $value "protocol_version") -isnot [string] -or (& $value "protocol_version") -cne "1.0")) { $errors.Add("protocol_version: must be '1.0'") }
    foreach ($name in "request_id", "mission_id", "minion_id", "capability", "requested_by", "policy_hash", "signing_key_id") {
        if ($names -ccontains $name -and -not (Test-NonEmptyText (& $value $name))) { $errors.Add("${name}: must be a non-empty string") }
    }
    if ($names -ccontains "nonce" -and -not (Test-NonEmptyText (& $value "nonce") 16)) { $errors.Add("nonce: must be a string of at least 16 characters") }
    foreach ($name in "issued_at", "expires_at") {
        if ($names -ccontains $name -and -not ((Test-JsonNumber (& $value $name)) -and [double](& $value $name) -ge 0)) { $errors.Add("${name}: must be a non-negative number") }
    }
    if ($names -ccontains "policy_decision" -and (-not (Test-NonEmptyText (& $value "policy_decision")) -or @("ALLOW", "PAUSE", "BLOCK", "REJECTED") -cnotcontains (& $value "policy_decision"))) { $errors.Add("policy_decision: must be ALLOW, PAUSE, BLOCK or REJECTED") }
    if ($names -ccontains "signature" -and ((& $value "signature") -isnot [string] -or (& $value "signature") -cnotmatch '^[0-9a-f]{128}$')) { $errors.Add("signature: must be 128 lowercase hex characters") }
    foreach ($name in "target", "parameters", "approval_evidence") {
        if ($names -ccontains $name -and -not (Test-JsonObject (& $value $name))) { $errors.Add("${name}: must be an object") }
    }

    if ($names -ccontains "execution") {
        $executionNames = @("max_attempts", "retry_interval_seconds", "attempt_timeout_seconds", "overall_timeout_seconds", "heartbeat_interval_seconds", "claim_lease_seconds")
        $execution = & $value "execution"
        if (Test-Members $execution "execution" $executionNames $executionNames) {
            foreach ($name in $executionNames) {
                if ((Get-JsonMemberNames $execution) -ccontains $name -and -not (Test-JsonInteger (Get-JsonMember $execution $name) 1)) { $errors.Add("execution/${name}: must be an integer >= 1") }
            }
        }
    }

    if ($names -ccontains "obligations") {
        $obligations = & $value "obligations"
        if (-not (Test-JsonArray $obligations)) { $errors.Add("obligations: must be an array") }
        else {
            foreach ($item in $obligations) {
                if (Test-Members $item "obligations/item" @("type", "data") @("type", "data")) {
                    $itemNames = Get-JsonMemberNames $item
                    if ($itemNames -ccontains "type" -and -not (Test-NonEmptyText (Get-JsonMember $item "type"))) { $errors.Add("obligations/item/type: must be a non-empty string") }
                    if ($itemNames -ccontains "data" -and -not (Test-JsonObject (Get-JsonMember $item "data"))) { $errors.Add("obligations/item/data: must be an object") }
                }
            }
        }
    }

    if ((& $value "capability") -ceq "windows.patch.reconcile") {
        $target = & $value "target"
        if (Test-JsonObject $target) {
            if (Test-Members $target "target" @("servers") @("servers")) {
                $servers = Get-JsonMember $target "servers"
                if (-not (Test-JsonArray $servers) -or @($servers).Count -lt 1 -or @($servers | Where-Object { -not (Test-NonEmptyText $_) }).Count) { $errors.Add("target/servers: must be a non-empty array of non-empty strings") }
            }
        }
        $parameters = & $value "parameters"
        if (Test-JsonObject $parameters) {
            if (Test-Members $parameters "parameters" @("patch_sources", "patch_constraints") @("patch_sources", "patch_constraints", "maintenance_window")) {
                $parameterNames = Get-JsonMemberNames $parameters
                if ($parameterNames -ccontains "patch_sources") {
                    $sources = Get-JsonMember $parameters "patch_sources"
                    if (-not (Test-JsonArray $sources) -or @($sources | Where-Object { $_ -isnot [string] -or @("wsus", "nessus_catalog") -cnotcontains $_ }).Count) { $errors.Add("parameters/patch_sources: must be an array of wsus or nessus_catalog") }
                }
                if ($parameterNames -ccontains "patch_constraints") {
                    $constraints = Get-JsonMember $parameters "patch_constraints"
                    $constraintNames = @("allowed_patch_types", "allow_reboot", "outside_window", "window_override")
                    if (Test-Members $constraints "parameters/patch_constraints" @("allowed_patch_types", "allow_reboot") $constraintNames) {
                        $present = Get-JsonMemberNames $constraints
                        if ($present -ccontains "allowed_patch_types") {
                            $types = Get-JsonMember $constraints "allowed_patch_types"
                            if (-not (Test-JsonArray $types) -or @($types | Where-Object { $_ -isnot [string] }).Count) { $errors.Add("parameters/patch_constraints/allowed_patch_types: must be an array of strings") }
                        }
                        if ($present -ccontains "allow_reboot" -and (Get-JsonMember $constraints "allow_reboot") -isnot [bool]) { $errors.Add("parameters/patch_constraints/allow_reboot: must be a boolean") }
                        if ($present -ccontains "outside_window") {
                            $outside = Get-JsonMember $constraints "outside_window"
                            if ($null -ne $outside -and ($outside -isnot [string] -or @("WAIT", "BLOCK") -cnotcontains $outside)) { $errors.Add("parameters/patch_constraints/outside_window: must be WAIT, BLOCK or null") }
                        }
                        if ($present -ccontains "window_override") {
                            $override = Get-JsonMember $constraints "window_override"
                            if (Test-Members $override "parameters/patch_constraints/window_override" @("approved_by", "approved_at") @("approved_by", "approved_at")) {
                                $overrideNames = Get-JsonMemberNames $override
                                if ($overrideNames -ccontains "approved_by" -and -not (Test-NonEmptyText (Get-JsonMember $override "approved_by"))) { $errors.Add("parameters/patch_constraints/window_override/approved_by: must be a non-empty string") }
                                if ($overrideNames -ccontains "approved_at" -and -not ((Test-JsonNumber (Get-JsonMember $override "approved_at")) -and [double](Get-JsonMember $override "approved_at") -ge 0)) { $errors.Add("parameters/patch_constraints/window_override/approved_at: must be a non-negative number") }
                            }
                        }
                    }
                }
                if ($parameterNames -ccontains "maintenance_window") {
                    $window = Get-JsonMember $parameters "maintenance_window"
                    if ($null -ne $window -and (Test-Members $window "parameters/maintenance_window" @("timezone", "days", "start", "end") @("timezone", "days", "start", "end"))) {
                        $windowNames = Get-JsonMemberNames $window
                        if ($windowNames -ccontains "timezone" -and -not (Test-NonEmptyText (Get-JsonMember $window "timezone"))) { $errors.Add("parameters/maintenance_window/timezone: must be a non-empty string") }
                        if ($windowNames -ccontains "days") {
                            $days = Get-JsonMember $window "days"
                            $validDays = @("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN")
                            if (-not (Test-JsonArray $days) -or @($days).Count -lt 1 -or @($days | Where-Object { $_ -isnot [string] -or $validDays -cnotcontains $_ }).Count -or @($days | Select-Object -Unique).Count -ne @($days).Count) { $errors.Add("parameters/maintenance_window/days: must be a non-empty array of unique MON..SUN values") }
                        }
                        foreach ($name in "start", "end") {
                            if ($windowNames -ccontains $name) {
                                $time = Get-JsonMember $window $name
                                if ($time -isnot [string] -or $time -cnotmatch '^([01]\d|2[0-3]):[0-5]\d$') { $errors.Add("parameters/maintenance_window/${name}: must be an HH:MM time") }
                            }
                        }
                    }
                }
            }
        }
    }
    return $errors.ToArray()
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
    if ($Envelope.protocol_version -isnot [string] -or $Envelope.protocol_version -cne "1.0") {
        return @{ IsValid = $false; Reason = "UNSUPPORTED_PROTOCOL_VERSION"; Message = "Protocol version '$($Envelope.protocol_version)' is unsupported." }
    }

    # 2. Structure: every required field, with the right type, and nothing unknown
    $schemaErrors = @(Get-MissionEnvelopeSchemaErrors -Envelope $Envelope)
    if ($schemaErrors.Count -gt 0) {
        return @{ IsValid = $false; Reason = "SCHEMA_INVALID"; Message = "Mission envelope does not match the protocol schema: $($schemaErrors[0])" }
    }

    # 3. Intended Minion ID validation
    if ($Envelope.minion_id -cne $ExpectedMinionId) {
        return @{ IsValid = $false; Reason = "MINION_ID_MISMATCH"; Message = "Mission addressed to '$($Envelope.minion_id)', expected '$ExpectedMinionId'." }
    }

    # 4. Capability validation
    if ($SupportedCapabilities -cnotcontains $Envelope.capability) {
        return @{ IsValid = $false; Reason = "UNSUPPORTED_CAPABILITY"; Message = "Capability '$($Envelope.capability)' not supported by this Minion." }
    }

    # 5. Validity window
    $nowEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $clockSkewSeconds = 300
    if ([double]$Envelope.expires_at -lt $nowEpoch) {
        return @{ IsValid = $false; Reason = "MISSION_EXPIRED"; Message = "Mission expired at $($Envelope.expires_at), current time is $nowEpoch." }
    }
    if ([double]$Envelope.issued_at -gt $nowEpoch + $clockSkewSeconds -or [double]$Envelope.expires_at -le [double]$Envelope.issued_at) {
        return @{ IsValid = $false; Reason = "INVALID_VALIDITY_WINDOW"; Message = "Mission issued_at/expires_at are not a plausible validity window." }
    }

    # 6. SluiceGate signature verification
    $signature = $Envelope.signature
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

    # 7. Replay protection: consume the nonce atomically, only after the Mission is known to be authentic.
    if (-not $AllowConsumedNonce) {
        $retainUntil = [long][math]::Ceiling([double]$Envelope.expires_at) + $clockSkewSeconds
        if (-not (Register-MinionNonce -Nonce $Envelope.nonce -NonceStorePath $NonceStorePath -RetainUntil $retainUntil)) {
            return @{ IsValid = $false; Reason = "REPLAY_DETECTED"; Message = "Nonce '$($Envelope.nonce)' has already been consumed." }
        }
    }

    return @{ IsValid = $true; Reason = $null; Message = "Mission envelope is valid." }
}

function Get-MinionApiKey {
    <#
    .SYNOPSIS
        Reads the Minion API key from the protected file named by ApiKeyPath. An inline ApiKey setting is rejected.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Config
    )

    if ($Config.PSObject.Properties.Name -contains 'ApiKey') {
        throw "An inline ApiKey in the configuration is not supported. Set ApiKeyPath to a protected key file."
    }
    $path = $Config.ApiKeyPath
    if ([string]::IsNullOrWhiteSpace($path)) {
        throw "Configuration setting ApiKeyPath is required."
    }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "API key file not found: $path"
    }
    $key = (Get-Content -LiteralPath $path -Raw).Trim()
    if (-not $key) {
        throw "API key file is empty: $path"
    }
    return $key
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
        [string]$ApiKey,

        [hashtable]$ReleaseReport
    )

    $url = "$($MissionControlUrl.TrimEnd('/'))/internal/v1/minions/$MinionId/check-in"
    $headers = @{
        "Authorization" = "Bearer $ApiKey"
        "Content-Type"  = "application/json"
    }

    try {
        $body = if ($ReleaseReport) { $ReleaseReport | ConvertTo-Json -Compress } else { $null }
        $response = Invoke-MinionHttp -Method Post -Uri $url -Headers $headers -Body $body -TimeoutSec 15
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

function New-MinionStatusBody {
    <#
    .SYNOPSIS
        Builds the signed body of a status event. The body is the canonical text itself, so the service
        parses exactly the values that were signed. Signature covers event_id, mission_id, minion_id,
        claim_generation, status, detail and occurred_at.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$MinionId,
        [Parameter(Mandatory = $true)][string]$MissionId,
        [Parameter(Mandatory = $true)][string]$ClaimToken,
        [Parameter(Mandatory = $true)][int]$ClaimGeneration,
        [Parameter(Mandatory = $true)][string]$PrivateKeyPath,
        [Parameter(Mandatory = $true)][string]$Status,
        [hashtable]$Detail = @{},
        [string]$EventId = ("evt-" + [System.Guid]::NewGuid().ToString("N")),
        [long]$OccurredAt = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    )

    $signedPayload = [ordered]@{
        event_id         = $EventId
        mission_id       = $MissionId
        minion_id        = $MinionId
        claim_generation = $ClaimGeneration
        status           = $Status
        detail           = $Detail
        occurred_at      = $OccurredAt
    }
    $signature = New-MinionSignature -CanonicalJson (ConvertTo-CanonicalJson -InputObject $signedPayload) -PrivateKeyPath $PrivateKeyPath
    return (ConvertTo-CanonicalJson -InputObject ([ordered]@{
        event_id         = $EventId
        claim_token      = $ClaimToken
        claim_generation = $ClaimGeneration
        status           = $Status
        detail           = $Detail
        occurred_at      = $OccurredAt
        signature        = $signature
    }))
}

function New-MinionResultBody {
    <#
    .SYNOPSIS
        Builds the signed body of a terminal result. Signature covers event_id, mission_id, minion_id,
        claim_generation, status and result.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$MinionId,
        [Parameter(Mandatory = $true)][string]$MissionId,
        [Parameter(Mandatory = $true)][string]$ClaimToken,
        [Parameter(Mandatory = $true)][int]$ClaimGeneration,
        [Parameter(Mandatory = $true)][string]$PrivateKeyPath,
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][hashtable]$Result,
        [string]$EventId = ("evt-" + [System.Guid]::NewGuid().ToString("N"))
    )

    $signedPayload = [ordered]@{
        event_id         = $EventId
        mission_id       = $MissionId
        minion_id        = $MinionId
        claim_generation = $ClaimGeneration
        result           = $Result
        status           = $Status
    }
    $signature = New-MinionSignature -CanonicalJson (ConvertTo-CanonicalJson -InputObject $signedPayload) -PrivateKeyPath $PrivateKeyPath
    return (ConvertTo-CanonicalJson -InputObject ([ordered]@{
        event_id         = $EventId
        claim_token      = $ClaimToken
        claim_generation = $ClaimGeneration
        status           = $Status
        result           = $Result
        signature        = $signature
    }))
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
        [int]$ClaimGeneration,

        [Parameter(Mandatory = $true)]
        [string]$PrivateKeyPath,

        [Parameter(Mandatory = $true)]
        [string]$Status,

        [hashtable]$Detail = @{}
    )

    $url = "$($MissionControlUrl.TrimEnd('/'))/internal/v1/minions/$MinionId/missions/$MissionId/status"
    $headers = @{
        "Authorization" = "Bearer $ApiKey"
        "Content-Type"  = "application/json"
    }

    $body = New-MinionStatusBody -MinionId $MinionId -MissionId $MissionId -ClaimToken $ClaimToken -ClaimGeneration $ClaimGeneration -PrivateKeyPath $PrivateKeyPath -Status $Status -Detail $Detail

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
        [int]$ClaimGeneration,

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

    $body = New-MinionResultBody -MinionId $MinionId -MissionId $MissionId -ClaimToken $ClaimToken -ClaimGeneration $ClaimGeneration -PrivateKeyPath $PrivateKeyPath -Status $Status -Result $Result

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
    Register-MinionNonce, `
    Get-MissionEnvelopeSchemaErrors, `
    Test-MissionEnvelope, `
    Set-MinionTransportSecurity, `
    Invoke-MinionHttp, `
    Get-MinionHttpStatusCode, `
    Get-MinionApiKey, `
    Invoke-MinionCheckIn, `
    Get-MinionMissionClaim, `
    Send-MinionHeartbeat, `
    New-MinionStatusBody, `
    New-MinionResultBody, `
    Send-MinionStatus, `
    Send-MinionResult
