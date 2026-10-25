[CmdletBinding()]
param(
    # Directory with canonical-json.json and envelope-fixtures.json.
    [Parameter(Mandatory = $true)]
    [string]$VectorDirectory,

    # Writable scratch directory for keys and nonce stores.
    [Parameter(Mandatory = $true)]
    [string]$WorkDirectory,

    # JSON written by the Python test: { minion_id, public_key_pem, envelopes: [ { name, envelope } ] }.
    [Parameter(Mandatory = $true)]
    [string]$ScenarioFile
)

# Exercises the PowerShell side of the Mission Control protocol and prints one JSON document that the pytest
# wrapper (sg-service/tests/test_protocol_powershell.py) checks against the Python implementation.

$ErrorActionPreference = "Stop"
$modulePath = Join-Path $PSScriptRoot "../SluiceGate.Minion.Core.psm1"
Import-Module $modulePath -Force

function Read-Json([string]$Path) {
    return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
}

$supportsDateKind = (Get-Command ConvertFrom-Json).Parameters.ContainsKey("DateKind")
$results = [ordered]@{}

# 1. Canonical JSON vectors
$vectors = Read-Json (Join-Path $VectorDirectory "canonical-json.json")
$canonicalResults = foreach ($case in $vectors.canonical) {
    if ($case.requires_string_dates -and -not $supportsDateKind) {
        [ordered]@{ name = $case.name; skipped = $true }
        continue
    }
    $parsed = if ($supportsDateKind) { ConvertFrom-Json -InputObject $case.input -NoEnumerate -DateKind String } else { ConvertFrom-Json -InputObject $case.input -NoEnumerate }
    [ordered]@{ name = $case.name; expected = $case.canonical; actual = (ConvertTo-CanonicalJson -InputObject $parsed) }
}
$results.canonical = @($canonicalResults)

# 2. Signature vector: the same bytes, verified and re-signed with openssl
$publicKeyPath = Join-Path $WorkDirectory "vector-public.pem"
$privateKeyPath = Join-Path $WorkDirectory "vector-private.pem"
[System.IO.File]::WriteAllText($publicKeyPath, $vectors.signature.public_key_pem)
[System.IO.File]::WriteAllText($privateKeyPath, $vectors.signature.private_key_pem)
$payloadCanonical = ConvertTo-CanonicalJson -InputObject $vectors.signature.payload
$results.signature = [ordered]@{
    payload_matches   = ($payloadCanonical -ceq $vectors.signature.canonical)
    verifies          = [bool](Test-MinionSignature -CanonicalJson $vectors.signature.canonical -SignatureHex $vectors.signature.signature_hex -PublicKeyPath $publicKeyPath)
    tampered_verifies = [bool](Test-MinionSignature -CanonicalJson ($vectors.signature.canonical + " ") -SignatureHex $vectors.signature.signature_hex -PublicKeyPath $publicKeyPath)
    resigned_matches  = ((New-MinionSignature -CanonicalJson $vectors.signature.canonical -PrivateKeyPath $privateKeyPath) -ceq $vectors.signature.signature_hex)
}

# 3. Envelope structure: must agree with the JSON Schema on every fixture
$fixtures = Read-Json (Join-Path $VectorDirectory "envelope-fixtures.json")
$results.fixtures = @(foreach ($fixture in $fixtures.fixtures) {
    $errors = @(Get-MissionEnvelopeSchemaErrors -Envelope $fixture.envelope)
    [ordered]@{ name = $fixture.name; expected = [bool]$fixture.valid; actual = ($errors.Count -eq 0); first_error = $(if ($errors.Count) { $errors[0] } else { $null }) }
})

# 4. Nonce store
$nonceStore = Join-Path $WorkDirectory "nonces-basic.txt"
$future = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 3600
$nonce = [ordered]@{}
$nonce.first = [bool](Register-MinionNonce -Nonce "nonce-one" -NonceStorePath $nonceStore -RetainUntil $future)
$nonce.replay = [bool](Register-MinionNonce -Nonce "nonce-one" -NonceStorePath $nonceStore -RetainUntil $future)
$nonce.different = [bool](Register-MinionNonce -Nonce "nonce-two" -NonceStorePath $nonceStore -RetainUntil $future)

$expiredStore = Join-Path $WorkDirectory "nonces-expired.txt"
[System.IO.File]::WriteAllLines($expiredStore, [string[]]@("old-nonce`t1"))
$nonce.expired_entry_can_be_reused = [bool](Register-MinionNonce -Nonce "old-nonce" -NonceStorePath $expiredStore -RetainUntil $future)

# Older entries must survive however many newer ones exist.
$largeStore = Join-Path $WorkDirectory "nonces-large.txt"
[System.IO.File]::WriteAllLines($largeStore, [string[]]@(1..12000 | ForEach-Object { "nonce-{0:D5}`t{1}" -f $_, $future }))
$null = Register-MinionNonce -Nonce "nonce-new" -NonceStorePath $largeStore -RetainUntil $future
$nonce.oldest_survives_large_store = -not [bool](Register-MinionNonce -Nonce "nonce-00001" -NonceStorePath $largeStore -RetainUntil $future)

$legacyStore = Join-Path $WorkDirectory "nonces-legacy.txt"
[System.IO.File]::WriteAllLines($legacyStore, [string[]]@("legacy-nonce"))
$nonce.legacy_entry_is_a_replay = -not [bool](Register-MinionNonce -Nonce "legacy-nonce" -NonceStorePath $legacyStore -RetainUntil $future)

# Bind-mounted directories in containers often do not enforce file locks, so contention is tested on a local temp path.
$concurrentStore = Join-Path ([System.IO.Path]::GetTempPath()) ("sg-nonces-concurrent-" + [guid]::NewGuid().ToString("N") + ".txt")
$outcomes = 1..8 | ForEach-Object -Parallel {
    Import-Module $using:modulePath -Force
    [bool](Register-MinionNonce -Nonce "contended" -NonceStorePath $using:concurrentStore -RetainUntil $using:future)
} -ThrottleLimit 8
$nonce.concurrent_winners = @($outcomes | Where-Object { $_ }).Count
$results.nonce = $nonce

# 5. Signed status and result bodies, verified by Python
$detail = @{
    worker_process_id         = 4321
    worker_process_started_at = 1800000000.25
    process_detail            = @{ phase = "INSTALLING"; note = "Zugriff verweigert: é 日本 😀 <x>" }
}
$result = @{
    capability = "windows.patch.reconcile"
    success    = $false
    retryable  = $true
    error      = "é <&> '"
    ratio      = 0.5
    targets    = @(@{ server = "SERVER-01"; patches = @() })
}
$results.bodies = [ordered]@{
    status = (New-MinionStatusBody -MinionId "PATCH-01" -MissionId "MISSION-1" -ClaimToken ("t" * 48) -ClaimGeneration 3 -PrivateKeyPath $privateKeyPath -Status "MISSION_IN_PROGRESS" -Detail $detail -EventId "evt-status" -OccurredAt 1800000100)
    result = (New-MinionResultBody -MinionId "PATCH-01" -MissionId "MISSION-1" -ClaimToken ("t" * 48) -ClaimGeneration 3 -PrivateKeyPath $privateKeyPath -Status "MISSION_COMPLETE_FAILED" -Result $result -EventId "evt-result")
}

# 6. Mission envelopes signed by Python
$scenarios = Read-Json $ScenarioFile
$envelopeResults = foreach ($scenario in $scenarios.envelopes) {
    $store = Join-Path $WorkDirectory ("nonces-" + $scenario.store + ".txt")
    $publicKey = Join-Path $WorkDirectory "service-public.pem"
    [System.IO.File]::WriteAllText($publicKey, $scenarios.public_key_pem)
    $validation = Test-MissionEnvelope -Envelope $scenario.envelope -ExpectedMinionId $scenarios.minion_id -SluiceGatePublicKeyPath $publicKey -NonceStorePath $store -SupportedCapabilities @($scenarios.supported_capabilities)
    [ordered]@{ name = $scenario.name; valid = [bool]$validation.IsValid; reason = $validation.Reason }
}
$results.envelopes = @($envelopeResults)

$results | ConvertTo-Json -Depth 8 -Compress
