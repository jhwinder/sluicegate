[CmdletBinding()]
param(
    [string]$DataRoot = "$env:ProgramData\SluiceGate\Minion",
    [string]$ServiceAccount
)

# Stores the Minion API key in its protected file. The key is read as hidden input and never appears on a command line.
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "MinionInstallHelpers.ps1")

$keysDirectory = Join-Path $DataRoot "keys"
$apiKeyPath = Join-Path $keysDirectory "minion-api-key.txt"
$accountSid = if ($ServiceAccount) { Resolve-ServiceAccountSid -Account $ServiceAccount } else { $null }

New-Item -ItemType Directory -Path $keysDirectory -Force | Out-Null
Set-MinionRestrictedAcl -Path $keysDirectory -AccountSid $accountSid

$secureKey = Read-Host -Prompt "Minion API key (input is hidden)" -AsSecureString
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
try {
    $key = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
}
finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
}
if ([string]::IsNullOrWhiteSpace($key)) {
    throw "No API key was entered."
}

[System.IO.File]::WriteAllText($apiKeyPath, $key.Trim(), [System.Text.UTF8Encoding]::new($false))
# The file inherits the protected ACL of the keys directory, which already includes the service account once installed.
Write-Host "API key stored at $apiKeyPath (access: the protected keys directory's Administrators, SYSTEM, and service account)."
