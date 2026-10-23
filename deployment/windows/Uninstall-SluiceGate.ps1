[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$InstallRoot = "$env:ProgramFiles\SluiceGate\Minion",
    [string]$DataRoot = "$env:ProgramData\SluiceGate\Minion",
    [string]$ContainerName = "sluicegate-service",
    # Also deletes the Minion configuration, keys, nonce store, and Mission Diary under DataRoot.
    [switch]$RemoveData
)

$ErrorActionPreference = "Stop"
$serviceName = "SluiceGateMinion"

if ($PSCmdlet.ShouldProcess($serviceName, "Stop and remove SluiceGate Minion service")) {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -ne "Stopped") {
            Stop-Service -Name $serviceName -Force
        }
        sc.exe delete $serviceName | Out-Null
    }
    if ([System.Diagnostics.EventLog]::SourceExists($serviceName)) {
        [System.Diagnostics.EventLog]::DeleteEventSource($serviceName)
    }
}

if ($PSCmdlet.ShouldProcess($ContainerName, "Stop and remove SluiceGate service container")) {
    docker rm -f $ContainerName 2>$null | Out-Null
}

if ($PSCmdlet.ShouldProcess($InstallRoot, "Remove SluiceGate Minion installation files")) {
    if (Test-Path -LiteralPath $InstallRoot) {
        Remove-Item -LiteralPath $InstallRoot -Recurse -Force
    }
}

if (Test-Path -LiteralPath $DataRoot) {
    if ($RemoveData) {
        if ($PSCmdlet.ShouldProcess($DataRoot, "Delete Minion configuration, keys, and state")) {
            Remove-Item -LiteralPath $DataRoot -Recurse -Force
        }
    } else {
        Write-Host "Kept $DataRoot (configuration, keys, nonce store, Mission Diary). Re-run with -RemoveData to delete it."
    }
}
