[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$InstallRoot = "$env:ProgramFiles\SluiceGate\Minion",
    [string]$DataRoot = "$env:ProgramData\SluiceGate\Minion",
    [string]$WslDistribution = "Ubuntu",
    [string]$ContainerName = "sluicegate-service",
    # Also deletes the service database, its secrets and policy inside WSL, and the Minion configuration, keys, and state.
    [switch]$RemoveData
)

$ErrorActionPreference = "Stop"
$serviceName = "SluiceGateMinion"
. (Join-Path $PSScriptRoot "WslServiceContainer.ps1")

if ($PSCmdlet.ShouldProcess($serviceName, "Stop and remove the SluiceGate Minion service and WSL startup task")) {
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
    if (Get-ScheduledTask -TaskName "SluiceGateWsl" -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName "SluiceGateWsl" -Confirm:$false
    }
}

if ($PSCmdlet.ShouldProcess($ContainerName, "Remove the sg-service container")) {
    Remove-SluiceGateServiceContainer -Distribution $WslDistribution -ContainerName $ContainerName -RemoveData:$RemoveData
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
        Write-Host "Kept $DataRoot and the service data inside WSL (/opt/sluicegate and the sluicegate-service-data volume). Re-run with -RemoveData to delete them."
    }
}
