[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$InstallRoot = "$env:ProgramFiles\SluiceGate\Minion",
    [string]$ContainerName = "sluicegate-service"
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
}

if ($PSCmdlet.ShouldProcess($ContainerName, "Stop and remove SluiceGate service container")) {
    docker rm -f $ContainerName 2>$null | Out-Null
}

if ($PSCmdlet.ShouldProcess($InstallRoot, "Remove SluiceGate Minion installation files")) {
    if (Test-Path -LiteralPath $InstallRoot) {
        Remove-Item -LiteralPath $InstallRoot -Recurse -Force
    }
}
