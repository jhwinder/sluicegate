<#
.SYNOPSIS
    SluiceGate Patching Execution Engine Module
.DESCRIPTION
    Implements SHA-256 preflight verification, target file staging,
    constrained remote process invocation with %PATCHPATH% substitution,
    exit code analysis, reboot detection, and WSUS OS-update integration.
#>

function Test-PatchFileHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedHash
    )

    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        Write-Warning "Patch file not found: $FilePath"
        return $false
    }

    $actualHash = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256).Hash
    return ($actualHash.ToLowerInvariant() -eq $ExpectedHash.Trim().ToLowerInvariant())
}

function Invoke-TargetPatchInstall {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetServer,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$PatchRow,

        [string]$StagingDirectory = "C$\Windows\Temp\SluiceGate\Staging",

        [int]$TimeoutSeconds = 600,

        [bool]$DryRun = $false
    )

    $patchPath     = $PatchRow.patch_path
    $expectedSha   = $PatchRow.patch_sha256
    $installCmdTpl = $PatchRow.install_command
    $pluginId      = $PatchRow.plugin_id
    $patchId       = $PatchRow.patch_id

    $result = [ordered]@{
        target          = $TargetServer
        plugin_id       = $pluginId
        patch_id        = $patchId
        status          = "FAILED"
        exit_code       = $null
        reboot_required = $false
        reboot_performed= $false
        error           = $null
        duration_sec    = 0
    }

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        # 1. Pre-flight SHA-256 hash check on the share
        Write-Host "Verifying SHA-256 hash for patch '$patchId' ($patchPath)..."
        if (-not (Test-PatchFileHash -FilePath $patchPath -ExpectedHash $expectedSha)) {
            $result.error = "SHA-256 hash check failed for source file: $patchPath"
            return $result
        }

        if ($DryRun) {
            $result.status = "SUCCESS"
            $result.exit_code = 0
            $result.error = "DryRun: Verification succeeded."
            return $result
        }

        # 2. Stage file to target server
        $fileName = [System.IO.Path]::GetFileName($patchPath)
        $remoteSharePath = "\\$TargetServer\$StagingDirectory"
        if (-not (Test-Path -LiteralPath $remoteSharePath)) {
            New-Item -ItemType Directory -Path $remoteSharePath -Force | Out-Null
        }
        $destinationFile = Join-Path $remoteSharePath $fileName

        Write-Host "Staging patch to $destinationFile..."
        Copy-Item -LiteralPath $patchPath -Destination $destinationFile -Force

        # Local path on the target server
        $localStagedPath = "C:\Windows\Temp\SluiceGate\Staging\$fileName"

        # 3. Substitute %PATCHPATH% token
        $effectiveCommand = $installCmdTpl.Replace("%PATCHPATH%", $localStagedPath)

        # 4. Constrained Remote Process Execution
        Write-Host "Executing installer on $TargetServer: $effectiveCommand"
        $scriptBlock = [scriptblock]::Create(@"
            `$procInfo = New-Object System.Diagnostics.ProcessStartInfo
            `$procInfo.FileName = 'cmd.exe'
            `$procInfo.Arguments = '/c $effectiveCommand'
            `$procInfo.UseShellExecute = `$false
            `$procInfo.RedirectStandardOutput = `$true
            `$procInfo.RedirectStandardError = `$true
            `$procInfo.CreateNoWindow = `$true

            `$proc = [System.Diagnostics.Process]::Start(`$procInfo)
            `$proc.WaitForExit($($TimeoutSeconds * 1000))
            `$exitCode = `$proc.ExitCode
            return `$exitCode
"@)

        $exitCode = Invoke-Command -ComputerName $TargetServer -ScriptBlock $scriptBlock -ErrorAction Stop
        $result.exit_code = $exitCode

        # 5. Determine success / reboot requirement
        # Standard Windows installer return codes: 0 = Success, 3010 = Success (Reboot required)
        if ($exitCode -eq 0) {
            $result.status = "SUCCESS"
        }
        elseif ($exitCode -eq 3010) {
            $result.status = "SUCCESS"
            $result.reboot_required = $true
        }
        else {
            $result.status = "FAILED"
            $result.error = "Installer exited with non-zero code: $exitCode"
        }

        # 6. Cleanup staged file on target
        if (Test-Path -LiteralPath $destinationFile) {
            Remove-Item -LiteralPath $destinationFile -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        $result.status = "FAILED"
        $result.error = $_.ToString()
        Write-Error "Error executing patch $patchId on $TargetServer: $_"
    }
    finally {
        $stopwatch.Stop()
        $result.duration_sec = [math]::Round($stopwatch.Elapsed.TotalSeconds, 2)
    }

    return $result
}

function Invoke-TargetWsusUpdate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetServer,

        [bool]$AllowReboot = $false,

        [bool]$DryRun = $false
    )

    $result = [ordered]@{
        target          = $TargetServer
        source          = "wsus"
        status          = "SUCCESS"
        updates_applied = @()
        reboot_required = $false
        error           = $null
    }

    if ($DryRun) {
        $result.error = "DryRun: WSUS update queried successfully."
        return $result
    }

    try {
        # Remote execution to trigger Windows Update Agent scan and installation
        $wsusScript = {
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
            $applied = @()

            if ($searchResult.Updates.Count -gt 0) {
                $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
                foreach ($update in $searchResult.Updates) {
                    if ($update.IsDownloaded) {
                        $updatesToInstall.Add($update) | Out-Null
                        $applied += $update.Title
                    }
                }
                if ($updatesToInstall.Count -gt 0) {
                    $installer = $updateSession.CreateUpdateInstaller()
                    $installer.Updates = $updatesToInstall
                    $installationResult = $installer.Install()
                    return @{
                        Success = ($installationResult.ResultCode -eq 2)
                        RebootRequired = $installationResult.RebootRequired
                        Applied = $applied
                    }
                }
            }
            return @{ Success = $true; RebootRequired = $false; Applied = @() }
        }

        $res = Invoke-Command -ComputerName $TargetServer -ScriptBlock $wsusScript -ErrorAction Stop
        if ($res) {
            $result.updates_applied = @($res.Applied)
            $result.reboot_required = [bool]$res.RebootRequired
        }
    }
    catch {
        $result.status = "FAILED"
        $result.error = $_.ToString()
    }

    return $result
}

function Invoke-PatchReconcile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Envelope,

        [Parameter(Mandatory = $true)]
        [string]$CatalogPath,

        [Parameter(Mandatory = $true)]
        [string]$NessusMappingPath,

        [bool]$DryRun = $false
    )

    $targets          = @($Envelope.target.servers)
    $parameters       = $Envelope.parameters
    $patchSources     = @($parameters.patch_sources)
    $patchConstraints = $parameters.patch_constraints
    $allowedTypes     = if ($patchConstraints.allowed_patch_types) { @($patchConstraints.allowed_patch_types) } else { @("SECURITY") }
    $allowReboot      = if ($patchConstraints.allow_reboot) { [bool]$patchConstraints.allow_reboot } else { $false }

    Write-Host "Starting patch reconciliation for $($targets.Count) target(s)..."
    Write-Host "Sources: $($patchSources -join ', ')"
    Write-Host "Allowed Types: $($allowedTypes -join ', ')"
    Write-Host "Allow Reboot: $allowReboot"

    $catalogRows = Import-PatchCatalog -Path $CatalogPath
    $mappingRows = Import-NessusMapping -Path $NessusMappingPath

    $resolvedPatches = Resolve-TargetPatches `
        -MappingRows $mappingRows `
        -ApprovedCatalogRows $catalogRows `
        -TargetServers $targets `
        -AllowedPatchTypes $allowedTypes `
        -AllowReboot $allowReboot

    $targetResults = [System.Collections.Generic.List[object]]::new()
    $anyFailure = $false
    $anySuccess = $false

    foreach ($server in $targets) {
        $normalizedServer = $server.Trim().ToLowerInvariant()
        $serverPatches = $resolvedPatches[$normalizedServer]
        $installedForServer = [System.Collections.Generic.List[object]]::new()
        $wsusResult = $null

        # 1. WSUS OS update reconciliation if enabled
        if ($patchSources -contains "wsus") {
            Write-Host "Running WSUS update reconciliation on $server..."
            $wsusResult = Invoke-TargetWsusUpdate -TargetServer $server -AllowReboot $allowReboot -DryRun $DryRun
            if ($wsusResult.status -eq "FAILED") {
                $anyFailure = $true
            }
        }

        # 2. Non-OS Nessus IAVM patch installation if enabled
        if ($patchSources -contains "nessus_catalog") {
            if ($null -ne $serverPatches -and $serverPatches.Count -gt 0) {
                Write-Host "Applying $($serverPatches.Count) qualifying patch(es) to $server..."
                foreach ($patchRow in $serverPatches) {
                    $installOutcome = Invoke-TargetPatchInstall `
                        -TargetServer $server `
                        -PatchRow $patchRow `
                        -DryRun $DryRun

                    $installedForServer.Add($installOutcome)

                    if ($installOutcome.status -eq "SUCCESS") {
                        $anySuccess = $true
                    }
                    else {
                        $anyFailure = $true
                    }
                }
            }
            else {
                Write-Host "No qualifying non-OS catalog patches for $server."
            }
        }

        $targetResults.Add([ordered]@{
            server          = $server
            catalog_patches = $installedForServer
            wsus_result     = $wsusResult
        })
    }

    # Determine aggregate mission status
    $terminalStatus = "MISSION_COMPLETE_SUCCEEDED"
    if ($anyFailure -and $anySuccess) {
        $terminalStatus = "MISSION_COMPLETE_PARTIAL"
    }
    elseif ($anyFailure -and (-not $anySuccess)) {
        $terminalStatus = "MISSION_COMPLETE_FAILED"
    }

    return @{
        Status = $terminalStatus
        Result = [ordered]@{
            capability       = "windows.patch.reconcile"
            targets_count    = $targets.Count
            target_results   = $targetResults
            executed_at      = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        }
    }
}

Export-ModuleMember -Function `
    Test-PatchFileHash, `
    Invoke-TargetPatchInstall, `
    Invoke-TargetWsusUpdate, `
    Invoke-PatchReconcile
