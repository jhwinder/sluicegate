<#
.SYNOPSIS
    SluiceGate Patching Catalog and Nessus Mapping Module
.DESCRIPTION
    Parses and validates the patch registry CSV and Nessus finding-to-host CSV mapping.
    Performs deterministic joining and constraint filtering for SluiceGate Missions.
#>

$RequiredCatalogHeaders = @(
    "patch_status",
    "plugin_id",
    "iavm_id",
    "vendor",
    "title",
    "patch_id",
    "patch_title",
    "patch_type",
    "requires_reboot",
    "patch_path",
    "patch_sha256",
    "source_url",
    "install_command",
    "notes"
)

function Import-PatchCatalog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Patch catalog file not found: $Path"
    }

    $records = Import-Csv -LiteralPath $Path -Encoding UTF8
    if ($null -eq $records -or $records.Count -eq 0) {
        return @()
    }

    # Validate header columns
    $firstRecord = $records[0]
    $headerNames = $firstRecord.PSObject.Properties.Name
    foreach ($req in $RequiredCatalogHeaders) {
        if ($headerNames -notcontains $req) {
            throw "Patch catalog is missing required header column: '$req'"
        }
    }

    # Filter to APPROVED rows only (ignoring DRAFT and RETIRED)
    $approvedRows = @($records | Where-Object { $_.patch_status -eq "APPROVED" })

    # Validate uniqueness of plugin_id among APPROVED rows
    $seenPlugins = @{}
    foreach ($row in $approvedRows) {
        $pId = $row.plugin_id.Trim()
        if (-not $pId) {
            throw "Approved patch catalog record has an empty plugin_id."
        }
        if ($seenPlugins.ContainsKey($pId)) {
            throw "Duplicate approved catalog row found for plugin_id '$pId'."
        }
        $seenPlugins[$pId] = $row

        # Validate required fields in approved row
        if (-not $row.patch_path) {
            throw "Approved patch row for plugin_id '$pId' is missing patch_path."
        }
        if (-not $row.patch_sha256 -or $row.patch_sha256.Length -ne 64) {
            throw "Approved patch row for plugin_id '$pId' has invalid SHA-256 digest."
        }
        if (-not $row.install_command) {
            throw "Approved patch row for plugin_id '$pId' is missing install_command."
        }
    }

    return $approvedRows
}

function Import-NessusMapping {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Nessus mapping file not found: $Path"
    }

    $records = Import-Csv -LiteralPath $Path -Encoding UTF8
    if ($null -eq $records -or $records.Count -eq 0) {
        return @()
    }

    $firstRecord = $records[0]
    $props = $firstRecord.PSObject.Properties.Name
    $pluginCol = $props | Where-Object { $_ -like "*PLUGIN_ID*" -or $_ -like "*plugin_id*" } | Select-Object -First 1
    $dnsCol    = $props | Where-Object { $_ -like "*DNS_NAME*" -or $_ -like "*dns_name*" } | Select-Object -First 1

    if (-not $pluginCol -or -not $dnsCol) {
        throw "Nessus mapping CSV must contain PLUGIN_ID and DNS_NAME columns."
    }

    $normalized = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $records) {
        $pId = $r.$pluginCol
        $dns = $r.$dnsCol
        if ($pId -and $dns) {
            $normalized.Add([PSCustomObject]@{
                PluginId = $pId.ToString().Trim()
                DnsName  = $dns.ToString().Trim().ToLowerInvariant()
            })
        }
    }
    return $normalized
}

function Resolve-TargetPatches {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$MappingRows,

        [Parameter(Mandatory = $true)]
        [object[]]$ApprovedCatalogRows,

        [Parameter(Mandatory = $true)]
        [string[]]$TargetServers,

        [string[]]$AllowedPatchTypes = @("SECURITY"),

        [bool]$AllowReboot = $false
    )

    # Normalize target servers list
    $normalizedTargets = @($TargetServers | ForEach-Object { $_.Trim().ToLowerInvariant() })

    # Build catalog lookup by plugin_id
    $catalogByPlugin = @{}
    foreach ($cat in $ApprovedCatalogRows) {
        $catalogByPlugin[$cat.plugin_id.Trim()] = $cat
    }

    # Intersect mapping rows with authorized servers
    $resolvedByServer = [ordered]@{}
    foreach ($srv in $normalizedTargets) {
        $resolvedByServer[$srv] = [System.Collections.Generic.List[object]]::new()
    }

    foreach ($m in $MappingRows) {
        $serverName = $m.DnsName
        if ($normalizedTargets -contains $serverName) {
            $pluginId = $m.PluginId
            if ($catalogByPlugin.ContainsKey($pluginId)) {
                $catalogRow = $catalogByPlugin[$pluginId]

                # Check patch_type constraint
                $pType = $catalogRow.patch_type.Trim().ToUpperInvariant()
                $typeAllowed = $false
                foreach ($allowed in $AllowedPatchTypes) {
                    if ($pType -eq $allowed.Trim().ToUpperInvariant()) {
                        $typeAllowed = $true
                        break
                    }
                }
                if (-not $typeAllowed) {
                    continue
                }

                # Check requires_reboot constraint
                $rebootStr = $catalogRow.requires_reboot.Trim().ToLowerInvariant()
                $requiresReboot = ($rebootStr -eq "true" -or $rebootStr -eq "1" -or $rebootStr -eq "yes")
                if ($requiresReboot -and (-not $AllowReboot)) {
                    # Policy does not permit reboot; exclude this patch
                    continue
                }

                # Avoid duplicate patch for same server
                $alreadyAdded = $false
                foreach ($existing in $resolvedByServer[$serverName]) {
                    if ($existing.plugin_id -eq $catalogRow.plugin_id) {
                        $alreadyAdded = $true
                        break
                    }
                }
                if (-not $alreadyAdded) {
                    $resolvedByServer[$serverName].Add($catalogRow)
                }
            }
        }
    }

    return $resolvedByServer
}

Export-ModuleMember -Function `
    Import-PatchCatalog, `
    Import-NessusMapping, `
    Resolve-TargetPatches
