# Windows Server Deployment

## Target

- Windows Server 2022 VM.
- Latest stable Docker version supported on Windows Server 2022.
- SG Minion Windows service running under a dedicated, least-privilege AD identity.
- `sg_service` container hosted on the same VM with Minion Mission Control bound to host loopback (`127.0.0.1:8443`).

The `sg_service` container does not need an AD identity. The Minion service identity needs only the approved patch-catalog/mapping/repository access and remote execution/reboot rights for its authorized target scope. The installer configures the service logon (`-ServiceAccount`, a gMSA or domain account) and the file ACLs on the Minion's own files; it does not grant share or target access, which stays with the organization's Windows administration process.

For the two-server topology (Mission Control on Linux), install only the Minion with `-SkipServiceContainer` and omit `-ServiceImage` when building the bundle.

## Installed Layout

| Location | Contents | Access |
| --- | --- | --- |
| `C:\Program Files\SluiceGate\Minion` (`InstallRoot`) | `SluiceGate.Minion.Service.exe` and `runtime\` (Patching Minion script and modules, Mission schema, `version.json`) | Replaced on upgrade |
| `C:\ProgramData\SluiceGate\Minion\config` | `minion.config.json` (no secrets) | Administrators/SYSTEM full, service account read |
| `C:\ProgramData\SluiceGate\Minion\keys` | `minion-api-key.txt`, `minion-private-key.pem`, `sg-public-key.pem`, optional `sg-server-cert.pem` | Administrators/SYSTEM full, service account read |
| `C:\ProgramData\SluiceGate\Minion\data` and `MissionDiary` | Replay-protection nonces and Mission recovery state | Administrators/SYSTEM full, service account modify |

The service starts as `SluiceGate.Minion.Service.exe --config <DataRoot>\config\minion.config.json`; that path is the single configuration contract shared by the installer, the service host, and the PowerShell runtime. Upgrades replace only `InstallRoot` and keep everything under `DataRoot`.

## Package Contents

The release bundle is expected to contain:

```text
Install-SluiceGate.ps1
Uninstall-SluiceGate.ps1
Set-MinionApiKey.ps1              # stores the API key from hidden input
MinionInstallHelpers.ps1
minion.config.template.json       # non-secret defaults; DryRun is true
Minion/SluiceGate.Minion.Service.exe
Minion/runtime/                   # PatchingMinion.ps1, modules, protocol/, version.json
images/sg-service-image.tar       # same-host topology only
service.env.example               # same-host topology only; template, no secrets
SHA256SUMS.txt                    # SHA-256 of every file in the bundle
```

The repository includes the compiled, framework-dependent Windows x64 executable at [deployment/windows/Minion/SluiceGate.Minion.Service.exe](deployment/windows/Minion/SluiceGate.Minion.Service.exe), alongside its C# source in [deployment/windows/MinionHost/](deployment/windows/MinionHost/). The .NET 10 x64 Runtime must be installed on the Windows Server 2022 host. The executable does not bundle the .NET runtime. Operators do not need a .NET SDK to install it; developers can rebuild it using the instructions below.

Build the bundle from the repository root's `deployment/windows` directory. `-Version` is required and is recorded in `Minion/runtime/version.json`; omit `-ServiceImage` for a Minion-only bundle. The output directory must be empty so stale files are never bundled.

```powershell
./Build-DeploymentBundle.ps1 `
  -MinionExecutable .\Minion\SluiceGate.Minion.Service.exe `
  -Version 1.0.0 `
  -ServiceImage sluicegate/sg-service:1.0.0
```

If testing in a lab or development environment without a commercial code-signing certificate, pass `-SkipSignatureCheck` to `Build-DeploymentBundle.ps1` and `Install-SluiceGate.ps1`.

The builder exports the selected service image and generates SHA-256 records. Image tags should be pinned to the SluiceGate release; avoid `latest` for deployed artifacts even though the host Docker Engine is the latest stable supported release.

### Compiling the C# Windows Service

The Windows Service host source code is located at [deployment/windows/MinionHost/](deployment/windows/MinionHost/). It can be compiled using either the .NET 10 SDK or a standard Docker container.

#### Option A: Using Docker (cross-platform, no local .NET SDK needed)
```bash
docker run --rm \
  -v "$PWD/deployment/windows/MinionHost:/src" \
  -v "$PWD/deployment/windows/Minion:/out" \
  -w /src \
  mcr.microsoft.com/dotnet/sdk:10.0 \
  dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -p:DebugType=None -o /out
```
This writes the rebuilt framework-dependent `SluiceGate.Minion.Service.exe` directly to [deployment/windows/Minion/](deployment/windows/Minion/). The .NET 10 x64 Runtime is required on the Windows Server 2022 host.

#### Option B: Using local .NET 10 SDK on Windows
```powershell
cd deployment/windows/MinionHost
dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -p:DebugType=None -o ..\Minion
```

## Configuration and Install

1. Install the .NET 10 x64 Runtime and validate it with `dotnet --list-runtimes`. Also install and validate the latest stable Docker release supported on Windows Server 2022.
2. Create the dedicated AD service identity and grant its share/target permissions outside this package. Configure its service logon through Windows Service Control Manager or an approved deployment tool.
3. Provision the SluiceGate Ed25519 signing key at the configured host path using the organization's key-management process. The installer mounts this file read-only in the service container; the key is not part of the bundle.
3a. Provision the Mission Control TLS certificate and private key as `InstallRoot\tls\server-cert.pem` and `InstallRoot\tls\server-key.pem` (for a self-signed certificate, see `deployment/tls/new-selfsigned-certificate.sh` and the Installation Guide). The installer requires an `https://` Minion URL, mounts this directory read-only, and starts the container with `SG_TLS_CERT_FILE` and `SG_TLS_KEY_FILE`, so HTTP is never served. The certificate's names must include the host in `MissionControlUrl` (for `127.0.0.1`, an IP address entry). Restrict the key file to administrators. Set `TrustedServerCertificatePath` in the Minion configuration to the certificate so the Minion trusts it.
4. Prepare `service.env` from `service.env.example`, supplying the one-time bootstrap secret and production policy path through approved secret management. Place the policy at `InstallRoot\policy\production-policy.yml`; the installer mounts only this policy directory read/write so the authenticated Policies view can safely replace the file. Do not place secrets in this directory. Do not commit or distribute the completed environment file in the bundle. After issuing named Agent/Minion/admin keys, remove the bootstrap secret from the service environment.
5. Provision the Minion's keys under `DataRoot\keys` before installing, so they never travel in a package or on a command line. Create the Minion key pair (see the Installation Guide), copy the SluiceGate public key to `sg-public-key.pem`, and store the API key with `.\Set-MinionApiKey.ps1` (hidden prompt; it creates the protected `keys` directory first). The installer refuses to proceed if any of the three files is missing.
6. Run an elevated PowerShell session from the extracted bundle. `-ServiceAccount` is a gMSA (`CONTOSO\svc-minion$`, no password) or a domain account (prompted for its password, never passed on a command line). `-CatalogPath` and `-NessusMappingPath` are written into the generated configuration. Add `-TrustedServerCertificate <pem>` when the service uses a self-signed or private-CA certificate; the installer copies it, records its SHA-256 fingerprints, and pins the Minion to it. The Minion starts with `DryRun` true; pass `-DisableDryRun` only after dry-run validation.

```powershell
.\Install-SluiceGate.ps1 `
  -PackageRoot (Get-Location).Path `
  -ServiceImage 'registry.example.gov/sluice/sg-service:VERSION' `
  -MissionControlUrl 'https://127.0.0.1:8443' `
  -MinionId 'PATCH-01' `
  -CatalogPath '\\fileserver\patchrepo\patch_catalog.csv' `
  -NessusMappingPath '\\fileserver\patchrepo\nessus_mapping.csv' `
  -ServiceAccount 'CONTOSO\svc-minion$' `
  -TrustedServerCertificate '.\server-cert.pem' `
  -SkipSignatureCheck
```

For a Minion-only installation, drop `-ServiceImage` and add `-SkipServiceContainer`. The installer fails if the service does not stay running for ten seconds after it starts.

The installer registers the `SluiceGateMinion` Event Log source, creates the service, and sets recovery to restart it twice (60 seconds apart) and then leave it stopped. The service host checks the installation at startup: missing runtime files, a missing or invalid configuration, an inline `ApiKey`, an empty or missing key file, or a non-HTTPS Mission Control URL each write a critical entry to the Application log (source `SluiceGateMinion`) and stop the service with a failure exit code. If the PowerShell worker exits five times in a row within a minute of starting, the service also stops as failed instead of restarting forever. Check `Get-Service SluiceGateMinion` and the Application log first when the Minion does not check in.

Existing configuration is kept on upgrade; pass `-ReplaceConfig` to regenerate it. The container steps still need the secrets described above (`service.env`, signing key, TLS files, policy) under `InstallRoot`.

## Upgrade and Uninstall

Upgrade using a versioned bundle and the same approved configuration process. Re-run `Install-SluiceGate.ps1` from the new bundle: it stops the service, replaces the files under `InstallRoot`, keeps `DataRoot` (configuration, keys, nonces, Mission Diary) untouched, and starts the service again. Verify Minion Mission Control check-in afterwards.

To remove the installation:

```powershell
.\Uninstall-SluiceGate.ps1
```

The uninstall script removes the Windows service, Event Log source, container, and `InstallRoot`. It keeps `DataRoot` (configuration, keys, nonce store, Mission Diary) unless `-RemoveData` is given. Export or preserve service logs and required local Mission recovery state before using `-RemoveData`.

## Validation Checklist

- Windows Server 2022 and the installed Docker Engine are supported and healthy.
- The container exposes Minion Mission Control only on loopback for the single-VM deployment.
- The Minion service starts as the configured identity and authenticates to Minion Mission Control.
- The Minion can read the configured Nessus mapping/catalog CSVs and patch files, and can perform remote execution only on its authorized target scope.
- Credentials do not appear in script arguments, process command lines, logs, source control, Mission Envelopes, or package defaults.
- Install, upgrade, restart/resume, and uninstall behavior has been tested on a clean VM snapshot.
