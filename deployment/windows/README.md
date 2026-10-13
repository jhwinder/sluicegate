# Windows Server Deployment

## Target

- Windows Server 2022 VM.
- Latest stable Docker version supported on Windows Server 2022.
- SG Minion Windows service running under a dedicated, least-privilege AD identity.
- `sg_service` container hosted on the same VM with Minion Mission Control bound to host loopback (`127.0.0.1:8443`).

The `sg_service` container does not need an AD identity. The Minion service identity needs only the approved patch-catalog/mapping/repository access and remote execution/reboot rights for its authorized target scope. Configure service logon identity and ACLs using the organization's approved Windows administration process; the installer does not grant target access.

## Package Contents

The release bundle is expected to contain:

```text
Install-SluiceGate.ps1
Uninstall-SluiceGate.ps1
Minion/SluiceGate.Minion.Service.exe
Minion/SluiceGate.Minion.Service.exe.config
images/sg-service-image.tar       # optional offline image bundle
service.env.example              # template only; no secrets
```

The repository includes the compiled, self-contained Windows x64 executable at [deployment/windows/Minion/SluiceGate.Minion.Service.exe](deployment/windows/Minion/SluiceGate.Minion.Service.exe), alongside its C# source in [deployment/windows/MinionHost/](deployment/windows/MinionHost/). This lets operators install it without a local .NET toolchain; developers can rebuild it using the instructions below.

Build the bundle using the repository executable:

```powershell
./Build-DeploymentBundle.ps1 `
  -MinionExecutable .\Minion\SluiceGate.Minion.Service.exe `
  -ServiceImage sluicegate/sg-service:VERSION
```

If testing in a lab or development environment without a commercial code-signing certificate, pass `-SkipSignatureCheck` to `Build-DeploymentBundle.ps1` and `Install-SluiceGate.ps1`.

The builder exports the selected service image and generates SHA-256 records. Image tags should be pinned to the SluiceGate release; avoid `latest` for deployed artifacts even though the host Docker Engine is the latest stable supported release.

### Compiling the C# Windows Service

The Windows Service host source code is located at [deployment/windows/MinionHost/](deployment/windows/MinionHost/). It can be compiled using either the .NET 8 SDK or a standard Docker container.

#### Option A: Using Docker (cross-platform, no local .NET SDK needed)
```bash
docker run --rm \
  -v "$PWD/deployment/windows/MinionHost:/src" \
  -v "$PWD/deployment/windows/Minion:/out" \
  -w /src \
  mcr.microsoft.com/dotnet/sdk:8.0 \
  dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o /out
```
This writes the rebuilt self-contained `SluiceGate.Minion.Service.exe` directly to [deployment/windows/Minion/](deployment/windows/Minion/).

#### Option B: Using local .NET 8 SDK on Windows
```powershell
cd deployment/windows/MinionHost
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o ..\Minion
```

## Configuration and Install

1. Install and validate the latest stable Docker release supported on Windows Server 2022.
2. Create the dedicated AD service identity and grant its share/target permissions outside this package. Configure its service logon through Windows Service Control Manager or an approved deployment tool.
3. Provision the SluiceGate Ed25519 signing key at the configured host path using the organization's key-management process. The installer mounts this file read-only in the service container; the key is not part of the bundle.
4. Prepare `service.env` from `service.env.example`, supplying the one-time bootstrap secret and production policy path through approved secret management. Do not commit or distribute the completed environment file in the bundle. After issuing named Agent/Minion/admin keys, remove the bootstrap secret from the service environment.
5. Prepare the Minion service configuration through the organization's protected secret-management process. The Minion API key shall not be passed as an installer argument or placed in an unprotected JSON/config file. Grant the Minion service identity read access only to its protected configuration and signing key.
6. Run an elevated PowerShell session from the extracted bundle:

```powershell
.\Install-SluiceGate.ps1 `
  -PackageRoot (Get-Location).Path `
  -ServiceImage 'registry.example.gov/sluice/sg-service:VERSION' `
  -MinionMissionControlUrl 'https://127.0.0.1:8443' `
  -MinionId 'PATCH-01' `
  -SkipSignatureCheck
```

After installation, configure the Windows service to run as the approved AD identity and confirm it can read its protected Minion configuration. Restrict ACLs so only administrators and that identity can access the configuration and private key.

The current script skeleton assumes a service executable and a `service.env` deployment file in the package. The release build must provide these assets, sign the Windows executable/scripts, validate their hashes, and test the exact Docker command/options on the target Server 2022 environment before production use.

## Upgrade and Uninstall

Upgrade using a versioned bundle and the same approved configuration process. Stop the Minion service, replace only versioned binaries, update the pinned service image, then restart and verify Minion Mission Control check-in. Do not overwrite local secrets with package defaults.

To remove the installation:

```powershell
.\Uninstall-SluiceGate.ps1
```

The uninstall script removes the Windows service, container, and installation directory. Export or preserve service logs and required local Mission recovery state before uninstalling.

## Validation Checklist

- Windows Server 2022 and the installed Docker Engine are supported and healthy.
- The container exposes Minion Mission Control only on loopback for the single-VM deployment.
- The Minion service starts as the configured identity and authenticates to Minion Mission Control.
- The Minion can read the configured Nessus mapping/catalog CSVs and patch files, and can perform remote execution only on its authorized target scope.
- Credentials do not appear in script arguments, process command lines, logs, source control, Mission Envelopes, or package defaults.
- Install, upgrade, restart/resume, and uninstall behavior has been tested on a clean VM snapshot.
