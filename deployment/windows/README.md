# Windows Server Deployment Package

This directory builds and contains the installer for SluiceGate on a single Windows Server 2022 machine. It documents the package itself: what is in it, what the installer does, and where things end up. The step-by-step procedure, including preparing the server, is the [Installation Guide](../../docs/Installation_Guide.md); follow that to install.

## What gets installed

| Component | Runs as | Files live in |
| --- | --- | --- |
| **Minion** (patching worker) | A native Windows service, `SluiceGateMinion`, under a dedicated service account | `C:\Program Files\SluiceGate\Minion` (program) and `C:\ProgramData\SluiceGate\Minion` (configuration, keys, state) |
| **sg-service** (SluiceGate service, Admin Console, Mission Control) | A Linux container in Docker Engine running inside a WSL 2 Ubuntu distribution | `/opt/sluicegate` inside WSL, plus the Docker volume `sluicegate-service-data` (the database) |
| **WSL keep-alive** | A scheduled task, `SluiceGateWsl`, started at boot | Windows Task Scheduler |

The service listens on `127.0.0.1:8443` and is reached from Windows through WSL's localhost forwarding. Docker Desktop is not used: Docker does not support it on Windows Server, and Docker Engine for Windows runs only Windows containers, so the Linux container engine lives inside WSL.

## Prerequisites

The Installation Guide, section 3, gives the commands for each item.

- Windows Server 2022 with the .NET 10 x64 Runtime (the Minion service host needs it).
- WSL 2 with an Ubuntu distribution that has systemd enabled and Docker Engine installed and running. WSL 2 needs hardware virtualization, which a virtual machine must expose to the guest (nested virtualization).
- OpenSSL for Windows (`openssl.exe` on `PATH`). The Minion runtime uses it to sign and verify, and the installer uses it to create the Minion's key pair.
- A dedicated service account for the Minion: a gMSA (`DOMAIN\name$`) or a domain account. It needs read access to the patch catalog and mapping share and the remote-execution rights on its authorized targets. The installer does not grant those.

## Terms and files

The installer creates and manages these. Nothing here needs hand-editing before the first install.

| Name | What it is | Created by | Where |
| --- | --- | --- | --- |
| **`service.env`** | The container's settings file: a list of `NAME=value` environment variables. It is not the policy. | Installer, from `service.env.example` | `/opt/sluicegate/service.env` in WSL, readable only by root |
| **Bootstrap admin key** | The `SG_BOOTSTRAP_ADMIN_KEY` line in `service.env`: a random one-time password for the first Admin Console sign-in. Installation Guide section 9 replaces it with named administrator keys and revokes it. | Installer (random, never shown or logged) | Inside `service.env` |
| **Policy** (`production-policy.yml`) | The YAML rules that decide whether a request is allowed, paused for approval, or blocked. It starts as `policy.starter.yml`, which blocks everything. You then author rules in the Admin Console's **Policies** tab, which validates and saves them. | Installer, only if none exists (or from `-PolicyFile`) | `/opt/sluicegate/policy/production-policy.yml` in WSL |
| **Signing key** | The private Ed25519 key `sg-service` uses to sign Missions. It never leaves WSL. | Installer, only if none exists | `/opt/sluicegate/secrets/sg-signing-key.pem` in WSL |
| **SluiceGate public key** | The matching public half; the Minion uses it to verify Missions. | Installer exports it from WSL | `DataRoot\keys\sg-public-key.pem` |
| **TLS certificate and key** | Make the service HTTPS. Self-signed (generated) or one you supply. | Installer | `/opt/sluicegate/tls` in WSL |
| **Minion key pair** | The Minion's own Ed25519 keys. You register the public key in the Admin Console. | Installer, only if none exists | `DataRoot\keys\minion-private-key.pem`, `minion-public-key.pem` |
| **Minion API key** | The password the Minion presents to Mission Control. Issued by the Admin Console when you register the Minion, then stored with `Set-MinionApiKey.ps1`. | You | `DataRoot\keys\minion-api-key.txt` |
| **`minion.config.json`** | The Minion's settings. It contains no secrets, only paths and URLs. | Installer, from `minion.config.template.json` | `DataRoot\config\` |

Existing `service.env`, policy, signing key, certificate, and Minion configuration are never overwritten on upgrade, so edits made in the Admin Console and issued keys survive.

## Package contents

```text
Install-SluiceGate.ps1
Uninstall-SluiceGate.ps1
Set-MinionApiKey.ps1              # stores the Minion API key from hidden input
MinionInstallHelpers.ps1          # helpers used by the scripts above
WslServiceContainer.ps1           # runs the container inside WSL
minion.config.template.json       # non-secret Minion defaults; DryRun is true
service.env.example               # template for the container settings
policy.starter.yml                # initial policy: blocks everything
new-selfsigned-certificate.sh     # makes a self-signed TLS certificate
Minion/SluiceGate.Minion.Service.exe
Minion/runtime/                   # PatchingMinion.ps1, modules, protocol/, version.json
images/sg-service-image.tar       # the sg-service container image
SHA256SUMS.txt                    # SHA-256 of every file in the bundle
```

## Building the package

Done by a maintainer on any machine with Docker; the output is one folder to copy to the server.

1. **Service host.** The C# source is in [MinionHost/](MinionHost/) with its tests in [MinionHost.Tests/](MinionHost.Tests/); the compiled, framework-dependent Windows x64 build is checked in at [Minion/SluiceGate.Minion.Service.exe](Minion/SluiceGate.Minion.Service.exe). Only `bin/` and `obj/` build output is ignored by git. Rebuild after changing the source. Signing with an Authenticode certificate is optional: an unsigned executable only produces a warning, and `-RequireSignature` (on the bundle builder and the installer) turns that into an error. Signing lets Windows and tools such as AppLocker or WDAC verify the binary; the installer does not otherwise depend on it:

   ```bash
   docker run --rm -v "$PWD/deployment/windows/MinionHost:/src" -v "$PWD/deployment/windows/Minion:/out" -w /src \
     mcr.microsoft.com/dotnet/sdk:10.0 \
     dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -p:DebugType=None -o /out
   ```

   With a local .NET 10 SDK on Windows: `dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -p:DebugType=None -o ..\Minion` from `MinionHost`.
2. **Service image.** From the repository root: `docker build -f sg-service/Dockerfile -t sluicegate/sg-service:1.0.0 .` Use a release tag, not `latest`.
3. **Bundle.** From `deployment/windows` on Windows PowerShell. `-Version` is recorded in `Minion/runtime/version.json`; the output directory must be empty:

   ```powershell
   .\Build-DeploymentBundle.ps1 -MinionExecutable .\Minion\SluiceGate.Minion.Service.exe `
     -ServiceImage sluicegate/sg-service:1.0.0 -Version 1.0.0
   ```

   An unsigned Minion executable produces a warning. Pass `-RequireSignature` to refuse unsigned builds; the installer accepts the same switch.

## Installing

Run from an elevated PowerShell window in the extracted bundle. Parameters:

| Parameter | Required | Meaning |
| --- | --- | --- |
| `-PackageRoot` | Yes | The bundle folder, usually `(Get-Location).Path`. |
| `-ServiceImage` | Yes | The image tag inside the bundle, for example `sluicegate/sg-service:1.0.0`. |
| `-MissionControlUrl` | Yes | Where the Minion on this server connects. Use `https://127.0.0.1:8443` with `-SelfSignedCertificate`. |
| `-PublicUrl` | No | The address Agents and administrators on other machines use. Defaults to `-MissionControlUrl`. It is added to the certificate's names and used in email links. |
| `-MinionId` | Yes | The Minion's name, for example `PATCH-01`. Register the same ID in the Admin Console. |
| `-CatalogPath`, `-NessusMappingPath` | Yes | UNC paths to the patch catalog and Nessus mapping CSV files. |
| `-ServiceAccount` | Yes | `DOMAIN\name$` for a gMSA (no password), or a domain account (the installer prompts for its password). |
| `-SelfSignedCertificate` | One of these | Generate a self-signed certificate. The installer also makes the Minion trust exactly that certificate. |
| `-TlsCertificate`, `-TlsKey` | One of these | A certificate and private key you already have (PEM). |
| `-TrustedServerCertificate` | No | A private CA's root certificate, when Windows does not already trust it. |
| `-ReplaceCertificate` | No | Replace an existing certificate (renewal). |
| `-PolicyFile` | No | Install this policy on first install instead of the blocking starter. |
| `-WslDistribution` | No | The WSL distribution name. Default `Ubuntu`. |
| `-ReplaceConfig` | No | Regenerate `minion.config.json` instead of keeping the existing one. |
| `-DisableDryRun` | No | Start the Minion able to patch. By default `DryRun` is true and nothing is installed. |
| `-SkipStartupTask` | No | Do not register the WSL boot task (the installer otherwise asks for your password to register it). |

```powershell
.\Install-SluiceGate.ps1 `
  -PackageRoot (Get-Location).Path `
  -ServiceImage 'sluicegate/sg-service:1.0.0' `
  -MissionControlUrl 'https://127.0.0.1:8443' `
  -PublicUrl 'https://sluicegate.example.internal' `
  -MinionId 'PATCH-01' `
  -CatalogPath '\\fileserver\patchrepo\patch_catalog.csv' `
  -NessusMappingPath '\\fileserver\patchrepo\nessus_mapping.csv' `
  -ServiceAccount 'CONTOSO\svc-minion$' `
  -SelfSignedCertificate
```

In order, the installer:

1. Checks the bundle, the signature (unless skipped), that Docker answers inside WSL, and that `openssl.exe` is available.
2. Stops an existing Minion service, then copies the Minion program to `InstallRoot`.
3. Inside WSL, creates `/opt/sluicegate` (root-only) and, for anything missing, generates `service.env` with a random bootstrap key, the signing key, the TLS certificate (or copies yours), and the initial policy.
4. Loads the image, recreates the container, and waits until the service answers.
5. Exports the SluiceGate public key (and, for self-signed, the certificate) to the Minion's `keys` folder, and creates the Minion key pair if absent.
6. Writes `minion.config.json`, then restricts `DataRoot`: Administrators and SYSTEM full control, the service account read on `config` and `keys` and write on `data` and `MissionDiary`.
7. Registers the Event Log source and the `SluiceGateMinion` service (recovery: restart twice, then stay stopped), and the WSL boot task.
8. Starts the Minion if its API key file exists. On a first install it does not yet, because the Admin Console issues that key. The installer leaves the service stopped and prints the next steps.

## Service health

- `Get-Service SluiceGateMinion` and the Application event log (source `SluiceGateMinion`). At startup the host checks the runtime files, the configuration, the key files, and that the URL is HTTPS; a failed check is logged as critical and the service stops with a failure exit code. Five worker crashes in a row within a minute of starting also stop it as failed.
- The container: `wsl.exe -d Ubuntu -u root --exec docker logs --tail 100 sluicegate-service`.

## Upgrade, renewal, uninstall

- **Upgrade:** run the new bundle's installer with the same parameters. It replaces the program and the container and keeps all existing secrets, policy, certificate, configuration, and data.
- **Renew a self-signed certificate** (it lasts 365 days): `-SelfSignedCertificate -ReplaceCertificate -ReplaceConfig`. The Minion is restarted in the same run with trust in the new certificate.
- **Uninstall:** `.\Uninstall-SluiceGate.ps1` removes the service, boot task, container, and program. It keeps `DataRoot`, `/opt/sluicegate`, and the database volume. `-RemoveData` deletes those too; export what you need first.

## Validation checklist

- The Minion service starts under the service account and its last-contact time updates in the Admin Console.
- Credentials appear in no script argument, process command line, log, Mission Envelope, or package file.
- `DataRoot` is readable only by Administrators, SYSTEM, and the service account.
- Install, upgrade, reboot, and uninstall have been run on a clean Windows Server 2022 snapshot. This has not yet been done: the scripts were verified with automated tests and a simulated WSL, not on Windows Server.
