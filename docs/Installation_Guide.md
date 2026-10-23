# SluiceGate Installation Guide

This guide is for an administrator who is new to SluiceGate, WSL, and running Linux containers on Windows. It installs SluiceGate on **one Windows Server 2022 machine**:

- the **Minion** (the patching worker) runs as a normal Windows service, and
- **sg-service** (the SluiceGate service, Admin Console, and Mission Control) runs as a Linux container in Docker Engine inside **WSL 2**, the Windows Subsystem for Linux.

Follow the steps in order and use a test Windows target first. The package itself (what the installer does, parameters, file locations) is described in the [Windows Server Deployment README](../deployment/windows/README.md); this guide does not repeat it.

## 1. Plan the installation

Identify the machine and access you need before changing anything.

1. Choose a Windows Server 2022 machine for SluiceGate and record its host name and IP address. If it is a virtual machine, the hypervisor must expose hardware virtualization to it (nested virtualization), because WSL 2 runs a lightweight virtual machine.
2. If Agents or administrators will connect from other machines, choose a DNS name for the service, such as `sluicegate.example.internal`, that resolves to this server. If everything runs on this server, you can use `127.0.0.1`.
3. Choose the TLS certificate. A **self-signed** certificate is acceptable for the pilot: the installer creates it and makes the Minion trust exactly that certificate. Otherwise obtain a certificate and its private key (PEM files) for the DNS name from your certificate authority (CA).
4. Arrange a dedicated Windows identity for the Minion: a group managed service account (gMSA, name ending in `$`) is preferred, or a domain account. Give it only the file-share and remote-target permissions needed for the approved test scope.
5. Obtain the UNC paths of the approved patch catalog and Nessus mapping CSV files, and confirm the Minion identity can read them.
6. Obtain the approved release bundle. Maintainers build it as described in the deployment README.

## 2. Get and check the release bundle

Copy the bundle to the server, for example to `C:\SluiceGate-bundle`, and check every file against its hash list. Investigate any `MISMATCH` line before continuing.

```powershell
Set-Location 'C:\SluiceGate-bundle'
Get-Content .\SHA256SUMS.txt | ForEach-Object {
  $hash, $path = $_ -split '  ', 2
  if ((Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash -ne $hash) { "MISMATCH: $path" }
}
```

## 3. Prepare the Windows Server

Run these steps in an elevated PowerShell window as the administrator account that will later run the installer. A WSL distribution belongs to the Windows account that installs it, and the installer's startup task runs as that same account.

1. **.NET 10 runtime.** Install the .NET 10 x64 Runtime (not the SDK) through your approved process and check it with `dotnet --list-runtimes`.
2. **OpenSSL for Windows.** Install an approved OpenSSL build and confirm `openssl version` works in a new PowerShell window. The Minion uses it to sign and verify Missions.
3. **WSL 2 and Ubuntu.** Install WSL with Ubuntu, then restart the server when asked:

   ```powershell
   wsl.exe --install -d Ubuntu
   ```

   After the restart, Ubuntu finishes setup and asks you to create a Linux user name and password. Then confirm WSL 2 is in use:

   ```powershell
   wsl.exe --version
   wsl.exe --list --verbose
   ```

   The `VERSION` column for Ubuntu must show `2`.
4. **Enable systemd in Ubuntu.** Docker needs systemd to start automatically. Open Ubuntu (`wsl.exe -d Ubuntu`) and run:

   ```sh
   sudo tee /etc/wsl.conf >/dev/null <<'EOF'
   [boot]
   systemd=true
   EOF
   exit
   ```

   Then, from PowerShell, restart WSL and check systemd is running (`running` or `degraded` is fine):

   ```powershell
   wsl.exe --shutdown
   wsl.exe -d Ubuntu --exec systemctl is-system-running
   ```

5. **Docker Engine inside Ubuntu.** Docker Desktop is not supported on Windows Server, and Docker Engine for Windows runs only Windows containers, so the Linux engine must run inside WSL. Open Ubuntu and install Docker's official packages (these are Docker's documented steps for Ubuntu; check [their page](https://docs.docker.com/engine/install/ubuntu/) for changes):

   ```sh
   sudo apt update
   sudo apt install ca-certificates curl
   sudo install -m 0755 -d /etc/apt/keyrings
   sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
   sudo chmod a+r /etc/apt/keyrings/docker.asc
   sudo tee /etc/apt/sources.list.d/docker.sources <<EOF
   Types: deb
   URIs: https://download.docker.com/linux/ubuntu
   Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
   Components: stable
   Architectures: $(dpkg --print-architecture)
   Signed-By: /etc/apt/keyrings/docker.asc
   EOF
   sudo apt update
   sudo apt install docker-ce docker-ce-cli containerd.io
   sudo docker run --rm hello-world
   ```

   If the server cannot reach the internet, install from your organization's mirror or from Docker's downloadable packages instead. The last command should print a "Hello from Docker!" message.
6. **Check Docker from Windows.** The installer runs Docker as root inside WSL with this form. It must print a version number:

   ```powershell
   wsl.exe -d Ubuntu -u root --exec docker version --format '{{.Server.Version}}'
   ```

7. **Service account.** If you use a gMSA, confirm it is installed on this server and usable (`Test-ADServiceAccount svc-sluicegate-minion`). The installer grants it access to the Minion's own files only.

## 4. Install SluiceGate

In the extracted bundle folder, run the installer in an elevated PowerShell window. The parameters are explained in the [deployment README](../deployment/windows/README.md#installing). This example uses a self-signed certificate and keeps the Minion in dry-run mode:

```powershell
.\Install-SluiceGate.ps1 `
  -PackageRoot (Get-Location).Path `
  -ServiceImage 'sluicegate/sg-service:1.0.0' `
  -MissionControlUrl 'https://127.0.0.1:8443' `
  -PublicUrl 'https://sluicegate.example.internal' `
  -MinionId 'PATCH-01' `
  -CatalogPath '\\fileserver\patchrepo\patch_catalog.csv' `
  -NessusMappingPath '\\fileserver\patchrepo\nessus_mapping.csv' `
  -ServiceAccount 'CONTOSO\svc-sluicegate-minion$' `
  -SelfSignedCertificate
```

- An unsigned Minion executable only produces a warning. Add `-RequireSignature` if your policy demands an Authenticode-signed binary.
- For a CA-issued certificate, replace `-SelfSignedCertificate` with `-TlsCertificate .\fullchain.pem -TlsKey .\private.key`. If Windows does not already trust that CA, also pass its root certificate with `-TrustedServerCertificate`. A certificate must list the host name in `-MissionControlUrl` in its subject alternative names; use the DNS name there instead of `127.0.0.1` in that case.
- For an ordinary domain account (no `$`), the installer asks for its password at a hidden prompt. It also asks for your own password to register the startup task that keeps WSL running after a reboot.

When it finishes, the installer has created the service's settings, signing key, TLS certificate, and an initial policy that blocks everything; started the container; created the Minion's key pair; and installed the Minion service **without starting it**, because the Admin Console has not issued its API key yet. It prints the next steps. Check that the service answers on this server:

```powershell
Test-NetConnection 127.0.0.1 -Port 8443
```

`TcpTestSucceeded` must be `True`. If it is not, read the container log with `wsl.exe -d Ubuntu -u root --exec docker logs --tail 100 sluicegate-service`.

## 5. Sign in and author the policy

The policy is the rule set that decides whether a request is allowed, paused for approval, or blocked. You author it in the Admin Console; there is no separate editor.

1. Show the one-time **bootstrap admin key** that the installer generated. It is the first sign-in password and is displayed only on this screen; do not paste it into a ticket or chat:

   ```powershell
   wsl.exe -d Ubuntu -u root --exec sed -n 's/^SG_BOOTSTRAP_ADMIN_KEY=//p' /opt/sluicegate/service.env
   ```

2. In a browser on the server, open `https://127.0.0.1:8443/admin`. A self-signed certificate makes the browser warn; that is expected for the pilot, and you can continue after confirming the address. Paste the key into **Admin Bearer Token** and click **Save**.
3. Open the **Policies** tab. It shows the starter policy, which blocks every request. Replace its contents with a narrowly scoped policy for your test target, click **Validate**, then **Save and Activate**. This example pauses a request for one test server for approval and allows it after approval; use your own server name. Rule syntax and the required obligations are in [Policy DSL](Policy_DSL.md):

   ```yaml
   version: 1
   default: {decision: BLOCK}
   rules:
     - name: allow-test-target-after-approval
       when:
         - {path: action.name, eq: windows.patch.reconcile}
         - {path: target.servers, eq: [patch-test-01.example.internal]}
         - {path: context.approval.approved, eq: true}
       obligations:
         - type: allowed_patch_targets
           servers: [patch-test-01.example.internal]
         - type: patch_constraints
           patch_sources: [wsus, nessus_catalog]
           allowed_patch_types: [SECURITY]
           allow_reboot: false
           maintenance_window: null
         - type: allowed_patch_executables
           executables: [msiexec.exe]
       decision: ALLOW
     - name: pause-test-target-before-approval
       when:
         - {path: action.name, eq: windows.patch.reconcile}
         - {path: target.servers, eq: [patch-test-01.example.internal]}
         - {path: context.approval.approved, exists: false}
       obligations:
         - type: allowed_patch_targets
           servers: [patch-test-01.example.internal]
         - type: patch_constraints
           patch_sources: [wsus, nessus_catalog]
           allowed_patch_types: [SECURITY]
           allow_reboot: false
           maintenance_window: null
         - type: allowed_patch_executables
           executables: [msiexec.exe]
       decision: PAUSE
   ```

   The policy, not the Agent, decides which servers, patch types, and reboot behavior apply to a Mission.

## 6. Register the Agent and the Minion

The Admin Console issues each API key once, so copy each directly into its protected destination.

1. In **Agent Registry**, register an Agent for the operator or test client that will submit patch requests. Save its API key in the organization's approved password manager or secrets vault. Do not put it in source code, a normal text file, shell history, or a command-line argument.
2. In **Minion Registry**, register a Minion whose ID matches `-MinionId` (`PATCH-01` above), with runtime type `powershell`, environment `prod`, and the capability `windows.patch.reconcile`. Paste the Minion's public key, which you can display with:

   ```powershell
   Get-Content 'C:\ProgramData\SluiceGate\Minion\keys\minion-public-key.pem'
   ```

3. The Minion's API key is shown once after registration. Store it in the secrets vault, then put it into its protected file on the server. The script reads it at a hidden prompt, so it is never on a command line:

   ```powershell
   Set-Location 'C:\SluiceGate-bundle'
   .\Set-MinionApiKey.ps1
   ```

4. Start the Minion service:

   ```powershell
   Start-Service SluiceGateMinion
   ```

5. Confirm the Agent and the Minion show as enabled in their tabs.

## 7. Run a safe connectivity check

This checks that the service is healthy and talking to Mission Control with `DryRun` still `true`. It is a lab validation, not proof that recovery or production patching works.

1. If the service is stopped or restarting, the Application event log names the startup check that failed, such as a missing key file or a non-HTTPS address:

   ```powershell
   Get-Service SluiceGateMinion
   Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'SluiceGateMinion' } -MaxEvents 20 | Format-List TimeCreated, Message
   ```

2. In the Admin Console, confirm the Minion's last-contact time updates.
3. Review `C:\ProgramData\SluiceGate\Minion\config\minion.config.json` and confirm `DryRun` is `true`. Also confirm the catalog has only approved test rows with the required headers (`patch_status`, `plugin_id`, `patch_type`, `patch_path`, `patch_sha256`, `install_command`), the Nessus mapping has `PLUGIN_ID` and `DNS_NAME` columns, and the Minion identity can read both files and the patch packages they name. The [Windows Patching Minion](../minion-registry/minions/patching/README.md) README has the full schema.
4. If check-in fails, check the Minion ID, the API key, and that `https://127.0.0.1:8443/health` answers. Never paste API keys or private keys into logs, tickets, or chat.

## 8. Create a test request and review the result

Submit a request for the test server using only the Agent identity, and observe how the policy controls it. The Agent names the target; it does not choose patch types or reboot permissions. Keep dry-run enabled.

1. Enter the Agent key without echoing it or adding it to command history, and send the request with `curl.exe` (included with Windows Server 2022), which reads its settings from standard input. The `cacert` line makes curl trust the self-signed certificate; omit it for a CA certificate Windows trusts:

   ```powershell
   $agentKey = [System.Net.NetworkCredential]::new('', (Read-Host 'Agent API key' -AsSecureString)).Password
   @"
   url = "https://127.0.0.1:8443/api/v1/patch-requests"
   request = "POST"
   cacert = "C:\\ProgramData\\SluiceGate\\Minion\\keys\\sg-server-cert.pem"
   header = "Authorization: Bearer $agentKey"
   header = "Content-Type: application/json"
   data = "{\"servers\":[\"patch-test-01.example.internal\"]}"
   "@ | curl.exe --fail-with-body --config -
   Remove-Variable agentKey
   ```

   In a real Agent runtime, use its approved secrets integration instead of an interactive prompt.
2. Open **Missions & Audit** and inspect the request. Confirm the policy decision, target, Minion assignment, and status match expectations.
3. A `BLOCK` means the policy did not allow the request. A `PAUSE` waits for an authorized administrator to review it under **Pending Approvals** and approve it explicitly. Never approve a request just to make a test pass.
4. For a `QUEUED` request, watch the Minion pick it up and inspect the result. Do not change `DryRun` to `false` as part of installation validation.

## 9. Finish bootstrap

This removes the temporary setup password and records how to maintain the deployment.

1. Create a named administrator key. Set the bootstrap key in a variable from the protected source, then run:

   ```powershell
   $bootstrap = [System.Net.NetworkCredential]::new('', (Read-Host 'Bootstrap admin key' -AsSecureString)).Password
   @"
   url = "https://127.0.0.1:8443/admin/v1/credentials/admin/operator-alice"
   request = "POST"
   cacert = "C:\\ProgramData\\SluiceGate\\Minion\\keys\\sg-server-cert.pem"
   header = "Authorization: Bearer $bootstrap"
   "@ | curl.exe --fail --silent --show-error --config -
   Remove-Variable bootstrap
   ```

   Replace `operator-alice` with the operator's identifier. The response contains `key_id` and `api_key`, and the key is returned only once. Copy it directly into the secrets vault. Sign in to the Admin Console with it and confirm everything works before continuing. The console stores the token in that browser's local storage, so use a trusted administrator browser profile.
2. Revoke the bootstrap key while authenticated with the new administrator key:

   ```powershell
   $admin = [System.Net.NetworkCredential]::new('', (Read-Host 'Named admin API key' -AsSecureString)).Password
   @"
   url = "https://127.0.0.1:8443/admin/v1/credentials/KEY-BOOTSTRAP-ADMIN/revoke"
   request = "POST"
   cacert = "C:\\ProgramData\\SluiceGate\\Minion\\keys\\sg-server-cert.pem"
   header = "Authorization: Bearer $admin"
   "@ | curl.exe --fail --silent --show-error --config -
   Remove-Variable admin
   ```

3. Remove the bootstrap line from the settings file, then re-run the installer with the same parameters so the container is recreated with the updated file (a running container does not re-read it). The installer keeps the edited file:

   ```powershell
   wsl.exe -d Ubuntu -u root --exec sed -i '/^SG_BOOTSTRAP_ADMIN_KEY=/d' /opt/sluicegate/service.env
   ```

   Confirm the named administrator still works and the bootstrap key no longer signs in. Do not delete the only working administrator credential before testing its replacement.
4. Back up `C:\ProgramData\SluiceGate\Minion` and the WSL distribution (stop the container first, then `wsl.exe --export Ubuntu <path>.tar`) using your organization's backup process. The export contains the signing key and the database, so protect it as sensitive data, and test a restore before relying on it.
5. Record the service DNS name, the server's owner, the Minion ID and owner, the policy approval process, the backup location, the certificate renewal owner (a self-signed certificate lasts 365 days; see the deployment README for renewal), and the incident contact in the team's secure operations documentation. Do not record secret values there.

## 10. Optional: let other machines reach the service

By default the service answers only on this server (`127.0.0.1:8443`). If Agents or administrators connect from other machines, forward a network port to it and open the firewall. This uses port 443; the installer's `-PublicUrl` above matches it. Check from another machine afterwards. This step has not yet been verified on Windows Server 2022.

```powershell
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=443 connectaddress=127.0.0.1 connectport=8443
New-NetFirewallRule -DisplayName 'SluiceGate service' -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow
```

Ask the network administrator to allow only the machines that need access. With a self-signed certificate, remote clients must also be given the certificate to trust (`C:\ProgramData\SluiceGate\Minion\keys\sg-server-cert.pem`); a CA-issued certificate avoids that.

## Further reading

- [Windows Server Deployment](../deployment/windows/README.md): the package, installer parameters, file locations, upgrade and uninstall.
- [SluiceGate Service Operator Guide](../sg-service/README.md)
- [Windows Patching Minion](../minion-registry/minions/patching/README.md)
- [Policy DSL](Policy_DSL.md)
- [SluiceGate Feature Backlog](../planning/Feature_Backlog.md)
