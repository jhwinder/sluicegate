# SluiceGate Installation Guide

This guide is for an administrator who is new to Linux, Windows administration, and SluiceGate. It describes a two-machine setup: `sg-service` runs on a RHEL 10 server, and the Windows patching Minion connects to it over HTTPS. Follow the steps in order and use a test Windows target first.

## 1. Plan the installation

In this section, identify the machines and access you need before changing anything. SluiceGate has a Linux control-plane service and a Windows worker; keeping those roles clear makes it easier to configure network access and protect credentials.

1. Choose a supported Linux server for `sg-service` and a Windows Server machine for the patching Minion. Record their host names and IP addresses.
2. Choose a DNS name for the service, such as `sluicegate.example.internal`. The Windows machine must be able to resolve and reach this name.
3. Register a DNS name for the service and request a TLS server certificate for that exact name from your organization's certificate authority (CA). The certificate and its private key will be installed on the RHEL server's Nginx reverse proxy, not on the Minion. The proxy will accept HTTPS and pass requests over loopback to `sg-service`.
4. Ask the network administrator to allow HTTPS from the Windows Minion to the TLS endpoint. Keep the service's container port private to the Linux host.
5. Arrange a dedicated Windows identity (i.e., AD service account) for the Minion. Give it only the file-share and remote-target permissions needed for the approved test scope.
6. Obtain the UNC path to the approved patch catalog and Nessus mapping CSV files, and confirm that the Windows identity can read files at this location.
7. Obtain access to the SluiceGate GitHub repository and the approved Windows Minion files. The clone steps below use the configured upstream repository URL.

## 2. Clone the SluiceGate repository

In this section, download the SluiceGate source onto the RHEL server. Building from a recorded Git commit makes it possible to identify exactly which source produced the service image.

1. Sign in to the RHEL10 server as your named administrator. Install Git with RHEL's package manager, `dnf`:

   ```sh
  sudo dnf install -y git
   ```

2. Clone the repository from GitHub and enter the new directory:

  ```sh
  git clone https://github.com/jhwinder/sluicegate.git
  cd sluicegate
  git status --short
  git rev-parse HEAD
  ```

   `git status --short` should be empty after a fresh clone. Check out the release tag or commit approved by your team, replacing the placeholder with that exact value, then record the commit ID:

   ```sh
   git checkout --detach <approved-release-tag-or-commit>
   git rev-parse HEAD
   ```

## 3. Prepare the RHEL10 server

This section installs RHEL's native container runtime and the tools needed for key creation and TLS. Podman is daemonless and is the supported native choice here; Quadlet lets systemd start the service container after a reboot.

1. From the repository root, install Podman, Nginx, OpenSSL, curl, and SELinux tools:

  ```sh
  sudo dnf install -y podman nginx openssl curl policycoreutils-python-utils
  podman --version
  ```

  If your organization centrally manages RHEL packages, request these packages through that process.

2. Create protected directories for deployment files, TLS, and the service policy:

   ```sh
  sudo install -d -m 0700 /opt/sluicegate/secrets /opt/sluicegate/policies
  sudo install -d -m 0700 /etc/containers/systemd
   ```

3. Create the Ed25519 signing key used by  sg-service to sign Missions, then create its public half for the Windows Minion to verify those Missions:

   ```sh
   sudo openssl genpkey -algorithm ED25519 \
     -out /opt/sluicegate/secrets/sg-signing-key.pem
   sudo openssl pkey \
     -in /opt/sluicegate/secrets/sg-signing-key.pem -pubout \
     -out /opt/sluicegate/secrets/sg-public-key.pem
   sudo chmod 0600 /opt/sluicegate/secrets/sg-signing-key.pem
   sudo chmod 0644 /opt/sluicegate/secrets/sg-public-key.pem
   ```

   The private key must remain on the RHEL10 server. Only transfer `sg-public-key.pem` to the Windows Minion, using an approved secure method.

## 4. Author the SG policy in the Policy Editor

In this section, use SluiceGate's existing Policy Editor rather than writing YAML by hand. The editor validates the policy and saves it in the clone. It is a separate, single-user app with no authentication, so this guide binds it only to loopback and accesses it through an SSH tunnel.

1. From the repository root, create a working policy from the checked-in example without overwriting an existing file:

   ```sh
   test -f open-core/policies/policy.yml || cp open-core/policies/example-policy.yml open-core/policies/policy.yml
   ```

2. Build and start the Policy Editor container, publishing it only on the RHEL server's loopback interface:

   ```sh
   sudo podman build \
     -f open-core/src/sg_poledit/editor/Dockerfile \
     -t localhost/sluicegate-policy-editor:local .
   sudo podman run -d \
     --name sg-poledit \
     -p 127.0.0.1:8080:8080 \
     -e POLICIES_DIR=/policies \
     -v "$PWD/open-core/policies:/policies:Z" \
     localhost/sluicegate-policy-editor:local
   ```

3. From your administrator workstation, open an SSH tunnel to the RHEL server and leave that terminal open:

   ```sh
   ssh -L 8080:127.0.0.1:8080 your-linux-account@your-rhel-server
   ```

4. In a browser on your workstation, open `http://localhost:8080`. Use the editor to set the default decision to `BLOCK` and add a narrowly scoped rule for the test target. The editor's form and YAML preview let you create and validate the policy; click **Save** to write `open-core/policies/policy.yml`. Follow [Policy DSL](Policy_DSL.md) for rule syntax and semantics.

   The Policy Editor is not part of the Admin Console and has no login. Do not publish its port to the network. When finished editing, stop it with `sudo podman rm -f sg-poledit` and close the SSH tunnel.

5. Copy the validated policy to the path mounted into `sg-service`, and restrict write access:

   ```sh
   sudo install -m 0640 open-core/policies/policy.yml /opt/sluicegate/policies/policy.yml
   ```

   After the service is running, use **Reload Policy** in its Admin Console after each approved policy update. The current patch API/runtime still needs the policy-owned constraint work tracked in the backlog; see Section 11 before treating Agent-supplied patch options as controlled by policy.

## 5. Start `sg-service` on RHEL10 and configure HTTPS

In this section, build the service from the checked-out source, keep its HTTP port on loopback, and configure Nginx to terminate HTTPS. A reverse proxy is a web server that accepts the Minion's HTTPS connection, decrypts it using the TLS certificate on RHEL, forwards the HTTP request to the service over the same machine's loopback interface, and returns the response over HTTPS.

1. From the repository root, build the image from the exact commit you recorded in Section 2:

   ```sh
   sudo podman build -f sg-service/Dockerfile \
     -t localhost/sluicegate/sg-service:sgpilot .
   ```

   (An image tag such as `:sgpilot` is only a human-readable name and can be reused. For a release, use an image produced from an approved Git tag/commit and record the image digest (the `sha256:...` content identifier); a tag alone is not an immutable pin. This guide builds locally from the recorded source commit, so no separately supplied release image is needed.

2. Create a temporary bootstrap administrator key and protected environment file. This command writes the key to the file without printing it or putting it in command history:

   ```sh
   sudo sh -c 'umask 077; printf "SG_BOOTSTRAP_ADMIN_KEY=%s\nSG_DATABASE_PATH=/data/sg-service.sqlite3\nSG_SIGNING_KEY_PATH=/run/secrets/sg-signing-key.pem\nSG_POLICY_PATH=/config/policy.yml\n" "$(openssl rand -hex 32)" > /opt/sluicegate/service.env'
   sudo chmod 0600 /opt/sluicegate/service.env
   ```

    Keep the bootstrap key in the protected `service.env` file until you create and test a replacement administrator key in Section 11. To use it, retrieve it from the RHEL server with `sudo sed -n 's/^SG_BOOTSTRAP_ADMIN_KEY=//p' /opt/sluicegate/service.env` and paste it directly into the Admin Console's token field. Do not put it in a ticket, chat, or shell command.

  3. Create persistent storage and the systemd Quadlet definition. Quadlet runs the container as a system service and restarts it after a machine reboot:

   ```sh
    sudo podman volume create sg-service-data
    sudo tee /etc/containers/systemd/sg-service.container >/dev/null <<'EOF'
    [Unit]
    Description=SluiceGate service
    Wants=network-online.target
    After=network-online.target

    [Container]
    Image=localhost/sluicegate/sg-service:pilot
    ContainerName=sg-service
    PublishPort=127.0.0.1:8443:8443
    Volume=sg-service-data:/data
    Volume=/opt/sluicegate/secrets/sg-signing-key.pem:/run/secrets/sg-signing-key.pem:ro,Z
   Volume=/opt/sluicegate/policies:/config:rw,Z
    EnvironmentFile=/opt/sluicegate/service.env

    [Service]
    Restart=on-failure

    [Install]
    WantedBy=multi-user.target
    EOF
    sudo systemctl daemon-reload
    sudo systemctl enable --now sg-service.service
   ```

  4. Check that systemd started the container and the local health endpoint responds:

   ```sh
    sudo systemctl status sg-service.service --no-pager
    sudo podman ps --filter name=sg-service
   curl -fsS http://127.0.0.1:8443/health
   ```

    The health response should be `{"status":"ok"}`. If the request fails, inspect `sudo podman logs sg-service` and `sudo journalctl -u sg-service.service` for startup errors.

  5. Create a certificate signing request (CSR) on the RHEL10 server for the DNS name registered in Section 1. The private key remains on this server; send only the CSR to your organization's CA:

    ```sh
    sudo tee /tmp/sluicegate-csr.cnf >/dev/null <<'EOF'
    [req]
    prompt = no
    distinguished_name = subject
    req_extensions = extensions
    [subject]
    CN = sluicegate.example.internal
    [extensions]
    subjectAltName = @names
    [names]
    DNS.1 = sluicegate.example.internal
    EOF
    sudo openssl req -new -newkey rsa:3072 -nodes \
      -keyout /etc/pki/tls/private/sluicegate.key \
      -out /tmp/sluicegate.csr \
      -config /tmp/sluicegate-csr.cnf
    sudo chmod 0600 /etc/pki/tls/private/sluicegate.key
    ```

    Replace both example names before running the command. Give `/tmp/sluicegate.csr` to the CA using its approved request process. Never send `/etc/pki/tls/private/sluicegate.key` to the CA, Windows, or an Agent. Ask the CA for the issued server certificate and intermediate chain (often called a full-chain PEM file).

  6. Install the certificate returned by the CA at `/etc/pki/tls/certs/sluicegate-fullchain.pem`. Create the Nginx reverse-proxy configuration:

    ```sh
    sudo chmod 0644 /etc/pki/tls/certs/sluicegate-fullchain.pem
    sudo tee /etc/nginx/conf.d/sluicegate.conf >/dev/null <<'EOF'
    server {
       listen 443 ssl;
       server_name sluicegate.example.internal;

       ssl_certificate     /etc/pki/tls/certs/sluicegate-fullchain.pem;
       ssl_certificate_key /etc/pki/tls/private/sluicegate.key;

       location / {
          proxy_pass http://127.0.0.1:8443;
          proxy_http_version 1.1;
          proxy_set_header Host $host;
          proxy_set_header X-Real-IP $remote_addr;
          proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
          proxy_set_header X-Forwarded-Proto https;
       }
    }
    EOF
    ```

    Replace the example name in `server_name` with the certificate's DNS name. Nginx reads the certificate and private key and presents the certificate to HTTPS clients; the certificate is not mounted into `sg-service`.

  7. Permit Nginx to connect to the local service under SELinux, validate the configuration, and start Nginx:

    ```sh
    sudo setsebool -P httpd_can_network_connect 1
    sudo nginx -t
    sudo systemctl enable --now nginx
    ```

    Ask the Linux/network administrator to allow inbound TCP 443 to this server in the managed firewall. If `firewalld` is the approved host firewall, add its HTTPS service while preserving existing management access:

    ```sh
    sudo firewall-cmd --permanent --add-service=https
    sudo firewall-cmd --reload
    ```

  8. Test HTTPS on RHEL with the DNS name:

    ```sh
    curl --fail --show-error https://sluicegate.example.internal/health
    ```

    The response should be `{"status":"ok"}` with no certificate warning. HTTPS from the Minion now terminates at Nginx; Nginx's upstream connection to `sg-service` is plain HTTP over RHEL loopback only. Do not change the Podman publish address from `127.0.0.1`.

### Option: use a self-signed certificate instead of a CA-issued one

A self-signed certificate is acceptable for the pilot when the Minion is configured to trust exactly that certificate. The Minion still checks the host name and validity dates, and there is no setting that turns certificate checking off.

1. On the RHEL server, from the repository root, create the certificate and key. Replace the example name with the DNS name registered in Section 1; add any extra names or IP addresses clients will use:

   ```sh
   sudo OUTPUT_DIR=/etc/pki/tls/sluicegate sh deployment/tls/new-selfsigned-certificate.sh sluicegate.example.internal
   ```

   The script writes `sluicegate-server.pem` (the certificate) and `sluicegate-server.key` (the private key, mode 0600) and prints the certificate's SHA-256 fingerprint and expiry date. Without the script, run `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 -subj "/CN=NAME" -addext "subjectAltName=DNS:NAME" -keyout KEY -out CERT` yourself.
2. In the Nginx configuration above, point `ssl_certificate` at `/etc/pki/tls/sluicegate/sluicegate-server.pem` and `ssl_certificate_key` at `/etc/pki/tls/sluicegate/sluicegate-server.key`, then run `sudo nginx -t && sudo systemctl reload nginx`. Browsers will warn about the certificate unless they also trust it.
3. Copy only the certificate file (never the key) to the Windows Minion host, for example `C:\SluiceGate-bundle\sg-server-cert.pem`. On Windows, confirm it is the right file by comparing the fingerprint with the one the script printed, using `openssl x509 -in sg-server-cert.pem -noout -fingerprint -sha256`.
4. Pass that file to the installer with `-TrustedServerCertificate` in Section 8; it stores the certificate under `C:\ProgramData\SluiceGate\Minion\keys` and pins the Minion to it.

**Renewal or rotation.** The trust file may hold several certificates. Before replacing the server certificate, add the new certificate to the end of `C:\ProgramData\SluiceGate\Minion\keys\sg-server-cert.pem` and its fingerprint to `TrustedServerCertificateSha256` in `minion.config.json`, then restart the Minion service. Install the new certificate on the server, and later remove the old certificate and fingerprint. Replacing the server certificate first makes the Minion reject the service until its trust file is updated.

**Without Nginx.** The container can serve HTTPS itself: mount the certificate and key read-only into the container and set `SG_TLS_CERT_FILE` and `SG_TLS_KEY_FILE` to their container paths. The Windows same-host installer does this from `InstallRoot\tls\server-cert.pem` and `server-key.pem`.

## 6. Register the Agent and Minion

In this section, create the identities that may submit patch requests and claim Missions. The Admin Console uses the bootstrap secret for setup; Agent and Minion API keys are shown only when issued, so copy each directly into its protected destination.

1. Open `https://sluicegate.example.internal/admin` in a browser that trusts the service's TLS certificate. In **Admin Bearer Token**, enter the bootstrap secret from `service.env`, then save it.
2. In the **Agent Registry** tab, register an Agent for the operator or test client that will submit patch requests. Give it a clear name, owner team, and environment that matches the intended deployment. The generated API key is shown once. Save it as a secret in the organization's approved password manager or secrets vault, in a record named for this Agent. Grant only that Agent runtime access to the record; if the runtime cannot read the vault directly, have the deployment administrator inject it through the runtime's protected secret mechanism. Do not put it in source code, a normal text file, shell history, or a command-line argument. SluiceGate does not provide a secrets vault.
3. On the Windows Minion machine, create a unique Ed25519 key pair with OpenSSL. Use an approved OpenSSL installation and store the private key in a directory readable only by administrators and the Minion service identity:

   ```powershell
   New-Item -ItemType Directory -Force 'C:\ProgramData\SluiceGate\Minion\keys'
   openssl genpkey -algorithm ED25519 `
     -out 'C:\ProgramData\SluiceGate\Minion\keys\minion-private-key.pem'
   openssl pkey `
     -in 'C:\ProgramData\SluiceGate\Minion\keys\minion-private-key.pem' `
     -pubout -out 'C:\ProgramData\SluiceGate\Minion\keys\minion-public-key.pem'
   ```

   Do not send the private key to Linux. The public key is safe to register with SluiceGate. The installer in Section 8 restricts access to this directory to Administrators, SYSTEM, and the Minion service account.

4. In the **Minion Registry** tab, register a Minion with ID `PATCH-01` (or another ID you will use consistently), runtime type `powershell`, environment `prod`, and the capability `windows.patch.reconcile`. Paste the contents of `minion-public-key.pem` into the public-key field. Record the ID exactly; it must match `MinionId` in the Windows configuration.
5. The Minion API key is shown once after registration. Save it in the organization's approved secrets vault in a record named for this Minion. The Windows Minion identity needs access to this value; Section 7 stores it in a protected file with `Set-MinionApiKey.ps1`. SluiceGate does not create `minion.config.json` yet; that registry feature is tracked as P2.5 in the backlog, and until then the installer generates it. If the key is lost, rotate or re-register it and store the new key the same way.
6. Confirm both the Agent and Minion appear enabled in their registry tabs. Do not register capabilities that the deployed Minion runtime does not implement.

## 7. Prepare the Windows Minion host

This section places the release bundle and the Minion's keys on Windows. Binaries are installed under `C:\Program Files\SluiceGate\Minion` and replaced on upgrade; configuration, keys, and state live under `C:\ProgramData\SluiceGate\Minion` (`DataRoot`) and are never overwritten by an upgrade.

1. Extract the approved release bundle (built with `Build-DeploymentBundle.ps1`; see `deployment/windows/README.md`) to a temporary folder such as `C:\SluiceGate-bundle`. Check every file against the bundle's hash list and investigate any `MISMATCH` line:

   ```powershell
   Set-Location 'C:\SluiceGate-bundle'
   Get-Content .\SHA256SUMS.txt | ForEach-Object {
     $hash, $path = $_ -split '  ', 2
     if ((Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash -ne $hash) { "MISMATCH: $path" }
   }
   ```

2. Copy the Linux public signing key to `C:\ProgramData\SluiceGate\Minion\keys\sg-public-key.pem`. The Minion key pair from Section 6 is already in the same `keys` directory.
3. Store the Minion API key without putting it in a file you edit or a command line. From the bundle folder, run the helper and paste the key at the hidden prompt:

   ```powershell
   .\Set-MinionApiKey.ps1
   ```

   It writes `keys\minion-api-key.txt` with access limited to Administrators and SYSTEM; the installer later adds read access for the service account.
4. Decide how the Minion will trust the service certificate. If it was issued by a public CA already trusted by Windows, do nothing. If it is self-signed or from a private CA, keep the public certificate file (never the private key) for the installer's `-TrustedServerCertificate` parameter in Section 8, which pins the Minion to exactly that certificate (see Section 5, self-signed option). As an alternative for a private CA, an administrator can import the verified root CA certificate into **Trusted Root Certification Authorities** for the computer account using `mmc.exe`; this trusts that CA for every application on the server.
5. For a CA-issued certificate, verify that the Windows machine trusts the endpoint and can reach it:

   ```powershell
   Test-NetConnection sluicegate.example.internal -Port 443
   Invoke-RestMethod 'https://sluicegate.example.internal/health'
   ```

   The health response should report `status` as `ok`; `Invoke-RestMethod` must succeed without disabling certificate checks. This check is expected to fail for a self-signed certificate, because Windows does not trust it; the Minion's pinned trust is exercised when the service starts.
6. Give the dedicated Minion identity (a gMSA such as `CONTOSO\svc-sluicegate-minion$`, or a domain account) the following permissions. The installer applies the first three on the Minion host; you grant the rest:
   - Read and execute on the installed Minion runtime (the default `Program Files` permissions already allow this).
   - Read on `config` and `keys` under `DataRoot`; the installer removes every other reader except Administrators and SYSTEM.
   - Modify on `data` (the replay-protection nonce file) and `MissionDiary` under `DataRoot`.
   - Read on both the catalog/mapping share and their NTFS files, plus read access to patch package files referenced by approved catalog rows.

   The current patching code also performs remote PowerShell commands with `Invoke-Command` and stages files through each target's `C$` administrative share. Consequently, its target-side requirements are not least privilege: the Minion identity currently needs WinRM/PowerShell Remoting access, SMB access to `C$`, permission to create/write/delete `C:\Windows\Temp\SluiceGate\Staging`, and rights to run the Windows Update Agent and installers. In the current implementation this effectively requires local-administrator rights on each target. 

   Also grant that identity **Read** at both the SMB share and NTFS levels for the catalog, mapping, and approved patch files. Do not grant `Everyone` access. The installer's ACLs protect the Minion's own files; they do not reduce the broad local-administrator requirement the current remote patch implementation has on target servers.

   Do not store reusable credentials in the catalog or mapping file.

## 8. Install and configure the Windows Minion

In this section, run the installer. It copies the runtime, writes the Minion configuration, protects the data directory, registers the Windows service under the service account, and checks that the service stays running. The Minion ID must match the one registered in the Admin Console.

1. Open an elevated PowerShell window in the extracted bundle and run the installer. The Linux service hosts Mission Control in this topology, so install only the Minion. Add `-TrustedServerCertificate` for a self-signed or private-CA certificate; omit it when Windows already trusts the certificate. Use `-SkipSignatureCheck` only in a lab without a code-signing certificate:

   ```powershell
   .\Install-SluiceGate.ps1 `
     -PackageRoot (Get-Location).Path `
     -SkipServiceContainer `
     -MissionControlUrl 'https://sluicegate.example.internal' `
     -MinionId 'PATCH-01' `
     -CatalogPath '\\fileserver\patchrepo\patch_catalog.csv' `
     -NessusMappingPath '\\fileserver\patchrepo\nessus_mapping.csv' `
     -ServiceAccount 'CONTOSO\svc-sluicegate-minion$' `
     -TrustedServerCertificate '.\sg-server-cert.pem'
   ```

   For a gMSA account (name ending in `$`) there is no password. For an ordinary domain account the installer asks for its password at a hidden prompt; it is never placed on a command line. The installer stops with an error if a key file from Section 7 is missing.
2. The installer writes `C:\ProgramData\SluiceGate\Minion\config\minion.config.json`. It contains no secrets (the API key is read from the protected `ApiKeyPath` file) and starts with `DryRun` set to `true`:

   ```json
   {
     "MissionControlUrl": "https://sluicegate.example.internal",
     "MinionId": "PATCH-01",
     "ApiKeyPath": "C:\\ProgramData\\SluiceGate\\Minion\\keys\\minion-api-key.txt",
     "SluiceGatePublicKeyPath": "C:\\ProgramData\\SluiceGate\\Minion\\keys\\sg-public-key.pem",
     "MinionPrivateKeyPath": "C:\\ProgramData\\SluiceGate\\Minion\\keys\\minion-private-key.pem",
     "CatalogPath": "\\\\fileserver\\patchrepo\\patch_catalog.csv",
     "NessusMappingPath": "\\\\fileserver\\patchrepo\\nessus_mapping.csv",
     "NonceStorePath": "C:\\ProgramData\\SluiceGate\\Minion\\data\\nonces.txt",
     "MissionDiaryDirectory": "C:\\ProgramData\\SluiceGate\\Minion\\MissionDiary",
     "PollIntervalSeconds": 3600,
     "DryRun": true
   }
   ```

   JSON uses doubled backslashes in Windows paths. Re-running the installer keeps an existing file; edit it directly for later changes (for example, `DryRun` after validation) and restart the service, or use `-ReplaceConfig` to regenerate it. The service refuses to start, and logs why in the Application event log, if this file or any key it names is missing, an inline `ApiKey` is present, or the Mission Control URL is not `https://`.

   The Minion refuses to start with a Mission Control URL that is not `https://`, so the API key never crosses the network in clear text. When you pass `-TrustedServerCertificate`, the installer copies the certificate to `keys\sg-server-cert.pem` and adds these settings:

   ```json
     "TrustedServerCertificatePath": "C:\\ProgramData\\SluiceGate\\Minion\\keys\\sg-server-cert.pem",
     "TrustedServerCertificateSha256": ["FINGERPRINT_OF_EACH_CERTIFICATE_IN_THE_FILE"]
   ```

   With `TrustedServerCertificatePath`, the Minion trusts only that certificate (or a certificate issued by it) instead of the Windows store, and still checks the host name and validity dates. `TrustedServerCertificateSha256` is optional; when present, every certificate in the file must match a listed fingerprint, so an altered trust file stops the Minion. For a certificate from a CA that Windows already trusts, omit both settings. Plain `http://` is accepted only for a loopback address when `AllowInsecureHttp` is `true`, which is for local development and must not be set for the pilot.

3. Confirm the catalog has the required headers and only approved test rows. The patch catalog requires fields including `patch_status`, `plugin_id`, `patch_type`, `patch_path`, `patch_sha256`, and `install_command`. The Nessus mapping must include `PLUGIN_ID` and `DNS_NAME` columns. Use the patching Minion README and catalog contract for the complete schema.
4. Confirm the Minion identity can read both CSV files and the patch package paths referenced by approved catalog rows. Confirm `openssl` is available to the identity because the PowerShell core module uses it for signature verification and signing.

## 9. Run a safe connectivity check

This section checks that the installed service is healthy and talking to Mission Control with dry-run enabled. It checks service communication and configuration without intending to install patches; it is a lab validation, not proof that Windows service recovery or production patch execution works.

1. Confirm the service is running. If it is stopped or restarting, the Application event log (source `SluiceGateMinion`) names the startup check that failed, such as a missing key file or a non-HTTPS URL:

   ```powershell
   Get-Service SluiceGateMinion
   Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'SluiceGateMinion' } -MaxEvents 20 | Format-List TimeCreated, Message
   ```

2. Review `C:\ProgramData\SluiceGate\Minion\config\minion.config.json` and confirm `DryRun` is `true`, the Minion ID matches registration, and the Mission Control URL starts with `https://`.
3. Optionally run one foreground pass to see the output directly. Stop the service first so two workers are never active, run the pass as the Minion service account, then start the service again:

   ```powershell
   Stop-Service SluiceGateMinion
   & 'C:\Program Files\SluiceGate\Minion\runtime\PatchingMinion.ps1' `
     -ConfigPath 'C:\ProgramData\SluiceGate\Minion\config\minion.config.json' -SinglePass
   Start-Service SluiceGateMinion
   ```

   If PowerShell refuses to run the script, stop and have the administrator review the organization's script execution policy and verify the release signature. Do not disable security controls globally.

4. In the Admin Console, confirm the Minion's last-contact time updates. Review the Linux container logs for connection errors with `sudo podman logs --tail 100 sg-service` and `sudo journalctl -u sg-service.service`. Never paste API keys or private key contents into logs, support tickets, or chat.
5. If check-in fails, verify DNS, TCP port 443, certificate trust/name, the Minion ID, the API key, and the Linux TLS proxy route. Correct the cause and repeat the single-pass test.

## 10. Create a test request and review the result

In this section, submit a request for a server using only the Agent identity and observe how policy controls it. The Agent should identify the target; it should not choose patch types or reboot permissions. Keep dry-run enabled and use the disposable host named in the policy.

1. Using the registered Agent key from its protected secret source, submit only the target server to `POST /api/v1/patch-requests` at the TLS service URL. For an interactive Bash test, enter the key without echoing or adding it to command history, then use curl's standard input for the request configuration:

   ```sh
   read -rsp 'Agent API key: ' SG_AGENT_API_KEY
   printf '\n'
   curl --fail-with-body --config - <<EOF
   url = "https://sluicegate.example.internal/api/v1/patch-requests"
   request = "POST"
   header = "Authorization: Bearer $SG_AGENT_API_KEY"
   header = "Content-Type: application/json"
   data = "{\"servers\":[\"patch-test-01.example.internal\"]}"
   EOF
   unset SG_AGENT_API_KEY
   ```

   This keeps the key out of the curl command-line arguments and shell history. In a real Agent runtime, use its approved secrets integration instead of an interactive prompt.

2. Open **Missions & Audit** in the Admin Console and inspect the request. Confirm the policy decision, target host, Minion assignment, and Mission status match expectations.
3. A `BLOCK` decision means the policy did not allow the request; review the policy and request values before retrying. A `PAUSE` decision requires an authorized administrator to inspect and explicitly approve it. Never approve a request just to make a test pass.
4. Important current limitation: although the Agent request above contains only the target, the service currently supplies default patch settings and also accepts Agent-supplied overrides for patch source, patch type, and reboot. Its policy decision does not yet authoritatively set the execution constraints in the Mission. Do not treat policy as the sole enforcement of patch type or reboot behavior until the P2.6 backlog item is implemented and tested. This is why the example is for a controlled dry-run only.
5. For a `QUEUED` request in the lab, run one Minion pass with `DryRun` still set to `true`, then inspect the resulting Mission and Minion status. Do not change `DryRun` to `false` as part of installation validation.

## 11. Finish bootstrap and record operations

This section removes temporary setup access and records how to maintain the deployment. Doing this after successful lab checks reduces the chance that a temporary credential or undocumented configuration becomes permanent.

1. The current Admin Console has no button for creating another administrator. Use the credential-issuance API from a trusted administrator workstation. Set `SG_BASE_URL` to the HTTPS service URL and make the bootstrap key available from its protected source, then run:

    ```sh
   export SG_BASE_URL='https://sluicegate.example.internal'
   read -rsp 'Bootstrap admin key: ' SG_BOOTSTRAP_ADMIN_KEY
   printf '\n'
    curl --fail --silent --show-error --config - <<EOF
    url = "$SG_BASE_URL/admin/v1/credentials/admin/operator-alice"
    request = "POST"
    header = "Authorization: Bearer $SG_BOOTSTRAP_ADMIN_KEY"
    EOF
   unset SG_BOOTSTRAP_ADMIN_KEY
    ```

   Replace `operator-alice` with the operator's identifier. The response contains `key_id` and `api_key`; the API key is returned only once. Copy the `api_key` value directly from the response into the organization's approved secrets vault under that operator's access controls. This vault is separate from SluiceGate. Do not save the response to a shared file, check it into source control, or send it through email/chat. Sign in with the new key and verify the Admin Console works before proceeding. The current UI stores its entered bearer token in that browser's local storage, so use a trusted administrator browser profile.
2. Revoke the bootstrap key using the API while authenticated with the replacement administrator key:

    ```sh
   read -rsp 'Named admin API key: ' SG_NAMED_ADMIN_API_KEY
   printf '\n'
    curl --fail --silent --show-error --config - <<EOF
    url = "$SG_BASE_URL/admin/v1/credentials/KEY-BOOTSTRAP-ADMIN/revoke"
    request = "POST"
    header = "Authorization: Bearer $SG_NAMED_ADMIN_API_KEY"
    EOF
   unset SG_NAMED_ADMIN_API_KEY
    ```

    Then remove the `SG_BOOTSTRAP_ADMIN_KEY=...` line from `/opt/sluicegate/service.env` with `sudo nano` and save the file. Run `sudo systemctl restart sg-service.service`; the Quadlet unit reloads the environment file when the container is recreated. Confirm the named administrator still works and the bootstrap key no longer authenticates. Do not delete the only working administrator credential before testing its replacement.
3. Back up the Podman volume and the policy and key files using your organization's approved backup process. Protect the private signing key and database backups as sensitive data. Test restoration before relying on backups.
4. Record the service DNS name, Linux host owner, Windows Minion ID and owner, policy approval process, backup location, certificate renewal owner, and incident contact in the team's secure operations documentation. Do not record secret values there.

## Further reading

These documents provide the operator details and reference contracts used by this walkthrough.

- [SluiceGate Service Operator Guide](../sg-service/README.md)
- [Windows Server Deployment](../deployment/windows/README.md)
- [Windows Patching Minion](../minion-registry/minions/patching/README.md)
- [SluiceGate Policy Editor](../open-core/src/sg_poledit/editor/README.md)
- [Policy DSL](Policy_DSL.md)
- [SluiceGate Feature Backlog](../planning/Feature_Backlog.md)