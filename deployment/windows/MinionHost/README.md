# SluiceGate Windows Service Host (`SluiceGate.Minion.Service.exe`)

This project compiles the native Windows Service executable host for SluiceGate Minions on Windows Server 2022.

## How it works

1. Runs as a managed Windows Service under `LocalSystem` or a designated group Managed Service Account (gMSA).
2. Uses `.NET 8.0` Windows Service hosting (`Microsoft.Extensions.Hosting.WindowsServices`).
3. Dispatches scheduled/event-driven execution passes to the SluiceGate Minion runtime (`PatchingMinion.ps1`) in a secure, isolated sub-process with bounded logging.
4. Streams logs directly to Windows Event Log (`Application / SluiceGateMinion`) and console output.

## Building the Executable

From Windows build environment with `.NET 8 SDK`:

```powershell
dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o ..\bin\Minion
```

Then sign the resulting `SluiceGate.Minion.Service.exe` with your Authenticode code-signing certificate:

```powershell
Set-AuthenticodeSignature -FilePath ..\bin\Minion\SluiceGate.Minion.Service.exe -Certificate $codeSigningCert
```

Then invoke `Build-DeploymentBundle.ps1` to produce the final offline installation archive.
