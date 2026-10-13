# SluiceGate Windows Service Host (`SluiceGate.Minion.Service.exe`)

This project contains the C# source for the Windows Service executable host for SluiceGate Minions on Windows Server 2022. The repository also includes a precompiled framework-dependent Windows x64 executable at `../Minion/SluiceGate.Minion.Service.exe` for operators who do not have the .NET SDK. The .NET 8 x64 Runtime must be installed on the Windows server where the service runs.

## How it works

1. Runs as a managed Windows Service under `LocalSystem` or a designated group Managed Service Account (gMSA).
2. Uses `.NET 8.0` Windows Service hosting (`Microsoft.Extensions.Hosting.WindowsServices`).
3. Dispatches scheduled/event-driven execution passes to the SluiceGate Minion runtime (`PatchingMinion.ps1`) in a secure, isolated sub-process with bounded logging.
4. Streams logs directly to Windows Event Log (`Application / SluiceGateMinion`) and console output.

## Building the Executable

From this directory with the `.NET 8 SDK`, publish into the tracked deployment directory:

```powershell
dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -p:DebugType=None -o ..\Minion
```

The same build can be run from macOS or Linux with Docker; see [../README.md](../README.md#compiling-the-c-windows-service).

Then sign the resulting `SluiceGate.Minion.Service.exe` with your Authenticode code-signing certificate:

```powershell
Set-AuthenticodeSignature -FilePath ..\Minion\SluiceGate.Minion.Service.exe -Certificate $codeSigningCert
```

Then invoke `Build-DeploymentBundle.ps1` to produce the final offline installation archive.
