# SluiceGate Windows Service Host (`SluiceGate.Minion.Service.exe`)

This project contains the C# source for the Windows Service executable host for SluiceGate Minions on Windows Server 2022. The repository also includes a precompiled framework-dependent Windows x64 executable at `../Minion/SluiceGate.Minion.Service.exe` for operators who do not have the .NET SDK. The .NET 10 x64 Runtime must be installed on the Windows server where the service runs.

## How it works

1. Runs as a managed Windows Service under `LocalSystem` or a designated group Managed Service Account (gMSA).
2. Uses `.NET 10.0` Windows Service hosting (`Microsoft.Extensions.Hosting.WindowsServices`).
3. Starts the long-lived SluiceGate Minion runtime (`PatchingMinion.ps1`) in a child PowerShell process; the runtime reads its configured idle poll and Mission retry intervals and renews active claim leases itself.
4. Streams logs directly to Windows Event Log (`Application / SluiceGateMinion`) and console output.

The worker process remains alive between idle polls. `PollIntervalSeconds` controls empty-queue polling; the signed Mission's retry and heartbeat settings control active recovery. Stopping the Windows Service terminates the PowerShell worker process tree; a later service start recovers through the claim lease and local Mission Diary.

## Building the Executable

From this directory with the `.NET 10 SDK`, publish into the tracked deployment directory:

```powershell
dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -p:DebugType=None -o ..\Minion
```

The same build can be run from macOS or Linux with Docker; see [../README.md](../README.md#compiling-the-c-windows-service).

Then sign the resulting `SluiceGate.Minion.Service.exe` with your Authenticode code-signing certificate:

```powershell
Set-AuthenticodeSignature -FilePath ..\Minion\SluiceGate.Minion.Service.exe -Certificate $codeSigningCert
```

Then invoke `Build-DeploymentBundle.ps1` to produce the final offline installation archive.
