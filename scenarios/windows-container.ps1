<#
.SYNOPSIS
    Process-isolated Windows container attribution scenario (#371).

.DESCRIPTION
    Runs a process-isolated container, starts a long-lived process in it and a
    short-lived one with `docker exec`, and one short-lived process on the host.
    The ETW sensor must stamp the container's processes with the container id
    (EventMeta::container, the Host Compute Service id that Docker shows), and
    leave the host process without one.

    Alongside the checks it prints what the attribution rests on, so a FAIL can
    be told apart from a wrong assumption:
      - the ServerSiloId of each process `docker top` lists (the query the
        sensor makes at ProcessStart);
      - `hcsdiag list`, the Host Compute Service's view of the container;
      - the Kernel-Process server-silo records (EIDs 22-26) of the run, traced
        with logman: the sensor forgets a silo on their "Job ID", which must be
        the ServerSiloId above.

    Needs a host with the Containers feature and Docker in Windows-containers
    mode (Windows Server 2025, or Windows 11 22H2+ Pro/Enterprise), and an image
    whose build matches the host's (process isolation requires it).

.NOTES
    Self-checking run (elevated, no other agent running):
        cargo build --release -p agent      (in the agent checkout)
        powershell -ExecutionPolicy Bypass -File scenarios\windows-container.ps1 -AgentExe <agent checkout>\target\release\agent.exe

    Expected:
        - exec events from inside the container carry container.id = the
          container's full id (64 hex), including hostname.exe run by
          `docker exec` (a process that exits at once: it takes its parent's silo)
        - the host's hostname.exe exec has no container
        - the Kernel-Process silo records name the ServerSiloId docker top's
          processes run in

.LINK
    https://github.com/synthaea-lab/edr-agent/issues/39
#>
[CmdletBinding()]
param(
    [string]$Image = "mcr.microsoft.com/windows/nanoserver:ltsc2025",
    [string]$AgentExe = "",
    [string]$OutDir = ""
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common.ps1")
Set-StrictMode -Version Latest

$Name = "synthaea371"
$TraceName = "synthaea371-silo"

Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class SynthaeaSilo {
    [DllImport("ntdll.dll")] static extern int NtQueryInformationProcess(IntPtr h, int cls, out uint info, int len, out int retLen);
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    // 109 = ProcessMembershipInformation (ntddk.h), as the sensor queries it.
    public static string ServerSiloId(int pid) {
        IntPtr h = OpenProcess(0x1000, false, pid);
        if (h == IntPtr.Zero) return "open failed";
        uint silo; int len; int status = NtQueryInformationProcess(h, 109, out silo, 4, out len);
        CloseHandle(h);
        return status == 0 ? silo.ToString() : String.Format("status 0x{0:X8}", status);
    }
}
'@

# -- Scenario ------------------------------------------------------------------

function Assert-Prerequisites {
    Assert-Administrator "needs an elevated PowerShell (the agent's ETW session, logman, hcsdiag)"
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw "docker not found on PATH" }
    $osType = (docker info --format "{{.OSType}}" 2>$null)
    if ($osType -ne "windows") { throw "docker is not in Windows-containers mode (OSType=$osType)" }
    Write-Host "pulling $Image (once, before the trace starts)"
    Invoke-Native docker @("pull", "-q", $Image)
}

# The first processes of a container start before the Host Compute Service lists
# them, and a failed lookup is retried only after the sensor's RETRY_NS (10 s,
# silo.rs). A fixed sleep shorter than that races the short-lived `docker exec`
# below; wait until an event carries the container id instead (bounded), or,
# with no agent to watch, past one retry window.
function Wait-ContainerMapped($Agent, [string]$Id) {
    if (-not $Agent) { Start-Sleep -Seconds 12; return }
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        if (Select-String -LiteralPath $Agent.Events -SimpleMatch $Id -Quiet) { return }
        Start-Sleep -Milliseconds 500
    }
    Write-Host "warning: no event carried the container id within 30 s; the exec check may fail" -ForegroundColor Yellow
}

function Invoke-ContainerScenario($Agent) {
    docker rm -f $Name 2>$null | Out-Null
    Write-Host "docker run --isolation=process $Image (ping -t, kept running)"
    $id = (docker run -d --isolation=process --name $Name $Image cmd /c "ping -t 127.0.0.1").Trim()
    if ($LASTEXITCODE -ne 0 -or $id -notmatch '^[0-9a-f]{64}$') { throw "docker run failed: $id" }
    Write-Host "container id $id"
    Wait-ContainerMapped $Agent $id
    Write-Host "docker exec $Name hostname.exe (exits at once)"
    Invoke-Native docker @("exec", $Name, "hostname.exe")
    Write-Host "hostname.exe on the host"
    $hostProc = Start-Process -FilePath "$env:SystemRoot\System32\HOSTNAME.EXE" -WindowStyle Hidden -PassThru -Wait
    [pscustomobject]@{ Id = $id; HostPid = $hostProc.Id }
}

function Get-ContainerProcessSilos {
    # Each process `docker top` lists, with the ServerSiloId the sensor reads for it.
    foreach ($line in (docker top $Name 2>$null | Select-Object -Skip 1)) {
        $fields = $line -split '\s+' | Where-Object { $_ }
        $hostPid = $fields | Where-Object { $_ -match '^\d+$' } | Select-Object -First 1
        if (-not $hostPid) { continue }
        [pscustomobject]@{ Name = $fields[0]; Pid = $hostPid; Silo = [SynthaeaSilo]::ServerSiloId([int]$hostPid) }
    }
}

# The distinct real ServerSiloIds of $Processes: not 0 (the host) nor a failed query.
function Get-ServerSiloIds([object[]]$Processes = @()) {
    @($Processes | ForEach-Object { $_.Silo } | Where-Object { $_ -match '^\d+$' -and $_ -ne "0" } | Select-Object -Unique)
}

function Write-ContainerProcessSilos([object[]]$Processes = @()) {
    Write-Host ""
    Write-Host "docker top $Name, with each process's ServerSiloId:"
    foreach ($process in $Processes) {
        Write-Host ("  {0,-24} pid {1,-7} silo {2}" -f $process.Name, $process.Pid, $process.Silo)
    }
}

function Write-HcsDiagList {
    if (Get-Command hcsdiag -ErrorAction SilentlyContinue) {
        Write-Host ""
        Write-Host "hcsdiag list:"
        hcsdiag list | ForEach-Object { Write-Host "  $_" }
    }
}

function Get-SiloTraceRecords([string]$Dir) {
    $xml = Join-Path $Dir "silo.xml"
    Invoke-Native tracerpt @("$Dir\silo.etl", "-o", $xml, "-of", "XML", "-y")
    foreach ($e in ([xml](Get-Content -LiteralPath $xml -Raw)).Events.Event) {
        $eid = [int]$e.System.EventID
        if ($eid -lt 22 -or $eid -gt 26) { continue }
        $data = @{}
        # InnerText, not '#text': an empty <Data/> has no '#text' and strict mode throws.
        foreach ($d in $e.EventData.Data) { $data[$d.Name] = $d.InnerText.Trim() }
        [pscustomobject]@{ Eid = $eid; JobId = $data["Job ID"]; ContainerId = $data["Container ID"] }
    }
}

function Write-SiloTraceRecords([object[]]$Records = @()) {
    Write-Host ""
    Write-Host "Kernel-Process server-silo records (EIDs 22-26): $($Records.Count)"
    $Records | ForEach-Object { Write-Host ("  EID {0} Job ID {1} Container ID {2}" -f $_.Eid, $_.JobId, $_.ContainerId) }
}

# -- Verdict (-AgentExe) ---------------------------------------------------------

# The container id of an exec event, or $null for a host process (the agent
# omits meta.container there).
function Get-ExecContainerId($Exec) {
    Get-OptionalProperty (Get-OptionalProperty $Exec.meta "container") "id"
}

function Write-ProvisionalSiloIds([object[]]$Execs = @()) {
    $provisional = @($Execs | Where-Object { "$(Get-ExecContainerId $_)".StartsWith("silo:") })
    Write-Host ("info: {0} exec event(s) carried a provisional silo:<n> id: {1}" -f $provisional.Count,
        (($provisional | ForEach-Object { "$($_.meta.comm)=$(Get-ExecContainerId $_)" } | Select-Object -Unique) -join ', '))
}

function Get-ScenarioVerdict {
    # The checks of an -AgentExe run, from the agent's exec events, the run
    # ($Run: Id, HostPid) and the silo diagnostics, as { Check, Pass, Detail }
    # objects for Write-Verdict (common.ps1). Prints nothing.
    param(
        [AllowEmptyCollection()][object[]]$Execs = @(),
        [Parameter(Mandatory)]$Run,
        [AllowEmptyCollection()][object[]]$SiloIds = @(),
        [AllowEmptyCollection()][object[]]$SiloRecords = @()
    )
    $inContainer = @($Execs | Where-Object { (Get-ExecContainerId $_) -eq $Run.Id })
    [pscustomobject]@{
        Check = "exec events from the container carry its id"
        Pass = $inContainer.Count -gt 0
        Detail = "$($inContainer.Count) event(s): $(($inContainer | ForEach-Object { $_.meta.comm } | Select-Object -Unique) -join ', ')"
    }
    $execd = @($inContainer | Where-Object { $_.meta.comm -ieq "hostname.exe" })
    [pscustomobject]@{
        Check = "docker exec'd hostname.exe carries the container id"
        Pass = $execd.Count -ge 1
        Detail = "$($execd.Count) event(s)"
    }
    $hostExec = @($Execs | Where-Object { $_.meta.pid -eq $Run.HostPid })
    [pscustomobject]@{
        Check = "the host's hostname.exe has no container"
        Pass = ($hostExec.Count -ge 1) -and (@($hostExec | Where-Object { Get-ExecContainerId $_ }).Count -eq 0)
        Detail = "$($hostExec.Count) event(s) for pid $($Run.HostPid)"
    }
    $jobIds = @($SiloRecords | ForEach-Object { $_.JobId } | Select-Object -Unique)
    [pscustomobject]@{
        Check = "the silo records' Job ID is the ServerSiloId the processes run in"
        Pass = ($SiloIds.Count -eq 1) -and ($jobIds -contains $SiloIds[0])
        Detail = "ServerSiloId [$($SiloIds -join ',')], Job IDs [$($jobIds -join ',')]"
    }
}

# -- Main ------------------------------------------------------------------------

Assert-Prerequisites
$dir = Get-RunDirectory -OutDir $OutDir -Prefix "container"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$dir = (Resolve-Path $dir).Path

$agent = $null
$run = $null
$siloIds = @()
logman stop $TraceName -ets 2>$null | Out-Null
Invoke-Native logman @("start", $TraceName, "-p", "Microsoft-Windows-Kernel-Process", "0x4000", "-ets", "-o", "$dir\silo.etl")
try {
    if ($AgentExe) { $agent = Start-ScenarioAgent -AgentExe $AgentExe -Dir $dir -PipeName "synthaea-lab-container" }
    $run = Invoke-ContainerScenario $agent
    # Queried while the container still runs (the finally block removes it).
    $processes = @(Get-ContainerProcessSilos)
    Write-ContainerProcessSilos $processes
    Write-HcsDiagList
    # @(): a function's one-element array comes back unrolled to a bare string, and
    # Get-ScenarioVerdict's $SiloIds[0] then reads its first character ("2" of "220").
    $siloIds = @(Get-ServerSiloIds $processes)
    if ($agent) { Start-Sleep -Seconds 8 }
}
finally {
    Stop-ScenarioAgent $agent
    Invoke-NativeCleanup "container $Name" docker @("rm", "-f", $Name)
    Invoke-NativeCleanup "trace session $TraceName" logman @("stop", $TraceName, "-ets")
}
$siloRecords = @(Get-SiloTraceRecords $dir)
Write-SiloTraceRecords $siloRecords

if ($agent) {
    $execs = @(Read-AgentEvents -Path $agent.Events -Type "exec")
    $verdict = @(Get-ScenarioVerdict -Execs $execs -Run $run -SiloIds $siloIds -SiloRecords $siloRecords)
    Write-Host ""
    Write-ProvisionalSiloIds $execs
    Write-Verdict $verdict
    if (-not (Test-VerdictPassed $verdict)) {
        Write-Host "see $dir (events.jsonl, stderr.log, silo.xml)"
        exit 1
    }
}
else {
    Write-Host ""
    Write-Host "Done. Expected from the agent: exec events of the container with container.id $($run.Id),"
    Write-Host "and none on the host's hostname.exe (pid $($run.HostPid))."
}
