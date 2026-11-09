<#
.SYNOPSIS
    BITS download-then-exec scenario for T1197 (#284).

.DESCRIPTION
    Asserts the Bits-Client ETW path end to end: `bitsadmin /transfer` fetches
    a copy of whoami.exe from a local HTTP listener into %TEMP%, then runs it.
    The sensor reports the job (BitsJob file_added, then completed) and the
    T1197 download->exec join fires on the exec. BITS does the download from
    its own service, so without the Bits-Client provider nothing ties the file
    to bitsadmin.exe.

    The listener answers HEAD and ranged GETs: BITS sizes the file with a HEAD
    and fetches it with Range requests. Benign by construction: the "payload"
    is whoami.exe, and the only network traffic is to localhost.

    With -MicrosoftJob (needs internet), a second job fetches
    http://www.msftconnecttest.com/connecttest.txt: a Microsoft update host,
    so the sensor must drop it, with no bits_job event for that job.

.NOTES
    Self-checking run (elevated, no other agent running): the script writes a
    lab agent.toml, starts the agent, runs the scenario, stops the agent and
    prints PASS/FAIL per expectation (exit code 1 on any FAIL):
        cargo build --release -p agent      (in the agent checkout)
        powershell -ExecutionPolicy Bypass -File scenarios\bits-job.ps1 -AgentExe <agent checkout>\target\release\agent.exe -MicrosoftJob

    Expected:
        - two "bits_job" events for job "synthaea284", file_added then
          completed, comm bitsadmin.exe, url http://localhost:<port>/payload284.exe
        - one alert: T1197 -- pid=<p> comm=payload284.exe executes
          ...\payload284.exe, <n>s earlier by BITS job "synthaea284" of
          pid=<b> comm=bitsadmin.exe
        - with -MicrosoftJob: no bits_job event for synthaea284ms

    Without -AgentExe (any user, against an agent you started yourself), the
    script only runs the scenario, then prints the Bits-Client/Operational
    records for its jobs (16403 file added, 4 completed) as a self-check.

.LINK
    ATT&CK T1197 -- https://attack.mitre.org/techniques/T1197/
#>
[CmdletBinding()]
param(
    [int]$Port = 18284,
    [switch]$MicrosoftJob,
    [string]$AgentExe = "",
    [string]$OutDir = ""
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common.ps1")
Set-StrictMode -Version Latest

$JobName = "synthaea284"
$Source = "$env:SystemRoot\System32\whoami.exe"
$Target = Join-Path $env:TEMP "payload284.exe"
$Url = "http://localhost:$Port/payload284.exe"

# -- Agent harness (-AgentExe, Start-ScenarioAgent in common.ps1) ---------------

function Start-BitsAgent {
    Assert-Administrator "-AgentExe needs an elevated PowerShell: the agent's ETW session needs Administrator."
    Start-ScenarioAgent -AgentExe $AgentExe -Dir (Get-RunDirectory -OutDir $OutDir -Prefix "bits") -PipeName "synthaea-lab-bits"
}

# -- Scenario ------------------------------------------------------------------

function Start-PayloadListener([byte[]]$Bytes) {
    # The listener serves from its own runspace: bitsadmin /transfer blocks
    # until the job is done, and BITS makes several requests (HEAD, then
    # ranged GETs). The listener object is kept so Stop-PayloadListener can
    # stop it: stopping the runspace alone does not interrupt a blocked
    # GetContext().
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://localhost:$Port/")
    $listener.Start()
    $listenerScript = {
        param($Listener, $Bytes)
        try {
            while ($Listener.IsListening) {
                $context = $Listener.GetContext()
                $response = $context.Response
                $response.Headers.Add("Accept-Ranges", "bytes")
                $response.ContentType = "application/octet-stream"
                $first = 0
                $last = $Bytes.Length - 1
                $range = $context.Request.Headers["Range"]
                if ($range -match "^bytes=(\d+)-(\d*)$") {
                    $first = [int64]$Matches[1]
                    if ($Matches[2]) { $last = [Math]::Min([int64]$Matches[2], $last) }
                    $response.StatusCode = 206
                    $response.Headers.Add("Content-Range", "bytes $first-$last/$($Bytes.Length)")
                }
                $count = $last - $first + 1
                $response.ContentLength64 = $count
                if ($context.Request.HttpMethod -ne "HEAD") {
                    $response.OutputStream.Write($Bytes, $first, $count)
                }
                $response.Close()
            }
        }
        catch [System.Net.HttpListenerException] {
            # Stop() from Stop-PayloadListener: the blocked GetContext() returns here.
        }
    }
    $server = [PowerShell]::Create()
    [void]$server.AddScript($listenerScript).AddArgument($listener).AddArgument($Bytes)
    [pscustomobject]@{ Listener = $listener; Server = $server; Handle = $server.BeginInvoke() }
}

function Stop-PayloadListener($Payload) {
    $Payload.Listener.Stop()
    $Payload.Listener.Close()
    [void]$Payload.Handle.AsyncWaitHandle.WaitOne(5000)
    $Payload.Server.Dispose()
}

function Invoke-BitsDownloadExec {
    Write-Host "bitsadmin /transfer $JobName $Url -> $Target"
    Invoke-Native bitsadmin.exe @("/transfer", $JobName, "/download", "/priority", "foreground", $Url, $Target)
    if (-not (Test-Path -LiteralPath $Target)) { throw "bitsadmin reported success but $Target is missing" }

    Write-Host "running $Target"
    & $Target | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "$Target failed with exit code $LASTEXITCODE" }
}

function Invoke-MicrosoftHostJob {
    $msTarget = Join-Path $env:TEMP "connecttest284.txt"
    Write-Host "bitsadmin /transfer ${JobName}ms (Microsoft host, must be filtered)"
    Invoke-Native bitsadmin.exe @("/transfer", "${JobName}ms", "/download", "/priority", "foreground",
        "http://www.msftconnecttest.com/connecttest.txt", $msTarget)
    Remove-Item -LiteralPath $msTarget -Force -ErrorAction SilentlyContinue
}

function Invoke-BitsScenario {
    $payload = Start-PayloadListener ([IO.File]::ReadAllBytes($Source))
    try {
        Start-Sleep -Seconds 1
        if ($payload.Handle.IsCompleted) {
            $payload.Server.EndInvoke($payload.Handle)
            throw "the HTTP listener runspace exited at once"
        }
        Remove-Item -LiteralPath $Target -Force -ErrorAction SilentlyContinue
        Invoke-BitsDownloadExec
        if ($MicrosoftJob) { Invoke-MicrosoftHostJob }
    }
    finally {
        Stop-PayloadListener $payload
        Remove-Item -LiteralPath $Target -Force -ErrorAction SilentlyContinue
    }
}

# -- Bits-Client log self-check (no -AgentExe) -----------------------------------

function Get-BitsLogRecords([datetime]$Since) {
    # What the Bits-Client log recorded for our jobs, oldest first: the same
    # records the sensor reads over ETW.
    Start-Sleep -Seconds 1
    $records = @(Get-WinEvent -LogName "Microsoft-Windows-Bits-Client/Operational" -ErrorAction SilentlyContinue |
        Where-Object { $_.TimeCreated -ge $Since -and $_.Id -in 4, 5, 16403, 61 } |
        Where-Object { ([xml]$_.ToXml()).Event.EventData.Data | Where-Object { $_.InnerText -like "$JobName*" } })
    foreach ($record in ($records | Sort-Object TimeCreated)) {
        $data = @{}
        # InnerText, not '#text': an empty <Data/> has no '#text' and strict mode throws.
        ([xml]$record.ToXml()).Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.InnerText }
        [pscustomobject]@{
            Id = $record.Id
            JobTitle = $data["jobTitle"]
            ProcessId = $data["processId"]
            RemoteName = $data["RemoteName"]
            LocalName = $data["LocalName"]
        }
    }
}

function Write-BitsLogRecords([object[]]$Records = @()) {
    Write-Host ""
    Write-Host "Bits-Client records for ${JobName}*: $($Records.Count)"
    foreach ($record in $Records) {
        Write-Host ("  EID {0,-5} {1,-14} processId={2} {3} {4}" -f $record.Id, $record.JobTitle, $record.ProcessId, $record.RemoteName, $record.LocalName)
    }
    if (@($Records | Where-Object { $_.Id -eq 16403 }).Count -eq 0) {
        Write-Warning "no 16403 (file added) record: the sensor has nothing to report either"
    }
}

# -- Verdict (-AgentExe) ---------------------------------------------------------

function Get-ScenarioVerdict {
    # The checks of an -AgentExe run, from the agent's events and alerts, as
    # { Check, Pass, Detail } objects for Write-Verdict (common.ps1). Prints nothing.
    param(
        [Parameter(Mandatory)]$Agent,
        [Parameter(Mandatory)][string]$JobName,
        [switch]$MicrosoftJob
    )
    $jobs = @(Read-AgentEvents -Path $Agent.Events -Type "bits_job")
    $ours = @($jobs | Where-Object { $_.job_title -eq $JobName })
    $states = ($ours | ForEach-Object { $_.state }) -join ","
    [pscustomobject]@{
        Check = "bits_job file_added + completed for $JobName"
        Pass = ($states -eq "file_added,completed") -and (@($ours | Where-Object { $_.meta.comm -ne "bitsadmin.exe" }).Count -eq 0)
        Detail = "states=[$states] comm=[$(($ours | ForEach-Object { $_.meta.comm } | Select-Object -Unique) -join ',')] ($($jobs.Count) bits_job events in all)"
    }
    $t1197 = @()
    if (Test-Path $Agent.Alerts) {
        $t1197 = @(Get-Content -LiteralPath $Agent.Alerts | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json } |
            Where-Object { $_.technique -eq "T1197" -and $_.message -match "payload284\.exe" })
    }
    [pscustomobject]@{
        Check = "one T1197 alert for payload284.exe"
        Pass = $t1197.Count -eq 1
        Detail = if ($t1197.Count) { $t1197[0].message } else { "none" }
    }
    if ($MicrosoftJob) {
        $msJobs = @($jobs | Where-Object { $_.job_title -eq "${JobName}ms" })
        [pscustomobject]@{
            Check = "no bits_job for the Microsoft-host job ${JobName}ms"
            Pass = $msJobs.Count -eq 0
            Detail = "$($msJobs.Count) event(s)"
        }
    }
}

# -- Main ------------------------------------------------------------------------

$agent = $null
$started = Get-Date
try {
    if ($AgentExe) { $agent = Start-BitsAgent }
    Invoke-BitsScenario
    if ($agent) { Start-Sleep -Seconds 8 }
}
finally {
    Stop-ScenarioAgent $agent
}
Write-BitsLogRecords @(Get-BitsLogRecords $started)

if ($agent) {
    $verdict = @(Get-ScenarioVerdict -Agent $agent -JobName $JobName -MicrosoftJob:$MicrosoftJob)
    Write-Host ""
    Write-Verdict $verdict
    if (-not (Test-VerdictPassed $verdict)) {
        Write-Host "see $($agent.Dir) (events.jsonl, alerts.ndjson, stderr.log)"
        exit 1
    }
}
else {
    Write-Host ""
    Write-Host "Done. Expected from the agent: bits_job file_added + completed for $JobName,"
    Write-Host "then one T1197 alert for payload284.exe."
}
