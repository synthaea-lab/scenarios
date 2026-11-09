<#
.SYNOPSIS
    Pins the PASS/FAIL verdict of the bits-job.ps1 and windows-container.ps1
    -AgentExe runs on recorded agent output. Runs unprivileged on any pwsh
    (CI: Linux): the scenarios are not run, their verdict functions are
    loaded from the parsed scripts and fed fixture events.

        pwsh -NoProfile -File tools/test-scenario-verdicts.ps1
#>
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repo = Split-Path -Parent $PSScriptRoot
. (Join-Path $repo "scenarios/common.ps1")
$failures = 0

function Assert-That([string]$Description, [bool]$Condition, [string]$Detail = "") {
    if ($Condition) {
        Write-Host "ok: $Description"
    }
    else {
        Write-Host "FAIL: $Description $Detail"
        $script:failures++
    }
}

# Defines the named functions of a scenario script here without running the
# script (its top level starts an agent, a container, a BITS job).
function Import-ScenarioFunction([string]$Script, [string[]]$Names) {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repo $Script), [ref]$null, [ref]$null)
    foreach ($name in $Names) {
        $definition = $ast.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
            }, $true)
        if (-not $definition) { throw "$Script defines no function $name" }
        . ([scriptblock]::Create(($definition.Extent.Text -replace "^function\s+$name", "function script:$name")))
    }
}

# The lines Write-Verdict prints for $Results.
function Get-VerdictLines([object[]]$Results) {
    @(& { Write-Verdict $Results } 6>&1 | ForEach-Object { "$_" })
}

$work = Join-Path ([IO.Path]::GetTempPath()) ("test-scenario-verdicts-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $containerId = "a" * 64
    $events = Join-Path $work "events.jsonl"
    @(
        '{"type":"exec","meta":{"pid":1,"comm":"x.exe"}}'
        '{"type":"bits_job","job_title":"synthaea284","state":"file_added","meta":{"comm":"bitsadmin.exe"}}'
        '{"type":"bits_job","job_title":"synthaea284","state":"completed","meta":{"comm":"bitsadmin.exe"}}'
        '{"type":"bits_job","job_title":"synthaea284ms","state":"file_added","meta":{"comm":"bitsadmin.exe"}}'
        '{"type":"exec","meta":{"pid":7,"comm":"cmd.exe","container":{"id":"' + $containerId + '"}}}'
        '{"type":"exec","meta":{"pid":9,"comm":"hostname.exe","container":{"id":"' + $containerId + '"}}}'
        '{"type":"exec","meta":{"pid":10,"comm":"ping.exe","container":{"id":"silo:220"}}}'
        '{"type":"exec","meta":{"pid":11,"comm":"HOSTNAME.EXE"}}'
    ) | Set-Content -LiteralPath $events
    $alerts = Join-Path $work "alerts.ndjson"
    @('{"technique":"T1197","message":"pid=3 comm=payload284.exe executes C:\\t\\payload284.exe"}', '') |
        Set-Content -LiteralPath $alerts
    $agent = [pscustomobject]@{ Dir = $work; Events = $events; Alerts = $alerts }

    # -- bits-job.ps1 --------------------------------------------------------------
    Import-ScenarioFunction "scenarios/bits-job.ps1" @("Get-ScenarioVerdict")
    $jobLine = "PASS  bits_job file_added + completed for synthaea284: states=[file_added,completed] comm=[bitsadmin.exe] (3 bits_job events in all)"
    $alertLine = "PASS  one T1197 alert for payload284.exe: pid=3 comm=payload284.exe executes C:\t\payload284.exe"

    $verdict = @(Get-ScenarioVerdict -Agent $agent -JobName "synthaea284")
    $lines = Get-VerdictLines $verdict
    Assert-That "bits-job: job and alert checks pass" (($lines -join "`n") -eq (@($jobLine, $alertLine) -join "`n")) "got:`n$($lines -join "`n")"
    Assert-That "bits-job: verdict passes" (Test-VerdictPassed $verdict)

    $verdict = @(Get-ScenarioVerdict -Agent $agent -JobName "synthaea284" -MicrosoftJob)
    $lines = Get-VerdictLines $verdict
    $msLine = "FAIL  no bits_job for the Microsoft-host job synthaea284ms: 1 event(s)"
    Assert-That "bits-job -MicrosoftJob: a reported Microsoft-host job fails" (($lines -join "`n") -eq (@($jobLine, $alertLine, $msLine) -join "`n")) "got:`n$($lines -join "`n")"
    Assert-That "bits-job -MicrosoftJob: verdict fails" (-not (Test-VerdictPassed $verdict))

    $noAlerts = [pscustomobject]@{ Dir = $work; Events = $events; Alerts = (Join-Path $work "missing.ndjson") }
    $lines = Get-VerdictLines @(Get-ScenarioVerdict -Agent $noAlerts -JobName "synthaea284")
    Assert-That "bits-job: no alerts file is a FAIL, not an error" ($lines[1] -eq "FAIL  one T1197 alert for payload284.exe: none") "got '$($lines[1])'"

    # -- windows-container.ps1 -------------------------------------------------------
    Import-ScenarioFunction "scenarios/windows-container.ps1" @("Get-ExecContainerId", "Get-ScenarioVerdict", "Write-ProvisionalSiloIds", "Get-ServerSiloIds")
    $execs = @(Read-AgentEvents -Path $events -Type "exec")
    $run = [pscustomobject]@{ Id = $containerId; HostPid = 11 }
    $records = @([pscustomobject]@{ Eid = 22; JobId = "220"; ContainerId = "x" })
    $containerLines = @(
        "PASS  exec events from the container carry its id: 2 event(s): cmd.exe, hostname.exe"
        "PASS  docker exec'd hostname.exe carries the container id: 1 event(s)"
        "PASS  the host's hostname.exe has no container: 1 event(s) for pid 11"
    )

    $verdict = @(Get-ScenarioVerdict -Execs $execs -Run $run -SiloIds @("220") -SiloRecords $records)
    $lines = Get-VerdictLines $verdict
    $expected = $containerLines + "PASS  the silo records' Job ID is the ServerSiloId the processes run in: ServerSiloId [220], Job IDs [220]"
    Assert-That "windows-container: every check passes" (($lines -join "`n") -eq ($expected -join "`n")) "got:`n$($lines -join "`n")"
    Assert-That "windows-container: verdict passes" (Test-VerdictPassed $verdict)

    $verdict = @(Get-ScenarioVerdict -Execs $execs -Run $run -SiloIds @("220", "221") -SiloRecords $records)
    $lines = Get-VerdictLines $verdict
    $expected = $containerLines + "FAIL  the silo records' Job ID is the ServerSiloId the processes run in: ServerSiloId [220,221], Job IDs [220]"
    Assert-That "windows-container: two silos fail the silo check" (($lines -join "`n") -eq ($expected -join "`n")) "got:`n$($lines -join "`n")"
    Assert-That "windows-container: verdict fails" (-not (Test-VerdictPassed $verdict))

    $info = @(& { Write-ProvisionalSiloIds $execs } 6>&1 | ForEach-Object { "$_" })
    Assert-That "windows-container: provisional silo ids line" ($info -join "`n" -eq "info: 1 exec event(s) carried a provisional silo:<n> id: ping.exe=silo:220") "got '$info'"

    $processes = @(
        [pscustomobject]@{ Name = "cmd.exe"; Pid = "40"; Silo = "220" }
        [pscustomobject]@{ Name = "ping.exe"; Pid = "41"; Silo = "220" }
        [pscustomobject]@{ Name = "smss.exe"; Pid = "42"; Silo = "0" }
        [pscustomobject]@{ Name = "gone.exe"; Pid = "43"; Silo = "open failed" }
    )
    $ids = @(Get-ServerSiloIds $processes)
    Assert-That "windows-container: ServerSiloIds are distinct, without 0 or failed queries" (($ids -join ",") -eq "220") "got [$($ids -join ',')]"
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures) {
    Write-Host "$failures check(s) failed"
    exit 1
}
