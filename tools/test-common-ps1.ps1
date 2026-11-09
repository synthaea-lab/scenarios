<#
.SYNOPSIS
    Checks the agent-harness helpers in scenarios/common.ps1 and that every
    tracked PowerShell script parses. Runs unprivileged on any pwsh (CI: Linux)
    and starts nothing: Start-ScenarioAgent is only driven to its first
    precondition.

        pwsh -NoProfile -File tools/test-common-ps1.ps1
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

$work = Join-Path ([IO.Path]::GetTempPath()) ("test-common-ps1-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
try {
    # The template the -AgentExe runs wrote inline before it moved to common.ps1;
    # the agent reads it, so a change here is a change to every lab run.
    $expected = @(
        "schema_version = 1"
        ""
        "[server]"
        "control_plane_url = `"https://cp.lab.invalid`""
        "mtls_cert = '$work\certs\client.crt'"
        "mtls_key = '$work\certs\client.key'"
        "mtls_passphrase = `"envvar:SYNTHAEA_MTLS_PASSPHRASE`""
        "offline_fallback = true"
        ""
        "[log]"
        "dir = '$work\logs'"
        "level = `"info`""
        "max_mb = 64"
        ""
        "[storage]"
        "state_dir = '$work\state'"
        "spool_max_mb = 64"
        ""
        "[ipc]"
        "endpoint = '\\.\pipe\synthaea-lab-test'"
        ""
        "[resources]"
        "worker_threads = 0"
        "max_reconnect_backoff_ms = 60000"
        ""
    ) -join "`n"
    $config = New-LabAgentConfig -Dir $work -PipeName "synthaea-lab-test"
    Assert-That "New-LabAgentConfig returns the agent.toml path" ($config -eq (Join-Path $work "agent.toml")) "got '$config'"
    # Line endings follow the platform and the checkout (.gitattributes: CRLF), not the template.
    $written = (Get-Content -LiteralPath $config -Raw) -replace "`r", ""
    Assert-That "New-LabAgentConfig writes the lab template" ($written -eq $expected) "got:`n$written"
    $bytes = [IO.File]::ReadAllBytes($config)
    Assert-That "agent.toml is ASCII" (@($bytes | Where-Object { $_ -gt 0x7F }).Count -eq 0)

    $missingExe = Join-Path $work "no-such-agent.exe"
    $runDir = Join-Path $work "run"
    $message = ""
    try { Start-ScenarioAgent -AgentExe $missingExe -Dir $runDir -PipeName "synthaea-lab-test" | Out-Null }
    catch { $message = $_.Exception.Message }
    Assert-That "Start-ScenarioAgent refuses a missing agent.exe" ($message -like "agent.exe not found at $missingExe*") "got '$message'"
    Assert-That "Start-ScenarioAgent creates nothing before its checks pass" (-not (Test-Path $runDir))

    $exec = '{"type":"exec","meta":{"pid":7,"comm":"hostname.exe","container":{"id":"silo:220"}}}' | ConvertFrom-Json
    $hostExec = '{"type":"exec","meta":{"pid":8,"comm":"hostname.exe"}}' | ConvertFrom-Json
    $container = Get-OptionalProperty $exec.meta "container"
    Assert-That "Get-OptionalProperty reads a present property" ((Get-OptionalProperty $container "id") -eq "silo:220")
    Assert-That "Get-OptionalProperty is null for an omitted property" ($null -eq (Get-OptionalProperty $hostExec.meta "container"))
    Assert-That "Get-OptionalProperty is null on a null object" ($null -eq (Get-OptionalProperty $null "id"))

    $threw = $false
    try { Stop-ScenarioAgent $null } catch { $threw = $true }
    Assert-That "Stop-ScenarioAgent without an agent is a no-op" (-not $threw)

    Assert-That "Get-RunDirectory keeps an explicit -OutDir" ((Get-RunDirectory -OutDir $runDir -Prefix "bits") -eq $runDir)
    $savedTemp = $env:TEMP
    try {
        $env:TEMP = $work
        $default = Get-RunDirectory -Prefix "bits"
    }
    finally { $env:TEMP = $savedTemp }
    # Join-Path turns the backslash into / on Linux.
    $defaultShape = ($default -replace '\\', '/') -like (($work -replace '\\', '/') + "/synthaea-lab-validation/bits-*")
    Assert-That "Get-RunDirectory defaults under %TEMP%\synthaea-lab-validation" $defaultShape "got '$default'"
    Assert-That "Get-RunDirectory creates nothing" (-not (Test-Path (Join-Path $work "synthaea-lab-validation*")))

    $eventsFile = Join-Path $work "events.jsonl"
    @(
        '{"type":"exec","meta":{"pid":1}}'
        '{"type":"exec_args","meta":{"pid":2}}'
        '{"type":"bits_job","job_title":"j"}'
        '{"type":"exec","meta":{"pid":3}}'
    ) | Set-Content -LiteralPath $eventsFile
    $read = @(Read-AgentEvents -Path $eventsFile -Type "exec")
    Assert-That "Read-AgentEvents keeps only events of the exact type" (($read | ForEach-Object { $_.meta.pid }) -join "," -eq "1,3") "got $($read.Count) event(s)"

    $results = @(
        [pscustomobject]@{ Check = "first"; Pass = $true; Detail = "fine" }
        [pscustomobject]@{ Check = "second"; Pass = $false; Detail = "0 event(s)" }
    )
    $printed = @(& { Write-Verdict $results } 6>&1 | ForEach-Object { "$_" })
    Assert-That "Write-Verdict prints one PASS/FAIL line per result" (($printed -join "|") -eq "PASS  first: fine|FAIL  second: 0 event(s)") "got '$($printed -join '|')'"
    $returned = @(& { Write-Verdict $results } 6>$null)
    Assert-That "Write-Verdict returns nothing" ($returned.Count -eq 0)
    $quiet = @(& { Test-VerdictPassed $results } 6>&1)
    Assert-That "Test-VerdictPassed prints nothing and fails on one FAIL" (($quiet.Count -eq 1) -and ($quiet[0] -eq $false))
    Assert-That "Test-VerdictPassed passes when every result passes" (Test-VerdictPassed @($results[0]))
    Assert-That "Test-VerdictPassed passes on no results" (Test-VerdictPassed @())
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Push-Location $repo
try { $scripts = @(git ls-files "*.ps1" "*.psm1" "*.psd1") } finally { Pop-Location }
foreach ($script in $scripts) {
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repo $script), [ref]$null, [ref]$errors)
    Assert-That "$script parses" (@($errors).Count -eq 0) (($errors | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" }) -join "; ")
}

# Every scenario declares its parameters (so a typo in a switch fails instead of
# being ignored) and runs under strict mode. common.ps1 is dot-sourced: it
# inherits the caller's.
foreach ($script in ($scripts | Where-Object { $_ -like "scenarios/*.ps1" -and $_ -ne "scenarios/common.ps1" })) {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repo $script), [ref]$null, [ref]$null)
    $binding = $ast.ParamBlock -and @($ast.ParamBlock.Attributes | Where-Object { $_.TypeName.Name -eq "CmdletBinding" }).Count -eq 1
    Assert-That "$script has a [CmdletBinding()] param block" $binding
    $strict = @($ast.EndBlock.Statements | Where-Object { $_.Extent.Text -eq "Set-StrictMode -Version Latest" }).Count -eq 1
    Assert-That "$script sets Set-StrictMode -Version Latest at top level" $strict
}

if ($failures) {
    Write-Host "$failures check(s) failed"
    exit 1
}
