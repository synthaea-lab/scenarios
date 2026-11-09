<#
.SYNOPSIS
    Helpers shared by the Windows scenarios, dot-sourced by each of them.

.DESCRIPTION
    Every .ps1 here and in the agent repo's demo/ must run on a stock Windows PowerShell 5.1
    under any locale (#433), which rules out three things:
      - Non-ASCII characters. PowerShell 5.1 reads a BOM-less file as the ANSI
        code page, and an em dash decodes to a closing smart quote that breaks
        parsing. The scripts stay ASCII-only (tools/check-ps1-ascii.py).
      - Locale-formatted literals. `schtasks /SD 12/31/2099` is rejected on a
        French locale ("date de debut incorrecte"); use Get-FarFutureDate.
      - Unchecked native calls. A scenario that prints "created" after the tool
        failed cannot validate a detection; use Invoke-Native.
      - Native prompts. Invoke-Native feeds the tool one empty line and closes
        its stdin, so a prompt gets Enter instead of waiting forever on a
        console whose output goes to Out-Null. A tool that needs real input
        then fails loudly rather than hanging: `schtasks /Change` asks for the
        run-as password even with /IT or /RU, hung the first cut of the
        task-hijack scenario, and rejects the empty line (lab, fr-FR,
        2026-09-25). Rewrite a task's action with Set-ScheduledTask instead.
#>

function Invoke-Native {
    <#
    .SYNOPSIS
        Runs a native tool with one empty line on stdin, discards its output,
        throws on a non-zero exit code. Arguments listed in -Redact (e.g. a password) show as
        *** in the error.
    #>
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @(),
        [string[]]$Redact = @()
    )
    "" | & $FilePath @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        $shown = $Arguments | ForEach-Object { if ($Redact -contains $_) { "***" } else { $_ } }
        throw "$FilePath $($shown -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Invoke-NativeCleanup {
    <#
    .SYNOPSIS
        Cleanup counterpart of Invoke-Native: warns instead of throwing, so one
        failed delete in a `finally` block does not skip the remaining ones.
    #>
    param(
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @()
    )
    "" | & $FilePath @Arguments | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  deleted $Description"
    }
    else {
        Write-Warning "could not delete $Description ($FilePath exit code $LASTEXITCODE), remove it by hand"
    }
}

function Get-FarFutureDate {
    <#
    .SYNOPSIS
        A date 70 years out, in the current culture's short date format, which
        is what `schtasks /SD` parses (lab, fr-FR, 2026-09-25: dd/MM/yyyy).
    #>
    (Get-Date).AddYears(70).ToString((Get-Culture).DateTimeFormat.ShortDatePattern)
}

# -- Agent harness: the -AgentExe self-checking runs -----------------------------

function Assert-Administrator {
    <#
    .SYNOPSIS
        Throws $Message unless this PowerShell runs elevated.
    #>
    param([Parameter(Mandatory)][string]$Message)
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw $Message
    }
}

function New-LabAgentConfig {
    <#
    .SYNOPSIS
        Writes an offline lab agent.toml into $Dir, keeping certs, logs and state
        under it, with its IPC endpoint at \\.\pipe\$PipeName. Returns its path.
    #>
    param(
        [Parameter(Mandatory)][string]$Dir,
        [Parameter(Mandatory)][string]$PipeName
    )
    $config = Join-Path $Dir "agent.toml"
    # Same template as rig\runner\windows\validate-admin.ps1: offline, nothing
    # outside the run directory.
    @"
schema_version = 1

[server]
control_plane_url = "https://cp.lab.invalid"
mtls_cert = '$Dir\certs\client.crt'
mtls_key = '$Dir\certs\client.key'
mtls_passphrase = "envvar:SYNTHAEA_MTLS_PASSPHRASE"
offline_fallback = true

[log]
dir = '$Dir\logs'
level = "info"
max_mb = 64

[storage]
state_dir = '$Dir\state'
spool_max_mb = 64

[ipc]
endpoint = '\\.\pipe\$PipeName'

[resources]
worker_threads = 0
max_reconnect_backoff_ms = 60000
"@ | Set-Content -LiteralPath $config -Encoding Ascii
    $config
}

function Start-ScenarioAgent {
    <#
    .SYNOPSIS
        Starts $AgentExe on a fresh lab config in $Dir (created if missing) and
        waits until its ETW trace runs. Returns { Process, Dir, Events, Alerts }
        for Stop-ScenarioAgent and the scenario's checks. The caller asserts
        elevation first (Assert-Administrator).
    #>
    param(
        [Parameter(Mandatory)][string]$AgentExe,
        [Parameter(Mandatory)][string]$Dir,
        [Parameter(Mandatory)][string]$PipeName
    )
    if (-not (Test-Path $AgentExe)) { throw "agent.exe not found at $AgentExe (cargo build --release -p agent)" }
    if (Get-Process -Name "agent" -ErrorAction SilentlyContinue) {
        throw "An agent.exe is already running; stop it first (this run starts its own)."
    }
    $exe = (Resolve-Path $AgentExe).Path
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    $Dir = (Resolve-Path $Dir).Path
    $config = New-LabAgentConfig -Dir $Dir -PipeName $PipeName
    $events = Join-Path $Dir "events.jsonl"
    $alerts = Join-Path $Dir "alerts.ndjson"
    $agentArgs = @("--config", "`"$config`"", "run", "--alerts", "`"$alerts`"", "--events", "`"$events`"")
    $proc = Start-Process -FilePath $exe -ArgumentList $agentArgs -WorkingDirectory $Dir `
        -RedirectStandardOutput "$Dir\stdout.log" -RedirectStandardError "$Dir\stderr.log" `
        -WindowStyle Hidden -PassThru
    Write-Host "agent started (pid $($proc.Id)), output in $Dir"
    # Ready once the first event lands: the pid store is seeded and the trace runs.
    $deadline = (Get-Date).AddSeconds(30)
    while (-not ((Test-Path $events) -and (Get-Item $events).Length -gt 0)) {
        if ($proc.HasExited) { throw "the agent exited at startup; see $Dir\stderr.log" }
        if ((Get-Date) -gt $deadline) { throw "the agent produced no events in 30s; see $Dir\stderr.log" }
        Start-Sleep -Milliseconds 500
    }
    # The Event Log sensor keeps writing events when ETW is down, so the first
    # event alone does not prove the trace is up.
    Start-Sleep -Seconds 2
    if ((Get-Content -LiteralPath "$Dir\stderr.log" -Raw -ErrorAction SilentlyContinue) -match "ETW sensor failed") {
        Stop-Process -Id $proc.Id -Force
        throw "the agent's ETW sensor failed to start; see $Dir\stderr.log"
    }
    [pscustomobject]@{ Process = $proc; Dir = $Dir; Events = $events; Alerts = $alerts }
}

function Stop-ScenarioAgent {
    <#
    .SYNOPSIS
        Kills an agent Start-ScenarioAgent started and waits up to 10 s for it to
        exit. A $null $Agent (no -AgentExe run) is a no-op.
    #>
    param($Agent)
    if ($Agent -and -not $Agent.Process.HasExited) {
        Stop-Process -Id $Agent.Process.Id -Force
        $Agent.Process.WaitForExit(10000) | Out-Null
    }
}
