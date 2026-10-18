<#
.SYNOPSIS
  Demo of scenarios A/B/C, offline pinned verification and tamper detection.
.DESCRIPTION
  Starts ONE service (java or python) as a real process on a synthetic temporary
  database, drives it over HTTP, verifies an export offline with the pinned public
  key using the independent Python verifier, then tampers with the SQLite file while
  the service is stopped and shows the detection after restart.
  Uses only synthetic data and the documented dev API keys. Nothing is pushed or published.
.EXAMPLE
  .\scripts\demo.ps1 -Service python
  .\scripts\demo.ps1 -Service java     # needs: mvn -f java/pom.xml package
#>
param(
    [ValidateSet('python', 'java')][string]$Service = 'python',
    [int]$Port = 18080,
    [string]$WorkDir = ''
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $WorkDir) { $WorkDir = [IO.Path]::GetTempPath() }
$py = Join-Path $root 'python\.venv\Scripts\python.exe'
if (-not (Test-Path $py)) { $py = 'python' }
$jar = Join-Path $root 'java\target\audit-log-service-0.1.0-SNAPSHOT.jar'
$home_ = Join-Path $WorkDir ("audit-demo-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force "$home_\tmp" | Out-Null
$base = "http://127.0.0.1:$Port"
$script:proc = $null

$env:AUDIT_ENV = 'dev'; $env:AUDIT_LEDGER_ID = 'synthetic-demo-ledger'
$env:AUDIT_DB_PATH = "$home_\audit.db"
$env:AUDIT_SIGNING_PRIVATE_KEY = "$home_\keys\private.pem"
$env:AUDIT_SIGNING_PUBLIC_KEY = "$home_\keys\public.b64"
$env:AUDIT_ARCHIVE_DIR = "$home_\archives"; $env:AUDIT_EXPORT_DIR = "$home_\exports"

function Start-Service-Process {
    if ($Service -eq 'java') {
        if (-not (Test-Path $jar)) { throw "Build the jar first: mvn -f java/pom.xml package" }
        $script:proc = Start-Process java -PassThru -WindowStyle Hidden `
            -ArgumentList "-Djava.io.tmpdir=$home_\tmp", '-jar', $jar, "--server.port=$Port" `
            -RedirectStandardOutput "$home_\service.out" -RedirectStandardError "$home_\service.err"
    } else {
        $script:proc = Start-Process $py -PassThru -WindowStyle Hidden -WorkingDirectory (Join-Path $root 'python') `
            -ArgumentList '-m', 'uvicorn', 'audit_log_service.app:create_app', '--factory', '--host', '127.0.0.1', '--port', $Port `
            -RedirectStandardOutput "$home_\service.out" -RedirectStandardError "$home_\service.err"
    }
    for ($i = 0; $i -lt 240; $i++) {
        if ($script:proc.HasExited) { throw "service exited at startup; see $home_\service.err" }
        try { Invoke-RestMethod "$base/health" | Out-Null; return } catch { Start-Sleep -Milliseconds 500 }
    }
    throw "service did not become healthy; see $home_\service.err"
}
function Stop-ServiceProcess {
    if ($script:proc -and -not $script:proc.HasExited) { $script:proc.Kill(); $script:proc.WaitForExit() }
}
function Call($method, $path, $key, $body) {
    $args_ = @{ Method = $method; Uri = "$base$path"; Headers = @{ 'X-API-Key' = $key } }
    if ($body) { $args_.Body = ($body | ConvertTo-Json -Depth 8); $args_.ContentType = 'application/json' }
    Invoke-RestMethod @args_
}
function Verify-Offline($file, $key) {
    & $py -m audit_log_service.verifier --bundle $file --pinned-key $key
    return $LASTEXITCODE
}

try {
    Write-Host "== Starting $Service service (home: $home_)"
    Start-Service-Process
    $pinned = (Invoke-RestMethod "$base/audit/public-key").publicKey
    Write-Host "Pinned public key (obtained out of band in a real deployment): $pinned"

    Write-Host "`n== Scenario A: append / query / verify"
    1..5 | ForEach-Object {
        Call POST '/audit/events' 'dev-writer-only' @{ eventType = 'DOCUMENT_VIEWED'; actorId = 'alice'; resourceType = 'DOCUMENT'; resourceId = "doc-$_"; payload = @{ note = "secret-$_" } } | Out-Null
    }
    $page = Call GET '/audit/events?limit=2' 'dev-reader-only'
    Write-Host "first page seqs: $(($page.items | ForEach-Object seq) -join ',')  nextCursor present: $([bool]$page.nextCursor)"
    $v = Call GET '/audit/verify' 'dev-auditor-only'
    Write-Host "verify: intact=$($v.intact) headSeq=$($v.headSeq)"

    Write-Host "`n== Scenario B: redact, export, offline verify"
    $first = (Call GET '/audit/events?limit=1&order=asc' 'dev-reader-only').items[0]
    $r = Call POST '/audit/admin/redactions' 'dev-admin-only' @{ eventId = $first.eventId; paths = @('/note'); reason = 'demo'; ticketId = 'DEMO-1' }
    Write-Host "redaction cleanupStatus=$($r.cleanupStatus)"
    $bundle = "$home_\bundle.json"
    $resp = Invoke-WebRequest "$base/audit/export?actorId=alice" -Headers @{ 'X-API-Key' = 'dev-auditor-only' } -UseBasicParsing
    [IO.File]::WriteAllBytes($bundle, $resp.RawContentStream.ToArray())
    $code = Verify-Offline $bundle $pinned
    Write-Host "offline verify with pinned key -> exit $code (0 = verified)"

    Write-Host "`n== Scenario C: account access report"
    foreach ($o in @(@{ outcome = 'GRANTED' }, @{ outcome = 'DENIED'; denialReason = 'no entitlement' })) {
        $payload = @{ dataCategory = 'BALANCES'; accessType = 'VIEW'; accessPurpose = 'SERVICING'; channel = 'API' } + $o
        Call POST '/audit/events' 'dev-writer-only' @{ eventType = 'ACCOUNT_DATA_ACCESS'; actorId = 'bob'; resourceType = 'CLIENT_ACCOUNT'; resourceId = 'acct-1'; payload = $payload } | Out-Null
    }
    $year = (Get-Date).Year
    $report = Call GET "/compliance/account-access-report?accountId=acct-1&from=$($year - 1)-01-01T00:00:00Z&to=$($year + 1)-01-01T00:00:00Z" 'dev-auditor-only'
    Write-Host "report trustworthy=$($report.trustworthy) label=$($report.trustLabel)"

    Write-Host "`n== Tamper: stop service, edit the SQLite file, restart"
    Stop-ServiceProcess
    & $py (Join-Path $root 'scripts\synthetic_tamper.py') "$home_\audit.db" edit-field --seq 3 --i-understand-this-is-synthetic-data
    Start-Service-Process
    $v = Call GET '/audit/verify' 'dev-auditor-only'
    Write-Host "verify after tamper: intact=$($v.intact) firstViolation=$($v.firstViolation | ConvertTo-Json -Compress)"
    $v.violations | ForEach-Object { Write-Host "  $($_.type) seq=$($_.seq)" }
    if ($v.intact) { throw 'tampering was NOT detected' }
    Write-Host "`nDemo complete. Synthetic data left in $home_"
} finally {
    Stop-ServiceProcess
}
