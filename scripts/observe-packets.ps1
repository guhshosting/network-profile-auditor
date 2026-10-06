# Validation only: bounded NIC counters, without packet payload capture.
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
$status = & pktmon status 2>&1
$status | Set-Content artifacts/packet-status-before.txt
if ($LASTEXITCODE -ne 0 -or ($status -join ' ') -notmatch 'not running') { throw 'Packet Monitor unavailable or an existing session is active; will not disturb it.' }
& pktmon filter list 2>&1 | Set-Content artifacts/packet-filters.txt
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect packet filters' }
& pktmon start --capture --counters-only --comp nics --file-size 16 --file-name artifacts/observation.etl 2>&1 | Set-Content artifacts/packet-start.txt
if ($LASTEXITCODE -ne 0) { throw 'Cannot start bounded observation' }
try {
    $start = [DateTime]::UtcNow
    foreach ($iteration in 1..5) {
        & ./build-release/network-profile-auditor.exe --all --json | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Auditor failed during observation' }
    }
    $end = [DateTime]::UtcNow
    "Five audits; start=$($start.ToString('o')); end=$($end.ToString('o')); elapsed_seconds=$(($end-$start).TotalSeconds)" | Set-Content artifacts/packet-window.txt
    & pktmon counters --json 2>&1 | Set-Content artifacts/packet-counters.json
} finally {
    & pktmon stop 2>&1 | Set-Content artifacts/packet-stop.txt
}
& pktmon status 2>&1 | Set-Content artifacts/packet-status-after.txt
