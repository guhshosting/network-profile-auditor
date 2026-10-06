$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
$forbidden = '\b(socket|WSASocket[AW]?|connect|WSAConnect|send|sendto|recv|recvfrom|getaddrinfo|GetAddrInfo[AW]?|DnsQuery\w*|IcmpSend\w*|WinHttp\w*|InternetOpen\w*|URLDownload\w*|Wlan\w*|SetCategory|SetIfEntry\w*|SetIp\w*|CreateIp\w*|DeleteIp\w*|RegSet\w*|RegCreate\w*|RegDelete\w*|StartService\w*|ControlService\w*|CreateProcess\w*|ShellExecute\w*|system|_wsystem)\s*\('
$violations = & rg -n $forbidden src include
if ($LASTEXITCODE -ne 1) { throw "Forbidden API search failed or matched: $violations" }
$dlls = Select-String -Path artifacts/imports.txt -Pattern '^\s+\S+\.dll\s*$' -CaseSensitive:$false
"Application source forbidden-API search: PASS`nDirect imported DLLs:`n$($dlls.Line -join "`n")`nManual review required for COM getters and application output APIs; this is not packet-level proof." | Set-Content artifacts/source-audit.txt
