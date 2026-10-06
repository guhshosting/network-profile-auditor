$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
function Read-Json([string]$Exe, [string[]]$Arguments, [string]$Artifact) {
    $info = [System.Diagnostics.ProcessStartInfo]::new()
    $info.FileName = (Resolve-Path $Exe).Path
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false, $true)
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    $process = [System.Diagnostics.Process]::Start($info)
    $output = $process.StandardOutput.ReadToEnd()
    $errors = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0 -or $errors) { throw "JSON acquisition failed: $errors exit $($process.ExitCode)" }
    [IO.File]::WriteAllText((Join-Path $PWD "artifacts/$Artifact.json"), $output, [Text.UTF8Encoding]::new($false))
    $parsed = ConvertFrom-Json -InputObject $output
    $process.Dispose()
    foreach ($property in 'schema_version','application_version','networks','profiles','interfaces','correlations','findings','warnings','limitations') {
        if ($parsed.PSObject.Properties.Name -notcontains $property) { throw "Missing $property" }
    }
    if ($parsed.schema_version -ne '1.0' -or $parsed.application_version -ne '1.0.0') { throw 'Invalid versions' }
    foreach ($connection in $parsed.correlations) {
        if ($connection.interface_id -and @($parsed.interfaces.id) -notcontains $connection.interface_id) { throw 'Invalid interface reference' }
        if ($connection.network_id -and @($parsed.networks.id) -notcontains $connection.network_id) { throw 'Invalid network reference' }
    }
    return $parsed
}
$live = Read-Json 'build-release/network-profile-auditor.exe' @('--all','--json') 'live'
$current = Read-Json 'build-release/network-profile-auditor.exe' @('--json') 'current'
if (Test-Path 'install/bin/network-profile-auditor.exe') {
    $installed = Read-Json 'install/bin/network-profile-auditor.exe' @('--all','--json') 'installed'
    if (-not $installed.profile_api_available -or -not $installed.interface_api_available) { throw 'Installed acquisition unavailable' }
}
if (@($current.networks | Where-Object connected -EQ $false).Count) { throw 'Disconnected network in current selection' }
$fixture = Read-Json 'build-release/npa_tests.exe' @('--fixture-json') 'synthetic'
if ($fixture.profiles[0].name -ne "公共🌐`"`n" -or $fixture.interfaces[0].friendly_name -ne '以太网🚀') { throw 'Unicode/escape mismatch' }
if ($fixture.interfaces[0].luid -ne '18446744073709551615' -or $fixture.profiles[3].category_raw -ne 99) { throw 'Numeric fidelity failed' }
if ($fixture.correlations[4].adapter_id -ne $null -or $fixture.correlations[2].interface_id -ne $null) { throw 'Null metadata failed' }
"Independent JSON parser PASS; live networks=$(@($live.networks).Count), interfaces=$(@($live.interfaces).Count), correlations=$(@($live.correlations).Count); synthetic Unicode, escaping, nulls and 64-bit fidelity PASS" | Tee-Object artifacts/json-validation.txt
