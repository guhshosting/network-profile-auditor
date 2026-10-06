param(
    [string]$LLVM = 'C:\Program Files\LLVM\bin',
    [string]$Cppcheck = 'C:\Program Files\Cppcheck\cppcheck.exe'
)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
New-Item -ItemType Directory -Force artifacts | Out-Null
function Invoke-Logged([string]$Label, [string]$Command) {
    "COMMAND: $Command" | Set-Content "artifacts/$Label.txt"
    & $env:ComSpec /d /s /c "devcmd.cmd $Command" 2>&1 | Tee-Object -FilePath "artifacts/$Label.txt" -Append
    $resultCode = $LASTEXITCODE
    "EXIT: $resultCode" | Add-Content "artifacts/$Label.txt"
    if ($resultCode -ne 0) { throw "$Label failed ($resultCode)" }
}
foreach ($entry in @(
    @{ Name='debug'; Dir='build-msvc'; Flags='-DCMAKE_BUILD_TYPE=Debug' },
    @{ Name='release'; Dir='build-release'; Flags='-DCMAKE_BUILD_TYPE=Release' },
    @{ Name='independent'; Dir='build-independent'; Flags='-DCMAKE_BUILD_TYPE=Release' },
    @{ Name='analyze'; Dir='build-analyze'; Flags='-DCMAKE_BUILD_TYPE=Release -DNPA_ANALYZE=ON' },
    @{ Name='asan'; Dir='build-asan'; Flags='-DCMAKE_BUILD_TYPE=RelWithDebInfo -DNPA_ASAN=ON' }
)) {
    Invoke-Logged "$($entry.Name)-configure" "cmake -S . -B $($entry.Dir) -G Ninja $($entry.Flags)"
    Invoke-Logged "$($entry.Name)-build" "cmake --build $($entry.Dir)"
    Invoke-Logged "$($entry.Name)-ctest" "ctest --test-dir $($entry.Dir) --output-on-failure --timeout 30"
}
Invoke-Logged 'clang-configure' "cmake -S . -B build-clang -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_CXX_COMPILER=`"$LLVM/clang-cl.exe`""
Invoke-Logged 'clang-build' 'cmake --build build-clang'
Invoke-Logged 'clang-ctest' 'ctest --test-dir build-clang --output-on-failure --timeout 30'
foreach ($file in Get-ChildItem src,tests -Filter '*.cpp') {
    Invoke-Logged "tidy-$($file.BaseName)" "`"$LLVM/clang-tidy.exe`" -p build-clang $($file.FullName)"
}
Invoke-Logged 'cppcheck' "`"$Cppcheck`" --enable=warning,style,performance,portability --inconclusive --std=c++17 --platform=win64 --language=c++ --inline-suppr --suppress=missingIncludeSystem --error-exitcode=1 -I include -D_WIN32 -D_WIN32_WINNT=0x0A00 -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX src tests"
Invoke-Logged 'imports' 'dumpbin /imports build-release/network-profile-auditor.exe'
Invoke-Logged 'manifest' 'mt -inputresource:build-release/network-profile-auditor.exe;#1 -out:artifacts/manifest.xml'
Invoke-Logged 'install' 'cmake --install build-release --prefix install'
Invoke-Logged 'installed-version' 'install/bin/network-profile-auditor.exe --version'
Invoke-Logged 'nonadmin' 'build-release/npa_nonadmin.exe build-release/network-profile-auditor.exe'
& "$PSScriptRoot/verify-json.ps1"
& "$PSScriptRoot/audit-source.ps1"
