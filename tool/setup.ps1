# One-time host setup for running the litert_crypto CLI (or `flutter test`)
# on Windows x64. The first run compiles BoringSSL through package:webcrypto's
# build hook, and that build assembles x64 sources with NASM — this script
# checks for NASM, installs it via winget if missing, and repairs PATH.
#
#   powershell -ExecutionPolicy Bypass -File tool/setup.ps1
#
# Background: litert_crypto_docs/host-build-nasm.md

$ErrorActionPreference = 'Stop'

function Find-Nasm {
    $cmd = Get-Command nasm -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    # winget's NASM.NASM installs per-user by default; older installers used
    # Program Files. Check both before declaring it absent.
    $candidates = @(
        (Join-Path $env:LOCALAPPDATA 'bin\NASM\nasm.exe'),
        (Join-Path $env:ProgramFiles 'NASM\nasm.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'NASM\nasm.exe')
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) { return $c }
    }
    return $null
}

$nasm = Find-Nasm

if (-not $nasm) {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Error ("NASM not found, and winget is unavailable to install it. " +
            "Install NASM from https://www.nasm.us, then re-run this script to fix PATH.")
    }
    Write-Host 'NASM not found — installing with winget (NASM.NASM)...'
    winget install --id NASM.NASM --exact --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -ne 0) {
        Write-Error "winget install exited with code $LASTEXITCODE."
    }
    $nasm = Find-Nasm
    if (-not $nasm) {
        Write-Error ("NASM was installed but nasm.exe was not found in the usual " +
            "locations. Find its folder and add it to PATH manually.")
    }
}

$nasmDir = Split-Path $nasm

# The installer does not always register PATH; do it ourselves (user scope).
if (-not (Get-Command nasm -ErrorAction SilentlyContinue)) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (($userPath -split ';') -notcontains $nasmDir) {
        [Environment]::SetEnvironmentVariable('Path', "$userPath;$nasmDir", 'User')
        Write-Host "Added $nasmDir to your user PATH."
    }
    $env:Path = "$env:Path;$nasmDir"
}

& $nasm -v
Write-Host ''
Write-Host 'NASM is ready. Open a NEW terminal (already-open ones do not see PATH'
Write-Host 'changes), then re-run your dart/flutter command.'
