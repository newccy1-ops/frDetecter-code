param([switch]$InstallPackages)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$dependencies = Join-Path $root 'dependencies'
New-Item -ItemType Directory -Path $dependencies -Force | Out-Null
$archive = Join-Path $dependencies 'msys2-base-x86_64-20260927.sfx.exe'
$bash = Join-Path $dependencies 'msys64\usr\bin\bash.exe'
if (-not (Test-Path -LiteralPath $bash)) {
    if (-not (Test-Path -LiteralPath $archive)) {
        Invoke-WebRequest -Uri 'https://repo.msys2.org/distrib/x86_64/msys2-base-x86_64-20260927.sfx.exe' -OutFile $archive -TimeoutSec 300
    }
    Write-Output ('Downloaded archive SHA256: ' + (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash)
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne 'AD336CCCFDA47758B5E15CDA993FBBA421115CB0B126697DAEF1EE4DFE37209F') {
        throw 'MSYS2 archive hash differs from the pinned downloaded version'
    }
    & $archive '-y' ('-o' + $dependencies)
    if ($LASTEXITCODE -ne 0) { throw 'MSYS2 extraction failed' }
}
$env:MSYSTEM = 'MSYS'
$env:CHERE_INVOKING = '1'
& $bash -lc 'true'
if ($LASTEXITCODE -ne 0) { throw 'MSYS2 initialization failed' }
if ($InstallPackages) {
    # Isolated workspace prefix: no global PATH/registry/WSL changes.
    $configUnix = '/' + $root.Substring(0,1).ToLower() + $root.Substring(2).Replace('\','/') + '/msys-pacman.conf'
    & $bash -lc 'pacman --config "$1" --noconfirm -Sy --needed gcc make cmake gmp-devel openssl-devel git patch' '--' $configUnix
    if ($LASTEXITCODE -ne 0) { throw 'MSYS2 dependency installation failed' }
}
Write-Output ('Portable bash: ' + $bash)
