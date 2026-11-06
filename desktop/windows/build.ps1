param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [string]$Platform = "x64"
)

$ErrorActionPreference = "Stop"
& (Join-Path $PSScriptRoot 'restore-wireguard-nt.ps1')
if (-not $env:VCPKG_INSTALLATION_ROOT) {
    throw "Set VCPKG_INSTALLATION_ROOT to an existing vcpkg installation to restore the declared OpenSSL dependency."
}
$vcpkg = Join-Path $env:VCPKG_INSTALLATION_ROOT "vcpkg.exe"
if (-not (Test-Path -LiteralPath $vcpkg)) {
    throw "Set VCPKG_INSTALLATION_ROOT to an existing vcpkg installation to restore the declared OpenSSL dependency."
}
Push-Location $PSScriptRoot
try {
    & $vcpkg install --triplet x64-windows-static --disable-metrics
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL dependency restore failed." }
} finally { Pop-Location }
$solution = Join-Path $PSScriptRoot "TELIPHONES.sln"
$msbuild = Get-Command msbuild.exe -ErrorAction SilentlyContinue
if (-not $msbuild) {
    throw "MSBuild was not found. Open this script from a Visual Studio 2022 Developer PowerShell with the C++ and MFC components installed."
}

& $msbuild.Source $solution /m /p:Configuration=$Configuration /p:Platform=$Platform /verbosity:minimal
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "Application: $(Join-Path $PSScriptRoot "build\$Configuration\TELIPHONES.exe")"
Write-Host "Core tests:  $(Join-Path $PSScriptRoot "build\$Configuration\TeliphonesCoreTests.exe")"
Write-Host "Diagnostics tests: $(Join-Path $PSScriptRoot "build\$Configuration\SessionDiagnosticsTests.exe")"
