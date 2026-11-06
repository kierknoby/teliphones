$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'This privileged fixture provisions only an ephemeral GitHub-hosted Windows runner, never a workstation.'
}
$installerSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../src/platform/WireGuardInstaller.cpp') -Raw
$hostName = [regex]::Match($installerSource, 'kHost\[\] = L"([^"]+)"').Groups[1].Value
$path = [regex]::Match($installerSource, 'kPath\[\] = L"([^"]+)"').Groups[1].Value
$sha256 = [regex]::Match($installerSource, 'kSha256\[\] = "([0-9a-f]{64})"').Groups[1].Value
if (-not $hostName -or -not $path -or -not $sha256) { throw 'Cannot read reviewed production WireGuard installer pin.' }
$msi = Join-Path $env:RUNNER_TEMP 'TELIPHONES-WireGuard-fixture.msi'
try {
    Invoke-WebRequest -Uri "https://$hostName$path" -OutFile $msi -MaximumRedirection 0
    if ((Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash -ine $sha256) {
        throw 'Official WireGuard fixture installer hash mismatch.'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $msi
    if ($signature.Status -ne 'Valid' -or
        $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -ne 'WireGuard LLC') {
        throw 'Official WireGuard fixture installer signature/publisher verification failed.'
    }
    $process = Start-Process msiexec.exe -ArgumentList @('/i', "`"$msi`"", '/qn', '/norestart') -PassThru -Wait
    if ($process.ExitCode -ne 0) { throw "WireGuard fixture install failed or needs reboot: $($process.ExitCode)" }
    $exe = Join-Path $env:ProgramFiles 'WireGuard/wireguard.exe'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'Official tunnel service executable missing after fixture install.' }
    $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($exe)
    if ($version.ProductVersion -notmatch '^1\.1\.1(?:\.0)?$') { throw "Unexpected official WireGuard fixture version: $($version.ProductVersion)" }
    Write-Host "Official WireGuard fixture: $($version.ProductVersion); installer SHA256 $sha256"
} finally {
    if (Test-Path -LiteralPath $msi) { Remove-Item -LiteralPath $msi }
}
