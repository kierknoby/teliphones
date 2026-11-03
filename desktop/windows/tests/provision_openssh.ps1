$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

if (-not [Environment]::Is64BitProcess) {
    throw 'OpenSSH provisioning requires 64-bit PowerShell to avoid System32 redirection.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Official OpenSSH capability installation and isolated SYSTEM fixture require an elevated runner.'
}
foreach ($tool in @('python.exe', 'cmake.exe', 'ctest.exe', 'icacls.exe', 'schtasks.exe', 'whoami.exe')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "Windows test tool missing: $tool. Use the supported windows-2022 image."
    }
}
if ((Get-Service Schedule).Status -ne 'Running') {
    throw 'Task Scheduler must be running to launch the isolated SYSTEM sshd fixture.'
}
Write-Host "Runner OS: $([Environment]::OSVersion.VersionString); identity: $($identity.Name); elevated x64 process."
try {
    Import-Module Dism
    Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*' |
        Format-Table Name, State | Out-Host
    foreach ($name in @('OpenSSH.Client~~~~0.0.1.0', 'OpenSSH.Server~~~~0.0.1.0')) {
        $capability = Get-WindowsCapability -Online -Name $name
        if ($capability.Name -ne $name) {
            throw "Windows servicing did not enumerate required capability $name."
        }
        if ($capability.State -ne 'Installed') {
            Write-Host "Installing official Windows capability $name via Windows servicing."
            $result = Add-WindowsCapability -Online -Name $name
            $result | Format-List Path, Online, RestartNeeded | Out-Host
            if ($result.RestartNeeded) {
                throw "Capability $name requires a reboot; this job cannot validate it before reboot."
            }
        }
        $verified = Get-WindowsCapability -Online -Name $name
        if ($verified.State -ne 'Installed') {
            throw "Capability $name remains $($verified.State) after installation."
        }
    }
} catch {
    $failure = $_
    if ($env:STARTUP_DIAGNOSTICS) {
        foreach ($log in @("$env:SystemRoot\Logs\DISM\dism.log", "$env:SystemRoot\Logs\CBS\CBS.log")) {
            if (Test-Path -LiteralPath $log) {
                Get-Content -LiteralPath $log -Tail 160 |
                    Set-Content -LiteralPath (Join-Path $env:STARTUP_DIAGNOSTICS ([IO.Path]::GetFileName($log)))
            }
        }
    }
    throw "Official OpenSSH capability provisioning failed: $($failure.Exception.Message) (HRESULT $($failure.Exception.HResult)). Inspect DISM/CBS diagnostics. No alternate package was downloaded. A version-pinned official Microsoft Win32-OpenSSH package URL and trusted SHA256 would require separate approval."
}

$openSsh = Join-Path $env:SystemRoot 'System32\OpenSSH'
foreach ($name in @('ssh.exe', 'ssh-keygen.exe', 'sshd.exe')) {
    $path = Join-Path $openSsh $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Capability reports Installed but executable is absent: $path"
    }
    $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($path)
    Write-Host "$name file version: $($version.FileVersion); SHA256: $((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash)"
}
$env:PATH = "$openSsh;$env:PATH"
$openSsh >> $env:GITHUB_PATH
# Older Windows sshd has no -V: -? executes its loader and prints version/usage.
foreach ($probe in @(
    @{ File = 'ssh.exe'; Arguments = @('-V'); Pattern = 'OpenSSH' },
    @{ File = 'sshd.exe'; Arguments = @('-?'); Pattern = 'OpenSSH|usage: sshd' },
    @{ File = 'ssh-keygen.exe'; Arguments = @('-?'); Pattern = 'usage: ssh-keygen' }
)) {
    $path = Join-Path $openSsh $probe.File
    $probeArguments = $probe.Arguments
    $output = (& $path @probeArguments 2>&1 | Out-String)
    $code = $LASTEXITCODE
    if ($code -notin @(0, 1, 255) -or $output -notmatch $probe.Pattern) {
        throw "$path cannot execute correctly (exit $code): $output"
    }
    if ($probe.File -eq 'ssh-keygen.exe' -and ($output -notmatch '-Y sign' -or $output -notmatch '-Y verify')) {
        throw "The installed Windows ssh-keygen lacks required SSHSIG support: $output. An approved newer, version-pinned official Microsoft distribution is required; no alternate download was attempted."
    }
    Write-Host "$($probe.File) loader probe (exit $code): $($output.Trim())"
}
Write-Host 'Official client/server capabilities installed and executable. No sshd/ssh-agent service was started or enabled; tests use a unique temporary SYSTEM task and loopback config.'
$global:LASTEXITCODE = 0
