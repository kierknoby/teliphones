"""Diagnostic-only Windows PowerShell module probes, independent of security tests."""
import json
import os
from pathlib import Path
import subprocess


def main():
    if os.name != "nt":
        raise RuntimeError("PowerShell environment diagnostics require actual Windows.")
    executable = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    names = ("PSModulePath", "PSHOME", "PSExecutionPolicyPreference", "POWERSHELL_DISTRIBUTION_CHANNEL")
    print("Inherited PowerShell discovery environment: " +
          json.dumps({name: os.environ.get(name) for name in names}), flush=True)
    print("Exact child executable: " + str(executable), flush=True)
    script = r"""
$ErrorActionPreference = 'Stop'
Write-Output ("PSHOME=" + $PSHOME)
Write-Output ("PSModulePath=" + $env:PSModulePath)
Write-Output ("Edition=" + $PSVersionTable.PSEdition + "; version=" + $PSVersionTable.PSVersion)
$failed = $false
foreach ($probe in @(
    @{ Module = 'Microsoft.PowerShell.Security'; Command = 'Get-Acl' },
    @{ Module = 'Microsoft.PowerShell.Utility'; Command = 'Get-FileHash' }
)) {
    try {
        Write-Output ("Probing " + $probe.Module + "/" + $probe.Command)
        Get-Module -ListAvailable $probe.Module |
            Select-Object Name, Version, Path | Format-List | Out-String | Write-Output
        Import-Module $probe.Module -ErrorAction Stop
        $command = Get-Command $probe.Command -ErrorAction Stop
        Write-Output ("Resolved " + $probe.Command + ": " + $command.Source)
    } catch {
        $failed = $true
        Write-Output ("ErrorId=" + $_.FullyQualifiedErrorId)
        Write-Output $_.Exception.ToString()
    }
}
if ($failed) { exit 1 }
exit 0
"""
    results = {}
    for mode in ("inherited", "discovery-reset"):
        environment = os.environ.copy()
        if mode == "discovery-reset":
            for name in list(environment):
                if name.casefold() in ("psmodulepath", "pshome"):
                    del environment[name]
        try:
            result = subprocess.run([str(executable), "-NoLogo", "-NoProfile", "-NonInteractive",
                                     "-Command", script], env=environment, capture_output=True,
                                    text=True, timeout=30, errors="replace")
            results[mode] = result.returncode
            print(f"{mode}: exit={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}", flush=True)
        except (OSError, subprocess.TimeoutExpired) as error:
            results[mode] = str(error)
            print(f"{mode}: process launch/probe failure: {error}", flush=True)
    print("Diagnostic results (not ACL test results): " + json.dumps(results), flush=True)
    if results.get("inherited") == 1 and results.get("discovery-reset") == 0:
        print("This runner demonstrates an inherited module-discovery environment problem.", flush=True)
    else:
        print("Do not infer the original runner's cause from these results; inspect the recorded exceptions.", flush=True)


if __name__ == "__main__":
    main()
