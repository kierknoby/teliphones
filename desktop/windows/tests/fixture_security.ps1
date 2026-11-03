param(
    [Parameter(Mandatory)][ValidateSet('File', 'Task')][string]$Kind,
    [Parameter(Mandatory)][string]$Target,
    [string]$UserSid
)
$ErrorActionPreference = 'Stop'
if ($Kind -eq 'File') {
    $acl = Get-Acl -LiteralPath $Target
    [ordered]@{
        owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        protected = $acl.AreAccessRulesProtected
        sddl = $acl.Sddl
        rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {
            [ordered]@{
                sid = $_.IdentityReference.Value
                allow = $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow
                inherited = $_.IsInherited
                mask = [int]$_.FileSystemRights
                inheritance = [int]$_.InheritanceFlags
                propagation = [int]$_.PropagationFlags
            }
        })
    } | ConvertTo-Json -Depth 5 -Compress
} else {
    if ($Target -notmatch '^TELIPHONES-sshd-test-[a-f0-9]{16}$' -or
        $UserSid -notmatch '^S-1-5-21-(\d+-){3}\d+$') {
        throw 'Refusing to alter a task outside the uniquely owned fixture namespace.'
    }
    $scheduler = New-Object -ComObject 'Schedule.Service'
    $scheduler.Connect()
    $task = $scheduler.GetFolder('\').GetTask($Target)
    $expected = "O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;$UserSid)"
    try {
        # TASK_DONT_ADD_PRINCIPAL_ACE: SYSTEM already has an explicit grant.
        $task.SetSecurityDescriptor($expected, 0x10)
    } catch {
        Write-Host "Expected task SDDL: $expected"
        Write-Host "Observed task SDDL: $($task.GetSecurityDescriptor(7))"
        throw
    }
    $sddl = $task.GetSecurityDescriptor(7)
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($sddl)
    $principalSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    if ($task.Definition.Principal.UserId -ne $principalSid.Value) {
        $account = [Security.Principal.NTAccount]::new($task.Definition.Principal.UserId)
        $principalSid = $account.Translate([Security.Principal.SecurityIdentifier])
    }
    [ordered]@{
        owner = $descriptor.Owner.Value
        protected = ($descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -ne 0
        sddl = $sddl
        principal = $principalSid.Value
        logon_type = [int]$task.Definition.Principal.LogonType
        run_level = [int]$task.Definition.Principal.RunLevel
        rules = @($descriptor.DiscretionaryAcl | ForEach-Object {
            [ordered]@{
                sid = $_.SecurityIdentifier.Value
                allow = $_.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessAllowed
                inherited = ($_.AceFlags -band [Security.AccessControl.AceFlags]::Inherited) -ne 0
                mask = $_.AccessMask
                inheritance = [int]($_.AceFlags -band 3)
                propagation = [int]($_.AceFlags -band 12)
            }
        })
    } | ConvertTo-Json -Depth 5 -Compress
}
