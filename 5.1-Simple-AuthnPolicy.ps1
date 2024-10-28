<#
    Engineering Active Directory by Evgenij Smirnov
    Chapter 5: Engineering Authentication
    Code 5.1:  Create a simple Authentication Policy
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$PolicyName,
    [Parameter(Mandatory=$false)]
    [ValidateRange(10,65535)]
    [int]$TGTLifeTimeMinutes = 240,
    [Parameter(Mandatory=$true)]
    [string]$ComputerGroup
)
try {
    Import-Module ActiveDirectory -EA Stop
} catch {
    Write-Warning $_.Exception.Message
    exit
}
try {
    $existingPolicy = Get-ADAuthenticationPolicy -Filter {Name -eq $PolicyName} -EA Stop
} catch {
    Write-Warning $_.Exception.Message
    exit
}
if ($null -ne $existingPolicy) {
    Write-Warning 'Policy already exists in this forest!'
    exit
}
try {
    $adGroup = Get-ADGroup -Filter {Name -eq $ComputerGroup} -EA Stop
} catch {
    Write-Warning $_.Exception.Message
    exit
}
if ($null -eq $adGroup) {
    Write-Warning 'Computer group does not exist!'
    exit
}
$groupSID = $adGroup.SID.Value
$fromSDDL = "O:SYG:SYD:(XA;OICI;CR;;;WD;((Member_of_any {SID($groupSID)}) || (Member_of_any {SID(ED)})))"
$authNPolicyParms = @{
    'Name' = $PolicyName
    'Enforce' = $true
    'UserTGTLifetimeMins' = $TGTLifeTimeMinutes
    'UserAllowedToAuthenticateFrom' = $fromSDDL
}
try {
    New-ADAuthenticationPolicy @authNPolicyParms -EA Stop
    Write-Host 'Authentication Policy created successfully' -ForegroundColor Green
} catch {
    Write-Warning $_.Exception.Message
}