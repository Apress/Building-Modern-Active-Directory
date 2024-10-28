<#
    Engineering Active Directory by Evgenij Smirnov
    Chapter 6: Engineering Authorization
    Code 6.1:  Estimate token size for current user (no parameters) or for a user specified by sAMAccountName or UPN
               Sample code - uses "Names" attributes and only evaluates sidHistory for groups from the current domain
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [string]$UserName,
    [Parameter(Mandatory=$false)]
    [switch]$SkipSIDHistoryForGroups
)
$rootDSE = New-Object System.DirectoryServices.DirectoryEntry('LDAP://rootDSE')
if ($rootDSE.forestFunctionality[0] -lt 7) {
    Write-Warning 'This script will only work with Server 2016 FFL or later!'
    exit
}
if (-not [string]::IsNullOrWhiteSpace($UserName)) {
    $filter = '(&(objectClass=user)(objectCategory=person)(|(sAMAccountName={0})(userPrincipalName={0})))' -f $UserName
} else {
    $filter = '(&(objectClass=user)(objectCategory=person)(sAMAccountName={0}))' -f [Environment]::UserName
}
$dSearcher = New-Object System.DirectoryServices.DirectorySearcher
$dSearcher.SearchRoot = 'LDAP://{0}' -f $rootDSE.defaultNamingContext[0]
$dSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
$dSearcher.Filter = $filter
$userSR = $dSearcher.FindAll()
if ($userSR.Count -eq 0) {
    Write-Warning 'User not found!'
    exit
} elseif ($userSR.Count -gt 1) {
    Write-Warning 'Multiple users found - have you used wildcards in UserName?'
    exit
}
$result = [PSCustomObject]@{
    'User' = $userSR[0].Properties['distinguishedName'][0]
    'UserSidHistory' = 0
    'GroupSidHistory' = 0
    'GroupsFromLocalDomain' = 0
    'GroupsFromOtherDomains' = 0
    'LSATokenGroups' = 0
    'KRBTokenSizeEstimate' = 0
    'KRBTokenSizeSubjectToSIDCompression' = $false
}
$userDN = 'LDAP://{0}' -f $userSR[0].Properties['distinguishedName'][0]
$dSearcher.SearchRoot = $userDN
$dSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
$dSearcher.Filter = '(sAMAccountName=*)'
$null = $dSearcher.PropertiesToLoad.Add('sAMAccountName')
$null = $dSearcher.PropertiesToLoad.Add('sIDHistory')
$null = $dSearcher.PropertiesToLoad.Add('msds-tokenGroupNames')
$null = $dSearcher.PropertiesToLoad.Add('msds-tokenGroupNamesGlobalAndUniversal')
$null = $dSearcher.PropertiesToLoad.Add('msds-tokenGroupNamesNoGCAcceptable')
$userSR = $dSearcher.FindOne()
$result.UserSidHistory = $userSR.Properties['sIDHistory'].Count
$result.GroupsFromLocalDomain = $userSR.Properties['msds-tokenGroupNamesNoGCAcceptable'].Count
if (-not $SkipSIDHistoryForGroups) {
    $dSearcher = New-Object System.DirectoryServices.DirectorySearcher
    $dSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
    $dSearcher.Filter = '(sAMAccountName=*)'
    $null = $dSearcher.PropertiesToLoad.Add('sIDHistory')
    foreach ($groupDN in $userSR.Properties['msds-tokenGroupNamesNoGCAcceptable']) {
        $dSearcher.SearchRoot = 'LDAP://{0}' -f $groupDN
        $groupSR = $dSearcher.FindOne()
        $result.GroupSidHistory += $groupSR.Properties['sIDHistory'].Count
    }
}
$result.GroupsFromOtherDomains = $userSR.Properties['msds-tokenGroupNames'].Count - $userSR.Properties['msds-tokenGroupNamesNoGCAcceptable'].Count
$result.LSATokenGroups = $userSR.Properties['msds-tokenGroupNames'].Count
$result.KRBTokenSizeEstimate = 1200 + (8 * $result.GroupsFromLocalDomain) + (40 * $result.GroupsFromOtherDomains) + (40 * $result.UserSidHistory) + (40 * $result.GroupSidHistory)
$result.KRBTokenSizeSubjectToSIDCompression = (0 -lt $result.GroupsFromOtherDomains)
$result