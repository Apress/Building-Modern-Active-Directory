<#
    Engineering Active Directory by Evgenij Smirnov
    Chapter 7: Engineering Configuration
    Code 7.2:  Backup GPOs with the version number incremented since the last execution of the script
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [string]$BackupPath = 'C:\GPOBACKUP',
    [Parameter(Mandatory=$false)]
    [string]$StateFile = 'C:\ProgramData\GPOBACKUP\LastBackup.csv'
)
try {
    Import-Module GroupPolicy -EA Stop
} catch {
    Write-Warning $_.Exception.Message
    exit
}
if (-not (Test-Path -Path $BackupPath -PathType Container)) {
    try {
        $null = New-Item -Path $BackupPath -ItemType Directory -Force -EA Stop
    } catch {
        Write-Warning ('Could not create missing backup folder: {0}' -f $_.Exception.Message)
        exit
    }
}
if (Test-Path -Path $StateFile -PathType Leaf) {
    try {
        $lastState = Import-CSV -Delimiter ';' -Path $StateFile -EA Stop
    } catch {
        Write-Warning ('Could not import last state: {0}' -f $_.Exception.Message)
        exit
    }
} else {
    $stateFolder = Split-Path -Path $StateFile -Parent
    if (-not (Test-Path -Path $stateFolder -PathType Container)) {
        try {
            $null = New-Item -Path $stateFolder -ItemType Directory -Force -EA Stop
        } catch {
            Write-Warning ('Could not create missing state folder: {0}' -f $_.Exception.Message)
            exit
        }
    }
    $lastState = @()
}
$currentState = @()
try {
    $gpoList = Get-GPO -All -EA Stop
} catch {
    Write-Warning ('Could not enumerate GPOs: {0}' -f $_.Exception.Message)
    exit
}
foreach ($gpo in $gpoList) {
    $res = [PSCustomObject]@{
        'Id' = $gpo.Id.Guid
        'DisplayName' = $gpo.DisplayName
        'VersionC' = $gpo.Computer.DSVersion
        'VersionU' = $gpo.User.DSVersion
        'LastMod' = Get-Date $gpo.ModificationTime -Format 'yyyy-MM-ddTHH:mm:ss'
    }
    
    $doBackup = $false
    $gpoState = $lastState.Where({$_.Id -eq $gpo.Id})
    if ($gpoState.Count -eq 0) {
        Write-Host ('New GPO: {0}' -f $gpo.DisplayName)
        $doBackup = $true
    } elseif (($gpoState[0].VersionC -lt $res.VersionC) -or ($gpoState[0].VersionU -lt $res.VersionU))  {
        Write-Host ('Updated GPO: {0}' -f $gpo.DisplayName)
        $doBackup = $true
    } else {
        $currentState += $res
    }
    if ($doBackup) {
        $gpoBackup = Join-Path -Path $BackupPath -ChildPath ('{0}_{1}' -f $gpo.Id.Guid, (Get-Date -Format 'yyyy-MM-dd'))
        try {
            $null = New-Item -Path $gpoBackup -ItemType Directory -Force -EA Stop
            $null = Backup-GPO -Guid $res.Id -Path $gpoBackup -EA Stop
            $currentState += $res
        } catch {
            Write-Warning $_.Exception.Message
            $currentState += $gpoState
        }
    }
}
try {
    $currentState | Export-Csv -Path $StateFile -Delimiter ';' -Encoding UTF8 -NoTypeInformation -Force -EA Stop 
} catch {
    Write-Warning ('Could not save current state: {0}' -f $_.Exception.Message)
}