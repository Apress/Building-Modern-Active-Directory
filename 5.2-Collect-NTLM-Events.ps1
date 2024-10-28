<#
    Engineering Active Directory by Evgenij Smirnov
    Chapter 5: Engineering Authentication
    Code 5.2:  Collect NTLM-related audit events
#>

$eventFilter = @{
    'LogName' = 'Microsoft-Windows-NTLM/Operational'
    'Id' = @('8001','8003','8004')
}
$events = Get-WinEvent -FilterHashtable $eventFilter
foreach ($event in $events) {
    $result = [ordered]@{
        'ID' = $event.Id
        'Source' = [Environment]::MachineName
        'UserName' = $null
        'UserDomain' = $null
        'Server' = $null
        'Resource' = $null
        'Protocol' = $null
        'Client' = $null
        'Application' = $null
    }
    switch ($event.Id) {
        '8001' {
            $result.UserName = $event.Properties[6].Value
            $result.UserDomain = $event.Properties[7].Value
            $result.Client = [Environment]::MachineName
            $result.Resource = $event.Properties[0].Value
            $result.Application = $event.Properties[4].Value
            if ($event.Properties[0].Value -match '^(?<proto>\w+)\/(?<host>[^\:]+)(\:(?<port>\d+))?(\/(?<svcname>.+))?$') {
                $result.Protocol = $Matches['proto'].ToUpper()
                $result.Server = $Matches['host']
            }
        }
        '8003' {
            $result.Server = [Environment]::MachineName
            $result.UserName = $event.Properties[0].Value
            $result.UserDomain = $event.Properties[1].Value
            $result.Client = $event.Properties[2].Value
            if (-not [string]::IsNullOrWhiteSpace($event.Properties[4].Value)) {
                $result.Resource = $event.Properties[4].Value
            } elseif($event.Properties[3].Value -eq 4) {
                $result.Resource = 'SYSTEM'
            } else {
                $result.Resource = ('PID-{0}' -f $event.Properties[3].Value)
            }
            
        }
        '8004' {
            $result.Server = $event.Properties[0].Value
            $result.UserName = $event.Properties[1].Value
            $result.UserDomain = $event.Properties[2].Value
            $result.Client = $event.Properties[3].Value
        }
    }
    [PSCustomObject]$result
}