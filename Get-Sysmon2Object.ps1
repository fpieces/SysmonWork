function Get-Sysmon2Object {
    <#
    .SYNOPSIS
    Converts sysmon message into an object to extract and run additional analysis on for trends, etc...

    .PARAMETER ID
    Sysmon Message ID

    .PARAMETER Limit
    Limit the result set 

    .EXAMPLE
    Get-Sysmon2Object -ID 1
    Get-Sysmon2Object -ID 1 -Limit 10

    .NOTES
    Written By @FPieces
    Revision 1

    #>

    param(
        [parameter(mandatory=$true, position=0)]
        [int] 
        $ID,

        [parameter(mandatory=$false, position=1)]
        [int]
        $Limit
    )

    $Filter = @{
    LogName = "Microsoft-Windows-Sysmon/Operational" #SysMonLog Quailfied Name
    ID = $ID

    }

    if (!($Limit)) {
        $SysmonMsgs = Get-WinEvent -FilterHashtable $Filter
    }
    else {
        $SysmonMsgs = Get-WinEvent -FilterHashtable $Filter | Select-Object -First $Limit
    }

    $SysmonMsgs | % {
        $Message = $_.Message -split "`n"
        $SysmonMsg = New-Object PSobject

        foreach ($item in $Message) {

            $Property = $item -split ": "
            $PropertyName = $Property[0]
            $PropertyValue = $Property[1]
    
            $SysmonMsg | Add-Member -MemberType NoteProperty -Name $PropertyName -Value $PropertyValue
        }
    
        Write-Output $SysmonMsg
    }
}