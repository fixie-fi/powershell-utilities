<#
The MIT License (MIT)

Copyright (c) 2020 Esa Ollitervo

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#>

# Configuration file
$ConfigFile = "config.ini"

# Load configuration
Function LoadSettings {
    Param ($file)
    $ini = @{}
    switch -regex -file $file
    {
        "^\[(.+)\]$" {
            $section = $matches[1].trim()
            $ini[$section] = @{}
        }
        "(.+)=(.+)" {
            $name,$value = $matches[1..2].trim().replace("`"","")
            if ($name -eq "Password") {
                [securestring]$value = ConvertTo-SecureString $value    
            }
            elif ($value -eq "true") { $value = $true }
            elif ($value -eq "false") { $value = $false }
            $ini[$section][$name] = $value
        }
    }
    return $ini
}

$Config = LoadSettings($ConfigFile)

<#
    .SYNOPSIS
    Sends information about one or more events in the EventLog in an email.

    .DESCRIPTION
    Sends information about one or more events in the EventLog in an email.
    This script allows you to specify the email account you are sending the message
    from, the event source, the number of events to retrieve, and more. This script
    could be particularly useful as a scheduled task that is triggered off of an
    event.

    Inspiration from: http://blachniet.com/blog/event-log-email-alerts-with-powershell/

    .EXAMPLE
    Send-EventEntryEmail -eventChannel $(eventChannel) -eventComputer $(eventComputer) -eventID $(eventID) -EventRecordID $(EventRecordID) -eventKeywords $(eventKeywords) -eventLevel $(eventLevel) -eventProvider $(eventProvider) -eventTask $(eventTask) -eventTimeCreated $(eventTimeCreated) -EventData $(EventData)

    Description
    -----------
    Attach script to Event as a Task with there parameters.

#>

Function Send-EventEntryEmail {

    [CmdletBinding(DefaultParameterSetName = 'CommandLine')]
    param(
        [Parameter(ParameterSetName = 'Event', Mandatory)] [string] $eventChannel,
        [Parameter(ParameterSetName = 'Event', Mandatory)] [string] $eventComputer,
        [Parameter(ParameterSetName = 'Event', Mandatory)] [int] $eventID,
        [Parameter(ParameterSetName = 'Event', Mandatory)] [int] $eventRecordID,
        [Parameter(ParameterSetName = 'Event', Mandatory)] [string] $eventKeywords,
        [Parameter(ParameterSetName = 'Event', Mandatory)] [string] $eventLevel,
        [Parameter(ParameterSetName = 'Event', Mandatory)] [string] $eventProvider,
        [Parameter(ParameterSetName = 'Event')] [string] $eventSecurity,
        [Parameter(ParameterSetName = 'Event', Mandatory)] [string] $eventTask,
        [Parameter(ParameterSetName = 'Event', Mandatory)] [string] $eventTimeCreated,
        [Parameter(ParameterSetName = 'Event', Mandatory)] [string] $eventData,

        # The name of the log to look for the event in.
        [Parameter(ParameterSetName = 'CommandLine')] [string] $LogName = $Config.Event.LogName,
        # The event log source that will be retrieved.
        [Parameter(ParameterSetName = 'CommandLine')] [string] $Source = $Config.Event.Source,
        # The types of entries to look for.
        [Parameter(ParameterSetName = 'CommandLine')] [string[]] $EntryType = $Config.Event.EntryType,
        # The ID of entries to look for.
        [Parameter(ParameterSetName = 'CommandLine')] [int]$ID = $Config.Event.ID,
        # The number of latest events to retrieve.
        [Parameter(ParameterSetName = 'CommandLine')] [int]$Newest = $Config.Event.Newest

    )

    function createEmail {
        Param($eventEntries)

        $header = 'Time', 'Machine', 'LogName', 'Type', 'Provider', 'Message'
        $template = Out-String -InputObject $(Get-Content $Config.Mail.Template -Raw)
        $expanded = $ExecutionContext.InvokeCommand.ExpandString($template)

        $MachineName = $eventEntries[0].MachineName
        $ProviderName = $eventEntries[0].ProviderName
        $Subject = $Config.Mail.Subject + $MachineName + "/" + $LogName + "/" + $ProviderName

        # Create the email.
        $email = New-Object System.Net.Mail.MailMessage( $Config.Mail.From , $Config.Mail.To )
        $email.Subject = $Subject
        $email.IsBodyHtml = $true
        $email.BodyEncoding = [System.Text.Encoding]::UTF8
        $email.Body = $expanded

        return $email
    }

    function sendEmail {
        Param($email)

        $SmtpClient = New-Object System.Net.Mail.SmtpClient(
            $Config.Smtp.Server,
            $Config.Smtp.Port
        );
        $SmtpClient.EnableSsl = $Config.Smtp.EnableSsl
        $SmtpClient.Credentials = New-Object System.Net.NetworkCredential(
            $Config.Smtp.UserName,
            $Config.Smtp.Password
        );

        # Send the email.
        "Sending mail..."        
        Write-Host($SmtpClient.Send( $email ))
        "Mail sent..."

    }

    #'Set name is: {0}' -f $PsCmdlet.ParameterSetName
    switch ($PsCmdlet.ParameterSetName) {
        "CommandLine" {            
            $eventEntries = Get-WinEvent -FilterHashtable @{Logname=$Logname;ID=$ID} -MaxEvents $Newest
        }
        "Event" {
            $eventEntries = @(@{
                TimeCreated = $eventTimeCreated;
                LogName = $eventChannel;
                MachineName = $eventComputer;
                ProviderName = $eventProvider;
                LevelDisplayName = $eventLevel;
                Message = $eventData;
            })            
        }
    }

    $email = createEmail($eventEntries)
    sendEmail($email)

}

Export-ModuleMember Send-EventEntryEmail
