<#
    .SYNOPSIS
        Author: James Miller
        Date: 10-14-2021
        Summary: Module file filled with various useful functions.
    .DESCRIPTION
        Module file of various useful functions.
    .NOTES
        Adapted scripts/functions credited to authors
#>

# System & Configuration
function Get-EnvPath {
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}
function Get-EC2InfoJSON {
    <#
        .SYNOPSIS
            Author: James Miller
            Date: 08/17/2022
            Summary: Quick function to collect local EC2 info
        .DESCRIPTION
            Function to collect EC2 information from the EC2 instance.
        .PARAMETER OutVariable
            Output variable name; creates a global variable using this name.
        .EXAMPLE
            Get-EC2InfoJSON -OutVariable "EC2JSON"
            Convert to object:
            $EC2Info = Get-EC2InfoJSON | ConvertFrom-Json
        .NOTES
            https://stackoverflow.com/questions/625644/how-to-get-the-instance-id-from-within-an-ec2-instance
    #>
    param (
        [Parameter()][string]$VariableName
    )
    If (![string]::IsNullOrWhiteSpace($VariableName)) {
        try {
            $JSON = (New-Object System.Net.WebClient).DownloadString("http://169.254.169.254/latest/dynamic/instance-identity/document")
            New-Variable -Scope Global -Name "$VariableName" -Value $JSON -Force
        }
        catch {
            Write-Host "AWS EC2: Could not retrieve info." -ForegroundColor Red
        }
        If ([string]::IsNullOrWhiteSpace($((Get-Variable -Name "$VariableName" -ErrorAction SilentlyContinue).Value))) {return $false} else {return $true}
    } else {
        try {
            $JSON = (New-Object System.Net.WebClient).DownloadString("http://169.254.169.254/latest/dynamic/instance-identity/document")
        }
        catch {
            <#Do this if a terminating exception happens#>
        }
        If ([string]::IsNullOrWhiteSpace($JSON)) {return $false} else {return $JSON}
        return $JSON
    }
}
function Push-PackageProvider ($Name) {
    # Force PSRepo registration & TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    If ((Get-PSRepository).Name -like "PSGallery") {
        #Write-Host "PSGallery present."
    } else {
        Register-PSRepository -Default -ErrorAction SilentlyContinue
        Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    }
    # If module is imported say that and do nothing
    If (Get-PackageProvider | Where-Object {$_.Name -eq $Name}) {
        #write-host "PackageProvider $Name is already imported."
        Return $true
    } else {
        # If module is not imported, but available on disk then import
        If (Get-PackageProvider -ListAvailable | Where-Object {$_.Name -eq $Name}) {
            Import-PackageProvider $Name #-Verbose
            Return $true
        } else {
            # If module is not imported, not available on disk, but is in online gallery then install and import
            If (Find-PackageProvider -Name $Name -Force | Where-Object {$_.Name -eq $Name}) {
                Install-PackageProvider -Name $Name -Force #-Scope CurrentUser #-Verbose
                Import-PackageProvider $Name #-Verbose
                Return $true
            } else {
                # If module is not imported, not available and not in online gallery then abort
                write-host "PackageProvider $Name not imported, not available and not in online gallery..."
                Return $false
            }
        }
    }
}
function Push-Module ($Name) {
    # Force PSRepo registration & TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    If ((Get-PSRepository).Name -like "PSGallery") {
        #Write-Host "PSGallery present."
    } else {
        Register-PSRepository -Default -ErrorAction SilentlyContinue
        Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    }
    # If module is imported say that and do nothing
    If (Get-Module | Where-Object {$_.Name -eq $Name}) {
        #write-host "Module $Name is already imported."
        Return $true
    } else {
        # If module is not imported, but available on disk then import
        If (Get-Module -ListAvailable | Where-Object {$_.Name -eq $Name}) {
            Import-Module $Name #-Verbose
            Return $true
        } else {
            # If module is not imported, not available on disk, but is in online gallery then install and import
            If (Find-Module -Name $Name | Where-Object {$_.Name -eq $Name}) {
                Install-Module -Name $Name -Force #-Scope CurrentUser #-Verbose
                Import-Module $Name #-Verbose
                Return $true
            } else {
                # If module is not imported, not available and not in online gallery then abort
                write-host "Module $Name not imported, not available and not in online gallery..."
                Return $false
            }
        }
    }
}
function New-FancyLog {
    <#
        .SYNOPSIS
            Author: James Miller
            Date: 02-04-2021
            Summary: Function to create FancyLog.
        .DESCRIPTION
            Function to create FancyLog and global variable for reference via Use-LogMatrix function.
        .PARAMETER Folder
            Folder where the FancyLog file will be created.
        .PARAMETER Filename
            Filename for the FancyLog
        .PARAMETER Title
            Title added as first line of the FancyLog
        .PARAMETER DebugLog
            A transcript (debug.log) created alongside the FancyLog.
        .EXAMPLE
            $LogLinePrefix = Use-LogMatrix -Info ; $LogLinePrefix + " INFO TEXT HERE..." | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $global:FancyLog -append -encoding ASCII}
            $LogLinePrefix = Use-LogMatrix -Warning ; $LogLinePrefix + " WARNING TEXT HERE..." | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $global:FancyLog -append -encoding ASCII}
            $LogLinePrefix = Use-LogMatrix -Critical ; $LogLinePrefix + " CRITICAL/ERROR TEXT HERE..." | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $global:FancyLog -append -encoding ASCII}
        .NOTES
            Created for use with Use-LogMatrix function.
    #>
    param (
        [Parameter(Mandatory=$True)][string]$Folder,
        [Parameter(Mandatory=$True)][string]$Filename,
        [Parameter(Mandatory=$True)][string]$Title,
        [Parameter()][switch]$DebugLog
    )
    # Variables
    $FLogLoc = "$Folder"
    $FLogName = "$Filename"
    $global:FancyLog = $FLogLoc + '\' + $FLogName
    # Create FancyLog files & folders
    If (!(Test-Path $FLogLoc)) {New-Item -Path $FLogLoc -ItemType Directory -Force | Out-Null}
    # Debug Log
    If ($DebugLog) {Start-Transcript -Path "$FLogLoc\Debug.log" -Force}
    New-Item -Path "$FLogLoc\$FLogName" -ItemType File -Force -Value "$Title" | Out-Null
    "`r`n________________________________________________________________" | Out-file -FilePath $global:FancyLog -Append -Encoding ASCII
}
function Use-LogMatrix {
    <#
        .SYNOPSIS
            Authors: James Miller
            Date: 06/24/2020
            Summary: Function to improve log formatting.
        .DESCRIPTION
            Created for improved legibly formatted logging.
            Includes timestamp and line information type.
        .PARAMETER Info
            Create line prefix for general information.
        .PARAMETER Warning
            Create line prefix for warning messages.
        .PARAMETER Critical
            Create line prefix for critical/error messages.
        .EXAMPLE
            $LogLinePrefix = Use-LogMatrix -Info ; $LogLinePrefix + " INFO TEXT HERE..." | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $global:FancyLog -append -encoding ASCII}
            $LogLinePrefix = Use-LogMatrix -Warning ; $LogLinePrefix + " WARNING TEXT HERE..." | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $global:FancyLog -append -encoding ASCII}
            $LogLinePrefix = Use-LogMatrix -Critical ; $LogLinePrefix + " CRITICAL/ERROR TEXT HERE..." | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $global:FancyLog -append -encoding ASCII}
        .NOTES
            Function based on code/concept by Reginald Johnson.
    #>
    param(
        [Parameter(Mandatory=$false,position=0)][switch]$Info,
        [Parameter(Mandatory=$false,position=1)][switch]$Warning,
        [Parameter(Mandatory=$false,position=2)][switch]$Critical
    )
    If ($info -eq $true) {
        (get-date -format 'yyyy-MM-dd HH:mm:ss.ffff') + " | INFO (1) :"
    }
    If ($Warning -eq $true) {
        (get-date -format 'yyyy-MM-dd HH:mm:ss.ffff') + " | WARNING (1) :"
    }
    If ($Critical -eq $true) {
        (get-date -format 'yyyy-MM-dd HH:mm:ss.ffff') + " | ERROR (1) :"
    }
}
Function Test-RegistryValue($Regkey,$Name) {
    # Test-Path for a RegKey\Item
    Get-ItemProperty $regkey $name -ErrorAction SilentlyContinue | Out-Null
    $?
}
function Set-DisksOnline {
    # Ensure All Detected Disks Online And Write Enabled
    $offlinedisk = get-disk | Where-Object {$_.isOffline -eq $true}
    $rawparts = get-disk | Where-Object {$_.PartitionStyle -eq "RAW"}
    If ($null -ne $offlinedisk) {
        $offlinedisk | ForEach-Object {
            Initialize-Disk -Number $_.Number -PartitionStyle GPT -ErrorAction SilentlyContinue
            $number = $_.DiskNumber
            Set-Disk -Number $_.DiskNumber -IsReadOnly $False -errorAction SilentlyContinue
            Start-Sleep .5
            Set-Disk -Number $_.DiskNumber -IsOffline $False -errorAction SilentlyContinue
            Start-Sleep .5
            $IsDiskOfflineNow = (Get-disk $_.DiskNumber).isOffline
            If ($IsDiskOfflineNow -eq $false) {
                Write-Host "Disk $number is now online, creating default partition..."
                New-Partition -DiskNumber $number -UseMaximumSize
            } else {Write-Host "Disk $number is still offline!" -ForegroundColor Red}
        }
    } else {Write-Host "No offline disks detected..."}
    If ($null -ne $rawparts) {
        $rawparts | ForEach-Object {
            Initialize-Disk -Number $_.Number -PartitionStyle GPT -ErrorAction SilentlyContinue
            $number = $_.DiskNumber
            Set-Disk -Number $_.DiskNumber -IsReadOnly $False -errorAction SilentlyContinue
            Start-Sleep .5
            Set-Disk -Number $_.DiskNumber -IsOffline $False -errorAction SilentlyContinue
            Start-Sleep .5
            $IsPartRAW = (Get-disk $_.DiskNumber).PartitionStyle
            If ($IsPartRAW -eq "GPT") {
                Write-Host "Disk $number is initialized and online, creating default partition..."
                New-Partition -DiskNumber $number -UseMaximumSize
            } else {Write-Host "Disk $number is not initialized!" -ForegroundColor Red}
        }
    } else {Write-Host "No RAW partitions detected..."}
}
function Get-DiskStatus {
    param (
        [Parameter()][string]$DriveLetter
    )
    $DiskCheck = Get-Disk | Get-Partition | Where-Object {$_.DriveLetter -eq "$DriveLetter"}
    If (([string]::IsNullOrEmpty($DiskCheck)) -eq $true) {
        return $false
    } else {
        return $true
    }
}
function Set-LoginTask {
    <#
    .SYNOPSIS
        Author: James Miller
        Summary: Function to create an at-login scheduled task.
    .DESCRIPTION
        Function to add a Windows Scheduled task with a trigger to run at logon.
        This task will apply to all users and will run as the user.
        Name, User, Path, & Script params (or TaskObject with these properties) required to add task.
    .PARAMETER Action
        Add, Remove, or Check scheduled task.
        Add will create a task based on the information supplied via params or taskobject.
        Remove will remove a task based on the taskname.
        Check will verify if the taskname exists.
    .PARAMETER Name
        The Taskname used by the Add, Remove, & Check actions.
    .PARAMETER User
        User for which to create login task - not required when AllUsers is enabled.
    .PARAMETER Path
        Path for the PS Script to run.
    .PARAMETER Script
        Name of the PS Script/Batch file to run.
        Note: AllUsers task creation method requires script be launched via a batch (.bat) file.
    .PARAMETER Params
        Optional script parameters for single user, PS Script task.
    .PARAMETER TaskObject
        PS Object containing all the required task creation params.
    .PARAMETER AllUsers
        Switch to toggle task creation for all users.
        Note: Task creation method requires script be launched via a batch (.bat) file.
    .EXAMPLE
        Add:
            # Create Scheduled task obj
                $TaskObj = "" | Select-Object Name,Path,User,Script,Params
                $TaskObj.Name = "Get-PSProfileStatus"
                $TaskObj.Path = $Scripts
                $TaskObj.Script = "Get-PSProfileStatus.bat"
            # Set PS Profile (includes Sync from Repo) task
                Set-LoginTask -Action Add -TaskObject $TaskObj -AllUsers
            # Check for Task
                If ((Set-LoginTask -Action Check -TaskObject $TaskObj)) {Write-Host "Task created successfully: $($TaskObj.Name)-At-Login"}
        Remove:
            Set-LoginTask -Action Remove -TaskObject $TaskObj
        Check:
            Set-LoginTask -Action Check -TaskObject $TaskObj
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][ValidateSet("Add","Remove","Check")][string[]]$Action,
        [Parameter(Mandatory=$false)][string]$Name,
        [Parameter(Mandatory=$false)][string]$Path,
        [Parameter(Mandatory=$false)][string]$Script,
        [Parameter(Mandatory=$false)][string]$Params,
        [Parameter(Mandatory=$false)][Object]$TaskObject,
        [Parameter(Mandatory=$false)][switch]$AllUsers,
        [Parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential
    )
    # Initialization & Variables
    $powershell = "${Env:WinDir}\System32\WindowsPowerShell\v1.0\powershell.exe"
    # Actions
    switch ($Action) {
        "Add" {
            If ($AllUsers) {
                If ($TaskObject) {
                    $Name = $TaskObject.Name
                    $Path = $TaskObject.Path
                    $Script = $TaskObject.Script
                    If ([string]::IsNullOrEmpty($Name)) {return $false} else {$script:Taskname = "$Name-At-Login"}
                    If ([string]::IsNullOrEmpty($Path)) {return $false} else {If (!(Test-Path $Path)) {return $false}}
                    If ([string]::IsNullOrEmpty($Script)) {return $false} else {
                        If (!(Test-Path "$Path\$Script")) {return $false}
                        If ($Script -notlike "*.bat") {Write-Host "AllUsers: Script must be a BAT file for this parameter." -ForegroundColor Red; return $false}
                    }
                    $Params = $false
                    $script:FullPath = "$Path\$Script"
                } else {
                    If ([string]::IsNullOrEmpty($Name)) {return $false} else {$script:Taskname = "$Name-At-Login"}
                    If ([string]::IsNullOrEmpty($Path)) {return $false} else { If (!(Test-Path $Path)) {return $false} }
                    If ([string]::IsNullOrEmpty($Script)) {return $false} else { If (!(Test-Path "$Path\$Script")) {return $false} }
                    $Params = $false
                    $script:FullPath = "$Path\$Script"
                }
                # Check for existing task
                $TaskCheck = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Select-Object *
                If (!([string]::IsNullOrEmpty($TaskCheck))) {
                    #Write-Host "Task already exists, exiting..."
                    return $true
                } else {
                    # Create Scheduled Task
                    $script:ShedService = New-Object -comobject 'Schedule.Service'
                    $ShedService.Connect()
                    $script:Task = $ShedService.NewTask(0)
                    $Task.RegistrationInfo.Description = "$TaskName"
                    $Task.Settings.Enabled = $true
                    $Task.Settings.AllowDemandStart = $true
                    $script:trigger = $task.triggers.Create(9)
                    $trigger.Enabled = $true
                    $script:action = $Task.Actions.Create(0)
                    $action.Path = "$FullPath"
                    $script:taskFolder = $ShedService.GetFolder("\")
                    $taskFolder.RegisterTaskDefinition("$TaskName", $Task , 6, 'Users', $null, 4)
                }
            } else {
                If ($TaskObject) {
                    $Name = $TaskObject.Name
                    $Path = $TaskObject.Path
                    $Script = $TaskObject.Script
                    If ([string]::IsNullOrEmpty($TaskObject.Params)) {$Params = $false} else {$Params = "$($TaskObject.Params)"}
                    If ([string]::IsNullOrEmpty($Name)) {Write-Host "Missing Name!" -ForegroundColor Red;return $false} else {$Taskname = "$Name-At-Login"}
                    If ([string]::IsNullOrEmpty($Credential)) {WWrite-Host "Missing Credential Object!" -ForegroundColor Red;return $false}
                    If ([string]::IsNullOrEmpty($Path)) {Write-Host "Missing Path!" -ForegroundColor Red;return $false} else {
                        If (!(Test-Path $Path)) {Write-Host "Cannot access $Path!" -ForegroundColor Red;return $false}
                    }
                    If ([string]::IsNullOrEmpty($Script)) {Write-Host "Missing Script!" -ForegroundColor Red;return $false} else {
                        If (!(Test-Path "$Path\$Script")) {Write-Host "Cannot access $Path\$Script!" -ForegroundColor Red;return $false}
                    }
                    If ([string]::IsNullOrEmpty($Params)) {$Params = $false}
                    $FullPath = "$Path\$Script"
                } else {
                    If ([string]::IsNullOrEmpty($Name)) {Write-Host "Missing Name!" -ForegroundColor Red;return $false} else {$Taskname = "$Name-At-Login"}
                    If ([string]::IsNullOrEmpty($Credential)) {Write-Host "Missing Credential Object!" -ForegroundColor Red;return $false}
                    If ([string]::IsNullOrEmpty($Path)) {Write-Host "Missing Path!" -ForegroundColor Red;return $false} else {
                        If (!(Test-Path $Path)) {Write-Host "Cannot access $Path!" -ForegroundColor Red;return $false}
                    }
                    If ([string]::IsNullOrEmpty($Script)) {Write-Host "Missing Script!" -ForegroundColor Red;return $false} else {
                        If (!(Test-Path "$Path\$Script")) {Write-Host "Cannot access $Path\$Script!" -ForegroundColor Red;return $false}
                    }
                    If ([string]::IsNullOrEmpty($Params)) {$Params = $false}
                    $FullPath = "$Path\$Script"
                }
                $TaskPrincipal = New-ScheduledTaskPrincipal -RunLevel Highest -UserId $Credential.UserName -LogonType Interactive
                $TaskTrigger = New-ScheduledTaskTrigger -AtLogon -User $Credential.UserName
                $TaskSettings = New-ScheduledTaskSettingsSet -Priority 4
                If ($Params) {
                    $TaskAction = (New-ScheduledTaskAction -Execute $powershell -Argument "-Command `"& '$FullPath' $Params`"") 
                } else {
                    $TaskAction = (New-ScheduledTaskAction -Execute $powershell -Argument "-Command `"& '$FullPath'`"") 
                }
                # Create Task
                $LoginTask = New-ScheduledTask -Action $TaskAction -Trigger $TaskTrigger -Principal $TaskPrincipal -Settings $TaskSettings
                $LoginTask | Register-ScheduledTask -TaskName $Taskname -User $Credential.UserName -Password $Credential.GetNetworkCredential().Password
                # Check for existing task
                $TaskCheck = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Select-Object *
                If (-not ([string]::IsNullOrEmpty($TaskCheck))) {
                    #Write-Host "Task already exists, exiting..."
                    return $true
                } else {
                    # Create Scheduled Task
                    Register-ScheduledTask -Force -TaskName $Taskname -InputObject $LoginTask
                }
            }
            # Determine results
            $TaskCheck = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Select-Object *
            Remove-Variable Credential
            If (-not ([string]::IsNullOrEmpty($TaskCheck))) {return $true} else {return $false}
        }
        "Remove" {
            If ($TaskObject) {
                $Name = $TaskObject.Name
                If ([string]::IsNullOrEmpty($Name)) {return $false} else {$global:Taskname = "$Name-At-Login"}
            } else {
                If ([string]::IsNullOrEmpty($Name)) {return $false} else {$global:Taskname = "$Name-At-Login"}
            }
            # Check for existing task
            $TaskCheck = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Select-Object *
            If (-not ([string]::IsNullOrEmpty($TaskCheck))) {
                Unregister-ScheduledTask -TaskName $Taskname -Confirm:$false
                # Determine results
                $TaskCheck = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Select-Object *
                If ([string]::IsNullOrEmpty($TaskCheck)) {return $true} else {return $false}
            } else {
                # Task not present
                return $false
            }
        }
        "Check" {
            If ($TaskObject) {
                $Name = $TaskObject.Name
                If ([string]::IsNullOrEmpty($Name)) {return $false} else {$global:Taskname = "$Name-At-Login"}
            } else {
                If ([string]::IsNullOrEmpty($Name)) {return $false} else {$global:Taskname = "$Name-At-Login"}
            }
            # Determine results
            $TaskCheck = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Select-Object *
            If (-not ([string]::IsNullOrEmpty($TaskCheck))) {return $true} else {return $false}
        }
    }
}
function Set-ScriptTask {
    <#
    .SYNOPSIS
        Author: James Miller
        Date: 04/25/2022
        Summary: Function to create a new scheduled Powershell script.
    .DESCRIPTION
        Function to add a Windows Scheduled task to run a Powershell/batch script.
        Name, User, Path, & Script params (or TaskObject with these properties) required to add task.
    .PARAMETER Action
        Add, Remove, or Check scheduled task.
        Add will create a task based on the information supplied via params or taskobject.
        Remove will remove a task based on the taskname.
        Check will verify if the taskname exists.
    .PARAMETER Name
        The Taskname used by the Add, Remove, & Check actions.
    .PARAMETER User
        User for which to create login task.
    .PARAMETER Path
        Path for the PS Script to run.
    .PARAMETER Script
        Name of the PS Script/Batch file to run.
    .PARAMETER Params
        Optional script parameters for single user, PS Script task.
    .PARAMETER TriggerParams
        Trigger parameters as a scriptblock.
        Example:
        $TriggerParams = @{
            Weekly = $true
            At = "3am"
            DaysOfWeek = "Sunday","Monday"
        }
        Note: For more information, see:
            https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasktrigger
    .PARAMETER TaskObject
        PS Object containing all the required task creation params.
    .EXAMPLE
        Add:
            # Create Scheduled task obj to run every day at 3am
                $TaskObj = "" | Select-Object Name,Path,User,Script,Params,TriggerParams
                $TaskObj.Name = "SQL-MoveBackupsToS3"
                $TaskObj.Path = $Scripts
                $TaskObj.Script = "Move-SQLBackupsToS3.ps1"
                $TaskObj.TriggerParams = @{
                    Daily = $true
                    At = "3am"
                }
            # Set PS task
                Set-ScriptTask -Action Add -TaskObject $TaskObj
            # Check for Task
                If ((Set-ScriptTask -Action Check -TaskObject $TaskObj)) {Write-Host "Task created successfully: $($TaskObj.Name)"}
        Remove:
            Set-ScriptTask -Action Remove -TaskObject $TaskObj
        Check:
            Set-ScriptTask -Action Check -TaskObject $TaskObj
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][ValidateSet("Add","Remove","Check")][string[]]$Action,
        [Parameter(Mandatory=$false)][string]$Name,
        [Parameter(Mandatory=$false)][string]$Path,
        [Parameter(Mandatory=$false)][string]$Script,
        [Parameter(Mandatory=$false)][string]$Params,
        [Parameter(Mandatory=$false)][string]$TriggerParams,
        [Parameter(Mandatory=$false)][Object]$TaskObject,
        [Parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential
    )
    # Initialization & Variables
    $powershell = "${Env:WinDir}\System32\WindowsPowerShell\v1.0\powershell.exe"
    # Actions
    switch ($Action) {
        "Add" {
            If ($TaskObject) {
                If ($Verbose) {$TaskObject}
                $Name = $TaskObject.Name
                $Path = $TaskObject.Path
                $Script = $TaskObject.Script
                $script:TrigParams = $TaskObject.TriggerParams
                If ([string]::IsNullOrEmpty($TaskObject.Params)) {$Params = $false} else {$Params = "$($TaskObject.Params)"}
                If ([string]::IsNullOrEmpty($Name)) {Write-Host "Missing Name!" -ForegroundColor Red;return $false} else {$Taskname = "$Name"}
                If ([string]::IsNullOrEmpty($Credential)) {Write-Host "Missing Credential Object!" -ForegroundColor Red;return $false}
                If ([string]::IsNullOrEmpty($Path)) {Write-Host "Missing Path!" -ForegroundColor Red;return $false} else {
                    If (!(Test-Path $Path)) {Write-Host "Cannot access $Path!" -ForegroundColor Red;return $false}
                }
                If ([string]::IsNullOrEmpty($Script)) {Write-Host "Missing Script!" -ForegroundColor Red;return $false} else {
                    If (!(Test-Path "$Path\$Script")) {Write-Host "Cannot access $Path\$Script!" -ForegroundColor Red;return $false}
                }
                If ([string]::IsNullOrEmpty($Params)) {$script:Params = $false}
                # Trigger validation
                If ([string]::IsNullOrEmpty($script:TrigParams)) {Write-Host "Missing Trigger Params!" -ForegroundColor Red;return $false}
                $FullPath = "$Path\$Script"
            } else {
                $script:TrigParams = $TriggerParams
                If ([string]::IsNullOrEmpty($Name)) {Write-Host "Missing Name!" -ForegroundColor Red;return $false} else {$Taskname = "$Name"}
                If ([string]::IsNullOrEmpty($Credential)) {Write-Host "Missing Credential Object!" -ForegroundColor Red;return $false}
                If ([string]::IsNullOrEmpty($Path)) {Write-Host "Missing Path!" -ForegroundColor Red;return $false} else {
                    If (!(Test-Path $Path)) {Write-Host "Cannot access $Path!" -ForegroundColor Red;return $false}
                }
                If ([string]::IsNullOrEmpty($Script)) {Write-Host "Missing Script!" -ForegroundColor Red;return $false} else {
                    If (!(Test-Path "$Path\$Script")) {Write-Host "Cannot access $Path\$Script!" -ForegroundColor Red;return $false}
                }
                If ([string]::IsNullOrEmpty($Params)) {$Params = $false}
                # Trigger validation
                If ([string]::IsNullOrEmpty($script:TrigParams)) {Write-Host "Missing Trigger Params!" -ForegroundColor Red;return $false}
                $FullPath = "$Path\$Script"
            }
            If ($Verbose) {
                Write-Host "Name: $Name"
                Write-Host "Path: $Path"
                Write-Host "Script: $Script"
                If ($Params) {Write-Host "Params: $Params"}
                If ($script:TrigParams) {
                    Write-Host "TrigParams:"
                    $script:TrigParams
                }
            }
            $TaskPrincipal = New-ScheduledTaskPrincipal -RunLevel Highest -UserId $Credential.UserName -LogonType Password
            # Trigger handling
            <#
            try {
                $TaskTrigger = @()
                $script:TrigParams | ForEach-Object {
                    $Params = $_
                    $TaskTrigger += $(New-ScheduledTaskTrigger @Params)
                }
                If ($Verbose) {
                    $TaskTrigger
                }
            }
            catch {
                If ($Verbose) {
                    $TaskTrigger
                }
                Write-Host "Invalid Trigger parameters!" -ForegroundColor Red
                return $false
            }
            #>
            If (($script:TrigParams.Enabled -contains $true) -and ($script:TrigParams.Count -gt 1)) {
                $TaskTrigger = $script:TrigParams
            } else {
                $TaskTrigger = New-ScheduledTaskTrigger @Params
            }
            If ($Verbose) {
                $TaskTrigger
            }
            If ($TaskTrigger) {Write-Host "Task Triggers generated"} else {Write-Host "Failed to create Task Triggers!" -ForegroundColor Red;return $false}
            $TaskSettings = New-ScheduledTaskSettingsSet -Priority 4
            If ($Params) {
                $TaskAction = (New-ScheduledTaskAction -Execute $powershell -Argument "-Command `"& '$FullPath' $Params`"") 
            } else {
                $TaskAction = (New-ScheduledTaskAction -Execute $powershell -Argument "-Command `"& '$FullPath'`"") 
            }
            # Create Task
            $ScriptTask = New-ScheduledTask -Action $TaskAction -Trigger $TaskTrigger -Principal $TaskPrincipal -Settings $TaskSettings
            $ScriptTask | Register-ScheduledTask -TaskName $Taskname -User $Credential.UserName -Password $Credential.GetNetworkCredential().Password
            # Check for existing task
            $TaskCheck = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Select-Object *
            If (-not ([string]::IsNullOrEmpty($TaskCheck))) {
                #Write-Host "Task already exists, exiting..."
                return $true
            } else {
                # Create Scheduled Task
                Register-ScheduledTask -Force -TaskName $Taskname -InputObject $ScriptTask
            }
            # Determine results
            $TaskCheck = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Select-Object *
            Remove-Variable Credential
            If (-not ([string]::IsNullOrEmpty($TaskCheck))) {return $true} else {return $false}
        }
        "Remove" {
            If ($TaskObject) {
                $Name = $TaskObject.Name
                If ([string]::IsNullOrEmpty($Name)) {return $false} else {$global:Taskname = "$Name"}
            } else {
                If ([string]::IsNullOrEmpty($Name)) {return $false} else {$global:Taskname = "$Name"}
            }
            # Check for existing task
            $TaskCheck = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Select-Object *
            If (-not ([string]::IsNullOrEmpty($TaskCheck))) {
                Unregister-ScheduledTask -TaskName $Taskname -Confirm:$false
                # Determine results
                $TaskCheck = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Select-Object *
                If ([string]::IsNullOrEmpty($TaskCheck)) {return $true} else {return $false}
            } else {
                # Task not present
                return $false
            }
        }
        "Check" {
            If ($TaskObject) {
                $Name = $TaskObject.Name
                If ([string]::IsNullOrEmpty($Name)) {return $false} else {$global:Taskname = "$Name"}
            } else {
                If ([string]::IsNullOrEmpty($Name)) {return $false} else {$global:Taskname = "$Name"}
            }
            # Determine results
            $TaskCheck = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Select-Object *
            If (-not ([string]::IsNullOrEmpty($TaskCheck))) {return $true} else {return $false}
        }
    }
}
function Set-ServiceDelayedStart {
    <#
        .SYNOPSIS
            Author: James Miller
            Date: 10/29/2021
            Summary: Function to set/confirm service(s) are set to Delayed Autostart.
        .DESCRIPTION
            Function will set/confirm a service or list of services (in CSV format) is set to
            Delayed Automatic Start type. Changes are applied to the registry and will not be
            in effect until a system reboot.
        .PARAMETER Name
            Service name or display name.
        .PARAMETER CSV
            A CSV list with DisplayName & Name columns.
        .EXAMPLE
            Single service:
                Set-ServiceDelayedStart -Name WpnService
                Set-ServiceDelayedStart -Name "Windows Push Notifications System Service"
            CSV List:
                $CSV = @"
                DisplayName,Name
                "Windows Push Notifications System Service",WpnService
                "Windows Push Notifications User Service_1ea52de",WpnUserService_1ea52de
                "Windows Push Notifications User Service_a8452",WpnUserService_a8452
                "@
                Set-ServiceDelayedStart -CSV $CSV
        .NOTES
            Partial match for display MAY work, however, function will return false if there are multiple matches.
    #>
    param (
        [Parameter()][string]$Name,
        [Parameter()][string]$CSV
    )
    If ((([string]::IsNullOrWhiteSpace($Name))) -and (([string]::IsNullOrWhiteSpace($CSV)))) {
        Write-Host "Service Name or CSV list not provided!" -ForegroundColor Red;return $false
    } else {
        If ($CSV) {
            $SvcList = ConvertFrom-Csv -InputObject $CSV
            $results = @()
            $SvcList | ForEach-Object {
                $Name = $($_.Name)
                $DisplayName = $($_.DisplayName)
                Write-Host "Checking service: $DisplayName"
                $KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
                If (Test-Path $KeyPath) {
                    $Key = Get-ItemProperty -Path $KeyPath
                    If ($Key.Start -ne "2") {
                        Set-ItemProperty -Path $KeyPath -Name "Start" -Value "2"
                    }
                    If (([string]::IsNullOrEmpty($Key.DelayedAutoStart)) -or ($Key.DelayedAutoStart -eq "0")) {
                        If (Test-Path "$KeyPath\DelayedAutoStart") {
                            Set-ItemProperty -Path $KeyPath -Name "DelayedAutoStart" -Value "1"
                        } else {
                            New-ItemProperty -Path $KeyPath -Name "DelayedAutoStart" -Value "1" -PropertyType DWORD | Out-Null
                        }
                    }
                    $_ | Add-Member -MemberType NoteProperty -Name SetStartType -Value $true
                    $results += $_
                } else {
                    Write-Host "Service is not present or not registered!" -ForegroundColor Red
                    $_ | Add-Member -MemberType NoteProperty -Name SetStartType -Value $false
                    $results += $_
                }
            }
            $fail = ($results.SetStartType | Where-Object {$_ -eq $false}).Count
            $success = ($results.SetStartType | Where-Object {$_ -eq $true}).Count
            $results | Out-Host | Format-Table
            If ($fail -ge $success) {return $false} else {return $true}
        } else {
            $Svc = Get-Service | Where-Object {($_.DisplayName -like "*$Name*")} | Select-Object DisplayName,Name
            If (!($Svc)) {
                $Svc = Get-Service | Where-Object {($_.Name -like "*$Name*")} | Select-Object DisplayName,Name
            }
            If ($Svc.Count -gt 1) {Write-Host "Two or more matches for: $Name" -ForegroundColor Red;Write-Host "Please check Name parameter value and try again." -ForegroundColor Red;return $false}
            $Name = $($Svc.Name)
            $DisplayName = $($Svc.DisplayName)
            Write-Host "Checking service: $DisplayName"
            $KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
            If (Test-Path $KeyPath) {
                $Key = Get-ItemProperty -Path $KeyPath
                If ($Key.Start -ne "2") {
                    Set-ItemProperty -Path $KeyPath -Name "Start" -Value "2"
                }
                If (([string]::IsNullOrEmpty($Key.DelayedAutoStart)) -or ($Key.DelayedAutoStart -eq "0")) {
                    If (Test-Path "$KeyPath\DelayedAutoStart") {
                        Set-ItemProperty -Path $KeyPath -Name "DelayedAutoStart" -Value "1"
                    } else {
                        New-ItemProperty -Path $KeyPath -Name "DelayedAutoStart" -Value "1" -PropertyType DWORD | Out-Null
                    }
                }
                return $true
            } else {
                Write-Host "Service is not present or not registered!" -ForegroundColor Red
                return $false
            }
        }
    }
}
Function Get-UACLevel {
    # Adapted from: https://superuser.com/a/1100227
    # Nested function
    Function Get-RegistryValue($key, $value) {
        (Get-ItemProperty $key $value).$value
    }
    # Variables
    $Key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $ConsentPromptBehaviorAdmin_Name = "ConsentPromptBehaviorAdmin"
    $PromptOnSecureDesktop_Name = "PromptOnSecureDesktop"
    $ConsentPromptBehaviorAdmin_Value = Get-RegistryValue $Key $ConsentPromptBehaviorAdmin_Name
    $PromptOnSecureDesktop_Value = Get-RegistryValue $Key $PromptOnSecureDesktop_Name
    # Main
    If ($ConsentPromptBehaviorAdmin_Value -Eq 0 -And $PromptOnSecureDesktop_Value -Eq 0) {
        Write-Host "Level 0 - Never notify"
    }
    ElseIf ($ConsentPromptBehaviorAdmin_Value -Eq 5 -And $PromptOnSecureDesktop_Value -Eq 0) {
        Write-Host "Level 1 - Notify me only when apps try to make changes to my computer(do not dim my desktop)"
    }
    ElseIf ($ConsentPromptBehaviorAdmin_Value -Eq 5 -And $PromptOnSecureDesktop_Value -Eq 1) {
        Write-Host "Level 2 - Notify me only when apps try to make changes to my computer(default)"
    }
    ElseIf ($ConsentPromptBehaviorAdmin_Value -Eq 2 -And $PromptOnSecureDesktop_Value -Eq 1) {
        Write-Host "Level 3 - Always notify"
    }
    Else {
        Write-Host "Unknown UAC Level" -ForegroundColor Red
    }
}
Function Set-UACLevel {
    # Adapted from: https://superuser.com/a/1100227
    param (
        [Parameter()][int]$Level= 2
    )
    # Variables
    $Key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $ConsentPromptBehaviorAdmin_Name = "ConsentPromptBehaviorAdmin"
    $PromptOnSecureDesktop_Name = "PromptOnSecureDesktop"
    New-Variable -Name PromptOnSecureDesktop_Value
    New-Variable -Name ConsentPromptBehaviorAdmin_Value
    # Nested Function
    Function Set-RegistryValue {
        param (
            [Parameter()][string]$Key,
            [Parameter()][string]$Name,
            [Parameter()][string]$Value,
            [Parameter()][string]$Type="Dword"
        )
        If (!(Test-Path -Path $key)) {New-Item -ItemType Directory -Path $key | Out-Null}
        Set-ItemProperty -Path $key -Name $name -Value $value -Type $type
    }
    # Main
    If ($Level -In 0, 1, 2, 3) {
        $ConsentPromptBehaviorAdmin_Value = 5
        $PromptOnSecureDesktop_Value = 1
        Switch ($Level) {
            0 {
                $ConsentPromptBehaviorAdmin_Value = 0
                $PromptOnSecureDesktop_Value = 0
            }
            1 {
                $ConsentPromptBehaviorAdmin_Value = 5
                $PromptOnSecureDesktop_Value = 0
            }
            2 {
                $ConsentPromptBehaviorAdmin_Value = 5
                $PromptOnSecureDesktop_Value = 1
            }
            3 {
                $ConsentPromptBehaviorAdmin_Value = 2
                $PromptOnSecureDesktop_Value = 1
            }
        }
        Set-RegistryValue -Key $Key -Name $ConsentPromptBehaviorAdmin_Name -Value $ConsentPromptBehaviorAdmin_Value
        Set-RegistryValue -Key $Key -Name $PromptOnSecureDesktop_Name -Value $PromptOnSecureDesktop_Value
        Get-UACLevel
    } else {
        Write-Host "Not a supported level value!" -ForegroundColor Red
        return $false
    }
}
function Add-RightToUser([string] $Username, $Right) {
    <#
        .SYNOPSIS
            Author: Keith Banner
            Date: 02/18/2021
            Summary: Function to add user rights.
        .DESCRIPTION
            Function to add User Rights/Permissions
        .PARAMETER Username
            Domain\User of account on which to add right(s).
        .PARAMETER Right
            Right or permission to add to user.
        .EXAMPLE
            Add Logon as a service:
            Add-RightToUser -Username 'MyDomain\MyUser' -Right 'SeServiceLogonRight'
        .NOTES
            Found on StackOverflow:
            https://stackoverflow.com/questions/313831/using-powershell-how-do-i-grant-log-on-as-service-to-an-account/66251990#66251990
    #>
    $tmp = New-TemporaryFile
    $TempConfigFile = "$tmp.inf"
    $TempDbFile = "$tmp.sdb"
    Write-Host "Getting current policy"
    secedit /export /cfg $TempConfigFile
    $sid = ((New-Object System.Security.Principal.NTAccount("$Username")).Translate([System.Security.Principal.SecurityIdentifier])).Value
    $currentConfig = Get-Content -Encoding ascii $TempConfigFile
    if ($currentConfig | Select-String -Pattern "^$Right .*$sid.*$") {
        Write-Host "Already has right"
    } else {
        Write-Host "Adding $Right to $Username"
        $newConfig = $currentConfig -replace "^$Right .+", "`$0,*$sid"
        Set-Content -Path $TempConfigFile -Encoding ascii -Value $newConfig
        Write-Host "Importing new policy on temp database"
        secedit /import /cfg $TempConfigFile /db $TempDbFile
        Write-Host "Applying new policy to machine"
        secedit /configure /db $TempDbFile /cfg $TempConfigFile
        Write-Host "Updating policy"
        gpupdate /force
        Remove-Item $tmp* -ea 0
    }
}
function Set-HostEntry {
    <#
        .SYNOPSIS
            Author: James Miller
            Date: 11/2/2021
            Summary: Function to Add, Remove, & Check/Verify entries in the Hosts file.
        .DESCRIPTION
            Function to Add, Remove, & Check/Verify entries in the Hosts file.
            Uses a nested function to collect & compare the contents of the Hosts file.
            To add entries, collects the current contents, clears the file, adds the 
            provided IP & Hostname, and repopulates the file. If the provided Hostname 
            is present, it will be replaced.
        .PARAMETER Action
            Validated set of options: Add, Remove, Check.
            Add: Adds an entry to the hosts file, will replace existing entries with a matching hostname.
            Remove: Removes an entry from the hosts file based on hostname.
            Check: Returns hosts file line(s) that match the IP and/or Hostname provided - if present. 
            All options will return a True/False.
        .PARAMETER IP
            IP Address of entry.
            Required for Add, optional for Check, not required for Remove.
        .PARAMETER Hostname
            Hostname of entry.
            Required for Add & Remove, optional for Remove.
        .EXAMPLE
            Set-HostEntry -Action Add -IP $IP -Hostname $Hostname
            Set-HostEntry -Action Remove -Hostname $Hostname
            Set-HostEntry -Action Check -Hostname $Hostname
            Set-HostEntry -Action Check -IP $IP
        .NOTES
            Based on Mark Embling's functions found here:
            https://gist.github.com/markembling/173887
    #>
    param (
        [Parameter(Mandatory=$true)][ValidateSet("Add","Remove","Check")][string[]]$Action,
        [Parameter(Mandatory=$false)][string]$IP,
        [Parameter(Mandatory=$false)][string]$Hostname
    )
    # Variables
    $Hosts = "$env:windir\System32\drivers\etc\hosts"
    # Nested Function
    function Get-Lines {
        param (
            [Parameter()][string]$Hostname,
            [Parameter()][string]$IP,
            [Parameter()][switch]$Check
        )
        $Hosts = "$env:windir\System32\drivers\etc\hosts"
        $file = Get-Content $Hosts
        $Lines = @()
        If ($Check) {
            foreach ($line in $file) {
                $parts = [regex]::Split($line,"\t+")
                if ($parts.count -eq 2) {
                    If ((!([string]::IsNullOrWhiteSpace($IP))) -and (!([string]::IsNullOrWhiteSpace($Hostname)))) {
                        if (($parts[0] -eq $IP) -and ($parts[1] -eq $Hostname)) {
                            $Lines += $line
                        }
                    } else {
                        If (!([string]::IsNullOrWhiteSpace($IP))) {
                            if ($parts[0] -eq $IP) {
                                $Lines += $line
                            }
                        }
                        If (!([string]::IsNullOrWhiteSpace($Hostname))) {
                            if ($parts[1] -eq $Hostname) {
                                $Lines += $line
                            }
                        }
                    }
                }
            }
        } else {
            foreach ($line in $file) {
                $parts = [regex]::Split($line,"\t+")
                if ($parts.count -eq 2) {
                    if ($parts[1] -ne $Hostname) {
                        $Lines += $line
                    }
                } else {
                    $Lines += $line
                }
            }
        }
        return $Lines
    }
    # Main
    If (!(Test-Path $Hosts)) {Write-Host "Cannot locate Hosts file: $Hosts" -ForegroundColor Red;return $false} else {
        switch ($Action) {
            "Add" {
                If (([string]::IsNullOrWhiteSpace($IP)) -or ([string]::IsNullOrWhiteSpace($Hostname))) {
                    Write-Host "Add Entry: IP Address & Hostname must be specified!" -ForegroundColor Red;return $false
                } else {
                    $newLines = Get-Lines -Hostname $Hostname
                    $newLines += $IP + "`t`t" + $Hostname
                    # Write file
                    Clear-Content $Hosts
                    foreach ($line in $newLines) {
                        try {
                            $line | Out-File -encoding ASCII -append $Hosts -ErrorAction SilentlyContinue
                        }
                        catch {
                            $line | Out-File -encoding ASCII -append $Hosts -ErrorAction SilentlyContinue
                        }
                    }
                }
            }
            "Remove" {
                If ([string]::IsNullOrWhiteSpace($Hostname)) {
                    Write-Host "Remove Entry: Hostname must be specified!" -ForegroundColor Red;return $false
                } else {
                    $newLines = Get-Lines -Hostname $Hostname
                    # Write file
                    Clear-Content $Hosts
                    foreach ($line in $newLines) {
                        try {
                            $line | Out-File -encoding ASCII -append $Hosts -ErrorAction SilentlyContinue
                        }
                        catch {
                            $line | Out-File -encoding ASCII -append $Hosts -ErrorAction SilentlyContinue
                        }
                    }
                }
            }
            "Check" {
                If (([string]::IsNullOrWhiteSpace($IP)) -and ([string]::IsNullOrWhiteSpace($Hostname))) {
                    Write-Host "Check Entry: IP Address or Hostname must be specified!" -ForegroundColor Red;return $false
                } 
                ElseIf (([string]::IsNullOrWhiteSpace($IP)) -and (!([string]::IsNullOrWhiteSpace($Hostname)))) {
                    $Lines = Get-Lines -Hostname $Hostname -Check
                    If ([string]::IsNullOrWhiteSpace($Lines)) {return $false} else {$Lines;return $true}
                }
                ElseIf ((!([string]::IsNullOrWhiteSpace($IP))) -and ([string]::IsNullOrWhiteSpace($Hostname))) {
                    $Lines = Get-Lines -IP $IP -Check
                    If ([string]::IsNullOrWhiteSpace($Lines)) {return $false} else {$Lines;return $true}
                }
                ElseIf ((!([string]::IsNullOrWhiteSpace($IP))) -and (!([string]::IsNullOrWhiteSpace($Hostname)))) {
                    $Lines = Get-Lines -Hostname $Hostname -IP $IP -Check
                    If ([string]::IsNullOrWhiteSpace($Lines)) {return $false} else {$Lines;return $true}
                } else {Write-Host "How did you get here?" -ForegroundColor Red;return $false}
            }
        }
    }
}
function Get-OSInfo {
    # Quick function to get OS info - JM
    param (
        [Parameter(Mandatory=$false)][string]$VariableName
    )
    $BuildVersion = [System.Environment]::OSVersion.Version
    $os = Get-CimInstance Win32_OperatingSystem # Get OS Information
    Write-Host "Detected OS: $($os.Caption)"
    If ($VariableName) {
        $OSnfo = "" | Select-Object Major,Minor,FullVer,Arch,Name
        $Osnfo.Name = $os.Caption
        $Osnfo.Major = $BuildVersion.Major
        $Osnfo.Minor = $BuildVersion.Minor
        $Osnfo.FullVer = $os.Version
        $Osnfo.Arch = $os.OSArchitecture
        New-Variable -Name $VariableName -Scope Global -Value $OSnfo
    } else {
        $global:OSnfo = "" | Select-Object Version,Major,Minor,FullVer,Arch,Name
        $Osnfo.Name = $os.Caption
        $OSnfo.Version = "$($Buildversion.Major).$($Buildversion.Minor)"
        $Osnfo.Major = $BuildVersion.Major
        $Osnfo.Minor = $BuildVersion.Minor
        $Osnfo.FullVer = $os.Version
        $Osnfo.Arch = $os.OSArchitecture
    }
}
function Get-dotNETframework {
    param (
        [Parameter(Mandatory=$false)][ValidateSet("3.5","4.0","4.72","4.8","4.8.1")][string[]]$Version
    )
    $script:dotnet = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse | 
        Get-ItemProperty -name Version,Release -EA 0 |
        Where-Object { $_.PSChildName -match '^(?!S)\p{L}'} |
        Select-Object PSChildName, Version, Release | Sort-Object version)
    If (!([string]::IsNullOrEmpty($Version))) {
        $script:results = $false
        If ($Version -eq "3.5") {
            $dotnet | ForEach-Object {
                $ver = $_.Version
                If ($ver -like "3.5.*") {$script:results = $true}
            }
        } ElseIf ($Version -eq "4.7.2") {
            $dotnet | ForEach-Object {
                $rel = $_.Release
                If ($rel -ge "461808") {$script:results = $true}
            }
        } ElseIf ($Version -eq "4.8.1") {
            $dotnet | ForEach-Object {
                $rel = $_.Release
                If ($rel -ge "528372") {$script:results = $true}
            }
        } else {
            $dotnet | ForEach-Object {
                $ver = $_.Version
                If ($ver -ge $Version) {$script:results = $true}
            }
        }
        return $results
    } else {Write-Output $dotnet | Format-Table}
}
function Enable-dotNET351 {
    # Nested Function
    Function Test-RegistryValue {
        param(
            [string]$RegKeyPath,
            [string]$Value
        )
        $ValueExist = $null -ne (Get-ItemProperty $RegKeyPath).$Value
        Return $ValueExist
    }
    # Variables
    $fldr = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing"
    $lschk = Test-RegistryValue -RegKeyPath $fldr -Value "LocalSourcePath"
    $rcchk = Test-RegistryValue -RegKeyPath $fldr -Value "RepairContentServerSource"   
    # Main
    # Set Registry values
    Write-Host "Setting Registry to use Windows Update for repair content..." -ForegroundColor Yellow
    If ($lschk -ne $true) {
        New-ItemProperty -Path $fldr -Name "LocalSourcePath" -PropertyType ExpandString -Value ""
    }
    If ($rcchk -eq $true) {
        $rcvl = Get-ItemPropertyValue -Path $fldr -Name "RepairContentServerSource"
        If ($rcvl -ne '2') {
            Set-ItemProperty -Path $fldr -Name "RepairContentServerSource" -Value "2"
        }
    } Else {
        New-ItemProperty -Path $fldr -Name "RepairContentServerSource" -PropertyType DWORD -Value "2"
    }
    # Enable .NET 3.5 SP1
    Write-Host "Installing .NET 3.5 SP1..." -ForegroundColor Yellow
    Dism /online /get-featureinfo /featurename:NetFx3
    Add-WindowsCapability -Online -Name NetFx3~~~~
}
function Install-dotNET {
    param (
        [Parameter()][ValidateSet("4.72","4.8","4.8.1")][string[]]$Version,
        [Parameter()][switch]$DevPack
    )
    # Initialization & Variables
    $script:BasePath = "C:\ProgramData\Mueller"
    $script:Rsrc = "$BasePath\Rsrc"
    $script:Files = "$Rsrc\Files"
    # Runtime
    $rt472url = "https://go.microsoft.com/fwlink/?LinkId=863262"
    $rt480url = "https://go.microsoft.com/fwlink/?LinkId=2085155"
    $rt481url = "https://go.microsoft.com/fwlink/?LinkId=2203304"
    $rt472exe = "ndp472-kb4054531-web.exe"
    $rt480exe = "ndp48-web.exe"
    $rt481exe = "ndp481-web.exe"
    # DevPack
    $dp472url = "https://go.microsoft.com/fwlink/?linkid=874338"
    $dp480url = "https://go.microsoft.com/fwlink/?linkid=2088517"
    $dp481url = "https://go.microsoft.com/fwlink/?linkid=2203306"
    $dp472exe = "ndp472-devpack-enu.exe"
    $dp480exe = "ndp48-devpack-enu.exe"
    $dp481exe = "ndp481-devpack-enu.exe"
    # Function
    function Start-dotNETInstall {
        param (
            [Parameter()][string]$Ver,
            [Parameter()][string]$URL,
            [Parameter()][string]$Folder,
            [Parameter()][string]$EXE,
            [Parameter()][switch]$Web
        )
        If (!(Test-Path $Folder)) {
            Write-Host "Creating file path: $Folder"
            New-Item -ItemType Directory -Path $Folder -Force | Out-Null
        }
        Write-Host "Downloading installer for dotNET $Ver"
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -OutFile "$Folder\$EXE" "$URL"
        If (Test-Path "$Folder\$EXE") {
            If ($Web) {
                Write-Host "Launching bootstrap installer for dotNET $Ver"
                Start-Process -FilePath "$Folder\$EXE" -ArgumentList "/q /norestart /serialdownload" -Wait
            } else {
                Write-Host "Launching devpack installer for dotNET $Ver"
                Start-Process -FilePath "$Folder\$EXE" -ArgumentList "/q /norestart" -Wait
            }
        }
    }
    # Main
    switch ($Version) {
        "4.72" {
            If (Get-dotNETframework -Version $Version) {Write-Host "dotNET $Version already installed";return $true} else {
                If ($DevPack) {
                    Start-dotNETInstall -Ver "$Version" -Folder "$Files" -URL "$dp472url" -EXE "$dp472exe"
                } else {
                    Start-dotNETInstall -Ver "$Version" -Folder "$Files" -URL "$rt472url" -EXE "$rt472exe" -Web
                }
                If (Get-dotNETframework -Version $Version) {return $true} else {
                    If (Get-InstalledStatus -program "Microsoft .NET Framework $Version") {
                        Write-Host "dotNET $Version installed, but not active. Please restart and check again." -ForegroundColor Red
                        return $true
                    } else {
                        Write-Host "dotNET $Version not installed and/or not active, please restart and check manually." -ForegroundColor Red
                        return $false
                    }
                }
            }
        }
        "4.8" {
            If (Get-dotNETframework -Version $Version) {Write-Host "dotNET $Version already installed";return $true} else {
                If ($DevPack) {
                    Start-dotNETInstall -Ver "$Version" -Folder "$Files" -URL "$dp480url" -EXE "$dp480exe"
                } else {
                    Start-dotNETInstall -Ver "$Version" -Folder "$Files" -URL "$rt480url" -EXE "$rt480exe" -Web
                }
                If (Get-dotNETframework -Version $Version) {return $true} else {
                    If (Get-InstalledStatus -program "Microsoft .NET Framework $Version") {
                        Write-Host "dotNET $Version installed, but not active. Please restart and check again." -ForegroundColor Red
                        return $true
                    } else {
                        Write-Host "dotNET $Version not installed and/or not active, please restart and check manually." -ForegroundColor Red
                        return $false
                    }
                }
            }
        }
        "4.8.1" {
            If (Get-dotNETframework -Version $Version) {Write-Host "dotNET $Version already installed";return $true} else {
                If ($DevPack) {
                    Start-dotNETInstall -Ver "$Version" -Folder "$Files" -URL "$dp481url" -EXE "$dp481exe"
                } else {
                    Start-dotNETInstall -Ver "$Version" -Folder "$Files" -URL "$rt481url" -EXE "$rt481exe" -Web
                }
                If (Get-dotNETframework -Version $Version) {return $true} else {
                    If (Get-InstalledStatus -program "Microsoft .NET Framework $Version") {
                        Write-Host "dotNET $Version installed, but not active. Please restart and check again." -ForegroundColor Red
                        return $true
                    } else {
                        Write-Host "dotNET $Version not installed and/or not active, please restart and check manually." -ForegroundColor Red
                        return $false
                    }
                }
            }
        }
    }
}
function Install-PSGallery {
    # Function to install/config PSGallery & PowershellGet on End-of-life servers.
    $PSGchk = Get-PSRepository -WarningAction SilentlyContinue
    If ($PSGchk.Name -notcontains "PSGallery") {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Register-PSRepository -Default -Verbose
        $PSGchk = Get-PSRepository
        If ($PSGchk.Name -notcontains "PSGallery") {
            Write-Host "Cannot register PSGallery." -ForegroundColor Red
            return $false
        } else {
            Write-Host "PSGallery successfully registered!"
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
            return $true
        }
    } else {
        return $true
    }
}
function Install-AWSModules {
    [CmdletBinding()]
    param (
        [Parameter()][switch]$Update
    )
    If (!(Install-PSGallery)) {Write-Host "PSGallery not registered, cannot continue!" -ForegroundColor Red;return $false}
    If (!($Update)) {
        $modules = Get-Module -ListAvailable | Select-Object Name,Version
        If ($modules.Name -contains "AWSPowerShell") {Import-Module "AWSPowerShell";return $true}
        ElseIf ($modules.Name -contains "AWSPowerShell.NetCore") {Import-Module "AWSPowerShell.NetCore";return $true}
        ElseIf ($modules.Name -contains "AWS.Tools.Installer") {
            If (($modules.Name -contains "AWS.Tools.Common") -and ($modules.Name -contains "AWS.Tools.IdentityManagement") -and ($modules.Name -contains "AWS.Tools.S3")) {
                Import-Module "AWS.Tools.Common"
                Import-Module "AWS.Tools.IdentityManagement"
                Import-Module "AWS.Tools.S3"
                Import-Module "AWS.Tools.EC2"
                return $true
            } else {
                Get-Module -Name AWS.Tools.* -ListAvailable | Select-Object -ExpandProperty ModuleBase | Remove-Item -Recurse -Force
                Install-Module -Name "AWS.Tools.Installer" -Force
                Install-AWSToolsModule AWS.Tools.IdentityManagement,AWS.Tools.S3,AWS.Tools.Common,AWS.Tools.EC2 -Force -SkipPublisherCheck
            }
        }
        Else {
            If (Get-dotNETframework -Version '4.72') {
                Install-Module -Name "AWS.Tools.Installer" -Force
                Install-AWSToolsModule AWS.Tools.IdentityManagement,AWS.Tools.S3,AWS.Tools.Common,AWS.Tools.EC2 -Force -SkipPublisherCheck
                $modules = Get-Module -ListAvailable | Select-Object Name,Version
                If (($modules.Name -contains "AWS.Tools.Common") -and ($modules.Name -contains "AWS.Tools.S3")) {return $true} else {return $false}
            } else {
                Install-Module "AWSPowerShell" -Force
                Import-Module "AWSPowerShell"
                If (Get-Module | Where-Object {$_.Name -eq "AWSPowerShell"}) {return $true} else {return $false}
            }
        }
    } else {
        $modules = Get-Module -ListAvailable | Select-Object Name,Version
        If ($modules.Name -contains "AWSPowerShell") {
            Remove-Module "AWSPowerShell"
            Update-Module "AWSPowerShell"
            Import-Module "AWSPowerShell"
            return $true
        }
        ElseIf ($modules.Name -contains "AWSPowerShell.NetCore") {
            Remove-Module "AWSPowerShell.NetCore"
            Update-Module "AWSPowerShell.NetCore"
            Import-Module "AWSPowerShell.NetCore"
            return $true
        }
        ElseIf ($modules.Name -contains "AWS.Tools.Installer") {
            try {
                Remove-Module -Name "AWS.Tools.Installer" -ErrorAction SilentlyContinue -Force
                Remove-Module -Name "AWS.Tools.Common" -ErrorAction SilentlyContinue -Force
                Remove-Module -Name "AWS.Tools.S3" -ErrorAction SilentlyContinue -Force
                Remove-Module -Name "AWS.Tools.EC2" -ErrorAction SilentlyContinue -Force
                Get-Module -Name AWS.Tools.* -ListAvailable | Select-Object -ExpandProperty ModuleBase | Remove-Item -Recurse -Force
                Install-Module -Name "AWS.Tools.Installer" -Force
                Install-AWSToolsModule AWS.Tools.IdentityManagement,AWS.Tools.S3,AWS.Tools.Common,AWS.Tools.EC2 -Force -SkipPublisherCheck
                return $true
            } catch {
                Write-Warning "AWS Module cleanup failed..."
                return $false
            }
        }
    }
}
function Install-AWSCLI {
    Write-Host "Installing AWS CLI v2 for Windows..."
    Start-Process msiexec.exe -ArgumentList "/i https://awscli.amazonaws.com/AWSCLIV2.msi /passive /qb" -Wait
    Get-EnvPath
    $clichk = (& aws --version)
    If ($clichk) {return $true} else {return $false}
}
function Get-FolderACL {
    <#
        .SYNOPSIS
            Author: James Miller
            Date: 03-03-2021
            Summary: Script set ACLs on a folder
        .DESCRIPTION
            Script to get and/or set ACLs on a folder by user/usergroup.
        .NOTES 
            Credit:
            Uses icacls try catch from: 
            https://www.itdroplets.com/powershell-replace-all-child-object-permission-entries-with-inheritable-permission-entries-from-this-object/
        .PARAMETER Action
            Required
            Validated set: Get, Set
            Get will display ACL access information
            Set will alter the ACLs based on other parameters
        .PARAMETER Folder
            Required
            Folder path on which to Get or Set ACLs
        .PARAMETER Domain
        .PARAMETER User
        .PARAMETER Permission
            Validated set: Read, ReadandExecute, Modify, FullControl, NoAccess
            Permissions info from:
            https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemrights?view=net-5.0

            Read:
            Specifies the right to open and copy folders or files as read-only. 
            This right includes the ReadData right, ReadExtendedAttributes right, ReadAttributes right, and ReadPermissions right.

            ReadandExecute:
            Specifies the right to open and copy folders or files as read-only, and to run application files. 
            This right includes the Read right and the ExecuteFile right.

            Modify:
            Specifies the right to read, write, list folder contents, delete folders and files, and run application files. 
            This right includes the ReadAndExecute right, the Write right, and the Delete right.

            FullControl:
            Specifies the right to exert full control over a folder or file, and to modify access control and audit rules. 
            This value represents the right to do anything with a file and is the combination of all rights in this enumeration.

            NoAccess:
            Same as FullControl, however, the AccessControlType is set to Deny.
        .PARAMETER Force
            Will Force application of the User & Permissions specified.
        .PARAMETER RuleObject
            This Parameter requires an array object of access rules.
            Example:
            $Folder = D:\Tableau_Server
            $Rules = @()
            $SYSTEM = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","ContainerInherit, ObjectInherit","None","Allow")
            $LocalSvc = New-Object System.Security.AccessControl.FileSystemAccessRule("Local Service","FullControl","ContainerInherit, ObjectInherit","None","Allow")
            $NetworkSvc = New-Object System.Security.AccessControl.FileSystemAccessRule("Network Service","FullControl","ContainerInherit, ObjectInherit","None","Allow")
            $domainuser = New-Object System.Security.AccessControl.FileSystemAccessRule("DOMAIN\domainuser","FullControl","ContainerInherit, ObjectInherit","None","Allow")
            $Rules += $SYSTEM,$LocalSvc,$NetworkSvc,$domainuser

            Get-FolderACL -Action Set -Folder $Folder -RuleObject $Rules
            or
            $SetACL = Get-FolderACL -Action Set -Folder $Folder -RuleObject $Rules
        .EXAMPLE
            Results of Set action are boolean.
            $sysacl = global:Get-FolderACL -Action Set -Folder $FolderPath -Domain $null -User "SYSTEM" -Permission FullControl -Force
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][ValidateSet("Get","Set")][string[]]$Action,
        [Parameter(Mandatory = $true)][string]$Folder,
        [Parameter(Mandatory = $false)][string]$User,
        [Parameter(Mandatory = $false)][string]$Domain,
        [Parameter(Mandatory = $false)][ValidateSet("Read","ReadandExecute","Modify","FullControl","NoAccess")][string[]]$Permission,
        [Parameter(Mandatory = $false)][Object]$RuleObject,
        [Parameter(Mandatory = $false)][string]$OutObject,
        [Parameter(Mandatory = $false)][switch]$Force
    )
    # Variables
    #$Hostname = (HOSTNAME.EXE)
    # Functions
    function Reset-ChildPermissions {
        param (
            [Parameter(Mandatory = $true)][string]$Folder
        )
        Write-Host "Applying permissions to child objects, please wait..."
        Try {
            $Path = $Folder
            #Start the job that will reset permissions for each file, don't even start if there are no direct sub-files
            $SubFiles = Get-ChildItem $Path -File
            If ($SubFiles) {
                $Job = Start-Job -ScriptBlock { $args[0] | ForEach-Object {icacls $_.FullName /Reset /C} } -ArgumentList $SubFiles
            }
            #Now go through each $Path's direct folder (if there's any) and start a process to reset the permissions, for each folder.
            $Processes = @()
            $SubFolders = Get-ChildItem $Path -Directory
            If ($SubFolders) {
                Foreach ($SubFolder in $SubFolders) {
                    #Start a process rather than a job, icacls should take way less memory than Powershell+icacls
                    $Processes += Start-Process icacls -WindowStyle Hidden -ArgumentList """$($SubFolder.FullName)"" /Reset /T /C" -PassThru
                }
            }
            #Now that all processes/jobs have been started, let's wait for them (first check if there was any subfile/subfolder)
            #Wait for $Job
            If ($SubFiles) {
                Wait-Job $Job -ErrorAction SilentlyContinue | Out-Null
                Remove-Job $Job
            }
            #Wait for all the processes to end, if there's any still active
            If ($SubFolders) {
                Wait-Process -Id $Processes.Id -ErrorAction SilentlyContinue
            }
            Write-Host "Completed resetting permissions under $($Path)."
            #return $true
        }
        Catch {
            $ErrorMessage = $_.Exception.Message
            Throw "There was an error applying permissions: $($ErrorMessage)"
            #return $false
        }
    }
    # Main
    switch ($Action) {
        "Get" {
            $ACL = Get-ACL -Path $Folder
            If ($OutObject) {
                New-Variable -Name "$OutObject" -Value $ACL.Access
            } else {
                Return ($ACL.Access | Format-Table IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -AutoSize)
            }
        }
        "Set" {
            $script:Reapply = $false
            $script:UseDmn = $true
            If (([string]::IsNullOrEmpty($RuleObject)) -eq $false) {
                $script:ACL = Get-ACL -Path $Folder
                $RuleObject | ForEach-Object {
                    $user = $_.IdentityReference
                    $perm = $_.FileSystemRights
                    $type = $_.AccessControlType
                    Write-Host "Adding Rule for: $user"
                    Write-Host "Permissions: $type - $perm"
                    $script:ACL.AddAccessRule($_)
                }
                $ACL.SetAccessRuleProtection($false,$true)
                $ACL | Set-Acl -Path $Folder
                # Update Child Objects with Parent ACL
                Reset-ChildPermissions -Folder $Folder
                # Verify ACL
                $script:ACL = Get-ACL -Path $Folder
                $RuleObject | ForEach-Object {
                    $user = $_.IdentityReference
                    $perm = $_.FileSystemRights
                    $type = $_.AccessControlType
                    If ($user -like "*\*") {
                        #$domain = ($user -split "\\")[0]
                        $user = ($user -split "\\")[1]
                        #Write-Host "Splitting $user into:"
                        #Write-Host "Domain: $domain"
                        #Write-Host "User: $user"
                    }
                    $result = ($ACL.Access).IdentityReference
                    If ($result -eq "$user") {
                        Write-Host "Found: $User"
                        $script:FileRights = ($ACL.Access | Where-Object {$_.IdentityReference -match "$User"}).FileSystemRights
                        $script:CtrlType = ($ACL.Access | Where-Object {$_.IdentityReference -match "$User"}).AccessControlType
                        $script:InheritFlags = ($ACL.Access | Where-Object {$_.IdentityReference -match "$User"}).InheritanceFlags
                        Write-Host "Access: $FileRights - $CtrlType"
                        If (($CtrlType -eq $type) -and ($FileRights -eq $perm)) {
                            Write-Host "Failed to apply rights..."
                            $_ | Add-Member -MemberType NoteProperty -Name "Applied" -Value "False"
                        } else {
                            $_ | Add-Member -MemberType NoteProperty -Name "Applied" -Value "True"
                        }
                    }
                }
                If ($RuleObject.Applied -match $false) {return $false} else {return $true}
            } else {
                If (([string]::IsNullOrEmpty($User)) -eq $true) {
                    do {
                        Write-Host "User not specified!"
                        $User = Read-Host "Please type username and press ENTER"
                    } until (([string]::IsNullOrEmpty($User)) -eq $false)
                }
                switch ($User) {
                    "system" {$script:UseDmn = $false}
                    "everyone" {$script:UseDmn = $false}
                    "network service" {$script:UseDmn = $false}
                    "local service" {$script:UseDmn = $false}
                    "creator owner" {$script:UseDmn = $false}
                    "authenticated users" {$script:UseDmn = $false}
                    Default {$script:UseDmn = $true}
                }
                If (($UseDmn -eq $true) -and (([string]::IsNullOrEmpty($Domain)) -eq $true)) {
                    do {
                        Write-Host "Domain not specified!"
                        $Domain = Read-Host "Please type Domain name and press ENTER"
                    } until (([string]::IsNullOrEmpty($Domain)) -eq $false)
                }
                If (([string]::IsNullOrEmpty($Permission)) -eq $true) {
                    do {
                        Write-Host "Permission not provided!"
                        Write-Host "1. Read"
                        Write-Host "2. ReadandExecute"
                        Write-Host "3. Modify"
                        Write-Host "4. FullControl"
                        Write-Host "5. NoAccess"
                        Write-Host "X. Cancel/Exit"
                        $ans = Read-Host "Please select access type and press ENTER (1/2/3/4/5/X)"
                    } until (($ans -eq "1") -or ($ans -eq "2") -or ($ans -eq "3") -or ($ans -eq "4") -or ($ans -eq "5") -or ($ans -eq "X"))
                    switch ($ans) {
                        "1" {$Permission = "Read"}
                        "2" {$Permission = "ReadandExecute"}
                        "3" {$Permission = "Modify"}
                        "4" {$Permission = "FullControl"}
                        "5" {$Permission = "NoAccess"}
                        "X" {Write-Host "Cancelling...";Return $false}
                    }
                }
                $script:ACL = Get-ACL -Path $Folder
                $result = ($ACL.Access).IdentityReference
                If (($result -eq "$Domain\$User") -or ($result -eq "$user")) {
                    If ($UseDmn -eq $false) {
                        Write-Host "Found: $User"
                        $script:FileRights = ($ACL.Access | Where-Object {$_.IdentityReference -match "$User"}).FileSystemRights
                        $script:CtrlType = ($ACL.Access | Where-Object {$_.IdentityReference -match "$User"}).AccessControlType
                        $script:InheritFlags = ($ACL.Access | Where-Object {$_.IdentityReference -match "$User"}).InheritanceFlags
                    } else {
                        Write-Host "Found: $Domain\$User"
                        $script:FileRights = ($ACL.Access | Where-Object {$_.IdentityReference -eq "$Domain\$User"}).FileSystemRights
                        $script:CtrlType = ($ACL.Access | Where-Object {$_.IdentityReference -eq "$Domain\$User"}).AccessControlType
                        $script:InheritFlags = ($ACL.Access | Where-Object {$_.IdentityReference -eq "$Domain\$User"}).InheritanceFlags
                    }
                    Write-Host "Access: $FileRights - $CtrlType - $InheritFlags"
                    If ($InheritFlags -ne "ContainerInherit, ObjectInherit") {$script:Reapply = $true}
                    If ($CtrlType -eq "Deny") {$script:CurrentRights = "NoAccess"} else {
                        If ($FileRights -eq "FullControl") {$script:CurrentRights = "FullControl"}
                        ElseIf ($FileRights -eq "Read, Synchronize") {$script:CurrentRights = "Read"}
                        ElseIf ($FileRights -eq "ReadAndExecute, Synchronize") {$script:CurrentRights = "ReadAndExecute"}
                        ElseIf ($FileRights -eq "Modify, Synchronize") {$script:CurrentRights = "Modify"}
                    }
                    If (($CurrentRights -eq $Permission) -and ($Force -eq $true)) {Write-Host "Permission type already set, but Force set to true."; Write-Host "Reapplying permissions...";$script:Reapply = $true}
                    ElseIf (($CurrentRights -eq $Permission) -and (($Force -eq $false) -or ($null -eq $Force))) {Write-Host "Permission type already set";Return $true} else {$script:Reapply = $true}
                    If ($script:Reapply -eq $true) {
                        # Strip existing access rule
                        Write-Host "Removing existing ACL..."
                        If ($UseDmn -eq $false) {
                            $script:AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$User","$CurrentRights","$InheritFlags","None","$CtrlType")
                        } else {
                            $script:AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$Domain\$User","$CurrentRights","$InheritFlags","None","$CtrlType")
                        }
                        $ACL.SetAccessRuleProtection($false,$true)
                        $ACL.RemoveAccessRule($AccessRule)
                        $ACL | Set-Acl -Path $Folder
                        # Update Child Objects with Parent ACL
                        #Reset-ChildPermissions -Folder $Folder
                        # Apply new access rule
                        Write-Host "Adding new ACL..."
                        $script:ACL = Get-ACL -Path $Folder
                        If ($UseDmn -eq $false) {
                            If ($Permission -eq "NoAccess") {
                                $script:AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$User","FullControl","ContainerInherit, ObjectInherit","None","Deny")
                            } else {
                                $script:AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$User","$Permission","ContainerInherit, ObjectInherit","None","Allow")
                            }
                        } else {
                            If ($Permission -eq "NoAccess") {
                                $script:AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$Domain\$User","FullControl","ContainerInherit, ObjectInherit","None","Deny")
                            } else {
                                $script:AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$Domain\$User","$Permission","ContainerInherit, ObjectInherit","None","Allow")
                            }
                        }
                        $ACL.SetAccessRuleProtection($false,$true)
                        $ACL.AddAccessRule($AccessRule)
                        $ACL | Set-Acl -Path $Folder
                        # Update Child Objects with Parent ACL
                        Reset-ChildPermissions -Folder $Folder
                        # Verify ACL
                        $script:ACL = Get-ACL -Path $Folder
                        $result = ($ACL.Access).IdentityReference
                        If (($result -eq "$Domain\$User") -or ($result -eq "$user")) {
                            If ($UseDmn -eq $false) {
                                Write-Host "Found: $User"
                                $script:FileRights = ($ACL.Access | Where-Object {$_.IdentityReference -match "$User"}).FileSystemRights
                                $script:CtrlType = ($ACL.Access | Where-Object {$_.IdentityReference -match "$User"}).AccessControlType
                                $script:InheritFlags = ($ACL.Access | Where-Object {$_.IdentityReference -match "$User"}).InheritanceFlags
                            } else {
                                Write-Host "Found: $Domain\$User"
                                $script:FileRights = ($ACL.Access | Where-Object {$_.IdentityReference -eq "$Domain\$User"}).FileSystemRights
                                $script:CtrlType = ($ACL.Access | Where-Object {$_.IdentityReference -eq "$Domain\$User"}).AccessControlType
                                $script:InheritFlags = ($ACL.Access | Where-Object {$_.IdentityReference -eq "$Domain\$User"}).InheritanceFlags
                            }
                            Write-Host "Access: $FileRights - $CtrlType"
                            If ($CtrlType -eq "Deny") {$script:CurrentRights = "NoAccess"} else {
                                If ($FileRights -eq "FullControl") {$script:CurrentRights = "FullControl"}
                                ElseIf ($FileRights -eq "Read, Synchronize") {$script:CurrentRights = "Read"}
                                ElseIf ($FileRights -eq "ReadAndExecute, Synchronize") {$script:CurrentRights = "ReadAndExecute"}
                                ElseIf ($FileRights -eq "Modify, Synchronize") {$script:CurrentRights = "Modify"}
                            }
                            If ($CurrentRights -ne $Permission) {Write-Host "Failed to apply rights...";return $false} else {return $true}
                        }
                    }
                } else {
                    If ($UseDmn -eq $false) {Write-Host "Permissions not found for: $User"} else {Write-Host "Permissions not found for: $Domain\$User"}
                    Write-Host "Creating Access Rule..."
                    $script:ACL = Get-ACL -Path $Folder
                    If ($UseDmn -eq $false) {
                        If ($Permission -eq "NoAccess") {
                            $script:AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$User","FullControl","ContainerInherit, ObjectInherit","None","Deny")
                        } else {
                            $script:AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$User","$Permission","ContainerInherit, ObjectInherit","None","Allow")
                        }
                    } else {
                        If ($Permission -eq "NoAccess") {
                            $script:AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$Domain\$User","FullControl","ContainerInherit, ObjectInherit","None","Deny")
                        } else {
                            $script:AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$Domain\$User","$Permission","ContainerInherit, ObjectInherit","None","Allow")
                        }
                    }
                    $ACL.SetAccessRuleProtection($false,$true)
                    $ACL.AddAccessRule($AccessRule)
                    $ACL | Set-Acl -Path $Folder
                    # Update Child Objects with Parent ACL
                    Reset-ChildPermissions -Folder $Folder
                    # Verify ACL
                    $script:ACL = Get-ACL -Path $Folder
                    $result = ($ACL.Access).IdentityReference
                    If (($result -eq "$Domain\$User") -or ($result -eq "$user")) {
                        If ($UseDmn -eq $false) {
                            Write-Host "Found: $User"
                            $script:FileRights = ($ACL.Access | Where-Object {$_.IdentityReference -match "$User"}).FileSystemRights
                            $script:CtrlType = ($ACL.Access | Where-Object {$_.IdentityReference -match "$User"}).AccessControlType
                            $script:InheritFlags = ($ACL.Access | Where-Object {$_.IdentityReference -match "$User"}).InheritanceFlags
                        } else {
                            Write-Host "Found: $Domain\$User"
                            $script:FileRights = ($ACL.Access | Where-Object {$_.IdentityReference -eq "$Domain\$User"}).FileSystemRights
                            $script:CtrlType = ($ACL.Access | Where-Object {$_.IdentityReference -eq "$Domain\$User"}).AccessControlType
                            $script:InheritFlags = ($ACL.Access | Where-Object {$_.IdentityReference -eq "$Domain\$User"}).InheritanceFlags
                        }
                        Write-Host "Access: $FileRights - $CtrlType"
                        If ($CtrlType -eq "Deny") {$script:CurrentRights = "NoAccess"} else {
                            If ($FileRights -eq "FullControl") {$script:CurrentRights = "FullControl"}
                            ElseIf ($FileRights -eq "Read, Synchronize") {$script:CurrentRights = "Read"}
                            ElseIf ($FileRights -eq "ReadAndExecute, Synchronize") {$script:CurrentRights = "ReadAndExecute"}
                            ElseIf ($FileRights -eq "Modify, Synchronize") {$script:CurrentRights = "Modify"}
                        }
                        If ($CurrentRights -ne $Permission) {Write-Host "Failed to apply rights...";return $false} else {return $true}
                    }
                }
            }
        }
    }
}
function Enable-LinkedConnections {
    # Confirm Linked Connections are enabled in the Registry
    $KeyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $RegItem = "EnableLinkedConnections"
    try {
        $ItemValue = Get-ItemPropertyValue -Path $KeyPath -Name $RegItem -ErrorAction SilentlyContinue
    }
    catch {
        $ItemValue = $null
    }
    If (([string]::IsNullOrWhiteSpace($ItemValue)) -or ($ItemValue -eq 0)) {
        Write-Host "Enabling Linked Connections..."
        New-ItemProperty -Path $KeyPath -Name $RegItem -Value 1 -PropertyType DWORD -Force | Out-Null
        Write-Host "Computer must be restarted to take affect..."
        #Restart-Computer -Force
        return $false
    } else {
        Write-Host "Linked Connections already enabled..."
        return $true
    }
}
Function Set-MapDrives {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)][string]$Letter,
        [Parameter(Mandatory=$false)][string]$DisplayName,
        [Parameter(Mandatory=$false)][string]$Path,
        [Parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential
    )
    If (([string]::IsNullOrEmpty($Letter)) -or ([string]::IsNullOrEmpty($DisplayName)) -or ([string]::IsNullOrEmpty($Path))) {
        Write-Host "Letter, DisplayName, Path parameters must be specified to continue."
        return $false
    } else {
        Write-Host "Mapping $Letter to $Path ..."
        If (!([string]::IsNullOrWhiteSpace($Credential))) {
            New-PSDrive -Name $Letter -Description $DisplayName -PSProvider FileSystem -Root $Path -Scope Global -Persist -Credential $Credential
        } else {
            New-PSDrive -Name $Letter -Description $DisplayName -PSProvider FileSystem -Root $Path -Scope Global -Persist
        }
        $sh = New-Object -com Shell.Application
        $sh.NameSpace($Letter + ":").Self.Name = "$DisplayName"
        If (Get-PSDrive -Name $Letter) {return $true} else {return $false}
    }
}
function Disable-InternetExplorerESC {
    # https://stackoverflow.com/questions/9368305/disable-ie-security-on-windows-server-via-powershell
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force
    Stop-Process -Name Explorer -Force
    Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green
}
function Unblock-ExplorerHiddenItems {
    # Function to unhide hidden files, folders, and file extensions.
    param (
        [Parameter()][switch]$SuperHidden
    )
    # Variables
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    # Nested Function
    function Get-ExplorerKeyValues {
        $script:Hidden = Get-ItemPropertyValue -Path $key -Name "Hidden"
        $script:HideFileExt = Get-ItemPropertyValue -Path $key -Name "HideFileExt"
        $script:ShowSuperHidden = Get-ItemPropertyValue -Path $key -Name "ShowSuperHidden"
    }
    Get-ExplorerKeyValues
    If ($script:Hidden -eq 0) {Set-ItemProperty -Path $key -Name "Hidden" -Value "1"}
    If ($script:HideFileExt -eq 1) {Set-ItemProperty -Path $key -Name "HideFileExt" -Value "0"}
    If ($SuperHidden) {
        If ($script:ShowSuperHidden -eq 0) {Set-ItemProperty -Path $key -Name "ShowSuperHidden" -Value "1"}
    }
    Stop-Process -processname explorer
    Start-Process -FilePath "C:\Windows\explorer.exe"
}
function Set-WindowsDarkMode {
        <#
    .SYNOPSIS
        Author: James Miller
        Date: 02/19/2024
        Summary: Sets Windows UI to dark mode regardless of Activation status.
    .DESCRIPTION
        Function sets Windows UI to dark mode via the registry.
        Setting is changed regardless of Activation status. May require a reboot to take effect.

        Sets the following registry keys to 0:
            HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\AppsUseLightTheme
            HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize\AppsUseLightTheme
    .NOTES
        https://www.thewindowsclub.com/turn-on-dark-theme-windows-10
    #>

    # Variables
    $AppDWORD = "AppsUseLightTheme"
    $SysDWORD = "SystemUsesLightTheme"
    $ValDWORD = "0"
    $hklmDMPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
    $hkcuDMPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
    # Main
    If (Test-Path $hklmDMPath) {
        #Write-Host "Found HKLM key..."
        If (Get-ItemProperty -Path $hkcuDMPath -Name $AppDWORD -ErrorAction SilentlyContinue) {
            #Write-Host "Found Apps DWORD..."
            If (!((Get-ItemPropertyValue -Path $hklmDMPath -Name $AppDWORD -ErrorAction SilentlyContinue) -eq $ValDWORD)) {
                Set-ItemProperty -Path $hklmDMPath -Name $AppDWORD -Value $ValDWORD -ErrorAction SilentlyContinue
            }
        } else {
            #Write-Host "Creating Apps DWORD..."
            New-ItemProperty -Path $hklmDMPath -Name $AppDWORD -PropertyType Dword -Value $ValDWORD -ErrorAction SilentlyContinue | Out-Null
        }
        If (Get-ItemProperty -Path $hkcuDMPath -Name $SysDWORD -ErrorAction SilentlyContinue) {
            #Write-Host "Found System DWORD..."
            If (!((Get-ItemPropertyValue -Path $hklmDMPath -Name $SysDWORD -ErrorAction SilentlyContinue) -eq $ValDWORD)) {
                Set-ItemProperty -Path $hklmDMPath -Name $SysDWORD -Value $ValDWORD -ErrorAction SilentlyContinue
            }
        } else {
            #Write-Host "Creating System DWORD..."
            New-ItemProperty -Path $hklmDMPath -Name $SysDWORD -PropertyType Dword -Value $ValDWORD -ErrorAction SilentlyContinue | Out-Null
        }
    } else {
        #Write-Host "Creating HKLM key..."
        New-Item -Path $hklmDMPath -ItemType Directory | Out-Null
        #Write-Host "Creating Apps & System DWORDs..."
        New-ItemProperty -Path $hklmDMPath -Name $AppDWORD -PropertyType Dword -Value $ValDWORD -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path $hklmDMPath -Name $SysDWORD -PropertyType Dword -Value $ValDWORD -ErrorAction SilentlyContinue | Out-Null
    }
    If (Test-Path $hkcuDMPath) {
        #Write-Host "Found HKCU key..."
        If (Get-ItemProperty -Path $hkcuDMPath -Name $AppDWORD -ErrorAction SilentlyContinue) {
            #Write-Host "Found Apps DWORD..."
            If (!((Get-ItemPropertyValue -Path $hkcuDMPath -Name $AppDWORD -ErrorAction SilentlyContinue) -eq $ValDWORD)) {
                Set-ItemProperty -Path $hkcuDMPath -Name $AppDWORD -Value $ValDWORD -ErrorAction SilentlyContinue
            }
        } else {
            #Write-Host "Creating Apps DWORD..."
            New-ItemProperty -Path $hkcuDMPath -Name $AppDWORD -PropertyType Dword -Value $ValDWORD -ErrorAction SilentlyContinue | Out-Null
        }
        If (Get-ItemProperty -Path $hkcuDMPath -Name $SysDWORD -ErrorAction SilentlyContinue) {
            #Write-Host "Found System DWORD..."
            If (!((Get-ItemPropertyValue -Path $hkcuDMPath -Name $SysDWORD -ErrorAction SilentlyContinue) -eq $ValDWORD)) {
                Set-ItemProperty -Path $hkcuDMPath -Name $SysDWORD -Value $ValDWORD -ErrorAction SilentlyContinue
            }
        } else {
            #Write-Host "Creating System DWORD..."
            New-ItemProperty -Path $hkcuDMPath -Name $SysDWORD -PropertyType Dword -Value $ValDWORD -ErrorAction SilentlyContinue | Out-Null
        }
    } else {
        #Write-Host "Creating HKCU key..."
        New-ItemProperty -Path $hkcuDMPath -ErrorAction SilentlyContinue
        #Write-Host "Creating Apps & System DWORDs..."
        New-ItemProperty -Path $hkcuDMPath -Name $AppDWORD -PropertyType Dword -Value $ValDWORD -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path $hkcuDMPath -Name $SysDWORD -PropertyType Dword -Value $ValDWORD -ErrorAction SilentlyContinue | Out-Null
    }
    # Results
    $script:failures = 0
    If ((Get-ItemPropertyValue -Path $hklmDMPath -Name $AppDWORD -ErrorAction SilentlyContinue) -eq $ValDWORD) {
        Write-Host "HKLM Apps Dark Mode enabled" -ForegroundColor Green
    } else {
        Write-Host "HKLM Apps Dark Mode not enabled" -ForegroundColor Red
        $failures = $failures+1
    }
    If ((Get-ItemPropertyValue -Path $hklmDMPath -Name $SysDWORD -ErrorAction SilentlyContinue) -eq $ValDWORD) {
        Write-Host "HKLM System Dark Mode enabled" -ForegroundColor Green
    } else {
        Write-Host "HKLM System Dark Mode not enabled" -ForegroundColor Red
        $failures = $failures+1
    }
    If ((Get-ItemPropertyValue -Path $hkcuDMPath -Name $AppDWORD -ErrorAction SilentlyContinue) -eq $ValDWORD) {
        Write-Host "HKLM Apps Dark Mode enabled" -ForegroundColor Green
    } else {
        Write-Host "HKLM Apps Dark Mode not enabled" -ForegroundColor Red
        $failures = $failures+1
    }
    If ((Get-ItemPropertyValue -Path $hkcuDMPath -Name $SysDWORD -ErrorAction SilentlyContinue) -eq $ValDWORD) {
        Write-Host "HKLM Apps Dark Mode enabled" -ForegroundColor Green
    } else {
        Write-Host "HKLM Apps Dark Mode not enabled" -ForegroundColor Red
        $failures = $failures+1
    }
    If ($failures -gt 1) {return $false} else {return $true}
}
function Start-FixDomainTrust {
    # Prompt for Domain Admin credentials, repairs machine password.
    $credential = Get-Credential
    Test-ComputerSecureChannel -Repair -Credential $credential
    Reset-ComputerMachinePassword -Server $env:LOGONSERVER -Credential $credential
}

# Software
function Get-InstalledStatus ($program) {
    $x86 = ((Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall") |
        Where-Object { $_.GetValue("DisplayName") -like "*$program*" }).Length -gt 0;
    $x64 = ((Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall") |
        Where-Object { $_.GetValue("DisplayName") -like "*$program*" }).Length -gt 0;
    return $x86 -or $x64;
}
function Get-AppInfo ($App) {
    <#
        .SYNOPSIS
            Author: James Miller
            Date: 06/16/2023
            Summary: Function to gather info on installed application.
        .DESCRIPTION
            Function to gather info on installed application.
            Collects info from the x86 and x64 application install keys in registry.
        .PARAMETER App
            String to match against application display name. Must match first part of display name.
        .EXAMPLE
            Get-AppInfo -App "Cyberark"

            DisplayName     : CyberArk Endpoint Privilege Manager Agent
            Version         : 369361763
            UninstallString : MsiExec.exe /I{4BEF8351-7815-43E2-870B-B1E5FCA12C5B}
            Publisher       : CyberArk Software Ltd
            ModifyPath      : MsiExec.exe /I{4BEF8351-7815-43E2-870B-B1E5FCA12C5B}
            InstallSource   : C:\Program Files\CyberArk\Endpoint Privilege Manager\Agent\tmp\
            InstallLocation : C:\Program Files\CyberArk\Endpoint Privilege Manager\Agent\
            InstallDate     : 20220610
            DisplayVersion  : 22.4.0867
        .NOTES
            Rework and expansion of previous function Get-InstalledStatus.
    #>
    $x86 = ((Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall") |
        Where-Object { $_.GetValue("DisplayName") -like "$App*" })
    $x64 = ((Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall") |
        Where-Object { $_.GetValue("DisplayName") -like "$App*" })
    If ((!([string]::IsNullOrWhiteSpace($x86)))) {
        If ($x86.Count -gt 1) {Write-Host "Search returned multiple items, please refine App name." -ForegroundColor Red; return $false} else {
            $obj = [PSCustomObject]@{
                DisplayName = $x86.GetValue("DisplayName")
                Version = $x86.GetValue("Version")
                UninstallString = $x86.GetValue("UninstallString")
                Publisher = $x86.GetValue("Publisher")
                ModifyPath = $x86.GetValue("ModifyPath")
                InstallSource = $x86.GetValue("InstallSource")
                InstallLocation = $x86.GetValue("InstallLocation")
                InstallDate = $x86.GetValue("InstallDate")
                DisplayVersion = $x86.GetValue("DisplayVersion")
            }
            $x86 = $obj
        }
    }
    If ((!([string]::IsNullOrWhiteSpace($x64)))) {
        If ($x64.Count -gt 1) {Write-Host "Search returned multiple items, please refine App name." -ForegroundColor Red; return $false} else {
            $obj = [PSCustomObject]@{
                DisplayName = $x64.GetValue("DisplayName")
                Version = $x64.GetValue("Version")
                UninstallString = $x64.GetValue("UninstallString")
                Publisher = $x64.GetValue("Publisher")
                ModifyPath = $x64.GetValue("ModifyPath")
                InstallSource = $x64.GetValue("InstallSource")
                InstallLocation = $x64.GetValue("InstallLocation")
                InstallDate = $x64.GetValue("InstallDate")
                DisplayVersion = $x64.GetValue("DisplayVersion")
            }
            $x64 = $obj
        }
    }
    If (([string]::IsNullOrWhiteSpace($x86)) -and (!([string]::IsNullOrWhiteSpace($x64)))) {return $x64}
    ElseIf ((!([string]::IsNullOrWhiteSpace($x86))) -and ([string]::IsNullOrWhiteSpace($x64))) {return $x86}
    ElseIf (([string]::IsNullOrWhiteSpace($x86)) -and ([string]::IsNullOrWhiteSpace($x64))) {return $false}
    ElseIf ((!([string]::IsNullOrWhiteSpace($x86))) -and (!([string]::IsNullOrWhiteSpace($x64)))) {
        $both =  @($x86,$x64)
        return $both
    } else {
        Write-Host "ERROR: This shouldn't ever be displayed!" -ForegroundColor Red
    }
}
function Install-MSI {
    <#
    .SYNOPSIS
        Author: James Miller
        Date: 12/08/2021
        Summary: Function for automating MSI install.
    .DESCRIPTION
        Function to automate MSI package install process.
    .PARAMETER MSI
        Full Path for MSI to install.
    .PARAMETER Arguments
        Install arguments after the /i [msi file path].
        Example: /qb /passive /norestart
    .PARAMETER ExitCode
        Switch parameter, when enabled reports Exitcode of install process.
    .EXAMPLE
        Install-MSI -MSI "C:\temp\application.msi" -Arguments "/qb /passive"
    .NOTES
        Exitcode return based on code from Install-AxAgentMSI.ps1 by Automox:
        https://patch.automox.com/rs/923-VQX-349/images/Install-AxAgentMsi.ps1
    #>
    param (
        [Parameter()][string]$MSI,
        [Parameter()][string]$Arguments,
        [Parameter()][switch]$ExitCode
    )
    If (Test-Path $MSI) {
        If ($Arguments) {
            $process = Start-Process -FilePath msiexec.exe -ArgumentList "/i `"$MSI`" $Arguments" -Verb RunAs -Wait -PassThru
        } else {
            $process = Start-Process -FilePath msiexec.exe -ArgumentList "/i `"$MSI`"" -Verb RunAs -Wait -PassThru
        }
        If ($ExitCode) {return $process.ExitCode} else {
            If ($process.ExitCode -eq '0') {return $true} else {return $false}
        }
    }
}
function Remove-Application {
    param (
        [parameter(Mandatory=$true, Position=0)][String]$App,
        [parameter(Mandatory=$true, Position=0)][ValidateSet('CIM','Registry')][string[]]$Method
    )
    #[parameter(Mandatory=$false)][ValidateSet($true,$false)][String[]]$Admin = $false
    If ($Method -eq "Registry") {
        $uninstall32 = Get-ChildItem "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" | ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_ -match $App } | Select-Object UninstallString
        $uninstall64 = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" | ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_ -match $App } | Select-Object UninstallString
        $($uninstall32.uninstallstring) | ForEach-Object {
            $fslsh = '/'
            $option = [System.StringSplitOptions]::RemoveEmptyEntries
            If (($_ -notlike "MsiExec.exe*") -and ([string]::IsNullOrEmpty($_) -eq $false)) {
                $uninstall32 = $_
                $uninstall32a,$uninstall32b = ($uninstall32.split($fslsh, $option))
                Write-Host  "Uninstalling $App..."
                start-process "$uninstall32a" -arg "/$uninstall32b"
                Start-Sleep 5
                $script:x86 = $true
                return
            }
            Elseif ($_) {
                $uninstall32 = $_ -Replace "msiexec.exe","" -Replace "/I","" -Replace "/X",""
                $uninstall32 = $uninstall32.Trim()
                Write-Host "Uninstalling $App..."
                start-process "msiexec.exe" -arg "/X $uninstall32 /qb"
                Start-Sleep 5
                $script:x86 = $true
                return
            }
            Else {
                Write-Host "Could not find x32 uninstall string for: $App..."
                $script:x86 = $false
                return
            }
        }
        $($uninstall64.uninstallstring) | ForEach-Object {
            $fslsh = '/'
            $option = [System.StringSplitOptions]::RemoveEmptyEntries
            If (($_ -notlike "MsiExec.exe*") -and ([string]::IsNullOrEmpty($_) -eq $false)) {
                $uninstall64 = $_
                $uninstall64a,$uninstall64b = ($uninstall64.split($fslsh, $option))
                Write-Host "Uninstalling $App..."
                start-process "$uninstall64a" -arg "/$uninstall64b"
                Start-Sleep 5
                $script:x64 = $true
                return
            }
            Elseif ($_) {
                $uninstall64 = $_ -Replace "msiexec.exe","" -Replace "/I","" -Replace "/X",""
                $uninstall64 = $uninstall64.Trim()
                Write-Host  "Uninstalling $App..."
                start-process "msiexec.exe" -arg "/X $uninstall64 /qb"
                Start-Sleep 5
                $script:x64 = $true
                return
            }
            Else {
                Write-Host "Could not find x64 uninstall string for: $App..."
                $script:x64 = $false
                return
            }
        }
        If (($script:x86 -eq $true) -or ($script:x64 -eq $true)) {
            return $true
        } else {
            return $false
        }
    }
    If ($Method -eq "CIM") {
        $Uninstall = Get-CimInstance -Class Win32_Product -Filter "Name='$App'"
        If (([string]::IsNullOrEmpty($Uninstall) -eq $false)) {
            $Uninstall | Invoke-CimMethod -MethodName Uninstall
            return $true
        } else {
            return $false
        }
    }
}
function Install-WinGet {
    # Function to automate install of WinGet
    param (
        [Parameter()][switch]$Force
    )
    # Variables
    $Basepath = "C:\ProgramData\Mueller"
    $Tools = "$Basepath\Tools"
    $WGfldr = "$Tools\WinGet"
    $wgURL = "https://github.com/microsoft/winget-cli/releases/latest"
    $wgFileName = "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
    $wgAppx = "$WGfldr\$wgFileName"
    # Check for WinGet
    $PSver = "$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)"
    If ($PSver -ge "7.1") {Import-Module -Name Appx -UseWindowsPowerShell} else {Import-Module -Name Appx}
    If ($(Get-Module).Name -contains "Appx") {Add-AppxPackage -Path $wgappx} else {Write-Host "Could not load Appx module!" -ForegroundColor Red;return $false}
    $AppxPacks = Get-AppxPackage
    If (($AppxPacks.Name -contains "Microsoft.Winget.Source") -and (!$Force)) {return $true} else {
        # Download & Extract WinGet AppX package
        $wgRequest = [System.Net.WebRequest]::Create($wgURL)
        $wgResponse = $wgRequest.GetResponse()
        $wgRealTagUrl = $wgResponse.ResponseUri.OriginalString
        $wgVersion = $wgRealTagUrl.split('/')[-1].Trim('v')
        $wgRealDownloadUrl = $wgRealTagUrl.Replace('tag', 'download') + '/' + $wgFileName
        # Version check
        If ($wgVersion) {Write-Host "Found version: $wgVersion"} else {Write-Host "Cannot determine latest version!" -ForegroundColor Red;return $false}
        # Download file
        Write-Host "Source: $wgRealDownloadUrl"
        Write-Host "Target: $wgAppx"
        If (-not (Test-Path $WGfldr)) {New-Item -ItemType Directory -Path $WGfldr -Force}
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $wgRealDownloadUrl -OutFile $wgAppx
        # Install WinGet Appx package
        If ($(Get-Module).Name -contains "Appx") {Add-AppxPackage -Path $wgappx} else {Write-Host "Could not load Appx module!" -ForegroundColor Red;return $false}
        $AppxPacks = Get-AppxPackage
        If ($AppxPacks.Name -contains "Microsoft.Winget.Source") {return $true} else {return $false}
    }
}
function Install-Chocolatey {
    # Force PSRepo registration & TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $choco = "C:\ProgramData\chocolatey\choco.exe"
    If (!(Test-Path $choco)) {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
    If (Test-Path $choco) {Get-EnvPath;return $true} else {return $false}
}
function Install-NPPwCfg {
    # Variables
    $choco = "C:\ProgramData\chocolatey\choco.exe"
    $configxml = "$env:APPDATA\Notepad++\config.xml"
# Splat
$cfgxml = @"
<?xml version="1.0" encoding="UTF-8" ?>
<NotepadPlus>
    <FindHistory nbMaxFindHistoryPath="10" nbMaxFindHistoryFilter="10" nbMaxFindHistoryFind="10" nbMaxFindHistoryReplace="10" matchWord="no" matchCase="no" wrap="yes" directionDown="yes" fIfRecuisive="yes" fIfInHiddenFolder="no" fIfProjectPanel1="no" fIfProjectPanel2="no" fIfProjectPanel3="no" fIfFilterFollowsDoc="no" fIfFolderFollowsDoc="no" searchMode="0" transparencyMode="1" transparency="150" dotMatchesNewline="no" isSearch2ButtonsMode="no" regexBackward4PowerUser="no">
        <Filter name="" />
        <Find name="FALSE" />
        <Find name="TRUE" />
        <Replace name="false" />
        <Replace name="true" />
    </FindHistory>
    <History nbMaxFile="10" inSubMenu="no" customLength="-1" />
    <ProjectPanels>
        <ProjectPanel id="0" workSpaceFile="" />
        <ProjectPanel id="1" workSpaceFile="" />
        <ProjectPanel id="2" workSpaceFile="" />
    </ProjectPanels>
    <GUIConfigs>
        <GUIConfig name="ToolBar" visible="yes">small</GUIConfig>
        <GUIConfig name="StatusBar">show</GUIConfig>
        <GUIConfig name="TabBar" dragAndDrop="yes" drawTopBar="yes" drawInactiveTab="yes" reduce="yes" closeButton="yes" doubleClick2Close="no" vertical="no" multiLine="no" hide="no" quitOnEmpty="no" iconSetNumber="0" />
        <GUIConfig name="ScintillaViewsSplitter">vertical</GUIConfig>
        <GUIConfig name="UserDefineDlg" position="undocked">hide</GUIConfig>
        <GUIConfig name="TabSetting" replaceBySpace="no" size="4" />
        <GUIConfig name="AppPosition" x="2334" y="137" width="1100" height="700" isMaximized="no" />
        <GUIConfig name="FindWindowPosition" left="2781" top="308" right="3370" bottom="672" />
        <GUIConfig name="FinderConfig" wrappedLines="no" purgeBeforeEverySearch="no" />
        <GUIConfig name="noUpdate" intervalDays="15" nextUpdateDate="20211027">yes</GUIConfig>
        <GUIConfig name="Auto-detection">yes</GUIConfig>
        <GUIConfig name="CheckHistoryFiles">no</GUIConfig>
        <GUIConfig name="TrayIcon">no</GUIConfig>
        <GUIConfig name="MaitainIndent">no</GUIConfig>
        <GUIConfig name="TagsMatchHighLight" TagAttrHighLight="yes" HighLightNonHtmlZone="no">yes</GUIConfig>
        <GUIConfig name="RememberLastSession">yes</GUIConfig>
        <GUIConfig name="DetectEncoding">yes</GUIConfig>
        <GUIConfig name="SaveAllConfirm">yes</GUIConfig>
        <GUIConfig name="NewDocDefaultSettings" format="0" encoding="4" lang="0" codepage="-1" openAnsiAsUTF8="yes" />
        <GUIConfig name="langsExcluded" gr0="0" gr1="0" gr2="0" gr3="0" gr4="0" gr5="0" gr6="0" gr7="0" gr8="0" gr9="0" gr10="0" gr11="0" gr12="0" langMenuCompact="yes" />
        <GUIConfig name="Print" lineNumber="yes" printOption="3" headerLeft="" headerMiddle="" headerRight="" footerLeft="" footerMiddle="" footerRight="" headerFontName="" headerFontStyle="0" headerFontSize="0" footerFontName="" footerFontStyle="0" footerFontSize="0" margeLeft="0" margeRight="0" margeTop="0" margeBottom="0" />
        <GUIConfig name="Backup" action="0" useCustumDir="no" dir="" isSnapshotMode="yes" snapshotBackupTiming="7000" />
        <GUIConfig name="TaskList">yes</GUIConfig>
        <GUIConfig name="MRU">yes</GUIConfig>
        <GUIConfig name="URL">0</GUIConfig>
        <GUIConfig name="uriCustomizedSchemes">svn:// cvs:// git:// imap:// irc:// irc6:// ircs:// ldap:// ldaps:// news: telnet:// gopher:// ssh:// sftp:// smb:// skype: snmp:// spotIfy: steam:// sms: slack:// chrome:// bitcoin:</GUIConfig>
        <GUIConfig name="globalOverride" fg="no" bg="no" font="no" fontSize="no" bold="no" italic="no" underline="no" />
        <GUIConfig name="auto-completion" autoCAction="0" triggerFromNbChar="1" autoCIgnoreNumbers="no" funcParams="no" />
        <GUIConfig name="auto-insert" parentheses="no" brackets="no" curlyBrackets="no" quotes="no" doubleQuotes="no" htmlXmlTag="no" />
        <GUIConfig name="sessionExt"></GUIConfig>
        <GUIConfig name="workspaceExt"></GUIConfig>
        <GUIConfig name="MenuBar">show</GUIConfig>
        <GUIConfig name="Caret" width="1" blinkRate="600" />
        <GUIConfig name="ScintillaGlobalSettings" enableMultiSelection="no" />
        <GUIConfig name="openSaveDir" value="0" defaultDirPath="" />
        <GUIConfig name="titleBar" short="no" />
        <GUIConfig name="stylerTheme" path="C:\Program Files (x86)\Notepad++\themes\DarkModeDefault.xml" />
        <GUIConfig name="insertDateTime" customizedFormat="yyyy-MM-dd HH:mm:ss" reverseDefaultOrder="no" />
        <GUIConfig name="wordCharList" useDefault="yes" charsAdded="" />
        <GUIConfig name="delimiterSelection" leftmostDelimiter="40" rightmostDelimiter="41" delimiterSelectionOnEntireDocument="no" />
        <GUIConfig name="multiInst" setting="0" />
        <GUIConfig name="MISC" fileSwitcherWithoutExtColumn="yes" fileSwitcherExtWidth="50" fileSwitcherWithoutPathColumn="yes" fileSwitcherPathWidth="50" backSlashIsEscapeCharacterForSql="yes" writeTechnologyEngine="0" isFolderDroppedOpenFiles="no" docPeekOnTab="no" docPeekOnMap="no" saveDlgExtFilterToAllTypes="no" muteSounds="no" />
        <GUIConfig name="Searching" monospacedFontFindDlg="no" stopFillingFindField="no" findDlgAlwaysVisible="no" confirmReplaceInAllOpenDocs="yes" replaceStopsWithoutFindingNext="no" />
        <GUIConfig name="searchEngine" searchEngineChoice="2" searchEngineCustom="" />
        <GUIConfig name="MarkAll" matchCase="no" wholeWordOnly="yes" />
        <GUIConfig name="SmartHighLight" matchCase="no" wholeWordOnly="yes" useFindSettings="no" onAnotherView="no">yes</GUIConfig>
        <GUIConfig name="DarkMode" enable="yes" colorTone="0" customColorTop="2105376" customColorMenuHotTrack="4210752" customColorActive="4210752" customColorMain="2105376" customColorError="176" customColorText="14737632" customColorDarkText="12632256" customColorDisabledText="8421504" customColorEdge="6579300" />
        <GUIConfig name="ScintillaPrimaryView" lineNumberMargin="show" lineNumberDynamicWidth="yes" bookMarkMargin="show" indentGuideLine="show" folderMarkStyle="box" lineWrapMethod="aligned" currentLineHilitingShow="show" scrollBeyondLastLine="yes" rightClickKeepsSelection="no" disableAdvancedScrolling="no" wrapSymbolShow="hide" Wrap="no" borderEdge="yes" isEdgeBgMode="no" edgeMultiColumnPos="" zoom="0" zoom2="0" whiteSpaceShow="hide" eolShow="hide" borderWidth="2" smoothFont="no" paddingLeft="0" paddingRight="0" distractionFreeDivPart="4" />
        <GUIConfig name="DockingManager" leftWidth="200" rightWidth="200" topHeight="200" bottomHeight="200">
            <ActiveTabs cont="0" activeTab="-1" />
            <ActiveTabs cont="1" activeTab="-1" />
            <ActiveTabs cont="2" activeTab="-1" />
            <ActiveTabs cont="3" activeTab="-1" />
        </GUIConfig>
    </GUIConfigs>
</NotepadPlus>
"@
    # Check for Chocolatey
    If (!(Install-Chocolatey)) {Write-Host "Chocolatey install failed - cannot continue!" -ForegroundColor Red;return $false}
    # Check for Notepad++, install If not present
    If (Get-InstalledStatus -program "Notepad++") {
        # Force upgrade
        # choco upgrade notepadplusplus -y --force
        Start-Process -FilePath $choco -ErrorAction SilentlyContinue -WindowStyle Minimized -ArgumentList "upgrade notepadplusplus -y --force --ignore-checksums" -Wait
        # Force config
        If (Get-Process -Name "notepad++" -ErrorAction SilentlyContinue) {Write-Host "Notepad++ running, closing...";Get-Process -Name "notepad++" | Stop-Process -Force}
        New-Item -ItemType File -Path $configxml -Force -Value $cfgxml | Out-Null
        return $true
    } else {
        Write-Host "Installing Notepad++..."
        #choco install notepadplusplus.install -y --force --ignore-checksums
        Start-Process -FilePath $choco -ErrorAction SilentlyContinue -WindowStyle Minimized -ArgumentList "install notepadplusplus -y --force --ignore-checksums" -Wait
        # Force config
        New-Item -ItemType File -Path $configxml -Force -Value $cfgxml | Out-Null
        If (Get-InstalledStatus -program "Notepad++") {return $true} else {return $false}
    }
}
function Install-Chrome {
    # Variables
    $choco = "C:\ProgramData\chocolatey\choco.exe"
    If (!(Install-Chocolatey)) {Write-Host "Chocolatey install failed - cannot continue!" -ForegroundColor Red;return $false}
    If (Get-InstalledStatus -program "Chrome") {return $true} else {
        Write-Host "Installing Google Chrome..."
        #choco install googlechrome -y --force --ignore-checksums
        Start-Process -FilePath $choco -ErrorAction SilentlyContinue -WindowStyle Minimized -ArgumentList "install googlechrome -y --force --ignore-checksums" -Wait
        If (Get-InstalledStatus -program "Chrome") {return $true} else {return $false}
    }
}
function Install-GitWindows {
    # Variables
    $choco = "C:\ProgramData\chocolatey\choco.exe"
    If (!(Install-Chocolatey)) {Write-Host "Chocolatey install failed - cannot continue!" -ForegroundColor Red;return $false}
    If (Get-InstalledStatus -program "Git") {return $true} else {
        Write-Host "Installing Git for Windows..."
        #choco install googlechrome -y --force --ignore-checksums
        Start-Process -FilePath $choco -ErrorAction SilentlyContinue -WindowStyle Minimized -ArgumentList "install git.install -y --force --ignore-checksums" -Wait
        If (Get-InstalledStatus -program "Git") {return $true} else {return $false}
    }
}
function Uninstall-UrlRewrite {
    # Variables
    $choco = "C:\ProgramData\chocolatey\choco.exe"
    # Check for Chocolatey
    If (!(Test-Path $choco)) {
        $choc = Install-Choco
        If (!($choc)) {Write-Host "Chocolatey install failed!";return $false}
    }
    #choco uninstall urlrewrite -y
    Start-Process -FilePath $choco -ErrorAction SilentlyContinue -WindowStyle Minimized -ArgumentList "uninstall urlrewrite -y --force --ignore-checksums" -Wait
}
function Install-UrlRewrite {
    # Variables
    $choco = "C:\ProgramData\chocolatey\choco.exe"
    # Check for Chocolatey
    If (!(Test-Path $choco)) {
        $choc = Install-Choco
        If (!($choc)) {Write-Host "Chocolatey install failed!";return $false}
    }
    #choco upgrade urlrewrite -y
    Start-Process -FilePath $choco -ErrorAction SilentlyContinue -WindowStyle Minimized -ArgumentList "upgrade urlrewrite -y --force --ignore-checksums" -Wait
}
function Install-VCRedist2010 {
    # Variables
    $choco = "C:\ProgramData\chocolatey\choco.exe"
    # Check for Chocolatey
    If (!(Test-Path $choco)) {
        $choc = Install-Choco
        If (!($choc)) {Write-Host "Chocolatey install failed!";return $false}
    }
    #choco upgrade vcredist2010 -y
    Start-Process -FilePath $choco -ErrorAction SilentlyContinue -WindowStyle Minimized -ArgumentList "upgrade vcredist2010 -y --force --ignore-checksums" -Wait
}
function Uninstall-ApplicationRequestRouting {
    # Variables
    $choco = "C:\ProgramData\chocolatey\choco.exe"
    # Check for Chocolatey
    If (!(Test-Path $choco)) {
        $choc = Install-Choco
        If (!($choc)) {Write-Host "Chocolatey install failed!";return $false}
    }
    #choco uninstall iis-arr -y
    Start-Process -FilePath $choco -ErrorAction SilentlyContinue -WindowStyle Minimized -ArgumentList "uninstall iis-arr -y --force --ignore-checksums" -Wait
}
function Install-ApplicationRequestRouting {
    # Variables
    $choco = "C:\ProgramData\chocolatey\choco.exe"
    # Check for Chocolatey
    If (!(Test-Path $choco)) {
        $choc = Install-Choco
        If (!($choc)) {Write-Host "Chocolatey install failed!";return $false}
    }
    #choco upgrade iis-arr -y
    Start-Process -FilePath $choco -ErrorAction SilentlyContinue -WindowStyle Minimized -ArgumentList "upgrade iis-arr -y --force --ignore-checksums" -Wait
}
function Uninstall-IIS {
    # uninstall IIS - this command will work on Windows Server 2012 R2
    Uninstall-WindowsFeature Web-Server
}
function Install-IIS {
    # install IIS - this command will work on Windows Server 2012 R2
    Install-WindowsFeature `
        Web-Server,                           #[ ] Web Server (IIS)                                            Web-Server                     Available
        Web-WebServer,                        #    [ ] Web Server                                              Web-WebServer                  Available
            Web-Common-Http,                  #        [ ] Common HTTP Features                                Web-Common-Http                Available
            Web-Default-Doc,                  #            [ ] Default Document                                Web-Default-Doc                Available
            Web-Dir-Browsing,                 #            [ ] Directory Browsing                              Web-Dir-Browsing               Available
            Web-Http-Errors,                  #            [ ] HTTP Errors                                     Web-Http-Errors                Available
            Web-Static-Content,               #            [ ] Static Content                                  Web-Static-Content             Available
            Web-Http-Redirect,                #            [ ] HTTP Redirection                                Web-Http-Redirect              Available
            # NOTE: WebDAV has conflicts with some of the allowed verbs and handlers.
            #Web-DAV-Publishing,              #            [ ] WebDAV Publishing                               Web-DAV-Publishing             Available 
        Web-Health,                           #        [ ] Health and Diagnostics                              Web-Health                     Available
            Web-Http-Logging,                 #            [ ] HTTP Logging                                    Web-Http-Logging               Available
            Web-Custom-Logging,               #            [ ] Custom Logging                                  Web-Custom-Logging             Available
            Web-Log-Libraries,                #            [ ] Logging Tools                                   Web-Log-Libraries              Available
            Web-ODBC-Logging,                 #            [ ] ODBC Logging                                    Web-ODBC-Logging               Available
            Web-Request-Monitor,              #            [ ] Request Monitor                                 Web-Request-Monitor            Available
            Web-Http-Tracing,                 #            [ ] Tracing                                         Web-Http-Tracing               Available
        Web-Performance,                      #        [ ] Performance                                         Web-Performance                Available
            Web-Stat-Compression,             #            [ ] Static Content Compression                      Web-Stat-Compression           Available
            Web-Dyn-Compression,              #            [ ] Dynamic Content Compression                     Web-Dyn-Compression            Available
        Web-Security,                         #        [ ] Security                                            Web-Security                   Available
            Web-Filtering,                    #            [ ] Request Filtering                               Web-Filtering                  Available
            Web-Basic-Auth,                   #            [ ] Basic Authentication                            Web-Basic-Auth                 Available
            Web-CertProvider,                 #            [ ] Centralized SSL CertIficate Support             Web-CertProvider               Available
            Web-Client-Auth,                  #            [ ] Client CertIficate Mapping Authentication       Web-Client-Auth                Available
            Web-Digest-Auth,                  #            [ ] Digest Authentication                           Web-Digest-Auth                Available
            Web-Cert-Auth,                    #            [ ] IIS Client CertIficate Mapping Authentication   Web-Cert-Auth                  Available
            Web-IP-Security,                  #            [ ] IP and Domain Restrictions                      Web-IP-Security                Available
            Web-Url-Auth,                     #            [ ] URL Authorization                               Web-Url-Auth                   Available
            Web-Windows-Auth,                 #            [ ] Windows Authentication                          Web-Windows-Auth               Available
        Web-App-Dev,                          #        [ ] Application Development                             Web-App-Dev                    Available
            Web-Net-Ext,                      #            [ ] .NET Extensibility 3.5                          Web-Net-Ext                    Available
            Web-Net-Ext45,                    #            [ ] .NET Extensibility 4.5                          Web-Net-Ext45                  Available
            Web-AppInit,                      #            [ ] Application Initialization                      Web-AppInit                    Available
            Web-ASP,                          #            [ ] ASP                                             Web-ASP                        Available
            Web-Asp-Net,                      #            [ ] ASP.NET 3.5                                     Web-Asp-Net                    Available
            Web-Asp-Net45,                    #            [ ] ASP.NET 4.5                                     Web-Asp-Net45                  Available
            Web-CGI,                          #            [ ] CGI                                             Web-CGI                        Available
            Web-ISAPI-Ext,                    #            [ ] ISAPI Extensions                                Web-ISAPI-Ext                  Available
            Web-ISAPI-Filter,                 #            [ ] ISAPI Filters                                   Web-ISAPI-Filter               Available
            Web-Includes,                     #            [ ] Server Side Includes                            Web-Includes                   Available
            Web-WebSockets,                   #            [ ] WebSocket Protocol                              Web-WebSockets                 Available
        Web-Ftp-Server,                       #    [ ] FTP Server                                              Web-Ftp-Server                 Available
            Web-Ftp-Service,                  #        [ ] FTP Service                                         Web-Ftp-Service                Available
            Web-Ftp-Ext,                      #        [ ] FTP Extensibility                                   Web-Ftp-Ext                    Available
        Web-Mgmt-Tools,                       #    [ ] Management Tools                                        Web-Mgmt-Tools                 Available
            Web-Mgmt-Console,                 #        [ ] IIS Management Console                              Web-Mgmt-Console               Available
            Web-Mgmt-Compat,                  #        [ ] IIS 6 Management Compatibility                      Web-Mgmt-Compat                Available
            Web-Metabase,                     #            [ ] IIS 6 Metabase Compatibility                    Web-Metabase                   Available
            Web-Lgcy-Mgmt-Console,            #            [ ] IIS 6 Management Console                        Web-Lgcy-Mgmt-Console          Available
            Web-Lgcy-Scripting,               #            [ ] IIS 6 Scripting Tools                           Web-Lgcy-Scripting             Available
            Web-WMI,                          #            [ ] IIS 6 WMI Compatibility                         Web-WMI                        Available
            Web-Scripting-Tools,              #        [ ] IIS Management Scripts and Tools                    Web-Scripting-Tools            Available
            Web-Mgmt-Service,                 #        [ ] Management Service                                  Web-Mgmt-Service               Available
        NET-Framework-Features,               #[ ] .NET Framework 3.5 Features                                 NET-Framework-Features         Available
        NET-Framework-Core,                   #    [ ] .NET Framework 3.5 (includes .NET 2.0 and 3.0)          NET-Framework-Core               Removed
        NET-HTTP-Activation,                  #    [ ] HTTP Activation                                         NET-HTTP-Activation            Available
        NET-Non-HTTP-Activ,                   #    [ ] Non-HTTP Activation                                     NET-Non-HTTP-Activ             Available
        NET-Framework-45-Features,            #[ ] .NET Framework 4.5 Features                                 NET-Framework-45-Features      Installed
        NET-Framework-45-Core,                #    [ ] .NET Framework 4.5                                      NET-Framework-45-Core          Installed
        NET-Framework-45-ASPNET,              #    [ ] ASP.NET 4.5                                             NET-Framework-45-ASPNET        Available
        NET-WCF-Services45,                   #    [ ] WCF Services                                            NET-WCF-Services45             Installed
            NET-WCF-HTTP-Activation45,        #        [ ] HTTP Activation                                     NET-WCF-HTTP-Activation45      Available
            NET-WCF-MSMQ-Activation45,        #        [ ] Message Queuing (MSMQ) Activation                   NET-WCF-MSMQ-Activation45      Available
            NET-WCF-Pipe-Activation45,        #        [ ] Named Pipe Activation                               NET-WCF-Pipe-Activation45      Available
            NET-WCF-TCP-Activation45,         #        [ ] TCP Activation                                      NET-WCF-TCP-Activation45       Available
            NET-WCF-TCP-PortSharing45         #        [ ] TCP Port Sharing                                    NET-WCF-TCP-PortSharing45      Installed
}
function Remove-AllWebSites {
    Get-WebSite | Select-Object -Property Name | ForEach-Object { Remove-Website $_.name }
}
function Remove-AllWebAppPools {
    Get-ChildItem IIS:\AppPools | Select-Object -Property Name | ForEach-Object { Remove-WebAppPool $_.name }
}
function Remove-IISDefaultArtifacts {
    Import-Module WebAdministration -Force
    Remove-AllWebAppPools
    Remove-AllWebSites
}

# SQL Functions
function Install-SQLTools {
    [CmdletBinding()]
    param (
        [Parameter()][switch]$PSModule,
        [Parameter()][switch]$SQLCmd
    )
    # Variables
    $ODBC17URL = "https://go.microsoft.com/fwlink/?linkid=2168524"
    $ODBC17MSI = "msodbcsql.msi"
    $SQLCmdURL = "https://go.microsoft.com/fwlink/?linkid=2142258"
    $SQLCmdMSI = "MsSqlCmdLnUtils.msi"
    # Param handling
    If ((!$PSModule) -and (!$SQLCmd)) {
        do {
            $instpsm = Read-Host "Do you want to install the SQLServer Powershell Module? (Y/N)"
        } until (($instpsm -eq "y") -or ($instpsm -eq "n"))
        do {
            $instcmd = Read-Host "Do you want to install SQLCMD & ODBC Drivers? (Y/N)"
        } until (($instcmd -eq "y") -or ($instcmd -eq "n"))
        If ($instpsm -eq "y") {$PSModule = $true} else {$PSModule = $false}
        If ($instcmd -eq "y") {$SQLCmd = $true} else {$SQLCmd = $false}
        If ((!$PSModule) -and (!$SQLCmd)) {
            Write-Host "No actions selected. Please try again later."
            Return $false
        }
    } else {
        If ($PSModule) {$PSModule = $true} else {$PSModule = $false}
        If ($SQLCmd) {$SQLCmd = $true} else {$SQLCmd = $false}
    }
    # Install SQLServer Module
    If ($PSModule) {
        If (!(Install-PSGallery)) {Write-Host "PSGallery not registered, cannot continue!" -ForegroundColor Red;return $false}
        $modules = Get-Module -ListAvailable | Select-Object Name,Version
        If (($modules.Name -contains "SQLServer")) {
            $SQLModule = $Modules | Where-Object {$_.Name -like "SQLServer"}
            If ($SQLModule.Version.Major -lt "22") {
                If ($SQLModule.Count -gt "1") {
                    $SQLModule | ForEach-Object {
                        $fullver = "$($_.Version.Major).$($_.Version.Minor).$($_.Version.Build)"
                        If ($_.Version.Major -lt "22") {
                            Write-Host "Removing SQL Server Module version $fullver..."
                            Uninstall-Module -Name $_.Name -RequiredVersion $fullver -Force
                        }
                    }
                } else {
                    $fullver = "$($SQLModule.Version.Major).$($SQLModule.Version.Minor).$($SQLModule.Version.Build)"
                    Write-Host "Removing SQL Server Module version $fullver..."
                    Uninstall-Module -Name $SQLModule.Name -RequiredVersion $fullver -Force
                }
                Write-Host "Installing SQL Server Module v22 or newer..."
                Push-PackageProvider -Name "Nuget"
                Install-Module -Name "SQLServer" -MinimumVersion "22.0.59" -Force -AllowClobber
                Import-Module -Name "SQLServer" -Force
            } else {
                Import-Module -Name "SQLServer" -Force
            }
        } else {
            Write-Host "Installing SQL Server Module v22 or newer..."
            Push-PackageProvider -Name "Nuget"
            Install-Module -Name "SQLServer" -MinimumVersion "22.0.59" -Force -AllowClobber
            Import-Module -Name "SQLServer" -Force
        }
    }
    # Install SQLCmd & ODBC17 Software
    If ($SQLCmd) {
        If (!(Test-Path "D:\Software\SQLTools")) {New-Item -ItemType Directory -Path "D:\Software\SQLTools" -Force | Out-Null}
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -OutFile "D:\Software\SQLTools\$ODBC17MSI" "$ODBC17URL" -ErrorAction SilentlyContinue
        Invoke-WebRequest -OutFile "D:\Software\SQLTools\$SQLCmdMSI" "$SQLCmdURL" -ErrorAction SilentlyContinue
        Write-Host "Installing SQLTools & Drivers..."
        Start-Process -FilePath msiexec.exe -ArgumentList "/i `"D:\Software\SQLTools\$ODBC17MSI`" /passive IACCEPTMSODBCSQLLICENSETERMS=YES ALLUSERS=1" -Verb RunAs -Wait
        Start-Process -FilePath msiexec.exe -ArgumentList "/i `"D:\Software\SQLTools\$SQLCmdMSI`" /passive IACCEPTMSSQLCMDLNUTILSLICENSETERMS=YES ALLUSERS=1" -Verb RunAs -Wait
        If ((Test-Path "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE") -and
            (Get-InstalledStatus -program "Microsoft Command Line Utilities 15 for SQL Server") -and 
            (Get-InstalledStatus -program "Microsoft ODBC Driver 17 for SQL Server")) {Write-Host "SQLCmd installed successfully!"} else {Write-Host "SQLCmd install failed!" -ForegroundColor Red}
    }
    # Results
    $script:results = $false
    If (($PSModule) -and ($SQLCmd)) {
        $modules = Get-Module -ListAvailable | Select-Object Name,Version
        If (($modules.Name -contains "SQLServer") -or ($modules.Name -contains "SQLPS")) {$psmod = $true} else {$psmod = $false}
        If ((Test-Path "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE") -and
            (Get-InstalledStatus -program "Microsoft Command Line Utilities 15 for SQL Server") -and 
            (Get-InstalledStatus -program "Microsoft ODBC Driver 17 for SQL Server")) {$sqlcmd = $true} else {Write-Host "SQLCMD & ODBC not present!" -ForegroundColor Red}
        If ($psmod -and $sqlcmd) {$results = $true}
    } else {
        If ($PSModule) {
            $modules = Get-Module -ListAvailable | Select-Object Name,Version
            If (($modules.Name -contains "SQLServer") -or ($modules.Name -contains "SQLPS")) {$results = $true} else {Write-Host "Could not load PS Module!" -ForegroundColor Red}
        }
        If ($SQLCmd) {
            If ((Test-Path "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE") -and
                (Get-InstalledStatus -program "Microsoft Command Line Utilities 15 for SQL Server") -and 
                (Get-InstalledStatus -program "Microsoft ODBC Driver 17 for SQL Server")) {$results = $true} else {Write-Host "SQLCMD & ODBC not present!" -ForegroundColor Red}
        }
    }
    return $results
}
function Install-SQLPackage {
    param (
        [Parameter()][string]$URL
    )
    # Variables & Param handling
    $BasePath = "C:\ProgramData\Mueller"
    $Rsrc = "$Basepath\Rsrc"
    $Files = "$Rsrc\Files"
    $URL = "https://go.microsoft.com/fwlink/?linkid=2196438"
    $MSI = "DacFramework.msi"
    $DACargs = "/passive"
    # Check Installation status
    If (Get-InstalledStatus -program "Microsoft SQL Data-Tier Application Framework") {
        Write-Host "Microsoft SQL Data-Tier Application Framework..."
        $results = $true
    } else {
        # Download installer
        $results = $null
        $Path = "$Files\$MSI"
        Write-Host "Downloading latest installer..."
        $MSIDir = Split-Path -Path $Path -Parent
        If (!(Test-Path $MSIDir)) {New-Item -ItemType Directory -Path $MSIDir}
        If (Test-Path $Path) {Write-Host "Found MSI"} else {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            try {
                Invoke-WebRequest -OutFile "$Path" "$URL" -ErrorAction SilentlyContinue
            } catch {
                Write-Host "Download failed, cannot continue." -ForegroundColor Red
                $results = $false
            }
        }
        If ([string]::IsNullOrWhiteSpace($results)) {
            # Install MSI
            Write-Host "Starting Microsoft SQL Data-Tier Application Framework installation..."
            $DAC = Install-MSI -MSI $Path -Arguments $DACargs
            If ($DAC) {
                Write-Host "Microsoft SQL Data-Tier Application Framework install completed successfully..."
                $results = $true
            } else {
                Write-Host "Microsoft SQL Data-Tier Application Framework install failed!" -ForegroundColor Red
                $results = $false
            }
        }
    }
    return $results
}
function Set-SQLServerACLs {
    <#
        .SYNOPSIS
            Author: James Miller
            Date: 11.15.2023
            Summary: Function to build ACL objects and apply to folders for SQL Server.
        .DESCRIPTION
            Function builds ACL objects and applies them recursively to each folder in $folders array.
            Folders array configured 
        .NOTES
            Written to set ACLs for datadog agent log collection.
    #>
    # Create ACL objects
    $Rules = @()
    $User = "NT SERVICE\MSSQLSERVER"
    $Folders = Get-DiskInfo
    # Verify user
    Install-SQLTools -PSModule
    Import-Module SqlServer
    $UserCheck = Get-SqlLogin -ServerInstance $env:COMPUTERNAME | Where-Object {$_.Name -eq $User}
    If (!([string]::IsNullOrWhiteSpace($UserCheck))) {
        $UserRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$User","FullControl","ContainerInherit, ObjectInherit","None","Allow")
        $Rules += $UserRule
        $SetACL = $null
        $Folders | ForEach-Object {
            $Path = $_.Name
            $Name = $_.VolumeLabel
            If (Test-Path $Path) {
                Write-Host "Setting permissions for: $Name ($Path) ..."
                Get-FolderACL -Action Set -Folder $Path -RuleObject $Rules
                $SetACL = $SetACL + "`n$true"
            } else {
                Write-Host "$Name ($Path) not found..." -ForegroundColor Yellow
                $SetACL = $SetACL + "`n$false"
            }
        }
        If (($SetACL -contains $false) -or ([string]::IsNullOrEmpty($SetACL))) {
            Write-Host "Permissions configuration failed, please set manually." -ForegroundColor Yellow
            $results = $false
        } else {
            Write-Host "Permissions configured successfully." -ForegroundColor Green
            $results = $true
        }
    } else {
        Write-Host "Cannot continue - User not found!" -ForegroundColor Red
        Write-Host "User: $User" -ForegroundColor Red
        $results = $false
    }
    return $results
}