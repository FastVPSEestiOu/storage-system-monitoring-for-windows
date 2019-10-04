<#
.SYNOPSIS
"FastvpsMonitoring.ps1" is a Powershell script to get data about
storage devices helth and  sent  report to FASTVPS monitoring.
.DESCRIPTION
The script FastvpsMonitoring.ps1 runs once per hour and receives information about the health of virtual and physical disks.
To get information, the script uses smartctl for disks and megacli / arcconf If a hardware raid is used.
The report is sent to monitor FASTVPS.
If you want to remove this script, run uninstall.exe.
.PARAMETER Test
Produce report about founded deviced and print to console.
.PARAMETER Verbose
Used to display diagnostic messages. Can be used in conjunction with parametr Test.
.EXAMPLE
FastvpsMonitoring.ps1
Standart mode. Silently generate report and send it to API.
.EXAMPLE
FastvpsMonitoring.ps1 -Test
Test mode. Similar to the Standart mode, but report will not send to API.
.NOTES
Version:        1.1
#>

######################################
##########    PROPERTY    ############
######################################

Param(
    [Parameter()][switch]$Test,
    [String]$VerboseDateFormat = 'yyyy-MM-dd HH.mm:ss'
)

######################################
########    SUBFUNCTIONS    ##########
######################################

Function Invoke-SendRequest
{
    Param(
        [Parameter(Mandatory=$True)][array]$RequestData,
        [String]$VerboseDateFormat = 'yyyy-MM-dd HH.mm:ss'
   )
    Try
    {
        [string]$API = 'https://fastcheck24.com/api/server-state/storage'
        [string]$RequestMethod = 'POST'
        [string]$RequestContentType = 'application/json; charset=utf8'

    	[hashtable]$RequestDataHash = @{
            'storage_devices' = $RequestData;
            'version' = "1.1";
        }

        #Convert the report to json format
        $RequestDataJson = $RequestDataHash | ConvertTo-Json -Depth 3
        #Encoding JSON data to UTF8
        $RequestDataEncodingJson = [System.Text.Encoding]::UTF8.GetBytes($RequestDataJson)

        Write-Verbose -Message "`n"
        Write-Verbose -Message "Request headers:"
        Write-Verbose -Message "`t`tURI: $API"
        Write-Verbose -Message "`t`tMethod: $RequestMethod"
        Write-Verbose -Message "`t`tContentType: $RequestContentType"
        Write-Verbose -Message "`t`tBody: $RequestDataJson"
        Write-Verbose -Message "`n"

        [string[]]$RequestResult = Invoke-WebRequest -Uri $API -Method $RequestMethod -Body $RequestDataEncodingJson -ContentType $RequestContentType

        return $RequestResult
    }
    Catch [System.Net.WebException]
    {
        $Response = $_.Exception.Response
        If ($Response)
        {
            $RequestStream = $Response.GetResponseStream()
            $StreamReader = New-Object System.IO.StreamReader $RequestStream
            $ResponseBody = $StreamReader.ReadToEnd()

            Write-Verbose -Message "`n"
            Write-Verbose -Message "Status: `{$([int]$Response.StatusCode)`: $($Response.StatusCode)`}"
            Write-Verbose -Message "Headers:"
            Write-Verbose -Message "{"

            ForEach ($HeaderKey in $Response.Headers) {
                $Caption = $HeaderKey
                Write-Verbose -Message "`t`t`t`t$Caption`: $($Response.Headers[$HeaderKey])";
            }

            Write-Verbose -Message "}"
            Write-Verbose -Message "Body: $ResponseBody`n"
        }
        Throw $_.Exception
    }
}

Function Get-PhysicalDiskSmartctlData
{
    Param(
        [Parameter(Mandatory=$True)][String]$Smartctl,
        [string]$VerboseDateFormat = 'yyyy-MM-dd HH.mm:ss'
   )
    Try
    {
        #Get the physical disks available for smartctl.
        #The found lines have the format like "dev/sda -d ata # /dev/sda"
        [string[]]$SmartctlScanResult = & $Smartctl --scan-open
        ForEach ($Drive in $SmartctlScanResult) {
            #Get drive name format like "/dev/sda"
            [string]$DriveName = $Drive.Split("{ }")[0]
            [string]$DriveType = $Drive.Split("{ }")[2]

            If ($DriveType -NotMatch 'nvme')
            {
                [string]$SmartEnable = & $Smartctl -i $DriveName | select-string "SMART.+Enabled$"
                If (-not $SmartEnable) {
                    Write-Warning -Message "The disk name is $($DriveName), the disk type is $($DriveType). This disk does not have SMART support. We do not check this disk"
                    Continue
                } Else {
                    Write-Verbose -Message "The disk name is $($DriveName), the disk type is $($DriveType). This disk has support for SMART. Trying get SMART info"
                }
            } Else {
                Write-Verbose -Message "The disk name is $($DriveName), the disk type is $($DriveType). Ignore check smart status"
            }

            [string[]]$SmartctlData = & $Smartctl -a $DriveName -d $DriveType
            [string]$DriveSize = $SmartctlData | Select-String "User Capacity:\s+(.*)$" -AllMatch | % {$_.Matches} | % {$_.groups[1].value}
            [string]$DriveStatus = $SmartctlData | Select-String "SMART overall-health self-assessment test result:\s+(.*)$" -AllMatch | % {$_.Matches} | % {$_.groups[1].value}
            [string]$DriveModel = $SmartctlData | Select-String "(Device Model:|Product:)\s+(.*)$" -AllMatch | % {$_.Matches} | % {$_.groups[2].value}
            [string]$SmartctlData = $SmartctlData | Out-String

            Write-Verbose -Message "Detect a new disk:"
            Write-Verbose -Message "Drive Name:  $($DriveName)"
            Write-Verbose -Message "Drive Type:  $($DriveType)"
            Write-Verbose -Message "Drive Model:  $($DriveModel)"
            Write-Verbose -Message "Drive Status:  $($DriveStatus)"
            Write-Verbose -Message "Drive Size:  $($DriveSize)"
            Write-Verbose -Message "Drive Data:  $($SmartctlData)"

            [hashtable]$DrivesHash = @{
                'size' = $DriveSize;
                'device_name' = $DriveName;
                'status' = $DriveStatus;
                'type' = "hard_disk";
                'diag' = $SmartctlData;
                'model' = $DriveModel;
            }
            [array]$DrivesArray += $DrivesHash
        }
        return $DrivesArray
    }
    Catch
    {
        Write-Warning "Get-PhysicalDiskSmartctlData failed to execute"
        Throw $_.Exception
    }
}

Function Get-SoftwareRaidData
{
    Param(
        [String]$VerboseDateFormat = 'yyyy-MM-dd HH.mm:ss'
   )
    Try
    {
        [array]$SoftwareRaidData = Get-StoragePool;
        If ($SoftwareRaidData)
        {
            ForEach ($SoftRaid in $SoftwareRaidData) {
                [string]$SoftwareRaidSize = [math]::Round(($SoftRaid.Size/1TB), 2).ToString() + "Tb" + "(" + ($SoftRaid.Size/1Gb).ToString() + "Gb)"
                [string]$SoftwareRaidName = $SoftRaid.FriendlyName
                [string]$SoftwareRaidStatus = $SoftRaid.HealthStatus
                [string]$SoftwareRaidModel = $SoftRaid.ResiliencySettingNameDefault
                [string]$SoftwareRaidData = $SoftRaid | Format-List * | out-string

                Write-Verbose -Message "Software Raid Name:  $($SoftwareRaidName)"
                Write-Verbose -Message "Software Raid Model:  $($SoftwareRaidModel)"
                Write-Verbose -Message "Software Raid Status:  $($SoftwareRaidStatus)"
                Write-Verbose -Message "Software Raid Size:  $($SoftwareRaidSize)"
                Write-Verbose -Message "Software Raid Data:  $($SoftwareRaidData)"

                [hashtable]$SoftwareRaidDrivesHash = @{
                    'size' = $SoftwareRaidSize;
                    'device_name' = $SoftwareRaidName;
                    'status' = $SoftwareRaidStatus;
                    'type' = "raid";
                    'diag' = $SoftwareRaidData;
                    'model' = $SoftwareRaidModel;
                }
                [array]$SoftwareRaidArray += $SoftwareRaidDrivesHash
            }
        return $SoftwareRaidArray
        }
    }
    Catch
    {
        Write-Warning "Get-SoftwareRaidData failed to execute"
        Throw $_.Exception
    }
}

Function Get-HardwareRaidDisksData
{
    Param(
        [Parameter(Mandatory=$True)][String]$RaidModel,
        [Parameter(Mandatory=$True)][String]$CLI,
        [Parameter(Mandatory=$True)][array]$HwraidVirtualDevices,
        [Parameter(Mandatory=$True)][String]$Smartctl,
        [String]$VerboseDateFormat = 'yyyy-MM-dd HH.mm:ss'
   )
    Try
    {
        #Get utility name. Available values 'MegaCli.exe' or 'arcconf.exe'
        [string]$CLIName = $CLI | %{ $_.Split('\')[-1]; }
        If ($CLIName -eq 'arcconf.exe')
        {
            ForEach ($VirtualDevice In $HwraidVirtualDevices) {
                #$VirtualDevice is a hash with the data of the found logical device.
                #Get information of the used logical devices from '$VirtualDevice.diag'.
                #Convert this data to array.
                [string[]]$VirtualDeviceData = $VirtualDevice.diag.split("`n")
                [string[]]$PhysicalDrivesSegments = $VirtualDeviceData | Select-String "Segment \d+"

                #We try to get SMART attributes by arcconf. Smartctl can't get this data for drives that are connected to hardware raid, because
                #it has troubles with getting information from scsi devices in Windows.
                [string[]]$SmartData = & $CLI getsmartstats 1

                #Convert an array with SMART data to xml for further parse. The format in which arcconf returns data is fucking shit.
                $SmartSataXml = ([xml]([Regex]::Match($SmartData, '(?s)<SmartStats.*?</SmartStats>')).Value)
                $SmartSasXml = ([xml]([Regex]::Match($SmartData, '(?s)<SASSmartStats.*?</SASSmartStats>')).Value)

                #Select the XML nodes "SATA" or "SAS".
                If ($SmartSataXml)
                {
                    [xml]$XML = $SmartSataXml
                }
                ElseIf ($SmartSasXml)
                {
                    [xml]$XML = $SmartSasXml
                }
                #$PhysicalDrivesSegments is an array with basic data about the disks that are used in this logical device.
                #The elements in this array have the format "Segment 0: Present (953869MB, SATA, HDD, Connector:0, Device:0) Z1D14SKC".
                ForEach ($PhysicalDriveSegment In $PhysicalDrivesSegments) {
                    #Get drive's path in conrtoller. It's need for using smartctl.
                    #Smartctl command for the "adaptec" raid should look like this "smartctl -a -d aacraid,X,Y,Z" where X - logical device number, Y - drive's connector number, Z - drive's device id.
                    [int]$LogicalDriveId = $VirtualDeviceData | Select-String "Logical Device number (\d+)" -SimpleMatch | % {$_.Matches} | % {$_.groups[1].value}
                    [int]$PhysicalDriveConnectorId = $PhysicalDriveSegment | Select-String "Connector:(\d+)" -AllMatches | % {$_.Matches} | % {$_.groups[1].value}
                    [int]$PhysicalDriveDeviceId = $PhysicalDriveSegment | Select-String "Device:(\d+)" -AllMatches | % {$_.Matches} | % {$_.groups[1].value}
                    [string]$PhysicalDrivePath =  "$LogicalDriveId,$PhysicalDriveConnectorId,$PhysicalDriveDeviceId"

                    Write-Verbose -Message "Logical Drive ID:  $($LogicalDriveId)"
                    Write-Verbose -Message "Physical Drive Connector ID:  $($PhysicalDriveConnectorId)"
                    Write-Verbose -Message "Physical Drive Device ID:  $($PhysicalDriveDeviceId)"

                    #Get available SMART data by smartctl.
                    [string[]]$PhysicalDriveSmartctlData = & $Smartctl -a -d "aacraid,$PhysicalDrivePath" /dev/sda
                    #Get the SMART attributes for the specIfied drive from xml.
                    [string[]]$PhysicalDriveArcconfData = ($XML.SelectNodes("/SmartStats/PhysicalDriveSmartStats") | where {$_.id -eq $PhysicalDriveDeviceId}).Attribute.OuterXml

                    If ($PhysicalDriveSmartctlData -match 'ARCIOCTL_SEND_RAW_SRB failed')
                    {
                        Write-Warning -Message "Can't get SMART information about drive by smartctl. Adaptec bug. Skip it"
                        [string]$PhysicalDriveData = $PhysicalDriveArcconfData | Out-String
                    }
                    Else
                    {
                        #Combine the data, received from arcconf and smartctl.
                        [string]$PhysicalDriveData = ($PhysicalDriveSmartctlData + $PhysicalDriveArcconfData) | Out-String
                    }

                    [string]$PhysicalDriveName = "Device #$PhysicalDriveDeviceId"
                    [string]$PhysicalDriveSize = $PhysicalDriveSmartctlData | Select-String "User Capacity:\s+(.*)$" -AllMatch | % {$_.Matches} | % {$_.groups[1].value}
                    [string]$PhysicalDriveModel = $PhysicalDriveSmartctlData | Select-String "(Device Model:|Product:)\s+(.*)$" -AllMatch | % {$_.Matches} | % {$_.groups[2].value}

                    Write-Verbose -Message "Physical Drive Name:  $($PhysicalDriveName)"
                    Write-Verbose -Message "Physical Drive Size:  $($PhysicalDriveSize)"
                    Write-Verbose -Message "Physical Drive Model:  $($PhysicalDriveModel)"
                    Write-Verbose -Message "Drive Data by Smartctl:  $($PhysicalDriveSmartctlData)"
                    Write-Verbose -Message "Drive Data by Arcconf:  $($PhysicalDriveArcconfData)"

                    [hashtable]$PhysicalDrivesHash = @{
                        'size' = $PhysicalDriveSize;
                        'device_name' = $PhysicalDriveName;
                        'status' = "undefined";
                        'type' = "hard_disk";
                        'diag' = $PhysicalDriveData;
                        'model' = $PhysicalDriveModel;
                    }
                    [array]$PhysicalDrivesArray += $PhysicalDrivesHash
                }
            }
        }
        ElseIf ($CLIName -eq 'MegaCli.exe')
        {
           [int]$PhysicalDriveDeviceId = & $CLI -EncInfo -aALL | Select-String "^\s+Device\sID\s+:\s(\d+)" -AllMatches | % {$_.Matches} | % {$_.groups[1].value}
           [int[]]$PhysicalDriveSlot = & $CLI -PDList -aALL | Select-String "\s*Slot\sNumber:\s(\d+)" -AllMatches | % {$_.Matches} | % {$_.groups[1].value}

           ForEach ($Slot in $PhysicalDriveSlot) {
               [string]$PhysicalDrivePath = "$PhysicalDriveDeviceId`:$Slot"
               [string[]]$PhysicalDriveData = & $CLI -pdInfo -PhysDrv [$PhysicalDrivePath] -aALL

               [string]$PhysicalDriveName = $PhysicalDriveData | Select-String "^\s*Device Id:\s(.*)$" -AllMatches
               [string]$PhysicalDriveSize = $PhysicalDriveData | Select-String "^\s*Raw Size:\s(.*)$" -AllMatches | % {$_.Matches} | % {$_.groups[1].value}
               [string]$PhysicalDriveModel = $PhysicalDriveData | Select-String "^\s*Inquiry Data:\s(.*)$" -AllMatches | % {$_.Matches} | % {$_.groups[1].value}
               [string]$PhysicalDriveFormatData = $PhysicalDriveData | Out-String

               Write-Verbose -Message "Physical Drive Name:  $($PhysicalDriveName)"
               Write-Verbose -Message "Physical Drive Size:  $($PhysicalDriveSize)"
               Write-Verbose -Message "Physical Drive Model:  $($PhysicalDriveModel)"
               Write-Verbose -Message "Physical Drive Data:  $($PhysicalDriveFormatData)"

               [hashtable]$PhysicalDrivesHash = @{
                   'size' = $PhysicalDriveSize;
                   'device_name' = $PhysicalDriveName;
                   'status' = "undefined";
                   'type' = "hard_disk";
                   'diag' = $PhysicalDriveFormatData;
                   'model' = $PhysicalDriveModel;
               }
               [array]$PhysicalDrivesArray += $PhysicalDrivesHash
           }
        }
        return $PhysicalDrivesArray
    }
    Catch
    {
        Write-Warning "Get-HardwareRaidDisksData failed to execute"
        Throw $_.Exception
    }
}

Function Get-HardwareRaidVirtDeviceData
{
    Param(
        [Parameter(Mandatory=$True)][String]$RaidModel,
        [Parameter(Mandatory=$True)][String]$CLI,
        [string]$VerboseDateFormat = 'yyyy-MM-dd HH.mm:ss'
   )
    Try
    {
        #Get utility name. Available values 'MegaCli.exe' or 'arcconf.exe'
        [string]$CLIName = $CLI | %{ $_.Split('\')[-1]; }

        If ($CLIName -eq 'arcconf.exe')
        {
            #Get all logical devices.
            [string[]]$LogicalDrives = & $CLI GETCONFIG 1 LD
            #Get "Logical Device number" for founded logical devices.
            [string[]]$LogicalDriveIDs = @($LogicalDrives | Select-String "Logical Device number (\d+)" -AllMatches | % {$_.Matches} | % {$_.groups[1].value})

            ForEach ($LogicalDriveID In $LogicalDriveIDs) {
                #Select logical device by the "Logical Device number".
                #Convert this array of data to a string and parse the required parameters.
                [string]$LogicalDriveData = & $CLI GETCONFIG 1 LD $LogicalDriveID | Out-String
                [string]$LogicalDriveName = [REGEX]::Matches($LogicalDriveData, 'Logical Device name\s+:\s(\w+\s\d*)') | % {$_.groups[1].value}
                [string]$LogicalDriveSize = [REGEX]::Matches($LogicalDriveData, 'Size\s+:\s(\d+\s\w+)') | % {$_.groups[1].value}
                [string]$LogicalDriveStatus = [REGEX]::Matches($LogicalDriveData, 'Status of Logical Device\s+:\s(\w+)') | % {$_.groups[1].value}

                Write-Verbose -Message "Logical Drive Name:  $($LogicalDriveName)"
                Write-Verbose -Message "Logical Drive Size:  $($LogicalDriveSize)"
                Write-Verbose -Message "Logical Drive Status:  $($LogicalDriveStatus)"
                Write-Verbose -Message "Logical Drive Data:  $($LogicalDriveData)"

                [hashtable]$LogicalDevicesHash = @{
                    'size' = $LogicalDriveSize;
                    'device_name' = $LogicalDriveName;
                    'status' = $LogicalDriveStatus;
                    'type' = "raid";
                    'diag' = $LogicalDriveData;
                    'model' = $RaidModel;
                }
                [array]$HwraidDeviceData += $LogicalDevicesHash
            }
        }
        ElseIf ($CLIName -eq 'MegaCli.exe') {
            [string[]]$LogicalDrivesId = & $CLI -LDInfo -Lall -Aall | Select-String "Virtual Drive:\s+(\d+)" -AllMatches | % {$_.Matches} | % {$_.groups[1].value}

            ForEach ($LogicalDriveId in $LogicalDrivesId) {
                [string[]]$LogicalDriveData = & $CLI -LDInfo -L"$LogicalDriveId" -aALL
                [string]$LogicalDriveName = $LogicalDriveData | Select-String "(Virtual Drive:\s+\d+)" -AllMatches | % {$_.Matches} | % {$_.groups[1].value}
                [string]$LogicalDriveSize = $LogicalDriveData | Select-String "^Size\s*: (.*)$" -AllMatches | % {$_.Matches} | % {$_.groups[1].value}
                [string]$LogicalDriveStatus = $LogicalDriveData | Select-String "^State\s*: (.*)$" -AllMatches | % {$_.Matches} | % {$_.groups[1].value}
                [string]$LogicalDriveFormatData = $LogicalDriveData | Out-String

                Write-Verbose -Message "Logical Drive Name:  $($LogicalDriveName)"
                Write-Verbose -Message "Logical Drive Size:  $($LogicalDriveSize)"
                Write-Verbose -Message "Logical Drive Status:  $($LogicalDriveStatus)"
                Write-Verbose -Message "Logical Drive Data:  $($LogicalDriveFormatData)"

                [hashtable]$LogicalDevicesHash = @{
                    'size' = $LogicalDriveSize;
                    'device_name' = $LogicalDriveName;
                    'status' = $LogicalDriveStatus;
                    'type' = "raid";
                    'diag' = $LogicalDriveFormatData;
                    'model' = "lsi";
                }
                [array]$HwraidDeviceData += $LogicalDevicesHash
            }
        }
        return $HwraidDeviceData
    }
    Catch
    {
        Write-Warning "Get-HardwareRaidVirtDeviceData failed to execute"
        Throw $_.Exception
    }
}

######################################
############    MAIN    ##############
######################################

#Get the path for the necessary utilities. Utilities must be located in the parent directory of the script or in one of its subdirectories.
[string]$MegacliPath = (Get-ChildItem -Recurse -Path $PSScriptRoot -Filter 'megacli.exe').FullName
[string]$ArcconfPath = (Get-ChildItem -Recurse -Path $PSScriptRoot -Filter 'arcconf.exe').FullName
[string]$SmartctlPath = (Get-ChildItem -Recurse -Path $PSScriptRoot -Filter 'smartctl.exe').FullName

#Hash, where the keys are a possible value for the "Manufacturer" property, and the keys are a suitable utility for this manufacturer.
#If the manufacturer = dell, perc or lsi, the utility 'megacli' will be searched.exe'. If the manufacturer = adaptec, Udet search utility ' arcconf.exe'.
[hashtable]$UtilityByModel = @{
    'adaptec' = $ArcconfPath;
    'dell' = $MegacliPath;
    'perc' = $MegacliPath;
    'lsi' = $MegacliPath;
}

#Find the drive that has properties "BusType" with the value "RAID" and "Manufacturer" with the value "adaptec|dell|perc.". This is a hardware raid.
[string]$HwraidModel =  Get-PhysicalDisk | where {$_.BusType -eq 'RAID'} | select -ExpandProperty "Manufacturer" -Unique

#If a hardware raid is detected, we are trying to select the utility "megacli.exe" or "arcconf.exe" based on the property's "Manufacturer" value.
If ($HwraidModel)
{
    $HwraidModel = $HwraidModel.trim()
    #Get cli utility path for founded hardware raid.
    [string]$CLIPath = $UtilityByModel.$HwraidModel
    If (-not $CLIPath)
    {
        Write-Error "This RAID controller model is not supported. Please check its status manually."
        exit
    }
    #Check the existence of a utility on a previously found path.
    [string]$CLIPathExist = Get-Command $CLIPath -ErrorAction SilentlyContinue
    If (-not $CLIPathExist)
    {
        Write-Error "Unable to find hardware raid utility"
        exit
    }
    #Get virtual or logical devices, created for hardware raid.
    [array]$HwraidVirtualDevices = Get-HardwareRaidVirtDeviceData -RaidModel $HwraidModel -CLI "$CLIPath"
    #Get the physical disks connected to the hardware raid.
    [array]$HwraidDisks = Get-HardwareRaidDisksData -RaidModel $HwraidModel -CLI "$CLIPath" -HwraidVirtualDevices $HwraidVirtualDevices -Smartctl "$SmartctlPath"
}
#Get software raid.
[array]$SoftwareRaidData = Get-SoftwareRaidData

#Check smartctl path
$SmartctlPathExist = Get-Command $SmartctlPath -ErrorAction SilentlyContinue
If (-not $SmartctlPathExist)
{
    write-error "Unable to find smartctl.exe"
    exit
}

#Get physical drives.
[array]$PhysicalDisks = Get-PhysicalDiskSmartctlData -Smartctl "$SmartctlPath"

#Merge all elements from previously defined arrays into one array. Arrays with a number of elements equal to 0 are ignored.
ForEach ($Array in ($HwraidVirtualDevices, $HwraidDisks, $SoftwareRaidData, $PhysicalDisks)) {
    If ($array.count -ne '0')
    {
        [array]$AllDeviceData += $Array
    }
}

#If the "Test" property is not set, the data is sent to the monitoring API.
If (-not $Test)
{
    Write-Verbose -Message "Mode 'Test' did not activate. Send request to API `n"
    [string[]]$SendRequestResult = Invoke-SendRequest -RequestData $AllDeviceData
}
Else
{
    If ($HwraidModel) {
        Write-Verbose -Message "Hardware raid detected. Manufacturer - $HwraidModel"
        Write-Verbose -Message "`n"
        If ($HwraidVirtualDevices.Count) {
            Write-Verbose -Message "Virtual Devices in a hardware RAID found - $($HwraidVirtualDevices.Count | Out-String)"
            Write-Verbose -Message "Information about Virtual Devices:`n"
            ForEach ($device in $HwraidVirtualDevices) {
                Write-Verbose -Message "`t`tName: $($device.device_name | Out-String)"
                Write-Verbose -Message "`t`tStatus: $($device.status | Out-String)"
                Write-Verbose -Message "`t`tSize: $($device.size | Out-String)"
                Write-Verbose -Message "`t`tType: $($device.type | Out-String)"
            }
            Write-Verbose -Message "`n"
        }
        If ($HwraidDisks.Count)
        {
            Write-Verbose -Message "Drives connected via hardware RAID found - $($HwraidDisks.Count | Out-String)"
            Write-Verbose -Message "Information about drives connected via hardware RAID:"
            ForEach ($device in $HwraidDisks) {
                Write-Verbose -Message "`t`tName: $($device.device_name | Out-String)"
                Write-Verbose -Message "`t`tType: $($device.type | Out-String)"
                Write-Verbose -Message "`t`tSize: $($device.size | Out-String)"
                Write-Verbose -Message "`t`tModel: $($device.model | Out-String)"
            }
            Write-Verbose -Message "`n"
        }
    }
    If ($SoftwareRaidData.Count)
    {
        Write-Verbose -Message "Software RAID found - $($SoftwareRaidData.Count | Out-String)"
        Write-Verbose -Message "Information about software RAID:"
        ForEach ($device in $SoftwareRaidData) {
            Write-Verbose -Message "`t`tName: $($device.device_name | Out-String)"
            Write-Verbose -Message "`t`tStatus: $($device.status | Out-String)"
            Write-Verbose -Message "`t`tSize: $($device.size | Out-String)"
        	Write-Verbose -Message "`t`tType: $($device.type | Out-String)"
        }
        Write-Verbose -Message "`n"
    }
    If ($PhysicalDisks.Count)
    {
        Write-Verbose -Message "Physical drives found - $($PhysicalDisks.Count | Out-String)"
        Write-Verbose -Message "Information about physical drives:"
        ForEach ($device in $PhysicalDisks) {
            Write-Verbose -Message "`t`tName: $($device.device_name | Out-String)"
        	Write-Verbose -Message "`t`tType: $($device.type | Out-String)"
            Write-Verbose -Message "`t`tSize: $($device.size | Out-String)"
            Write-Verbose -Message "`t`tModel: $($device.model | Out-String)"
        }
        Write-Verbose -Message "`n"
    }
    Write-Verbose -Message "Mode 'Test' activated. Request will not send to API `n"
}
Write-Verbose -Message "Finish"
