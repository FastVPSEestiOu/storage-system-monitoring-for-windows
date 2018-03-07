<#
.SYNOPSIS
"FastvpsMonitoring.ps1" is a Powershell script to get data about
storage devices helth and  sent  report to FASTVPS monitoring.
.DESCRIPTION
The script FastvpsMonitoring.ps1 runs once per hour and receives information about the health of virtual and physical disks.
To get information, the script uses smartctl for disks and megacli / arcconf if a hardware raid is used.
The report is sent to monitor FASTVPS.
If you want to remove this script, run uninstall.exe.
.PARAMETER Test
Produce report about founded deviced and print to console.
.EXAMPLE
FastvpsMonitoring.ps1
Standart mode. Silently generated report and sent it to API.
.EXAMPLE
FastvpsMonitoring.ps1 -Test
Debug mode. Print generated report to console.
Report is not sent to API.
.NOTES
  Version:        1.0
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
    
        [hashtable]$RequestDataHash = @{
            'storage_devices' = $RequestData;
            'version' = "1.0";
        }   

        #Convert the report to json and sent it to API.
        $RequestDataJson = $RequestDataHash | ConvertTo-Json -Depth 3
	
	[string[]]$RequestResult = Invoke-WebRequest -Uri $API -Method Post -Body ([System.Text.Encoding]::UTF8.GetBytes($RequestDataJson)) -ContentType "application/json; UTF-8"        
        return $RequestResult
    }
    Catch
    {
        Write-Warning "Invoke-SendRequest failed to execute"
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

        foreach ($Drive in $SmartctlScanResult) {
            #Get drive name format like "/dev/sda"
            [string]$DriveName = $Drive.Split("{ }")[0]
            #Check the possibility of getting S.M.A.R.T. for the drive. If not available - next disk.
            [string]$SmartEnable = & $Smartctl -i $DriveName | select-string "SMART.+Enabled$"
            if ( $SmartEnable )  {
                [string[]]$SmartctlData = & $Smartctl -a $DriveName
                [string]$DriveSize = $SmartctlData | Select-String "User Capacity:\s+(.*)$" -AllMatch | % {$_.Matches} | % {$_.groups[1].value}
                [string]$DriveStatus = $SmartctlData | Select-String "SMART overall-health self-assessment test result:\s+(.*)$" -AllMatch | % {$_.Matches} | % {$_.groups[1].value}
                [string]$DriveModel = $SmartctlData | Select-String "(Device Model:|Product:)\s+(.*)$" -AllMatch | % {$_.Matches} | % {$_.groups[2].value}
                [string]$SmartctlData = $SmartctlData | Out-String
                 
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
            else {
                Continue
            }
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
        if ($SoftwareRaidData) {
            foreach ($SoftRaid in $SoftwareRaidData) {
            
                [string]$SoftwareRaidSize = [math]::Round(($SoftRaid.Size/1TB), 2).ToString() + "Tb" + "(" + ($SoftRaid.Size/1Gb).ToString() + "Gb)" 
                [string]$SoftwareRaidName = $SoftRaid.FriendlyName
                [string]$SoftwareRaidStatus = $SoftRaid.HealthStatus
                [string]$SoftwareRaidData = $SoftRaid | Format-List * | out-string
                [string]$SoftwareRaidModel = $SoftRaid.ResiliencySettingNameDefault
        
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
        if ($RaidModel -match "adaptec") {
            foreach ($VirtualDevice In $HwraidVirtualDevices) {
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
                if ($SmartSataXml) {
                    [xml]$XML = $SmartSataXml
                }
                elseif ($SmartSasXml) {
                    [xml]$XML = $SmartSasXml
                }
        
                #$PhysicalDrivesSegments is an array with basic data about the disks that are used in this logical device.
                #The elements in this array have the format "Segment 0: Present (953869MB, SATA, HDD, Connector:0, Device:0) Z1D14SKC".
                foreach ($PhysicalDriveSegment In $PhysicalDrivesSegments) {
    
                    #Get drive's path in conrtoller. It's need for using smartctl.
                    #Smartctl command for the "adaptec" raid should look like this "smartctl -a -d aacraid,X,Y,Z" where X - logical device number, Y - drive's connector number, Z - drive's device id.
                    [int]$LogicalDriveId = $VirtualDeviceData | Select-String "Logical Device number (\d+)" -SimpleMatch | % {$_.Matches} | % {$_.groups[1].value}
                    [int]$PhysicalDriveConnectorId = $PhysicalDriveSegment | Select-String "Connector:(\d+)" -AllMatches | % {$_.Matches} | % {$_.groups[1].value}
                    [int]$PhysicalDriveDeviceId = $PhysicalDriveSegment | Select-String "Device:(\d+)" -AllMatches | % {$_.Matches} | % {$_.groups[1].value}
                    [string]$PhysicalDrivePath =  "$LogicalDriveId,$PhysicalDriveConnectorId,$PhysicalDriveDeviceId"
         
                    #Get available SMART data by smartctl.
                    [string[]]$PhysicalDriveSmartctlData = & $Smartctl -a -d "aacraid,$PhysicalDrivePath" /dev/sda
                    #Get the SMART attributes for the specified drive from xml.
                    [string[]]$PhysicalDriveArcconfData = ($XML.SelectNodes("/SmartStats/PhysicalDriveSmartStats") | where {$_.id -eq $PhysicalDriveDeviceId}).Attribute.OuterXml
                    #Combine the data, received from arcconf and smartctl.
                    [string]$PhysicalDriveData = ($PhysicalDriveSmartctlData + $PhysicalDriveArcconfData) | Out-String
                    
                    [string]$PhysicalDriveSize = $PhysicalDriveSmartctlData | Select-String "User Capacity:\s+(.*)$" -AllMatch | % {$_.Matches} | % {$_.groups[1].value}
                    [string]$PhysicalDriveModel = $PhysicalDriveSmartctlData | Select-String "(Device Model:|Product:)\s+(.*)$" -AllMatch | % {$_.Matches} | % {$_.groups[2].value}
                    [string]$PhysicalDriveName = "Device #$PhysicalDriveDeviceId"
                
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
        elseif ($RaidModel -match "dell|perc"){
    
                [int]$PhysicalDriveDeviceId = & $CLI -EncInfo -aALL | Select-String "^\s+Device\sID\s+:\s(\d+)" -AllMatches | % {$_.Matches} | % {$_.groups[1].value}
                [int[]]$PhysicalDriveSlot = & $CLI -PDList -aALL | Select-String "\s*Slot\sNumber:\s(\d+)" -AllMatches | % {$_.Matches} | % {$_.groups[1].value}
                
                foreach ($Slot in $PhysicalDriveSlot) {
                    [string]$PhysicalDrivePath = "$PhysicalDriveDeviceId`:$Slot"
                    [string[]]$PhysicalDriveData = & $CLI -pdInfo -PhysDrv [$PhysicalDrivePath] -aALL
                    
                    [string]$PhysicalDriveSize = $PhysicalDriveData | Select-String "^\s*Raw Size:\s(.*)$" -AllMatches | % {$_.Matches} | % {$_.groups[1].value}
                    [string]$PhysicalDriveName = $PhysicalDriveData | Select-String "^\s*Device Id:\s(.*)$" -AllMatches
                    [string]$PhysicalDriveModel = $PhysicalDriveData | Select-String "^\s*Inquiry Data:\s(.*)$" -AllMatches | % {$_.Matches} | % {$_.groups[1].value}
                    [string]$PhysicalDriveFormatData = $PhysicalDriveData | Out-String
            
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
        if ($RaidModel -match 'adaptec') {
            
            #Get all logical devices.
            [string[]]$LogicalDrives = & $CLI GETCONFIG 1 LD
        
            #Get "Logical Device number" for founded logical devices.
            [string[]]$LogicalDriveIDs = @( $LogicalDrives | Select-String "Logical Device number (\d+)" -AllMatches | % {$_.Matches} | % {$_.groups[1].value} )        
        
            foreach ($LogicalDriveID In $LogicalDriveIDs) {
                #Select logical device by the "Logical Device number".
                #Convert this array of data to a string and parse the required parameters.
                [string]$LogicalDriveData = & $CLI GETCONFIG 1 LD $LogicalDriveID | Out-String
            
                [string]$LogicalDriveSize = [REGEX]::Matches($LogicalDriveData, 'Size\s+:\s(\d+\s\w+)') | % {$_.groups[1].value}
                [string]$LogicalDriveName = [REGEX]::Matches($LogicalDriveData, 'Logical Device name\s+:\s(\w+\s\d*)') | % {$_.groups[1].value}
                [string]$LogicalDriveStatus = [REGEX]::Matches($LogicalDriveData, 'Status of Logical Device\s+:\s(\w+)') | % {$_.groups[1].value}

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
        elseif ($RaidModel -match "dell|perc") {

            [string[]]$LogicalDrivesId = & $CLI -LDInfo -Lall -Aall | Select-String "Virtual Drive:\s+(\d+)" -AllMatches | % {$_.Matches} | % {$_.groups[1].value} 
            foreach ($LogicalDriveId in $LogicalDrivesId){
                [string[]]$LogicalDriveData = & $CLI -LDInfo -L"$LogicalDriveId" -aALL
                
                [string]$LogicalDriveSize = $LogicalDriveData | Select-String "^Size\s*: (.*)$" -AllMatches | % {$_.Matches} | % {$_.groups[1].value} 
                [string]$LogicalDriveName = $LogicalDriveData | Select-String "(Virtual Drive:\s+\d+)" -AllMatches | % {$_.Matches} | % {$_.groups[1].value} 
                [string]$LogicalDriveStatus = $LogicalDriveData | Select-String "^State\s*: (.*)$" -AllMatches | % {$_.Matches} | % {$_.groups[1].value} 
                [string]$LogicalDriveFormatData = $LogicalDriveData | Out-String
            
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
[hashtable]$UtilityByModel = @{
    'adaptec' = $ArcconfPath;
    'dell' = $MegacliPath;
    'perc' = $MegacliPath;
}

#Find the drive that has properties "BusType" with the value "RAID" and "Manufacturer" with the value "adaptec|dell|perc.". This is a hardware raid.
[string]$HwraidModel =  Get-PhysicalDisk | where {$_.BusType -eq 'RAID'} | select -ExpandProperty "Manufacturer" -Unique

#If a hardware raid is detected, we are trying to select the utility "megacli.exe" or "arcconf.exe" based on the property's "Manufacturer" value.
if ( $HwraidModel ) {
    $HwraidModel = $HwraidModel.trim()
    #Get cli utility path for founded hardware raid.
    [string]$CLIPath = $UtilityByModel.$HwraidModel
    if ((Get-Command $CLIPath -ErrorAction SilentlyContinue) -eq $null) { 
        write-error "Unable to find hardware raid utility"
        exit
    }

    #Get virtual or logical devices, created for hardware raid.
    [array]$HwraidVirtualDevices = Get-HardwareRaidVirtDeviceData -RaidModel $HwraidModel -CLI "$CLIPath"
    
    #Get the physical disks connected to the hardware raid.
    [array]$HwraidDisks = Get-HardwareRaidDisksData -RaidModel $HwraidModel -CLI "$CLIPath" -HwraidVirtualDevices $HwraidVirtualDevices -Smartctl "$SmartctlPath"
    
}

    #Get software raid.
    [array]$SoftwareRaidData = Get-SoftwareRaidData
    
    #Get physical drives.
    [array]$PhysicalDisks = Get-PhysicalDiskSmartctlData -Smartctl "$SmartctlPath"
    if ((Get-Command $SmartctlPath -ErrorAction SilentlyContinue) -eq $null) { 
        write-error "Unable to find smartctl.exe"
        exit
    }
    
    #Merge all elements from previously defined arrays into one array. Arrays with a number of elements equal to 0 are ignored.
    foreach ($Array in ($HwraidVirtualDevices, $HwraidDisks, $SoftwareRaidData, $PhysicalDisks)) {
        if ( $array.count -ne '0' ) {
            [array]$AllDeviceData += $Array
        }
    }

#If the "Test" property is not set, the data is sent to the monitoring API.
if ( $Test ) {
write-host "Test mode on."
    if ( $HwraidModel ) {
        write-host "Hardware raid detected. Manufacturer:"$HwraidModel
        write-host "HWRAID Virtual devices found:"$HwraidVirtualDevices.Count
        if ($HwraidVirtualDevices.Count -ne '0') {
            write-host "HWRAID Virtual devices info:"
            foreach ($device in $HwraidVirtualDevices) {
            	write-host "Name:" $device.device_name
                write-host "Status:" $device.status
                write-host "Size:" $device.size
            	write-host "Type:" $device.type
            	write-host "Diagnostic data:`n" $device.diag
            }
        }
        write-host "HWRAID Physical drives found:"$HwraidDisks.Count
        if ($HwraidDisks.Count -ne '0') {
            write-host "HWRAID Physical drives info:"
            foreach ($device in $HwraidDisks) {
                write-host "Name:" $device.device_name
            	write-host "Type:" $device.type
                write-host "Size:" $device.size
                write-host "Model:" $device.model
                write-host "Diagnostic data:`n" $device.diag
            }
        }
    }
    write-host "Software raid found:"$SoftwareRaidData.Count
    if ($SoftwareRaidData.Count -ne '0') {
        write-host "Software raid info:"
        foreach ($device in $SoftwareRaidData) {
        	write-host "Name:" $device.device_name
            write-host "Status:" $device.status
            write-host "Size:" $device.size
        	write-host "Type:" $device.type
        	write-host "Diagnostic data:`n" $device.diag
        }
    }
    write-host "Physical drives found:"$PhysicalDisks.Count
    if ($PhysicalDisks.Count -ne '0') {
        write-host "Physical drives info:"
        foreach ($device in $PhysicalDisks) {
            write-host "Name:" $device.device_name
        	write-host "Type:" $device.type
            write-host "Size:" $device.size
            write-host "Model:" $device.model
            write-host "Diagnostic data:`n" $device.diag
        }
    }
}
#If the Test property is set, we create a report and display it on the console. The report is not sent to api.
else {
    [string[]]$SendRequestResult = Invoke-SendRequest -RequestData $AllDeviceData
}
