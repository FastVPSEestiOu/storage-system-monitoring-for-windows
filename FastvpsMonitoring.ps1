<#PSScriptInfo

.VERSION 1.7

.GUID 1d829f01-0b8d-432c-8aba-f96bd3255c2d

.AUTHOR dm@tele.hosting

.COMPANYNAME FASTVPS

.TAGS Storage Monitoring SMART RAID Adaptec LSI MegaRAID Windows Server

.PROJECTURI https://github.com/FastVPSEestiOu/storage-system-monitoring-for-windows/

#>

<#
.SYNOPSIS
    Storage monitoring agent for FastVPS infrastructure.

.DESCRIPTION
    Collects storage device health information using smartmontools and
    reports data to the monitoring API. Supports hardware RAID controllers
    (Adaptec, LSI/MegaRAID), software RAID, and direct-attached drives.

    The script runs via scheduled task and receives information
    about the health of virtual and physical disks. To get information, the
    script uses smartctl for disks and megacli/arcconf if hardware RAID is used.

.PARAMETER Test
    Run in test mode without sending data to the API. Produces report about
    found devices and prints to console.

.PARAMETER VerboseDateFormat
    Date format for verbose output timestamps. Default: 'yyyy-MM-dd HH.mm:ss'

.EXAMPLE
    FastvpsMonitoring.ps1
    Standard mode. Silently generates report and sends it to API.

.EXAMPLE
    FastvpsMonitoring.ps1 -Test
    Test mode. Similar to standard mode, but report will not be sent to API.

.EXAMPLE
    FastvpsMonitoring.ps1 -Test -Verbose
    Test mode with detailed diagnostic output.

.NOTES
    Version:  1.7
    Requires: PowerShell 5.0+
    Target:   Windows Server 2012 R2+
#>

#Requires -Version 5.0

[CmdletBinding()]
param(
    [Parameter(HelpMessage = 'Run in test mode without API submission')]
    [switch]$Test,

    [Parameter(HelpMessage = 'Date format for verbose output timestamps')]
    [ValidateNotNullOrEmpty()]
    [string]$VerboseDateFormat = 'yyyy-MM-dd HH.mm:ss'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# Verify administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error -Message 'This script requires administrator privileges to access disk and RAID information'
    exit 1
}

[string]$Script:ApiUrl = 'https://fastcheck24.com/api/server-state/storage'

# IP cache file path in system temp directory
[string]$Script:IPCacheFile = Join-Path -Path $env:TEMP -ChildPath 'fastvps_monitoring_ip_cache.txt'

# IP resolution providers ordered by priority
[hashtable[]]$Script:IPProviders = @(
    @{
        Type   = 'DNS'
        Name   = 'OpenDNS'
        Host   = 'myip.opendns.com'
        Server = '208.67.222.220'
    },
    @{
        Type      = 'DNS'
        Name      = 'Cloudflare'
        Host      = 'whoami.cloudflare'
        Server    = '1.1.1.1'
        TxtRecord = $true
    },
    @{
        Type = 'HTTP'
        Name = 'ipify'
        Url  = 'https://api.ipify.org'
    },
    @{
        Type = 'HTTP'
        Name = 'icanhazip'
        Url  = 'https://icanhazip.com'
    }
)

function Save-IPToCache {
    <#
    .SYNOPSIS
        Saves IP address to cache file.

    .DESCRIPTION
        Writes the IP address to a temporary cache file for later retrieval
        if all IP providers become unavailable.

    .PARAMETER IPAddress
        The IP address to cache.

    .OUTPUTS
        [void]
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$IPAddress
    )

    try {
        Set-Content -Path $Script:IPCacheFile -Value $IPAddress -Force -ErrorAction Stop
        Write-Verbose -Message "IP address cached to $Script:IPCacheFile"
    } catch {
        Write-Verbose -Message "Failed to cache IP address: $($PSItem.Exception.Message)"
    }
}

function Get-IPFromCache {
    <#
    .SYNOPSIS
        Retrieves cached IP address from file.

    .DESCRIPTION
        Reads previously cached IP address from temporary file.
        Returns empty string if cache file doesn't exist or is invalid.

    .OUTPUTS
        [string] Cached IP address or empty string if unavailable.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if (-not (Test-Path -Path $Script:IPCacheFile -PathType Leaf)) {
        Write-Verbose -Message 'IP cache file does not exist'
        return [string]::Empty
    }

    try {
        [string]$CachedIP = Get-Content -Path $Script:IPCacheFile -ErrorAction Stop | Select-Object -First 1

        if (-not [string]::IsNullOrWhiteSpace($CachedIP) -and $CachedIP -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
            Write-Verbose -Message "Retrieved cached IP: $CachedIP"
            return $CachedIP.Trim()
        }

        Write-Verbose -Message 'Cached IP is invalid or empty'
    } catch {
        Write-Verbose -Message "Failed to read IP cache: $($PSItem.Exception.Message)"
    }

    return [string]::Empty
}

function Get-ExternalIPAddress {
    <#
    .SYNOPSIS
        Retrieves external IP address using multiple fallback providers.

    .DESCRIPTION
        Attempts to resolve the server's external IP address using DNS-based
        methods first (OpenDNS, Cloudflare), then falls back to HTTP APIs.
        Each provider has a configurable timeout to prevent blocking when
        a provider is unreachable. Successfully retrieved IP is cached for
        fallback use when all providers are unavailable.

    .PARAMETER TimeoutSeconds
        Maximum time in seconds to wait for each provider. Default is 5.

    .OUTPUTS
        [string] External IP address or empty string if all providers fail.

    .EXAMPLE
        $ServerIP = Get-ExternalIPAddress -TimeoutSeconds 3
        Attempts to get external IP with 3 second timeout per provider.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(HelpMessage = 'Timeout in seconds for each provider')]
        [ValidateRange(1, 30)]
        [int]$TimeoutSeconds = 5
    )

    foreach ($Provider in $Script:IPProviders) {
        Write-Verbose -Message "Trying IP provider: $($Provider.Name)"

        try {
            [string]$IPAddress = switch ($Provider.Type) {
                'DNS' {
                    Get-IPFromDNSProvider -Provider $Provider -TimeoutSeconds $TimeoutSeconds
                }
                'HTTP' {
                    Get-IPFromHTTPProvider -Url $Provider.Url -TimeoutSeconds $TimeoutSeconds
                }
            }

            if (-not [string]::IsNullOrWhiteSpace($IPAddress)) {
                # Validate IPv4 format
                if ($IPAddress -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                    Write-Verbose -Message "Successfully retrieved IP from $($Provider.Name): $IPAddress"
                    # Cache the successfully retrieved IP for future fallback
                    Save-IPToCache -IPAddress $IPAddress
                    return $IPAddress
                } else {
                    Write-Verbose -Message "Invalid IP format from $($Provider.Name): $IPAddress"
                }
            }
        } catch {
            Write-Verbose -Message "Provider $($Provider.Name) failed: $($PSItem.Exception.Message)"
        }
    }

    # All providers failed - try to use cached IP as last resort
    Write-Warning -Message 'Failed to retrieve external IP from all providers, trying cached IP'
    [string]$CachedIP = Get-IPFromCache

    if (-not [string]::IsNullOrWhiteSpace($CachedIP)) {
        Write-Verbose -Message "Using cached IP address: $CachedIP"
        return $CachedIP
    }

    Write-Warning -Message 'No cached IP available'
    return [string]::Empty
}

function Get-IPFromDNSProvider {
    <#
    .SYNOPSIS
        Retrieves IP address using DNS resolution with timeout.

    .DESCRIPTION
        Uses Resolve-DnsName with a background job to enforce timeout.
        Supports both A records and TXT records (for Cloudflare whoami).

    .PARAMETER Provider
        Hashtable containing DNS provider configuration with keys:
        Host, Server, and optionally TxtRecord.

    .PARAMETER TimeoutSeconds
        Maximum wait time in seconds.

    .OUTPUTS
        [string] IP address or empty string on failure.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [hashtable]$Provider,

        [Parameter()]
        [int]$TimeoutSeconds = 5
    )

    [scriptblock]$DNSQuery = {
        param([string]$HostName, [string]$Server, [bool]$UseTxt)

        try {
            if ($UseTxt) {
                $Result = Resolve-DnsName -Name $HostName -Server $Server -Type TXT -ErrorAction Stop
                return $Result.Strings | Select-Object -First 1
            } else {
                $Result = Resolve-DnsName -Name $HostName -Server $Server -ErrorAction Stop
                return $Result.IPAddress | Select-Object -First 1
            }
        } catch {
            return $null
        }
    }

    $Job = Start-Job -ScriptBlock $DNSQuery -ArgumentList @(
        $Provider.Host,
        $Provider.Server,
        [bool]$Provider.TxtRecord
    )

    try {
        $Completed = Wait-Job -Job $Job -Timeout $TimeoutSeconds

        if ($null -eq $Completed) {
            Write-Verbose -Message "DNS query to $($Provider.Name) timed out after $TimeoutSeconds seconds"
            return [string]::Empty
        }

        [string]$Result = Receive-Job -Job $Job

        if (-not [string]::IsNullOrWhiteSpace($Result)) {
            return $Result.Trim()
        }
    } finally {
        Remove-Job -Job $Job -Force -ErrorAction SilentlyContinue
    }

    return [string]::Empty
}

function Get-IPFromHTTPProvider {
    <#
    .SYNOPSIS
        Retrieves IP address using HTTP API with timeout.

    .DESCRIPTION
        Makes HTTP request to IP detection service with built-in timeout.

    .PARAMETER Url
        URL of the IP detection API endpoint.

    .PARAMETER TimeoutSeconds
        Maximum wait time in seconds.

    .OUTPUTS
        [string] IP address or empty string on failure.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Url,

        [Parameter()]
        [int]$TimeoutSeconds = 5
    )

    try {
        $WebRequestParams = @{
            Uri             = $Url
            UseBasicParsing = $true
            TimeoutSec      = $TimeoutSeconds
            ErrorAction     = 'Stop'
        }

        $Response = Invoke-WebRequest @WebRequestParams

        if ($Response.StatusCode -eq 200) {
            return $Response.Content.Trim()
        }
    } catch {
        Write-Verbose -Message "HTTP request to $Url failed: $($PSItem.Exception.Message)"
    }

    return [string]::Empty
}

function Invoke-SendRequest {
    <#
    .SYNOPSIS
        Sends storage monitoring data to the FastVPS API.

    .DESCRIPTION
        Submits collected device data to the monitoring API endpoint.
        Handles JSON encoding and HTTP request configuration.

    .PARAMETER RequestData
        Array of hashtables containing device information.

    .OUTPUTS
        [string[]] API response content.

    .EXAMPLE
        $Result = Invoke-SendRequest -RequestData $AllDeviceData
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [array]$RequestData
    )

    # Safely retrieve script version with fallback
    [string]$ScriptVersion = 'unknown'
    try {
        $VersionInfo = Test-ScriptFileInfo -Path $PSCommandPath -ErrorAction Stop
        [string]$ScriptVersion = $VersionInfo.Version
    } catch {
        Write-Verbose -Message "Failed to retrieve script version: $($PSItem.Exception.Message)"
    }

    [string]$ServerIP = Get-ExternalIPAddress -TimeoutSeconds 5

    if ([string]::IsNullOrWhiteSpace($ServerIP)) {
        throw 'Failed to determine server external IP address'
    }

    [string]$ServerOS = (Get-CimInstance -ClassName CIM_OperatingSystem).Caption.Replace(' ', '_').ToLower()
    [string]$Name = 'storage-system-monitoring-for-windows'
    [string]$UserAgent = "${Name}-v${ScriptVersion}-${ServerOS}"

    [hashtable]$Headers = @{
        'FASTVPS-IP'   = $ServerIP
        'Content-Type' = 'application/json'
    }

    [hashtable]$RequestDataHash = @{
        'storage_devices' = $RequestData
        'version'         = $ScriptVersion
    }

    $RequestDataJson = ConvertTo-Json -InputObject $RequestDataHash -Depth 3
    $RequestDataEncodingJson = [System.Text.Encoding]::UTF8.GetBytes($RequestDataJson)

    Write-Verbose -Message "`nRequest headers:"
    Write-Verbose -Message "`t`tURI: $Script:ApiUrl"
    Write-Verbose -Message "`t`tMethod: POST"
    Write-Verbose -Message "`t`tUser-Agent: $UserAgent"
    Write-Verbose -Message "`t`tHeader: FASTVPS-IP: $ServerIP"
    Write-Verbose -Message "`t`tContentType: application/json; charset=utf8"
    Write-Verbose -Message "`t`tBody: $RequestDataJson`n"

    try {
        $WebRequestParams = @{
            Uri         = $Script:ApiUrl
            Method      = 'POST'
            Headers     = $Headers
            Body        = $RequestDataEncodingJson
            UserAgent   = $UserAgent
            ErrorAction = 'Stop'
        }

        [string[]]$RequestResult = Invoke-WebRequest @WebRequestParams
        return $RequestResult
    } catch [System.Net.WebException] {
        $Response = $PSItem.Exception.Response

        if ($Response) {
            $RequestStream = $Response.GetResponseStream()
            $StreamReader = New-Object -TypeName System.IO.StreamReader -ArgumentList $RequestStream
            $ResponseBody = $StreamReader.ReadToEnd()

            Write-Verbose -Message "`nStatus: {$([int]$Response.StatusCode): $($Response.StatusCode)}"
            Write-Verbose -Message 'Headers: {'

            foreach ($HeaderKey in $Response.Headers) {
                Write-Verbose -Message "`t`t`t`t${HeaderKey}: $($Response.Headers[$HeaderKey])"
            }

            Write-Verbose -Message '}'
            Write-Verbose -Message "Body: $ResponseBody`n"
        }

        throw $PSItem.Exception
    }
}

function Get-PhysicalDiskSmartctlData {
    <#
    .SYNOPSIS
        Collects SMART data from physical disks using smartctl.

    .DESCRIPTION
        Scans for available physical disks and retrieves SMART health
        information for each detected drive. Supports SATA, SAS, and NVMe.

    .PARAMETER Smartctl
        Full path to the smartctl executable.

    .OUTPUTS
        [system.collections.generic.list[hashtable]] Array of hashtables containing disk information.

    .EXAMPLE
        $Disks = Get-PhysicalDiskSmartctlData -Smartctl 'C:\smartctl.exe'
    #>
    [CmdletBinding()]
    [OutputType([system.collections.generic.list[hashtable]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Smartctl
    )

    $DrivesCollection = [system.collections.generic.list[hashtable]]::new()

    try {
        [system.collections.generic.list[string]]$SmartctlScanResult = & $Smartctl --scan-open

        foreach ($Drive in $SmartctlScanResult) {
            [string]$DriveName = $Drive.Split('{ }')[0]
            [string]$DriveType = $Drive.Split('{ }')[2]

            Write-Verbose -Message "$DriveName disk detected"

            if ($DriveType -match 'nvme') {
                if (($HwraidModel -eq 'adaptec') -and ($DriveName -eq '/dev/nvme0')) {
                    Write-Verbose -Message "It is not a real drive, but a '$HwraidModel' controller device. Skip it"
                    continue
                }
                Write-Verbose -Message "The disk type is $DriveType. Ignore check smart status"
            } else {
                [string]$SmartEnable = & "$Smartctl" -i $DriveName | Select-String -Pattern 'SMART.+Enabled$'

                if (-not $SmartEnable) {
                    Write-Warning -Message "The disk type is $DriveType. This disk does not have SMART support. We do not check this disk"
                    continue
                } else {
                    Write-Verbose -Message "The disk type is $DriveType. This disk has support for SMART, trying get SMART info"
                }
            }

            [system.collections.generic.list[string]]$SmartctlData = & "$Smartctl" -a $DriveName -d $DriveType

            $DriveSizeMatch = $SmartctlData |
                Select-String -Pattern 'User Capacity:\s+(.*)$' |
                ForEach-Object { $_.Matches.Groups[1].Value } |
                Select-Object -First 1
            [string]$DriveSize = if ([string]::IsNullOrWhiteSpace($DriveSizeMatch)) {
                'unknown'
            } else {
                $DriveSizeMatch
            }

            $DriveStatusMatch = $SmartctlData |
                Select-String -Pattern 'SMART overall-health self-assessment test result:\s+(.*)$' |
                ForEach-Object { $_.Matches.Groups[1].Value } |
                Select-Object -First 1
            [string]$DriveStatus = if ([string]::IsNullOrWhiteSpace($DriveStatusMatch)) {
                'unknown'
            } else {
                $DriveStatusMatch
            }

            $DriveModelMatch = $SmartctlData |
                Select-String -Pattern '(Device Model:|Product:)\s+(.*)$' |
                ForEach-Object { $_.Matches.Groups[2].Value } |
                Select-Object -First 1
            [string]$DriveModel = if ([string]::IsNullOrWhiteSpace($DriveModelMatch)) {
                'unknown'
            } else {
                $DriveModelMatch
            }

            [string]$SmartctlDataString = $SmartctlData | Out-String

            Write-Verbose -Message 'Detect a new disk:'
            Write-Verbose -Message "Drive Name:  $DriveName"
            Write-Verbose -Message "Drive Type:  $DriveType"
            Write-Verbose -Message "Drive Model:  $DriveModel"
            Write-Verbose -Message "Drive Status:  $DriveStatus"
            Write-Verbose -Message "Drive Size:  $DriveSize"
            Write-Verbose -Message "Drive Data:  $SmartctlDataString"

            [hashtable]$DrivesHash = @{
                'size'        = $DriveSize
                'device_name' = $DriveName
                'status'      = $DriveStatus
                'type'        = 'hard_disk'
                'diag'        = $SmartctlDataString
                'model'       = $DriveModel
            }

            $DrivesCollection.Add($DrivesHash)
        }

        return $DrivesCollection
    } catch {
        Write-Warning -Message 'Get-PhysicalDiskSmartctlData failed to execute'
        throw $PSItem.Exception
    }
}

function Get-SoftwareRaidData {
    <#
    .SYNOPSIS
        Retrieves software RAID configuration using VDS.

    .DESCRIPTION
        Uses Microsoft Virtual Disk Service (VDS) to enumerate software
        RAID volumes and their health status.

    .OUTPUTS
        [system.collections.generic.list[hashtable]] Array of hashtables containing software RAID information.

    .EXAMPLE
        $SoftRaids = Get-SoftwareRaidData
    #>
    [CmdletBinding()]
    [OutputType([system.collections.generic.list[hashtable]])]
    param()

    $SoftwareRaidCollection = [system.collections.generic.list[hashtable]]::new()

    try {
        # Use Add-Type instead of deprecated LoadWithPartialName
        Add-Type -AssemblyName 'Microsoft.Storage.Vds' -ErrorAction SilentlyContinue
        $VDSServiceLoader = New-Object -TypeName Microsoft.Storage.Vds.ServiceLoader -ErrorAction Stop
        $VDSService = $VDSServiceLoader.LoadService($null)
        $VDSService.WaitForServiceReady()

        $Packs = $VDSService.Providers | ForEach-Object {
            if ($PSItem.PSObject.Properties.Name -contains 'Packs') {
                $PSItem.Packs
            }
        }

        $SoftwareRaidData = [system.collections.generic.list[psobject]]@($Packs | ForEach-Object { $PSItem.Volumes })

        if ($SoftwareRaidData -and $SoftwareRaidData.Count -gt 0) {
            foreach ($SoftwareRaidVolume in $SoftwareRaidData) {
                [string]$SoftwareRaidName = if ([string]::IsNullOrWhiteSpace($SoftwareRaidVolume.Label)) {
                    $SoftwareRaidVolume.ID
                } else {
                    $SoftwareRaidVolume.Label
                }

                if ($SoftwareRaidVolume.AccessPaths) {
                    $SoftwareRaidName += "($($SoftwareRaidVolume.AccessPaths))"
                }

                if ($SoftwareRaidVolume.Size -le 1099511627776) {
                    [string]$SoftwareRaidSize = '{0:N2}Gb' -f ($SoftwareRaidVolume.Size / 1GB)
                } else {
                    [string]$SoftwareRaidSize = '{0:N2}Tb' -f ($SoftwareRaidVolume.Size / 1TB)
                }

                [string]$SoftwareRaidStatus = $SoftwareRaidVolume.Health
                [string]$SoftwareRaidModel = $SoftwareRaidVolume.Type
                [string]$SoftwareRaidDataString = $SoftwareRaidVolume | Format-List -Property * | Out-String

                Write-Verbose -Message "Software Raid Name:  $SoftwareRaidName"
                Write-Verbose -Message "Software Raid Model:  $SoftwareRaidModel"
                Write-Verbose -Message "Software Raid Status:  $SoftwareRaidStatus"
                Write-Verbose -Message "Software Raid Size:  $SoftwareRaidSize"
                Write-Verbose -Message "Software Raid Data:  $SoftwareRaidDataString"

                [hashtable]$SoftwareRaidDrivesHash = @{
                    'size'        = $SoftwareRaidSize
                    'device_name' = $SoftwareRaidName
                    'status'      = $SoftwareRaidStatus
                    'type'        = 'raid'
                    'diag'        = $SoftwareRaidDataString
                    'model'       = $SoftwareRaidModel
                }
                $SoftwareRaidCollection.Add($SoftwareRaidDrivesHash)
            }
        }
    } catch {
        Write-Warning -Message 'Get-SoftwareRaidData failed to execute'
        throw $PSItem.Exception
    }

    return $SoftwareRaidCollection
}

function Get-AdaptecVirtDeviceData {
    <#
    .SYNOPSIS
        Retrieves virtual device data from Adaptec RAID controllers.

    .PARAMETER CLI
        Full path to arcconf.exe.

    .OUTPUTS
        [system.collections.generic.list[hashtable]] Array of hashtables containing virtual device information.
    #>
    [CmdletBinding()]
    [OutputType([system.collections.generic.list[hashtable]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CLI
    )

    $HwraidDeviceCollection = [system.collections.generic.list[hashtable]]::new()

    try {
        [string[]]$LogicalDrives = & "$CLI" GETCONFIG 1 LD

        $LogicalDriveIDMatches = $LogicalDrives |
            Select-String -Pattern 'Logical Device number (\d+)' -AllMatches |
            ForEach-Object { $PSItem.Matches } |
            ForEach-Object { $PSItem.Groups[1].Value }
        [string[]]$LogicalDriveIDs = @($LogicalDriveIDMatches)

        foreach ($LogicalDriveID in $LogicalDriveIDs) {
            [string]$LogicalDriveData = & "$CLI" GETCONFIG 1 LD $LogicalDriveID | Out-String

            $NameMatches = [Regex]::Matches($LogicalDriveData, 'Logical Device name\s+:\s(\w+\s\d*)')
            [string]$LogicalDriveName = if ($NameMatches.Count -gt 0) {
                $NameMatches[0].Groups[1].Value
            } else {
                "Logical Device #$LogicalDriveID"
            }

            $SizeMatches = [Regex]::Matches($LogicalDriveData, 'Size\s+:\s(\d+\s\w+)')
            [string]$LogicalDriveSize = if ($SizeMatches.Count -gt 0) {
                $SizeMatches[0].Groups[1].Value
            } else {
                'unknown'
            }

            $StatusMatches = [Regex]::Matches($LogicalDriveData, 'Status of Logical Device\s+:\s(\w+)')
            [string]$LogicalDriveStatus = if ($StatusMatches.Count -gt 0) {
                $StatusMatches[0].Groups[1].Value
            } else {
                'unknown'
            }

            Write-Verbose -Message "Logical Drive Name:   $LogicalDriveName"
            Write-Verbose -Message "Logical Drive Size:   $LogicalDriveSize"
            Write-Verbose -Message "Logical Drive Status: $LogicalDriveStatus"
            Write-Verbose -Message "Logical Drive Data:   $LogicalDriveData"

            [hashtable]$LogicalDevicesHash = @{
                'size'        = $LogicalDriveSize
                'device_name' = $LogicalDriveName
                'status'      = $LogicalDriveStatus
                'type'        = 'raid'
                'diag'        = $LogicalDriveData
                'model'       = 'adaptec'
            }

            $HwraidDeviceCollection.Add($LogicalDevicesHash)
        }

        return $HwraidDeviceCollection
    } catch {
        Write-Warning -Message 'Get-AdaptecVirtDeviceData failed to execute'
        throw $PSItem.Exception
    }
}

function Get-AdaptecDisksData {
    <#
    .SYNOPSIS
        Retrieves physical disk data from Adaptec RAID controllers.

    .PARAMETER CLI
        Full path to arcconf.exe.

    .PARAMETER HwraidVirtualDevices
        Array of virtual device hashtables.

    .PARAMETER Smartctl
        Full path to the smartctl executable.

    .OUTPUTS
        [system.collections.generic.list[hashtable]] Array of hashtables containing physical disk information.
    #>
    [CmdletBinding()]
    [OutputType([system.collections.generic.list[hashtable]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CLI,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [array]$HwraidVirtualDevices,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Smartctl
    )

    $PhysicalDrivesCollection = [system.collections.generic.list[hashtable]]::new()

    try {
        foreach ($VirtualDevice in $HwraidVirtualDevices) {
            [string[]]$VirtualDeviceData = $VirtualDevice.diag.Split("`n")
            [string[]]$PhysicalDrivesSegments = $VirtualDeviceData | Select-String -Pattern 'Segment \d+'

            # Get SMART attributes via arcconf (smartctl has issues with SCSI devices on Windows)
            [string[]]$SmartData = & "$CLI" getsmartstats 1

            # Parse XML from arcconf output
            $SmartSataXml = ([xml]([Regex]::Match($SmartData, '(?s)<SmartStats.*?</SmartStats>')).Value)
            $SmartSasXml = ([xml]([Regex]::Match($SmartData, '(?s)<SASSmartStats.*?</SASSmartStats>')).Value)

            if ($SmartSataXml) {
                [xml]$XML = $SmartSataXml
            } elseif ($SmartSasXml) {
                [xml]$XML = $SmartSasXml
            }

            foreach ($PhysicalDriveSegment in $PhysicalDrivesSegments) {
                # Build smartctl path: aacraid,X,Y,Z where X=logical device, Y=connector, Z=device id
                $LogicalDriveIdMatch = $VirtualDeviceData |
                    Select-String -Pattern 'Logical Device number (\d+)' |
                    ForEach-Object { $_.Matches.Groups[1].Value } |
                    Select-Object -First 1

                if ([string]::IsNullOrWhiteSpace($LogicalDriveIdMatch)) {
                    Write-Warning -Message 'Failed to parse Logical Drive ID from virtual device data'
                    continue
                }
                [int]$LogicalDriveId = $LogicalDriveIdMatch

                $ConnectorMatch = $PhysicalDriveSegment |
                    Select-String -Pattern 'Connector:(\d+)' |
                    ForEach-Object { $_.Matches.Groups[1].Value } |
                    Select-Object -First 1
                [int]$PhysicalDriveConnectorId = $ConnectorMatch

                $DeviceMatch = $PhysicalDriveSegment |
                    Select-String -Pattern 'Device:(\d+)' |
                    ForEach-Object { $_.Matches.Groups[1].Value } |
                    Select-Object -First 1
                [int]$PhysicalDriveDeviceId = $DeviceMatch

                [string]$PhysicalDrivePath = "$LogicalDriveId,$PhysicalDriveConnectorId,$PhysicalDriveDeviceId"

                Write-Verbose -Message "Logical Drive ID:  $LogicalDriveId"
                Write-Verbose -Message "Physical Drive Connector ID:  $PhysicalDriveConnectorId"
                Write-Verbose -Message "Physical Drive Device ID:  $PhysicalDriveDeviceId"

                [string[]]$PhysicalDriveSmartctlData = & "$Smartctl" -a -d "aacraid,$PhysicalDrivePath" /dev/sda
                [string[]]$PhysicalDriveArcconfData = & "$CLI" getconfig 1 pd $PhysicalDriveConnectorId $PhysicalDriveDeviceId
                [string]$PhysicalDriveData = $PhysicalDriveArcconfData | Out-String

                if ($PhysicalDriveSmartctlData -notmatch 'ARCIOCTL_SEND_RAW_SRB failed') {
                    $PhysicalDriveData += $PhysicalDriveSmartctlData | Out-String
                } else {
                    Write-Warning -Message 'Cannot get SMART information via smartctl. Adaptec bug. Skip it'
                }

                [string]$PhysicalDriveName = "Device #$PhysicalDriveDeviceId"

                $SizeMatch = $PhysicalDriveSmartctlData |
                    Select-String -Pattern 'User Capacity:\s+(.*)$' |
                    ForEach-Object { $_.Matches.Groups[1].Value } |
                    Select-Object -First 1
                [string]$PhysicalDriveSize = if ([string]::IsNullOrWhiteSpace($SizeMatch)) {
                    'unknown'
                } else {
                    $SizeMatch
                }

                $ModelMatch = $PhysicalDriveSmartctlData |
                    Select-String -Pattern '(Device Model:|Product:)\s+(.*)$' |
                    ForEach-Object { $_.Matches.Groups[2].Value } |
                    Select-Object -First 1
                [string]$PhysicalDriveModel = if ([string]::IsNullOrWhiteSpace($ModelMatch)) {
                    'unknown'
                } else {
                    $ModelMatch
                }

                Write-Verbose -Message "Physical Drive Name:  $PhysicalDriveName"
                Write-Verbose -Message "Physical Drive Size:  $PhysicalDriveSize"
                Write-Verbose -Message "Physical Drive Model:  $PhysicalDriveModel"
                Write-Verbose -Message "Drive Data by Smartctl:  $PhysicalDriveSmartctlData"
                Write-Verbose -Message "Drive Data by Arcconf:  $PhysicalDriveArcconfData"

                [hashtable]$PhysicalDrivesHash = @{
                    'size'        = $PhysicalDriveSize
                    'device_name' = $PhysicalDriveName
                    'status'      = 'undefined'
                    'type'        = 'hard_disk'
                    'diag'        = $PhysicalDriveData
                    'model'       = $PhysicalDriveModel
                }

                $PhysicalDrivesCollection.Add($PhysicalDrivesHash)
            }
        }

        return $PhysicalDrivesCollection
    } catch {
        Write-Warning -Message 'Get-AdaptecDisksData failed to execute'
        throw $PSItem.Exception
    }
}

# LSI/MegaCLI hardware RAID Virtual Disks
function Get-MegaCliVirtDeviceData {
    <#
    .SYNOPSIS
        Retrieves virtual device data from MegaCli RAID controllers.

    .PARAMETER CLI
        Full path to MegaCli.exe.

    .OUTPUTS
        [system.collections.generic.list[hashtable]] Array of hashtables containing virtual device information.
    #>
    [CmdletBinding()]
    [OutputType([system.collections.generic.list[hashtable]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CLI
    )

    $HwraidDeviceCollection = [system.collections.generic.list[hashtable]]::new()

    try {
        $DriveIdMatches = & "$CLI" -LDInfo -Lall -Aall |
            Select-String -Pattern 'Virtual Drive:\s+(\d+)' -AllMatches |
            ForEach-Object { $PSItem.Matches } |
            ForEach-Object { $PSItem.Groups[1].Value }
        [string[]]$LogicalDrivesId = $DriveIdMatches

        foreach ($LogicalDriveId in $LogicalDrivesId) {
            [string[]]$LogicalDriveData = & "$CLI" -LDInfo -L"$LogicalDriveId" -aALL

            $NameMatch = $LogicalDriveData |
                Select-String -Pattern '(Virtual Drive:\s+\d+)' |
                ForEach-Object { $_.Matches.Groups[1].Value } |
                Select-Object -First 1
            [string]$LogicalDriveName = if ([string]::IsNullOrWhiteSpace($NameMatch)) {
                "Virtual Drive #$LogicalDriveId"
            } else {
                $NameMatch
            }

            $SizeMatch = $LogicalDriveData |
                Select-String -Pattern '^Size\s*: (.*)$' |
                ForEach-Object { $_.Matches.Groups[1].Value } |
                Select-Object -First 1
            [string]$LogicalDriveSize = if ([string]::IsNullOrWhiteSpace($SizeMatch)) {
                'unknown'
            } else {
                $SizeMatch
            }

            $StatusMatch = $LogicalDriveData |
                Select-String -Pattern '^State\s*: (.*)$' |
                ForEach-Object { $_.Matches.Groups[1].Value } |
                Select-Object -First 1
            [string]$LogicalDriveStatus = if ([string]::IsNullOrWhiteSpace($StatusMatch)) {
                'unknown'
            } else {
                $StatusMatch
            }

            [string]$LogicalDriveFormatData = $LogicalDriveData | Out-String

            Write-Verbose -Message "Logical Drive Name:  $LogicalDriveName"
            Write-Verbose -Message "Logical Drive Size:  $LogicalDriveSize"
            Write-Verbose -Message "Logical Drive Status:  $LogicalDriveStatus"
            Write-Verbose -Message "Logical Drive Data:  $LogicalDriveFormatData"

            [hashtable]$LogicalDevicesHash = @{
                'size'        = $LogicalDriveSize
                'device_name' = $LogicalDriveName
                'status'      = $LogicalDriveStatus
                'type'        = 'raid'
                'diag'        = $LogicalDriveFormatData
                'model'       = 'lsi'
            }

            $HwraidDeviceCollection.Add($LogicalDevicesHash)
        }

        return $HwraidDeviceCollection
    } catch {
        Write-Warning -Message 'Get-MegaCliVirtDeviceData failed to execute'
        throw $PSItem.Exception
    }
}

function Get-MegaCliDisksData {
    <#
    .SYNOPSIS
        Retrieves physical disk data from MegaCli RAID controllers.

    .PARAMETER CLI
        Full path to MegaCli.exe.

    .OUTPUTS
        [system.collections.generic.list[hashtable]] Array of hashtables containing physical disk information.
    #>
    [CmdletBinding()]
    [OutputType([system.collections.generic.list[hashtable]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CLI
    )

    $PhysicalDrivesCollection = [system.collections.generic.list[hashtable]]::new()

    try {
        $DeviceIdMatch = & "$CLI" -EncInfo -aALL |
            Select-String -Pattern '^\s+Device\sID\s+:\s(\d+)' -AllMatches |
            ForEach-Object { $PSItem.Matches } |
            ForEach-Object { $PSItem.Groups[1].Value }
        [int]$PhysicalDriveDeviceId = $DeviceIdMatch

        $SlotMatches = & "$CLI" -PDList -aALL |
            Select-String -Pattern '\s*Slot\sNumber:\s(\d+)' -AllMatches |
            ForEach-Object { $PSItem.Matches } |
            ForEach-Object { $PSItem.Groups[1].Value }
        [int[]]$PhysicalDriveSlot = $SlotMatches

        foreach ($Slot in $PhysicalDriveSlot) {
            [string]$PhysicalDrivePath = "${PhysicalDriveDeviceId}:$Slot"
            [string[]]$PhysicalDriveData = & "$CLI" -pdInfo -PhysDrv [$PhysicalDrivePath] -aALL

            $NameMatch = $PhysicalDriveData |
                Select-String -Pattern '^\s*Device Id:\s(.*)$' |
                ForEach-Object { $_.Matches.Groups[1].Value } |
                Select-Object -First 1
            [string]$PhysicalDriveName = if ([string]::IsNullOrWhiteSpace($NameMatch)) {
                "Device #$Slot"
            } else {
                $NameMatch
            }

            $SizeMatch = $PhysicalDriveData |
                Select-String -Pattern '^\s*Raw Size:\s(.*)$' |
                ForEach-Object { $_.Matches.Groups[1].Value } |
                Select-Object -First 1
            [string]$PhysicalDriveSize = if ([string]::IsNullOrWhiteSpace($SizeMatch)) {
                'unknown'
            } else {
                $SizeMatch
            }

            $ModelMatch = $PhysicalDriveData |
                Select-String -Pattern '^\s*Inquiry Data:\s(.*)$' |
                ForEach-Object { $_.Matches.Groups[1].Value } |
                Select-Object -First 1
            [string]$PhysicalDriveModel = if ([string]::IsNullOrWhiteSpace($ModelMatch)) {
                'unknown'
            } else {
                $ModelMatch
            }

            [string]$PhysicalDriveFormatData = $PhysicalDriveData | Out-String

            Write-Verbose -Message "Physical Drive Name:  $PhysicalDriveName"
            Write-Verbose -Message "Physical Drive Size:  $PhysicalDriveSize"
            Write-Verbose -Message "Physical Drive Model:  $PhysicalDriveModel"
            Write-Verbose -Message "Physical Drive Data:  $PhysicalDriveFormatData"

            [hashtable]$PhysicalDrivesHash = @{
                'size'        = $PhysicalDriveSize
                'device_name' = $PhysicalDriveName
                'status'      = 'undefined'
                'type'        = 'hard_disk'
                'diag'        = $PhysicalDriveFormatData
                'model'       = $PhysicalDriveModel
            }

            $PhysicalDrivesCollection.Add($PhysicalDrivesHash)
        }

        return $PhysicalDrivesCollection
    } catch {
        Write-Warning -Message 'Get-MegaCliDisksData failed to execute'
        throw $PSItem.Exception
    }
}

function Write-DeviceInfo {
    <#
    .SYNOPSIS
        Displays device information in verbose mode.

    .DESCRIPTION
        Helper function to output formatted device details during test mode.

    .PARAMETER Devices
        Array of device hashtables to display.

    .PARAMETER DeviceType
        Type description for display header.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Devices,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DeviceType
    )

    if ($Devices.Count -eq 0) {
        return
    }

    Write-Verbose -Message "$DeviceType found - $($Devices.Count)"
    Write-Verbose -Message "Information about ${DeviceType}:`n"

    foreach ($Device in $Devices) {
        Write-Verbose -Message "`t`tName: $($Device.device_name)"
        Write-Verbose -Message "`t`tStatus: $($Device.status)"
        Write-Verbose -Message "`t`tSize: $($Device.size)"
        Write-Verbose -Message "`t`tType: $($Device.type)"

        if ($Device.model) {
            Write-Verbose -Message "`t`tModel: $($Device.model)"
        }

        Write-Verbose -Message ''
    }
}

# Get utility paths - must be in script directory or subdirectories
$MegacliPathItem = Get-ChildItem -Recurse -Path $PSScriptRoot -Filter 'megacli.exe' -ErrorAction SilentlyContinue
[string]$MegacliPath = if ($MegacliPathItem) {
    $MegacliPathItem.FullName
} else {
    [string]::Empty
}

$ArcconfPathItem = Get-ChildItem -Recurse -Path $PSScriptRoot -Filter 'arcconf.exe' -ErrorAction SilentlyContinue
[string]$ArcconfPath = if ($ArcconfPathItem) {
    $ArcconfPathItem.FullName
} else {
    [string]::Empty
}

$SmartctlPathItem = Get-ChildItem -Recurse -Path $PSScriptRoot -Filter 'smartctl.exe' -ErrorAction SilentlyContinue
[string]$SmartctlPath = if ($SmartctlPathItem) {
    $SmartctlPathItem.FullName
} else {
    [string]::Empty
}

# Map RAID controller manufacturers to their CLI utilities
[hashtable]$UtilityByModel = @{
    'adaptec' = $ArcconfPath
    'dell'    = $MegacliPath
    'perc'    = $MegacliPath
    'lsi'     = $MegacliPath
}

# Initialize device collections using List for O(n) performance
$AllDeviceCollection = [system.collections.generic.list[hashtable]]::new()

# Initialize RAID variables to prevent null reference errors
[array]$HwraidVirtualDevices = @()
[array]$HwraidDisks = @()

# Detect hardware RAID controller by BusType
$HwraidDisk = Get-PhysicalDisk |
    Where-Object { $PSItem.BusType -eq 'RAID' } |
    Select-Object -ExpandProperty 'Manufacturer' -Unique

[string]$HwraidModel = if ($HwraidDisk) {
    $HwraidDisk.Trim()
} else {
    [string]::Empty
}

if (-not [string]::IsNullOrWhiteSpace($HwraidModel)) {
    Write-Verbose -Message "Hardware RAID detected: $HwraidModel"

    [string]$CLIPath = $UtilityByModel[$HwraidModel]

    if ([string]::IsNullOrWhiteSpace($CLIPath)) {
        Write-Error -Message 'This RAID controller model is not supported. Please check its status manually.'
        exit 1
    }

    $CLIPathExist = Get-Command -Name $CLIPath -ErrorAction SilentlyContinue

    if (-not $CLIPathExist) {
        Write-Error -Message 'Unable to find hardware RAID utility'
        exit 1
    }

    # Invoke controller-specific functions based on the identified hardware type
    switch ($HwraidModel.ToLower()) {
        'adaptec' {
            $HwraidVirtualDevices = @(Get-AdaptecVirtDeviceData -CLI $CLIPath)
            $HwraidDisks = @(Get-AdaptecDisksData -CLI $CLIPath -HwraidVirtualDevices $HwraidVirtualDevices -Smartctl $SmartctlPath)
        }
        { $PSItem -eq 'lsi' -or $PSItem -eq 'dell' -or $PSItem -eq 'perc' } {
            # MegaCli for LSI or Dell/PERC on older Windows
            $HwraidVirtualDevices = @(Get-MegaCliVirtDeviceData -CLI $CLIPath)
            $HwraidDisks = @(Get-MegaCliDisksData -CLI $CLIPath)
        }
        default {
            Write-Error -Message "Unknown RAID controller model: $HwraidModel"
            exit 1
        }
    }
}

# Get software RAID data
$SoftwareRaidData = [system.collections.generic.list[hashtable]]@(Get-SoftwareRaidData)

# Validate smartctl availability before usage
if ([string]::IsNullOrWhiteSpace($SmartctlPath)) {
    Write-Error -Message 'Unable to find smartctl.exe in script directory'
    exit 1
}

if (-not (Test-Path -Path $SmartctlPath -PathType Leaf)) {
    Write-Error -Message "smartctl.exe not found at: $SmartctlPath"
    exit 1
}

# Get physical drives
$PhysicalDisks = [system.collections.generic.list[hashtable]]@(Get-PhysicalDiskSmartctlData -Smartctl $SmartctlPath)

# Merge all device arrays into single collection
foreach ($Device in @($HwraidVirtualDevices + $HwraidDisks + $SoftwareRaidData + $PhysicalDisks)) {
    if ($Device -and $Device.Count -gt 0) {
        $AllDeviceCollection.Add($Device)
    }
}

# Send to API or display test results
if (-not $Test) {
    Write-Verbose -Message 'Sending request to API`n'

    try {
        Invoke-SendRequest -RequestData $AllDeviceCollection
        Write-Verbose -Message 'Request sent successfully'
    } catch {
        Write-Error -Message "Failed to send request: $($PSItem.Exception.Message)"
        exit 1
    }
} else {
    Write-Verbose -Message "Mode 'Test' activated. Request will not be sent to API`n"

    if (-not [string]::IsNullOrWhiteSpace($HwraidModel)) {
        Write-Verbose -Message "Hardware RAID detected. Manufacturer: $HwraidModel`n"
        Write-DeviceInfo -Devices $HwraidVirtualDevices -DeviceType 'Virtual Devices in hardware RAID'
        Write-DeviceInfo -Devices $HwraidDisks -DeviceType 'Drives connected via hardware RAID'
    }

    Write-DeviceInfo -Devices $SoftwareRaidData -DeviceType 'Software RAID volumes'
    Write-DeviceInfo -Devices $PhysicalDisks -DeviceType 'Physical drives'
}

Write-Verbose -Message 'Finish'
