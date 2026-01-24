# Storage System Monitoring for Windows

Storage monitoring agent for FastVPS infrastructure. This script collects health information from storage devices, including SMART data and RAID controller status, and reports it to the monitoring API for analysis and failure prediction.

## Requirements

- Operating System: Windows Server 2012, 2012 R2, 2016, 2019, 2019 R2, 2022.
- PowerShell: 5.0 or higher.
- Execution Policy: Ability to run PowerShell scripts.

## Features

- **Comprehensive Health Checks** - Collects SMART attributes from physical disks (SATA, SAS, NVMe).
- **RAID Support** - Monitors hardware RAID controllers (Adaptec, LSI) and Windows software RAID volumes.
- **Automated Reporting** - Runs hourly via a scheduled task to ensure continuous monitoring.
- **Secure Communication** - Transmits data via an encrypted HTTPS channel.
- **No Inbound Connections** - Does not open any network ports, ensuring server security.

## Installation

The easiest way to install the monitoring agent is to use the provided installer.

1. Download the [latest installer](https://github.com/FastVPSEestiOu/storage-system-monitoring-for-windows/releases/latest/download/fastvps_monitoring_install.exe).
2. Run `fastvps_monitoring_install.exe` and follow the on-screen instructions.

Alternatively, you can download and run the installer via PowerShell:

```powershell
$url = "https://github.com/FastVPSEestiOu/storage-system-monitoring-for-windows/releases/latest/download/fastvps_monitoring_install.exe"
$output = "$env:TEMP\fastvps_monitoring_install.exe"
Invoke-WebRequest -Uri $url -OutFile $output
Start-Process -FilePath $output -Wait
```

## Uninstallation

To remove the monitoring agent and its scheduled task from the system:

1. Navigate to the installation folder (default: `C:\FASTVPS\StorageMonitoring\`).
2. Run `uninstall.exe`.
3. All related files and the scheduled task will be removed.

## Usage

The script is designed to run automatically. However, you can run it manually for testing or diagnostic purposes.

### View Collected Data

To see the data being collected without sending it to the API:

```powershell
C:\FASTVPS\StorageMonitoring\FastvpsMonitoring.ps1 -Test -Verbose
```

### Manual Run

To run the script and send data immediately:

```powershell
C:\FASTVPS\StorageMonitoring\FastvpsMonitoring.ps1
```

### Parameters

- `-Test`: Performs all checks and generates the report but does **not** send data to the API.
- `-Verbose`: Displays detailed diagnostic output and the collected data on the console.
- `-VerboseDateFormat`: (Optional) Specifies the date format for verbose output timestamps.

## Configuration

- **Installation Directory**: Default is `C:\FASTVPS\StorageMonitoring\`.
- **Scheduled Task**: The installer creates a task named `FastVPS Monitoring` that executes the script hourly.
- **Included Utilities**: The project bundles essential tools in the `utilities` folder:
  - `smartmontools`: For SMART data collection.
  - `arcconf`: For Adaptec RAID controllers.
  - `megacli`: For LSI controllers (Legacy).

## Supported RAID Controllers

- **Adaptec**: All controllers supported by `arcconf`.
- **LSI / Broadcom**: All controllers supported by `MegaCLI`.
- **DELL PERC**: All LSI-based PERC controllers.

## Supported OS

- Windows Server 2012
- Windows Server 2012 R2
- Windows Server 2016
- Windows Server 2019
- Windows Server 2019 R2
- Windows Server 2022

## Troubleshooting

- Utility Errors: Verify that the `utilities` folder exists and contains the necessary executables for your hardware.
- Logs: Run the script with the `-Verbose` parameter to identify specific points of failure.
- Documentation: Use `Get-Help C:\FASTVPS\StorageMonitoring\FastvpsMonitoring.ps1 -Full` for built-in PowerShell documentation.

