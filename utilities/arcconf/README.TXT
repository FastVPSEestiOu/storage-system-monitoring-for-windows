README: maxView Storage Manager and ARCCONF Command Line Utility


Adaptec maxView Storage Manager
Adaptec Command Line Interface Utility (ARCCONF)

As of October 26, 2018
------------------------------------------------------------------------------------------------------------------------------------
Please check the product website for the newer versions of this file to ensure you are reviewing the latest information.

This file contains important information about issues and errata that were discovered after completion of 
the standard product documentation.

In the case of conflict between various parts of the documentation set, this file contains the most current information.
-----------------------------------------------------------------------------------------------------------------------------------

Table of Contents

Chapter 1. New Features in this Release

Chapter 2. Software Versions and Documentation

2.1. Utility Software
2.2. Documentation 
   2.2.1. Series 8 Product Documentation
   2.2.2. HBA 1000 Series Product Documentation
   2.2.3. SmartIOC Product Documentation

Chapter 3. Installation Notes

3.1. Installation and Setup
3.2. Supported Operating Systems
   3.2.1. Series 8 Controllers
   3.2.2. Smart Family Controllers
3.3. General Setup Notes
3.4. Remote Access
3.5. Windows 8 Setup
3.6. SLES Setup
3.7. Ubuntu Setup
3.8. XenServer Guest OS Setup
3.9. Installing ARCCONF on PowerPC 
3.10. Bootable USB Image Security Warnings 
3.11. RAW Device Setup (Series 8 Only) 
3.12. maxView Plugin for VMware vSphere Web Client

Chapter 4. Known Limitations

4.1. Global Limitations 
     4.1.1. Dual-Controller Systems
     4.1.2. Email Notifications
     4.1.3. SGPIO Enclosures 
     4.1.4. Non-RAID Mode Controllers 
     4.1.5. Browser Issues 
     4.1.6. Remote System Access on Linux and Windows 
     4.1.7. RAID 10 Segment Order 
     4.1.8. RAID 10 Rebuild Order 
     4.1.9. Locate Logical Drive Blink LED 
     4.1.10. ARCCONF Backward Compatibility 
     4.1.11. Updating Hard Disk Firmware on VMware Guest OS 
     4.1.12. Hot Swap Issues on VMware CentOS Guest OS 
     4.1.13. Enclosure Status Reporting 
     4.1.14. PHY Status on Enclosure Backplanes 
     4.1.15. Special Characters in Logical Device Names 
     4.1.16. Speaker Status on SuperMicro SAS2X28 Enclosures 
     4.1.17. Broadcasting Alerts About Status and Activity 
     4.1.18. User-Specified Archive Path 
     4.1.19. Clear Configuration Status After Re-Insertion 
     4.1.20. Configuration Changes in Device Manager 
     4.1.21. Online Help Issues 
4.2. Limitations for Series 8 Controllers 
     4.2.1. RAID-Level Migrations 
     4.2.2. maxCache Device Migration 
     4.2.3. ARCCONF maxCache Device Size Issue 
     4.2.4. Power Management Issues 
     4.2.5. Verify/Verify with Fix 
     4.2.6. ATA Secure Erase 
     4.2.7. Series 6 Controller Issues 
     4.2.8. Simple Volume Support 
     4.2.9. Auto-Volume Support 
     4.2.10. Hot-Removing Disk Drives on XenServer Guest OS 
     4.2.11. Viewing Logical Drive Details After Re-Insertion 
     4.2.12. VMware ESXi 6.X CIM Service Errors 
     4.2.13. Proxy/Firewall Connection Issues 
4.3. Limitations for Smart Family Controllers 
     4.3.1. SES Passthrough Commands to Expanders 
     4.3.2. Firmware Upgrade Issues 
     4.3.3. Mount Point Information with MPIO Support 
     4.3.4. Locate Physical Disk LED Behavior 
     4.3.5. Help Button Leads to Empty Login Page 
     4.3.6. Firefox Browser Crashes While Uploading Firmware 
     4.3.7. Backspace Recognized As Input Character 
     4.3.8. maxView Login Page Not Displayed After maxView Repair 
     4.3.9. VMware SFCB CIMMOM Causes Slowdown 
     4.3.10. Remote ARCCONF Command Delays 
     4.3.11. Locked ESXi User Account 
     4.3.12. Browser Automatically Fills Username and Password Fields 
     4.3.13. Expanding the Logical Volume to the Current Size is not Allowed 
     4.3.14. maxView Requires a Manual Refresh 
     4.3.15. Update the GCC Library After FreeBSD Installation 
     4.3.16. maxView or ARCCONF Application Operations are Slow in the Linux Kernel While Sanitizing the Drive 
     4.3.17. System Environment Variable is not Reflected on the PowerShell/Command Windows 
     4.3.18. maxView GUI is not Available for Solaris 
     4.3.19. Installation is not Supported in Standalone Mode on XenServer 
     4.3.20. Unable to Add Remote EXSi Server 
     4.3.21. maxView Unable to Detect Controllers on Ubuntu 18.04 after Upgrading to the Latest maxView Package 
     4.3.22. Commands are Stalled During a Specific I/O Operation in Linux 
--------------------------------------------------------------------------------------------------------------------------------------- 

Chapter 1. New Features in this Release

*  Added new features:
   *  Support for maxCrypto Controller-Based Encryption on the Microsemi Adaptec SmartRAID 3162-8i /e controller
   *  Support ARCCONF CLI in UEFI pre-boot environment
   *  Support for global physical drive write cache after logical creation
   *  Ability to set CacheLine size based maxCache size
   *  Support for PowerPC platforms running RHEL and Ubuntu on SmartIOC 2000 and HBA 1000 controllers
   *  Miscellaneous UI changes/enhancements
*  Bug fixes (see the Release Notes for a complete list)
---------------------------------------------------------------------------------------------------------------------------------------

Chapter 2. Software Versions and Documentation

2.1. Utility Software
*  Microsemi Adaptec® maxView Storage Manager Version 2.06.00 (B23164)
*  Microsemi Adaptec® ARCCONF Command Line Interface Utility Version 2.06.00 (B23164)

2.2. Documentation

2.2.1. Series 8 Product Documentation
PDF Format

*  maxView Storage Manager User's Guide for Microsemi Adaptec ARC-Family Controllers
*  Microsemi Adaptec RAID Controller Command Line Utility User's Guide
HTML and Text Format

*  maxView Storage Manager Online Help
*  maxView Storage Manager/ARCCONF README.TXT file

2.2.2. HBA 1000 Series Product Documentation
PDF:
*  maxView Storage Manager User's Guide for Microsemi Smart-Family Controllers
*  Microsemi Adaptec HBA 1000 Series Command Line Utility User's Guide

HTML and Text Format:

*  maxView Storage Manager for Smart-Family Controllers Online Help
*  maxView Storage Manager/ARCCONF README.TXT file

2.2.3. SmartIOC Product Documentation
PDF:

*  maxView Storage Manager User's Guide for Microsemi Smart-Family Controllers
*  Microsemi SmartIOC 2000 Command Line Utility User's Guide

HTML and Text Format:

*  maxView Storage Manager for Microsemi Smart-Family Controllers Online Help
*  maxView Storage Manager/ARCCONF README.TXT file
----------------------------------------------------------------------------------------------------------------------------------------

Chapter 3. Installation Notes

3.1. Installation and Setup
Refer to your product documentation for the installation and setup details:
*  Your product Installation and User's Guide contains complete installation information for your product's drivers.
*  The maxView Storage Manager User's Guide for your product contains installation information for the maxView Storage Manager software.
*  The Command Line Utility User's Guide for your product contains complete installation information for ARCCONF.

3.2. Supported Operating Systems
Notes: 
*  maxView Storage Manager and ARCCONF Command Line Utility are supported on 64-bit operating systems only.
*  The Boot USB (offline or pre-boot) for ARCCONF and maxView Storage Manager is supported on Linux.

3.2.1. Series 8 Controllers
Microsoft Windows
*  Microsoft® Windows® Server 2016 RS1 (64-bit)
*  Microsoft® Windows® Server 2012 (64-bit)
*  Microsoft® Windows® Server 2012 R2 (64-bit)
*  Microsoft® Windows® Server 2008 R2 SP1 (64-bit)
*  Microsoft® Windows® SBS 2011 (Standard and Essential, 64-bit)
*  Microsoft® Windows® 10 RS3 (64-bit)
*  Microsoft® Windows® 8.1, 8 (64-bit)
*  Microsoft® Windows® 7 (64-bit)
*  Microsoft® WinPE 5.x (64-bit)

Linux for x64
*  Red Hat® Enterprise Linux/CentOS 7.4 (64-bit)
*  Red Hat® Enterprise Linux/CentOS 7.3 (64-bit)
*  Red Hat® Enterprise Linux/CentOS 6.9 (64-bit)
*  Red Hat® Enterprise Linux/CentOS 6.8 (64-bit)
*  Red Hat® Enterprise Linux/CentOS 5.11, 5.10 (64-bit)
*  SuSE Linux Enterprise Server 12 SP3 (64-bit)
*  SuSE Linux Enterprise Server 12 SP2 (64-bit)
*  SuSE Linux Enterprise Server 12 (64-bit)
*  SuSE Linux Enterprise Server 11 SP4 (64-bit)
*  SuSE Linux Enterprise Server 11 SP3 (64-bit)
*  Debian Linux 8.1 (64-bit)
*  Ubuntu Linux 16.04.3 (64-bit)
*  Ubuntu Linux 14.04.5 (64-bit)
*  Oracle Linux 7.2 (64-bit)
*  Oracle Linux 6.8 with UEK R4U4, UEK R3U7 (64-bit)
*  Fedora Linux 22 (64-bit)

Linux for PowerPC
*  Red Hat® Enterprise Linux 7.3, 7.2 (64-bit)
*  SuSE Linux Enterprise Server 12 SP2, SP1 (64-bit)
*  Ubuntu Linux 16.04, 14.04.5 LTS, 14.04.4 (64-bit)
*  PowerKVM 3.1.0.1 (64-bit)
*  Pegas 1.0 (RHEL 7.4 for OP)

FreeBSD
*  FreeBSD® 10.3, 10.2 (64-bit)
*  FreeBSD® 9.3 (64-bit)

Solaris
*  Solaris 11 (64-bit)
*  Solaris 10 U9 (64-bit)

Virtual OS Environments
*  VMware vSphere 6.7 (64-bit)
*  VMware vSphere 6.5 U1 (64-bit)
*  VMware vSphere 2016 (6.5) (64-bit)
*  VMware vSphere 6.0 U3, U2 (64-bit)
*  Citrix XenServer 7.1 (64-bit)
*  Microsoft Hyper-V (64-bit)

Note: Hyper-V runs as a service on the Windows host OS and does not require a separate driver.

3.2.2. Smart Family Controllers
Microsoft Windows
*  Microsoft® Windows® Server 2016 RS1 (64-bit)
*  Microsoft® Windows® Server 2012 (64-bit)
*  Microsoft® Windows® Server 2012 R2 (64-bit)
*  Microsoft® Windows® Server 2008 R2 SP1 (64-bit)
*  Microsoft® Windows® 10 RS3 (64-bit)
*  Microsoft® Windows® 8.1, 8 (64-bit)
*  Microsoft® Windows® 7 (64-bit)

Linux for x86/x64
*  Red Hat® Enterprise Linux/CentOS 7.5, 7.4, 7.3, 7.2 (64-bit)
*  Red Hat® Enterprise Linux/CentOS 6.9, 6.8, 6.7 (64-bit)
*  SuSE Linux Enterprise Server 12 SP3, SP2, SP1 (64-bit)
*  SuSE Linux Enterprise Server 11 SP4, SP3 (64-bit)
*  Ubuntu Linux 16.04.4, 16.04.3, 16.04.01 (LTS) (64-bit)
*  Ubuntu Linux 14.04.05 (LTS) (64-bit)
*  Oracle Linux 7.2 UEK R4U2, UEK R3U7 (64-bit)
*  Oracle Linux 6.8 UEK R4U4, UEK R3U7 (64-bit)

Linux for PowerPC
*  Red Hat® Enterprise Linux ALT-7.5, ALT-7.4 (64-bit)
*  Ubuntu Linux 16.04.4, 18.04 (64-bit)
*  Virtual OS Environments
*  VMware ESXi 6.7 (64-bit)
*  VMware vSphere 6.0 U2, 6.0 (64-bit)
*  VMware vSphere 2016 (6.5) (64-bit)
*  VMware vSphere 2016 U2 (64-bit)
*  Citrix XenServer 7.1, 7.0 (64-bit)
*  FreeBSD 11 (64-bit)

3.3. General Setup Notes
*  maxView Storage Manager is not backwards-compatible with Series 5 and older Adaptec controller models.
*  maxView Storage Manager and legacy Adaptec Storage Manager (ASM) cannot coexist on the same system.
*  For Series 8 controllers:
   *  maxView Storage Manager is not supported on FreeBSD. Use ARCCONF to create and manage arrays.

3.4. Remote Access
*  maxView Storage Manager requires the following range of ports to be open for remote access:
   *  34570-34580 (TCP)
   *  34570 (UDP)
   *  34577-34580 (UDP)
See also Chapter 4, Section 1.6 for OS-specific issues and workarounds.

3.5. Windows 8 Setup
To log in and use maxView Storage Manager on a Windows 8 system, you must create a local user account; 
you cannot use your MS Live account. To create a local user account, perform the following steps:
1. Log into your MS Live account.
2. Select Settings?Change PC Settings?Users?Switch to Local user.
3. Provide account details.
4. Start maxView Storage Manager and log in with your local user account credentials.

3.6. SLES Setup
To avoid a problem with launching maxView Storage Manager on SLES 11 or SLES 12 x64 systems with DHCP enabled, 
ensure that the /etc/hosts file maps the server IP address to a valid host name; it is not sufficient to map the IP address to "localhost".

3.7. Ubuntu Setup
*  To avoid a maxView login failure on Ubuntu systems, you must ensure that the root user account is enabled. 
   (It is disabled by default on Ubuntu 14.04 and later because no password is set.)
   For example: sudo bash; sudo passwd root
*  When upgrading maxView Storage Manager on an existing Ubuntu Linux x64 installation, 
   you must enable the upgrade switch before installing the maxView .deb package:

   export maxView_Upgrade=true
   dpkg -i StorMan-*.deb

   To uninstall maxView after the upgrade:
 
   export maxView_Upgrade=false
   dpkg -r storman

3.8. XenServer Guest OS Setup
To avoid an operating problem with maxView Storage Manager or ARCCONF on a XenServer Guest OS, 
you must disable all LAN adapters in the Guest OS which are not connected to the network before 
installing the maxView or ARCCONF software.

3.9. Installing ARCCONF on PowerPC
About this task

Note:ARCCONF for PowerPC is supported on Microsemi Adaptec Series 8 controllers only. See the Readme for supported OS versions.

Procedure

Installing ARCCONF on PowerPC:

1. Installing on RHEL PowerPC 64-bit
   rpm -i Arcconf-2.02-xxxxx.ppc64le.rpm
2. Installing on Ubuntu PowerPC 64-bit
   dpkg -i Arcconf-2.02-xxxxx.ppc64el.deb
3. Installing on SLES PowerPC 64-bit
   rpm -i Arcconf-2.02-xxxxx.ppc64le.rpm
4. Installing ARCCONF in Petitboot:
   Extract package arcconf-2.02-xxxxx.tar.xz in the folder of your choice.

Results
Where xxxxx is the installer version.

3.10. Bootable USB Image Security Warnings
*  When running maxView Storage Manager from the bootable USB image, you may be prompted with one or more with security warnings before maxView launches. 
   In each case, acknowledge the warning and continue.
*  The bootable USB needs root permission. To do this, execute the sudo -i command before executing ARCCONF commands from the terminal.

3.11. RAW Device Setup (Series 8 Only)
On Adaptec Series 8 controllers, a RAW Pass Through device is analogous to a JBOD, supported by Adaptec Series 8 controllers and older. Any drive without 
Adaptec RAID metadata is exposed to the OS as a RAW Pass Through device. To remove the Adaptec metadata and convert the drive to a RAW device, 
use the Uninitialize command in maxView Storage Manager; any existing data on the drive is destroyed. (You can also run uninit from the BIOS or ARCCONF.) 
For more information about working with RAW devices, see "Controller Modes" in the CLI User's Guide, and BIOS "General Settings" in the RAID Controller 
Installation and User's Guide.

3.12. maxView Plugin for VMware vSphere Web Client
The maxView Plugin for VMware vSphere Web Client is supported on VMware 6.0 and 6.5.

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Chapter 4. Known Limitations

4.1. Global Limitations

4.1.1. Dual-Controller Systems
In dual-controller systems, the controller order in maxView Storage Manager and the BIOS differs. 
Example: with an Adaptec 72405 and 7805 installed, the BIOS reports the 72405 as controller 1 and 
the 7805 as controller 2; in the GUI, the controller order is reversed.

4.1.2. Email Notifications
On Linux systems, we recommend adding the SMTP host name and the system IP address, to the /etc/hosts file. 
Doing so ensures that email notifications will succeed if you specify the email server in maxView Storage Manager by host name. 
Otherwise, email notifications (including test messages) may fail if the DNS is unable to resolve the host name.
WORKAROUND: Specify the email server in maxView Storage Manager by IP address.

4.1.3. SGPIO Enclosures
In this release, maxView Storage Manager does not show connector information for SGPIO enclosures.

4.1.4. Non-RAID Mode Controllers
maxView Storage Manager can "see" RAID controllers operating in HBA mode, Auto-Volume mode, 
and Simple Volume mode (Adaptec Series 8, Smart Family controllers only). However, to change 
the controller mode on Series 8 controllers, you must use ARCCONF or the BIOS. With Adaptec Smart-Family controllers, 
you can also change the controller mode with maxView Storage Manager.

4.1.5. Browser Issues

*  To run maxView Storage Manager on the supported browsers, Javascript must be enabled.
*  With Ubuntu Linux, Firefox 46/47 has alignment problems in some parts of the maxView GUI.
   WORKAROUND: Upgrade to Firefox 48.
*  Due to a certificate bug in Firefox 31.x, maxView login may fail on RHEL systems with a "Secure Connection" error. 
   (Firefox 31.1 is the default browser on RHEL 6.6; on RHEL 7.1, it is 31.4.)
   WORKAROUND: Upgrade to the latest Firefox version.
*  With the default Security setting in Microsoft Internet Explorer 10 and 11, you may be unable to login to maxView Storage Manager 
   or experience certain GUI display issues in the maxView online Help system.
   WORKAROUND: Change the default Security setting from High (or Medium-High) to Medium. 
   Alternative: add the GUI IP address to the trusted sites list.
*  With Google Chrome, the scrollbar resets itself to the top after selecting a drive in the Logical Drive wizard. 
   To select another drive, you must scroll back down to the drive location.
*  With Microsoft Internet Explorer 10, the controller firmware update wizard does not show 
   the firmware update file name when the upload completes. To refresh the display, click Next then Back.
*  We do not recommend using multiple browsers simultaneously on the same maxView instance. 
   Doing so may cause display issues or freezes; to restore maxView, refresh the display by pressing F5.

4.1.6. Remote System Access on Linux and Windows
To avoid remote system access failures from Linux and Windows clients running maxView Storage Manager, 
check and update one or all of the following system and network settings:

Windows:
*  Ensure that the DNS server information is properly configured.
*  Ensure that the system is configured with the IP address.
*  Ensure that the OS hostname is according to the standard.
*  Ensure that the hostname to IP address mapping is updated in the DNS. At the minimum, ensure that the hostname to IP mapping is entered in /etc/hosts file.

RHEL/Linux:
*  Set server.properties file permissions to at least read-only at all levels
   Stop all maxView services.
*  Set the Permissions of server.properties file to read and write or read-only at all levels (Owner, Group, and Others). Apply and close.
*  Restart all services in the given order: cim, agent, tomcat
*  Now try to remote login to this system from any other system

4.1.7. RAID 10 Segment Order
maxView Storage Manager and the Ctrl-A BIOS report the wrong segment order for RAID 10s, 
regardless of the order in which the drives are selected.

Example 1: Create RAID 10 with 2 SDDs and 2 HDDs in maxView Storage Manager:
(1a) ARCCONF and maxView Storage Manager see the following RAID segment order:
                Device 2 (S1)
                Device 1 (H2)
                Device 3 (S2)
                Device 0 (H1)
   
(1b) the BIOS/CTRL-A sees the following RAID segment order:
                Device 2 (S1)
                Device 1 (H2)
                Device 0 (H1)
                Device 3 (S2)
   
(1c) the correct and expected RAID segment order is:
                Device 2 (S1)
                Device 0 (H1)
                Device 3 (S2)
                Device 1 (H2)

Example 2: Create RAID 10 with 2 SDDs and 2 HDDs with ARCCONF:
(2a) the BIOS/CTRL-A sees the following RAID segment order:
                      Device 0 (H1)
                      Device 2 (S1)
                      Device 1 (H2)
                      Device 3 (S2)
  
(2b) ARCCONF and maxView Storage Manager see the correct RAID segment order:
                      Device 2 (S1)
                      Device 0 (H1)
                      Device 3 (S2)
                      Device 1 (H2)

4.1.8. RAID 10 Rebuild Order
With a degraded RAID 10 logical drive, the drive is rebuilt one leg at a time, not in parallel.

4.1.9. Locate Logical Drive Blink LED
In maxView Storage Manager, Locate Logical Drive continues to blink the LED for 
a pulled physical drive in the array after the locate action is stopped. 
(For unpulled drives, the blinking stops.) This issue is not seen with ARCCONF.

4.1.10. ARCCONF Backward Compatibility
ARCCONF is backward compatible with older Adaptec controller models. 
As a result, the ARCCONF user's guide and online help show command options 
that are not supported by newer Adaptec controllers, like the Adaptec Series 8 or later products.
Example: With ARCCONF SETMAXCACHE, Adaptec Series 8 controllers do not support ADDTOPOOL or REMOVEFROMPOOL

4.1.11. Updating Hard Disk Firmware on VMware Guest OS
Updating the firmware for a SAS hard disk drive with ARCCONF/maxView can crash (PSOD) 
the VMware Guest OS. This issue is seen with SAS hard drives only; with SATA drives, 
the firmware update completes successfully.

4.1.12. Hot Swap Issues on VMware CentOS Guest OS
Due to a limitation with the VMware CentOS Guest OS network configuration, 
maxView Storage Manager does not show newly added or removed hot swap drives. 
(ARCCONF sees the configuration change but maxView does not.) 
WORKAROUND: (1) reboot the system or restart maxView services; 
(2) adjust the network configuration; contact Microsemi Support for more information.

4.1.13. Enclosure Status Reporting
In maxView Storage Manager, the enclosure status is event-driven. As a result, 
enclosures can have a "Degraded" status even if related resources (fan, temperature, power) 
are performing normally (Optimal status). For instance, the Enclosure status changes 
to "Degraded" if the system reports an "Enclosure device not responding ..." event, even if other sensor values are normal.

4.1.14. PHY Status on Enclosure Backplanes
In the Controller Properties window, maxView Storage Manager shows the Connector Info 
as "unknown" for all PHYs on an enclosure-based backplane (for instance, a backplane attached to connector 1).

4.1.15. Special Characters in Logical Device Names
Special characters are permitted in logical device names in maxView Storage Manager, 
the BIOS, and ARCCONF. However, with Linux ARCCONF (create, setname), 
special characters must be "escaped" to ensure proper interpretation. For example:
ARCCONF SETNAME 1 LOGICALDRIVE 1 arc_ldrive%\$12\&amp;

4.1.16. Speaker Status on SuperMicro SAS2X28 Enclosures
SuperMicro SAS2X28 enclosures do not propagate the speaker status to maxView Storage Manager. 
As a result, maxView always displays the speaker status as Off.

4.1.17. Broadcasting Alerts About Status and Activity
This feature is not supported by the maxView Storage Manager or 
ARCCONF and has been removed from the product documentation.

4.1.18. User-Specified Archive Path
While executing the savesupportarchive command where a user-specified path exists, 
ARCCONF will instead place the logs under the /var/log/ directory.

4.1.19. Clear Configuration Status After Re-Insertion
After removing a RAID member and then clearing the controller configuration, m
axView Storage Manager recovers the configuration for all RAID volumes and physical drives when the offline drive is re-inserted 
and the OS restarted. By design, RAID members store metadata about all other virtual devices. 
This allows the controller to recover the configuration from the re-inserted drive, even though the configuration was previously cleared.

4.1.20. Configuration Changes in Device Manager
After disabling/enabling the Microsemi Adaptec controller in the Device Manager, 
it can take up to 10 minutes for maxView Storage Manager to detect the configuration change.
WORKAROUND: Use the Refresh link in the maxView GUI to update the configuration.

4.1.21. Online Help Issues
*  Help from the Express Configuration wizard opens the Custom Configuration help panel.
   WORKAROUND: Open the Express Configuration Help panel from the Help System TOC pane.
*  Contrary to the online help topics, SMR drives are not supported for RAID volumes 
   or hot spares on Smart-Family controllers.
*  When opening the maxView Storage Manager help from a remote Linux system (e.g., over a VPN), 
   the help window may fail to open with a "can't establish connection to server" message.
   WORKAROUND: Replace 127.0.0.1:8443 in the URL with <system_ip_address>:8443
*  In IE11, topics in the help may display with a "Topics Not Found" message when their 
   corresponding links are clicked in the navigation pane of the help.
   WORKAROUND: Click on the "Add" browser prompt to add certification to view the content.

4.2. Limitations for Series 8 Controllers

4.2.1. RAID-Level Migrations
*  The following RAID-level migrations (RLM) are supported in this release:
   *  RAID 0 to RAID 5
   *  RAID 0 to RAID 10
   *  RAID 5 to RAID 6
   *  RAID 6 to RAID 5
   *  RAID 10 to RAID 5
   *  RAID 5 to RAID 10
   *  RAID 1 to RAID 5
   *  SIMPLE VOLUME to RAID 1
   *  RAID 1 to SIMPLE VOLUME
*  When migrating a Simple Volume to RAID 1, maxView Storage Manager reports 
   the logical drive state as Impacted (rather than Reconfiguring); this is normal.
*  We do not recommend performing a RAID-level migration or Online Capacity Expansion (OCE) 
   on a logical drive with maxCache SSD caching enabled.
   NOTE: maxView Storage Manager grays out the options for logical drives with maxCache enabled. ARCCONF terminates the task.
*  Always allow a RAID-level migration to complete before creating a support archive file. Otherwise, 
   the support archive will include incorrect partition information. Once the migration is complete, 
   the partition information will be reported correctly.

4.2.2. maxCache Device Migration
Only one maxCache Device is supported per controller. Moving the maxCache Device (all underlying SSDs) 
from one controller to another (assuming both controllers support maxCache) is supported only if (1) 
the new controller does not have a maxCache Device or any other maxCache Device with a conflicting device number 
and (2) only after a clean shutdown on the old controller.

4.2.3. ARCCONF maxCache Device Size Issue
ARCCONF supports >2 TB maxCache Devices if you create the device with the "max" parameter. 
However, the functional limit for the maxCache Device is 2 TB, which is also the limit in maxView Storage Manager.

4.2.4. Power Management Issues
Power management is not supported on FreeBSD.
Capturing support logs from maxView or ARCCONF will spin up drives when power management is active. This behavior is by design.
The Logical Drive Creation wizard no longer includes the option to enable power management settings.
WORKAROUND: Enable power management for the logical drive from the Set Properties window.

4.2.5. Verify/Verify with Fix
*  Incremental progress percentage information in SNMP is not updated for the Verify/Verify_Fix operations. Task progress shows 0% until complete, then 100%.
*  In maxView Storage Manager and ARCCONF, the Verify_Fix operation is NOT available when:
   *  The logical drive has a non-redundant RAID level.
   *  Other tasks are in progress on the logical drive.
   *  The logical drive is in a non-optimal or impacted state.

4.2.6. ATA Secure Erase
In ARCCONF, the ATA Secure Erase operation cannot be aborted. 
Once started, it continues to completion.
In maxView Storage Manager, the drive is locked during ATA Secure Erase. 
To recover, use the ARCCONF ATAPASSWORD CLEAR <passwd> command; the default password is 'pmc-sierra'.
NOTE: ATA Secure Erase is also available in the Ctrl-A BIOS.

4.2.7. Series 6 Controller Issues
The following issues are seen only with Microsemi Adaptec Series 6 RAID 
controllers:
*  In maxView Storage Manager, the Preserve Cache option on the Set Properties window is not supported on Series 6 RAID controllers. 
   Attempting to set this option for the Series 6 controller fails.
*  Renaming a RAID volume disables the write-cache (if enabled). You cannot re-enable the write-cache in maxView Storage Manager.
   WORKAROUND: Use ARCCONF to enable the write-cache.
*  In a VMware Guest OS under VMware 5.x, maxView Storage Manager and ARCCONF do not detect existing logical drive partitions. 
   As a result, attempting to delete, clear, or erase the logical drive may fail.
*  On Series 6 controllers, maxView Storage Manager deletes partitioned JBODs without issuing a warning message.
*  Series 6 controllers do not support the ARCCONF GETPERFORM command.

4.2.8. Simple Volume Support
*  In this release, you can create a maximum of 128 Simple Volumes in maxView Storage Manager, ARCCONF, or the BIOS.
*  When a Simple Volume fails, the status remains unchanged after drive replacement.
   WORKAROUND: Manually delete the Simple Volume to remove it.

4.2.9. Auto-Volume Support
*  Changing a controller into Auto-Volume mode (ARCCONF/BIOS) is not supported if the configuration includes 
   any logical device type other than Simple Volume, including a maxCache Device. The mode switch from RAID mode 
   to Auto-Volume mode is blocked if any other type of logical volume exists (including maxCache). After switching to Auto-Volume mode, 
   you can create and delete Simple Volumes only in maxView Storage Manager and ARCCONF.
*  In Auto-Volume mode, only the first 128 RAW drives are converted to Simple Volumes; the rest of the RAW drives remain unchanged. 
   If you uninitialize a Ready drive while the controller is in Auto-Volume mode, the firmware converts 
   the drive automatically until the Simple Volume count reaches the maximum.

4.2.10. Hot-Removing Disk Drives on XenServer Guest OS
XenServer does not support "hot-removal" of disk drives from a partitioned logical drive. 
As a result, if you hot remove a disk from a logical drive, the Guest OS becomes inaccessible 
because the drive partition remains visible to the OS instead of being cleared.
WORKAROUND: Reboot the XenServer host, detach the failed partition, and then restart the VM.

4.2.11. Viewing Logical Drive Details After Re-Insertion
If you remove/re-insert a RAID member when the controller's "Automatic Failover" property is enabled 
and there is no hot spare configured/protecting the logical device, you must click on the Refresh link 
in maxView Storage Manager to view the proper data of the re-inserted drive and RAID volume.

4.2.12. VMware ESXi 6.X CIM Service Errors
When running VMware ESXi 6.X, the CIM service becomes stuck and users cannot log in.
WORKAROUND: Disable the hhrcwrapper by following these steps:
1. esxcli system wbem set -e 0
2. esxcli system wbem provider list
3. esxcli system wbem provider set -e 0 -n vmw_hhrcwrapper
4. esxcli system wbem provider list
5. esxcli system wbem set -e 1

4.2.13. Proxy/Firewall Connection Issues
maxView uses WebSocket and server side event for notifying the logged in users instantaneously about the 
changes in the configuration. Occasionally, the proxy/firewall does not allow a connection to stay inactive 
for a longer period of time, and the connection usually gets closed automatically by the proxy.
SYMPTOMS: Event and changes for the operation performed through ARCCONF do not reflect in maxView GUI.
WORKAROUND:
*  Configure the proxy/firewall to allow inactive connection to stay for up to 5 minutes (with 2017.1, 
   recovery has been added in the code to reestablish the closed connection).
*  Use the refresh link provided in maxView GUI to get the updated configuration.

4.3. Limitations for Smart Family Controllers

4.3.1. SES Passthrough Commands to Expanders
SES passthrough commands to expanders fail.

4.3.2. Firmware Upgrade Issues
For systems using Adaptec HBA 1000 with an Adaptec SAS Expander 82885T card, 
where the ARCCONF utility is used to upgrade the expander firmware, ARCCONF may crash if 64-bit chunk sizes are used.
WORKAROUND: Use 32-bit chunk sizes to upgrade/downgrade the expander firmware.

4.3.3. Mount Point Information with MPIO Support
When Multipath I/O (MPIO) is enabled in Windows, mount point information is not available in maxView or ARCCONF.

4.3.4. Locate Physical Disk LED Behavior
Since the locate commands are executed at the physical device level, the LED that is used to locate 
physical disks in an array when using ARCCONF/maxView will continue to blink the physical device(s) even after deleting the array.

4.3.5. Help Button Leads to Empty Login Page
The Help Button in Controller Properties > Cache does not populate the Help Page as expected. Instead, an empty Login Page is shown.

4.3.6. Firefox Browser Crashes While Uploading Firmware
Uploading the firmware build (SmartFWx100.bin) file while using Firefox version 52.xxx can cause the browser to crash.
WORKAROUND: Upgrade to Firefox version 55.0.3 to resolve this issue.

4.3.7. Backspace Recognized As Input Character
In Linux operating system, the backspace and delete keys are considered input characters when the user tries 
to input maxCrypto crypto/user password using the prompt option.
WORKAROUND: Ensure that password string does not contain backspaces or other special characters 
like delete, escape, function, page up, page down, or home keys.

4.3.8. maxView Login Page Not Displayed After maxView Repair
The maxView login page does not load after a maxView repair. 
The maxView installer repair option cannot repair when the configuration files are missing.

4.3.9. VMware SFCB CIMMOM Causes Slowdown
In ESXi 6.0 U3, the user may experience a slow response in maxView and 
ARCCONF operations due to the known issue with VMware SFCB CIMMOM.

4.3.10. Remote ARCCONF Command Delays
Remote ARCCONF romupdate command takes longer to complete than the local ARCCONF. 
The delay is due to the file transfer between the remote ARCCONF and the hypervisor over the network.

4.3.11. Locked ESXi User Account
In ESXi Guest OS maxView, entering a wrong password for the ESXi hypervisor 
during installation may lock the ESXi user account. In this scenario, maxView login will fail 
even if the correct password is updated using changevmcredential utility.
WORKAROUND 1: Execute pam_tally2 --user root –reset command in ESXi hypervisor to unlock the account.
WORKAROUND 2: Reboot the ESXi hypervisor to unlock the account.

4.3.12. Browser Automatically Fills Username and Password Fields
Browsers can automatically fill the username and password fields.
WORKAROUND: Disable the password manager and autofill forms in the browser settings.

4.3.13. Expanding the Logical Volume to the Current Size is not Allowed
maxView or ARCCONF allows to expand the logical volume to that of a same size, but firmware does not initiate the expansion. 
When you create a logical device of a specific size (for example, 100 GB), a few MB of space is used for metadata. 
Therefore, you cannot expand the logical device to the requested size (100 GB).

4.3.14. maxView Requires a Manual Refresh
Issue: Whenever you remove and insert Microsemi's Linux driver module from\to kernel, 
it does not reflect the changes in maxView.
WORKAROUND: Perform a manual refresh to reflect changes in the maxView application.

4.3.15. Update the GCC Library After FreeBSD Installation
Issue: ARCCONF does not run in FreeBSD after installation.
WORKAROUND: To open ARCCONF in FreeBSD, you have to update the GCC library after OS installation. 
Run the following command before opening the ARCCONF application. This is a one-time activity.
pkg install lang/gcc

4.3.16. maxView or ARCCONF Application Operations are Slow in the Linux Kernel While Sanitizing the Drive
Due to limitation in the Linux kernel while sanitizing the drive, maxView operations and updates are slow, 
when you reboot the server while the 'Sanitize Erase' task is in progress on a hard drive.
WORKAROUND: Use ARCCONF commands with the nodiskinfo arguments until the 'Sanitize Erase' tasks are complete.

Note: maxView does resume operations with normal speed after the sanitization tasks are complete.

4.3.17. System Environment Variable is not Reflected on the PowerShell/Command Windows
After maxView installation, the exported %PATH% system environment variable does not get reflected 
in the newly opened PowerShell or Command windows. Therefore, you cannot run ARCCONF command 
from any directory location until you restart the windows.
WORKAROUND: You must run the ARCCONF command by changing the installation directory location.

4.3.18. maxView GUI is not Available for Solaris
The maxView GUI is not available for Solaris. Use the ARCCONF CLI tool for configuration and management.

4.3.19. Installation is not Supported in Standalone Mode on XenServer
The standalone mode installation is not supported on XenServer.

4.3.20. Unable to Add Remote EXSi Server
WORKAROUND:
1. Add the following configuration information in the sfcb.cfg file.
   *  vi /etc/sfcb/sfcb.cfg
   *  enableSSLv3:false
   *  enableTLSv1:true
   *  enableTLSv1_1:true
   *  enableTLSv1_2:true
2. Restart the sfcbd-watchdog service.

4.3.21. maxView Unable to Detect Controllers on Ubuntu 18.04 after Upgrading to the Latest maxView Package
After upgrading to the latest maxView package, maxView is unable to detect controllers on Ubuntu 18.04. 
This issue happens because the configuration files are not removed by Ubuntu OS during the previous maxView uninstallation.
WORKAROUND: After uninstalling maxView, execute the following command to remove the old configuration files if any.
dpkg --purge StorMan

4.3.22. Commands are Stalled During a Specific I/O Operation in Linux
Issue: As part of acquiring configuration in Linux, SDK library sends a call to the exposed OS volumes 
to identify the mount point and disk information. The call to open the device handle with the O_RDWR flag 
gets blocked in the kernel, resulting in any ARCCONF command getting stalled when a specific I/O operation is in progress on the device.
WORKAROUND: Send an optional command line argument NODISKINFO with ARCCONF to disable the discovery of mount point and disk information.
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Copyright (c) 2018 Microsemi Corporation. All rights reserved. Microsemi and 
the Microsemi logo are trademarks of Microsemi Corporation. All other 
trademarks and service marks are the property of their respective owners.

Microsemi Corporation (Nasdaq: MSCC) offers a comprehensive portfolio of 
semiconductor and system solutions for communications, defense and security, 
aerospace, and industrial markets. Products include high-performance and 
radiation-hardened analog mixed-signal integrated circuits, FPGAs, SoCs, and 
ASICs; power management products; timing and synchronization devices and 
precise time solutions; voice processing devices; RF solutions; discrete 
components; enterprise storage and communications solutions; security 
technologies and scalable anti-tamper products; Ethernet solutions; Power-
over-Ethernet ICs and midspans; custom design capabilities and services. 
Microsemi is headquartered in Aliso Viejo, California and has approximately 
4,800 employees world-wide. Learn more at www.microsemi.com.

PMC-2153191, Issue 8

Microsemi makes no warranty, representation, or guarantee regarding the 
information contained herein or the suitability of its products and services 
for any particular purpose, nor does Microsemi assume any liability whatsoever 
arising out of the application or use of any product or circuit. The products 
sold hereunder and any other products sold by Microsemi have been subject to 
limited testing and should not be used in conjunction with mission-critical 
equipment or applications. Any performance specific ations are believed to be 
reliable but are not verified, and Buyer must conduct and complete all 
performance and other testing of the products, alone and together with, or 
installed in, any end-products. Buyer shall not rely on any data and 
performance specifications or parameters provided by Microsemi. It is the 
Buyer's responsibility to independently determine suitability of any products 
and to test and verify the same. The information provided by Microsemi 
hereunder is provided "as is, where is" and with all faults, and the entire 
risk associated with such information is entirely with the Buyer. Microsemi 
does not grant, explicitly or implicitly, to any party any patent rights, 
licenses, or any other IP rights, whether with regard to such information 
itself or anything described by such information. Information provided in this 
document is proprietary to Microsemi, and Microsemi reserves the right to make 
any changes to the information in this document or to any products and 
services at any time without notice.

The technology discussed in this document may be protected by one or more 
patent grants.

