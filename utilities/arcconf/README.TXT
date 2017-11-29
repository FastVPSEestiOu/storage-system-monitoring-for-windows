README.TXT: Adaptec maxView Storage Manager & 
ARCCONF Command Line Interface Utility 
as of March 22, 2016
--------------------------------------------------------------------
Please check the product website for the later versions of this 
file to ensure you are reviewing the latest information. This 
file contains important information about issues and errata 
that were discovered after completion of the standard 
product documentation.

In the case of conflict between various parts of the documentation 
set, this file contains the most current information.

Table of Contents
1. New Features of this Release
2. Software Versions and Documentation
	2.1. Utility Software
	2.2. Documentation
		4.2.2.1. Series 6, 7, 8 Controller Documentation
		4.2.2.2. HBA 1000 Series Product Documentation
		4.2.2.3. SmartIOC Product Documentation
3. Installation Notes
	3.1. Installation and Setup
	3.2. Supported Operating Systems
		3.2.1. Series 6, 7, 8 Controllers
		3.2.2. Smart Family Controllers
	3.3. General Setup Notes
	3.4. Remote Access
	3.5. Windows 8 Setup
	3.6. SLES Setup
	3.7. Ubuntu Setup
	3.8. Bootable USB Image Security Warnings
	3.9. RAW Device Setup (Series 6, 7, 8 Only)
	3.10. maxView Plugin for VMware vSphere Web Client
4. Known Limitations
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
		4.1.17. Online Help Issues
		4.1.18. Broadcasting Alerts About Status and Activity
	4.2. Limitations Specific to Series 6, 7, 8 Controllers
		4.2.1. RAID-Level Migrations
		4.2.2. maxCache Device Migration
		4.2.3. ARCCONF maxCache Device Size Issue
		4.2.4. Power Management Issues
		4.2.5. Verify with Fix
		4.2.6. ATA Secure Erase
		4.2.7. Series 6 Controller Issues
		4.2.8. Simple Volume Support
		4.2.9. Auto-Volume Support
		4.2.10. Hot-Removing Disk Drives on Xenserver Guest OS
		4.2.11. Changing Read and Write Cache Settings for Logical Drive
	4.3. Limitations Specific to Smart Family Controllers
		4.3.1. SES Passthrough Commands to Expanders
		4.3.2. Firmware Upgrade Issues


1. New Features of this Release

	o Added new features:
		- New command to identify a device by blinking its LEDs.
		- Segment and Group Information of a RAID 10 Logical 
		  Device can now be displayed.
		- A new UNINIT/TASK command to clear drive configuration 
		  for physical devices containing RAID Information Sector 
		  (RIS) that have been masked in order to protect the 
		  configuration data.
		- Ability to show SGPIO virtual SEP information to show 
		  enclosure devices for SGPIO backplanes.
		- For cases where a logical drive fails, the array status 
		  is now reported.
		- Ability to display physical drive mount point information.
		- Ability to display logical drive mount point information.
		- Verify Write support is provided. 
		- Linux Hyper-V is supported for the maxView Storage Manager.
	o For Smart family products, added support for Citrix XenServer.
	o Bugfixes


2. Software Versions and Documentation

	2.1. Utility Software
	
		o Microsemi Adaptec maxView Storage Manager 
		  Version 2.01.00  (22268)
		o Microsemi Adaptec ARCCONF Command Line Interface 
		  Utility Version 2.01.00  (22268)
		
	2.2. Documentation
	
		2.2.1. Series 6, 7, 8 Controller Documentation
		
			PDF Format (English/Japanese)
			o maxView Storage Manager User's Guide
			o Adaptec RAID Controller Command Line Utility 
			  User's Guide
			
			HTML and Text Format
			o maxView Storage Manager Online Help
			o maxView Storage Manager README.TXT file
			
		2.2.2. HBA 1000 Series Product Documentation
		
			PDF:
			o Adaptec maxView Storage Manager User's Guide for 
			  Smart-Family Controllers
			o Adaptec HBA 1000 Series Command Line Utility 
			  User's Guide
			
			HTML and Text Format:
			o maxView Storage Manager for Smart-Family Controllers 
			  Online Help
			o maxView Storage Manager README.TXT file
			
		2.2.3. SmartIOC Product Documentation
		
			PDF:
			o Adaptec maxView Storage Manager User's Guide for 
			  Smart-Family Controllers
			o Adaptec SmartIOC 2000 Command Line Utility User's 
			  Guide
			
			HTML and Text Format:
			o maxView Storage Manager for Smart-Family Controllers 
			  Online Help
			o maxView Storage Manager README.TXT file


3. Installation Notes

	3.1. Installation and Setup
	
		Refer to your product documentation for the correct 
		installation and setup details:
		o Your product Installation and User's Guide contains 
		  complete installation information for your product's 
		  drivers.
		o The maxView Storage Manager User's Guide for your 
		  product contains installation information for the 
		  maxView Storage Manager software.
		o The Command Line Utility User's Guide for your product 
		  contains complete installation for ARCCONF.
			
	3.2. Supported Operating Systems
	
		3.2.1. Series 6, 7, 8 Controllers
		
			Microsoft Windows
			o Microsoft Windows Server 2012 (64-bit)
			o Microsoft Windows Server 2012 R2 (64-bit)
			o Microsoft Windows Server 2008 R2 SP1 (64-bit)
			o Microsoft Windows SBS 2011 (Standard and Essential)
			o Microsoft Windows 10 (32-bit and 64-bit)
			o Microsoft Windows 8.1 (32-bit and 64-bit)
			o Microsoft Windows 7 (32-bit and 64-bit)
			o Microsoft WinPE 8.1 (32-bit and 64-bit)
			
			Linux
			o Red Hat Enterprise Linux/CentOS 7.2, 7.1 (64-bit)
			o Red Hat Enterprise Linux/CentOS 6.7, 6.6 (64-bit)
			o Red Hat Enterprise Linux/CentOS 5.11, 5.10 (64-bit)
			o SuSE Linux Enterprise Server 12 SP1 (64-bit)
			o SuSE Linux Enterprise Server 12 (64-bit)
			o SuSE Linux Enterprise Server 11 SP4 and SP3 (64-bit)
			o Debian Linux 8.1 (64-bit)
			o Ubuntu Linux 14.04.3, 14.04 (64-bit)
			o Ubuntu Linux 12.04.5 (64-bit)
			o Fedora Linux 22 (64-bit)
			
			FreeBSD
			o FreeBSD 10.2 (64-bit)
			o FreeBSD 9.3 (64-bit)
			
			Virtual OS Environments
			o VMware ESXi 6.0 (64-bit)
			o VMware ESXi 5.5 U2 (64-bit)
			o Citrix XenServer 6.5.1 (64-bit)
			o Citrix XenServer 6.2 (32-bit)
			
			Solaris
			o Solaris 11 (32-bit)
			o Solaris 10 U9 (32-bit)
			
			Notes
			1.	The ARCCONF Command Line Utility is supported on 
				only 64-bit versions of Microsoft Windows and Linux.
			2.	Boot USB (offline or pre-boot) for the ARCCONF Command 
				Line Utility and maxView Storage Manager is supported 
				in Linux.
				
		3.2.2. Smart Family Controllers
		
			Microsoft Windows
			o Microsoft Windows  Server 2012 (64-bit)
			o Microsoft Windows  Server 2012 R2 (64-bit)
			o Microsoft Windows  Server 2008 R2 SP1 (64-bit)
			o Microsoft Windows  SBS 2011 (Standard and Essential)
			o Microsoft Windows  10 (32-bit and 64-bit)
			o Microsoft Windows  8.1 (32-bit and 64-bit)
			o Microsoft Windows 7 (32-bit and 64-bit)
			
			Linux
			o Red Hat Enterprise Linux/CentOS 7.2, 7.1 (64-bit)
			o Red Hat Enterprise Linux/CentOS 6.7, 6.6 (64-bit)
			o Red Hat Enterprise Linux/CentOS 5.11, 5.10 (64-bit)
			o SuSE Linux Enterprise Server 12 SP1 (64-bit)
			o SuSE Linux Enterprise Server 12 (64-bit)
			o SuSE Linux Enterprise Server 11 SP4 and SP3 (64-bit)
			o Ubuntu Linux 14.04.3, 14.04 (64-bit)
			o Ubuntu Linux 12.04.5 (64-bit)
			
			Virtual OS Environments
			o VMware ESXi 6.0, ESXi U1 (64-bit)
			o VMware ESXi 5.5 U2, ESXi 5.5 U3 (64-bit)
			o Citrix XenServer 6.5.1 (64-bit)
			o Citrix XenServer 6.2 (32-bit)
			
			Notes
			1.	The ARCCONF Command Line Utility is supported on 
				only 64-bit versions of Microsoft Windows and Linux.
			2.	Boot USB (offline or pre-boot) for the ARCCONF Command 
				Line Utility and maxView Storage Manager is supported 
				in Linux.
				
	3.3. General Setup Notes
	
		o maxView Storage Manager is not backwards-compatible with 
		  Series 5 and older Adaptec controller models.
		o maxView Storage Manager and legacy Adaptec Storage Manager 
		  (ASM) cannot coexist on the same system.
		o For Series 6, 7, 8 controllers:
			-	maxView Storage Manager is not supported on FreeBSD. 
				Use ARCCONF to create and manage arrays.
				
	3.4. Remote Access
	
		maxView Storage Manager requires the following range of 
		ports to be open for remote access:
		o 34570-34580 (TCP)
		o 34570 (UDP)
		o 34577-34580 (UDP)
		See also 4.1.6 for OS-specific issues and workarounds.
		
	3.5. Windows 8 Setup
	
		To log in and use maxView Storage Manager on a Windows 8 
		system, you must create a local user account; you cannot 
		use your MS Live account. 
		To create a local user account:
		1.	Log into your MS Live account.
		2.	Select Settings->Change PC Settings->Users->Switch to 
			Local user.
		3.	Provide account details.
		4.	Start maxView Storage Manager and log in with your 
			local user account credentials.
			
	3.6. SLES Setup
	
		o To avoid a problem with launching maxView Storage 
		  Manager on SLES 11 x64 systems with DHCP enabled, 
		  ensure that the /etc/hosts file maps the server 
		  IP address to a valid host name; it is not sufficient 
		  to map the IP address to 'localhost'.
			
	3.7. Ubuntu Setup
	
		o To avoid a maxView Login failure on Ubuntu systems, 
		  you must ensure that the root user account is enabled. 
		  (It is disabled, by default, on Ubuntu 14.04 
		  and later because no password is set.)
		  For example: sudo bash; sudo passwd root
		o When upgrading maxView Storage Manager on an existing 
		  Ubuntu Linux x64 installation, you must enable the 
		  upgrade switch before installing the maxView .deb 
		  package:
				export maxView_Upgrade=true 
				dpkg -i StorMan-*.deb
				To uninstall maxView after the upgrade:
				export maxView_Upgrade=false 
				dpkg -r storman
			
	3.8. Bootable USB Image Security Warnings
	
		When running maxView Storage Manager from the bootable 
		USB image, you may be prompted with one or more with 
		security warnings before maxView launches. In 
		each case, acknowledge the warning and continue.
		
	3.9. RAW Device Setup (Series 6, 7, 8 Only)
	
		On Adaptec Series 7 and Adaptec Series 8 controllers, 
		a RAW Pass Through device is analogous to a JBOD, supported 
		by Adaptec Series 6 controllers and older. Any drive without 
		Adaptec RAID metadata is exposed to the OS as a RAW Pass 
		Through device. To remove the Adaptec metadata and convert 
		the drive to a RAW device, use the Uninitialize command in 
		maxView Storage Manager; any existing data on the drive is 
		destroyed. (You can also run uninit from the BIOS or 
		ARCCONF.) For more information about working with RAW devices, 
		see 'controller modes' in the CLI User's Guide, and BIOS 
		'general settings' in the RAID Controller Installation and 
		User's Guide.
		
	3.10. maxView Plugin for VMware vSphere Web Client
	
		The maxView Plugin for VMware vSphere Web Client is 
		supported on VMware 5.5 and 6.0.

4. Known Limitations

	4.1. Global Limitations
	
		4.1.1. Dual-Controller Systems
		
			In dual-controller systems, the controller order in 
			maxView Storage Manager and the BIOS differs. Example: 
			with an Adaptec 72405 and 7805 installed, the BIOS reports 
			the 72405 as controller 1 and the 7805 as controller 2; 
			in the GUI, the controller order is reversed.
			
		4.1.2. Email Notifications
		
			o On Linux systems, we recommend adding the SMTP host 
			  name and the system IP address, to the /etc/hosts file. 
			  Doing so ensures that email notifications will succeed 
			  if you specify the email server in maxView Storage 
			  Manager by host name. Otherwise, email notifications 
			  (including test messages) may fail if the DNS is unable 
			  to resolve the host name.
				
			  WORKAROUND: Specify the email server in maxView Storage 
			  Manager by IP address.
				
			o On CentOS 5.9 x64, email notifications may not be sent 
			  for logical drive creations, degraded logical drives, 
			  or logical drives that are rebuilding or fully rebuilt.
				
		4.1.3. SGPIO Enclosures
		
			In this release, maxView Storage Manager does not show 
			connector information for SGPIO enclosures.
			
		4.1.4. Non-RAID Mode Controllers
		
			maxView Storage Manager can "see" RAID controllers 
			operating in HBA mode, Auto-Volume mode, and Simple Volume 
			mode (Adaptec Series 7, Adaptec Series 8, Smart Family 
			controllers only). However, to change the controller mode 
			on Adaptec Series 7/8 controllers, you must use ARCCONF 
			or the BIOS. With Adaptec Smart-Family controllers, you 
			can also change the controller mode with maxView Storage 
			Manager.
			
		4.1.5. Browser Issues
		
			To run maxView Storage Manager on the supported browsers. 
			Javascript must be enabled.
			
			o Due to a certificate bug in Firefox 31.x, maxView 
			  login may fail on RHEL systems with a "Secure 
			  Connection" error. (Firefox 31.1 is the default 
			  browser on RHEL 6.6; on RHEL 7.1, it is 31.4.)
			  WORKAROUND: Upgrade to Firefox 36.
				
			o With the default Security setting in Microsoft 
			  Internet Explorer 10 and 11, you may be unable to 
			  login to maxView Storage Manager or experience 
			  certain GUI display issues in the maxView online 
			  Help system.
			  WORKAROUND: Change the default Security setting 
			  from High (or Medium-High) to Medium. 
			  Alternative: add the GUI IP address to the trusted 
			  sites list.
				
			o With Google Chrome, the scrollbar resets itself to 
			  the top after selecting a drive in the Logical Drive 
			  wizard. To select another drive, you must 
			  scroll back down to the drive location.
				
			o With Microsoft Internet Explorer 10, the controller 
			  firmware update wizard does not show the f/w update 
			  file name when the upload completes. To refresh 
			  the display, click Next then Back.
				
			o We do not recommend using multiple browsers 
			  simultaneously on the same maxView 
			  instance. Doing so may cause display issues or freezes; 
			  to restore maxView, refresh the display by pressing F5.
				
		4.1.6. Remote System Access on Linux and Windows
		
			To avoid remote system access failures from Linux 
			and Windows clients running maxView Storage Manager, 
			check and update one or all of the following system 
			and network settings:
			
			Windows:
			o Ensure that the DNS server information is properly 
			  configured
			
			RHEL/Linux:
			
			o Set server.properties file permissions to at least 
			  read-only at all levels
				1.	Stop all maxView services.
				2.	Set the Permissions of server.properties file to 
					read and write or read-only at all levels 
					(Owner, Group and Others). 
				3.	Apply and close.
				4.	Restart all services in the given order - cim, 
					agent, tomcat
				5.	Now try to remote login to this system from any 
					other system
				
			o Check/update these network settings:
				1.	Disable SELinux
				2.	Disable firewall.
				3.	Disable the ipv6 in the system, if ipconfig shows 
					both ipv4 and ipv6 address.
				4.	Remove the virtual bridge virbr0, if present
				5.	Enter local ip address in 'localip' parameter in 
					server.properties file
					
		4.1.7. RAID 10 Segment Order
		
			maxView Storage Manager and the Ctrl-A BIOS report the 
			wrong segment order for RAID 10s, regardless of the order 
			in which the drives are selected.
			Example 1: Create RAID 10 with 2 SDDs and 2 HDDs in maxView 
			Storage Manager:
			
				(1a) ARCCONF and maxView Storage Manager see the 
					following RAID segment order: 
							Device 2 (S1) 
							Device 1 (H2) 
							Device 3 (S2) 
							Device 0 (H1) 
				
				(1b) the BIOS/CTRL-A sees the following RAID segment 
					order: 
							Device 2 (S1) 
							Device 1 (H2) 
							Device 0 (H1) 
							Device 3 (S2) 
				
				(1c) the correct and expected RAID segment order is: 
							Device 2 (S1) 
							Device 0 (H1) 
							Device 3 (S2) 
							Device 1 (H2)
							
			Example 2: Create RAID 10 with 2 SDDs and 2 HDDs 
			with ARCCONF:
			
				(2a) the BIOS/CTRL-A sees the following RAID segment 
					order: 
								  Device 0 (H1) 
								  Device 2 (S1) 
								  Device 1 (H2) 
								  Device 3 (S2) 
			   
				(2b) ARCCONF and maxView Storage Manager see the 
					correct RAID segment order: 
								  Device 2 (S1) 
								  Device 0 (H1) 
								  Device 3 (S2) 
								  Device 1 (H2)
								  
		4.1.8. RAID 10 Rebuild Order
		
			With a degraded RAID 10 logical drive, the drive is 
			rebuilt one leg at a time, not in parallel.
			
		4.1.9. Locate Logical Drive Blink LED
		
			In maxView Storage Manager, Locate Logical Drive 
			continues to blink the LED for a pulled physical drive 
			in the array after the locate action is stopped. 
			(For unpulled drives, the blinking stops.) This issue is 
			not seen with ARCCONF.
			
		4.1.10. ARCCONF Backward Compatibility
		
			ARCCONF is backward compatible with older Adaptec 
			controller models. As a result, the ARCCONF user's guide 
			and online help show command options that are not 
			supported by newer Adaptec controllers, like the 
			Adaptec Series 7 and Adaptec Series 8 or later products.
			
			Example: With ARCCONF SETMAXCACHE, Adaptec Series 7 and 
			Series 8 controllers do not support ADDTOPOOL or 
			REMOVEFROMPOOL
			
		4.1.11. Updating Hard Disk Firmware on VMware Guest OS
		
			Updating the firmware for a SAS hard disk drive with 
			ARCCONF/maxView can crash (PSOD) the VMware Guest OS. 
			This issue is seen with SAS hard drives only; with 
			SATA drives, the firmware update completes successfully.

		4.1.12. Hot Swap Issues on VMware CentOS Guest OS
		
			Due to a limitation with the VMware CentOS Guest OS 
			network configuration, maxView Storage Manager does not 
			show newly added or removed hot swap drives. 
			(ARCCONF sees the configuration change but maxView 
			does not.)
			
			WORKAROUND: (1) reboot the system or restart maxView 
			services; (2) adjust the network configuration; contact 
			Adaptec Support for more information.
			
		4.1.13. Enclosure Status Reporting
		
			Enclosure status, in maxView Storage Manager, is 
			event-driven. As a result, enclosures can have a 
			"Degraded" status even if related resources (fan, 
			temperature, power) are performing normally (Optimal 
			status). For instance, the Enclosure status changes 
			to "Degraded" if the system reports an "Enclosure 
			device not responding ..." event, even if other sensor 
			values are normal.
			
		4.1.14. PHY Status on Enclosure Backplanes
		
			In the Controller Properties window, maxView Storage 
			Manager shows the Connector Info as "unknown" for all 
			PHYs on an enclosure-based backplane (for instance, a 
			backplane attached to connector 1).
			
		4.1.15. Special Characters in Logical Device Names
		
			Special characters are permitted in logical device 
			names in maxView Storage Manager, the BIOS, and ARCCONF. 
			However, with Linux ARCCONF (create, setname), special 
			characters must be "escaped" to ensure proper 
			interpretation. For example:
			
			ARCCONF SETNAME 1 LOGICALDRIVE 1 arc_ldrive%\$12\&amp;
			
		4.1.16. Speaker Status on SuperMicro SAS2X28 Enclosures
		
			SuperMicro SAS2X28 enclosures do not propagate 
			the speaker status to maxView Storage Manager. As 
			a result, maxView always displays the speaker 
			status as Off.
			
		4.1.17. Online Help Issues
		
			o When opening the maxView Storage Manager help 
			  from a remote Linux system (eg, over a VPN), the 
			  help window may fail to open with a 'can't establish 
			  connection to server' message.
			
			  WORKAROUND: replace 127.0.0.1:8443 in the URL with 
			  <system_ip_address>:8443
				
			o In IE11, topics in the help may display with a 'Topics 
			  Not Found' message when their corresponding links are 
			  clicked in the navigation pane of the help.
				
			  WORKAROUND: click on the "Add" browser link to add 
			  certification to view the content.
			
		4.1.18. Broadcasting Alerts About Status and Activity
		
		This feature is not supported by the maxView Storage 
		Manager or ARCCONF and has been removed from the product 
		documentation.
		
	4.2. Limitations Specific to Series 6, 7, 8 Controllers
	
		4.2.1. RAID-Level Migrations
		
			o The following RAID-level migrations (RLM) are 
			  supported in this release:
				-	RAID 0 to RAID 5
				-	RAID 0 to RAID 10
				-	RAID 5 to RAID 6
				-	RAID 6 to RAID 5
				-	RAID 10 to RAID 5
				-	RAID 5 to RAID 10
				-	RAID 1 to RAID 5
				-	SIMPLE VOLUME to RAID 1
				-	RAID 1 to SIMPLE VOLUME
				
			o When migrating a Simple Volume to RAID 1, maxView 
			  Storage Manager reports the logical drive state as 
			  Impacted (rather than Reconfiguring); 
			  this is normal.
				
			o We do not recommend performing a RAID-level 
			  migration or Online Capacity Expansion (OCE) 
			  on a logical drive with maxCache SSD caching 
			  enabled.
				
			  NOTE: maxView Storage Manager grays out the 
			  options for logical drives with maxCache enabled. 
			  ARCCONF terminates the task.
				
			o Always allow a RAID-level migration to complete 
			  before creating a support archive file. Otherwise, 
			  the support archive will include incorrect 
			  partition information. Once the migration is 
			  complete, the partition information will be reported 
			  correctly.
				
		4.2.2. maxCache Device Migration
		
			Only one maxCache Device is supported per controller. 
			Moving the maxCache Device (all underlying SSDs) from 
			one controller to another (assuming both controllers 
			support maxCache) is supported only if (1) the new 
			controller does not have a maxCache Device or any other 
			maxCache Device with a conflicting device number and 
			(2) only after a clean shutdown 
			on the old controller.
			
		4.2.3. ARCCONF maxCache Device Size Issue
		
			ARCCONF supports >2TB maxCache Devices if you create 
			the device with the 'max' parameter. However, the 
			functional limit for the maxCache Device is 2TB, 
			which is also the limit in maxView Storage Manager.
			
		4.2.4. Power Management Issues
		
			o Power management is not supported on FreeBSD.
			
			o Capturing support logs from maxView or ARCCONF 
			  will spin up drives when power management is 
			  active. This behavior is by design.
				
			o The Logical Drive Creation wizard no longer 
			  includes the option to enable power management settings.
				
			  WORKAROUND: Enable power management for the 
			  logical drive from the Set Properties window.
				
		4.2.5. Verify with Fix
		
			In maxView Storage Manager and ARCCONF, the Verify 
			with Fix operation is NOT available when:
			
			1.	The logical drive has a non-redundant RAID level
			2.	Other tasks are in progress on the logical drive
			3.	The logical drive is in a non-optimal or impacted state
			
		4.2.6. ATA Secure Erase
		
			In ARCCONF, the ATA Secure Erase operation cannot 
			be aborted. Once started, it continues to completion.
			
			NOTE: ATA Secure Erase is also available in the 
			Ctrl-A BIOS and maxView Storage Manager.
			
		4.2.7. Series 6 Controller Issues
		
			The following issues are seen only with Adaptec 
			Series 6 RAID controllers:
			o In maxView Storage Manager, the Preserve Cache 
			  option on the Set Properties window is not 
			  supported on Series 6 RAID controllers. Attempting 
			  to set this option for the Series 6 controller fails.
				
			o Renaming a RAID volume disables the write-cache 
			  (if enabled). You cannot re-enable the write-cache 
			  in maxView Storage Manager.
				
			  WORKAROUND: Use ARCCONF to enable the write-cache.
				
			o In a VMware Guest OS under VMware 5.x, maxView 
			  Storage Manager and ARCCONF do not detect existing 
			  logical drive partitions. As a result, 
			  attempting to delete, clear, or erase the logical 
			  drive may fail.
				
			o On Series 6 controllers, maxView Storage Manager 
			  deletes partitioned JBODs without issuing a 
			  warning message.
				
			o Series 6 controllers do not support the ARCCONF 
			  GETPERFORM command.
			
		4.2.8. Simple Volume Support
		
			o In this release, you can create a maximum of 128 
			  Simple Volumes in maxView Storage Manager, ARCCONF, 
			  or the BIOS.
				
			o When a Simple Volume fails, the status remains 
			  unchanged after drive replacement.
				
			  WORKAROUND: Manually delete the Simple Volume to 
			  remove it.
				
		4.2.9. Auto-Volume Support
		
			o Changing a controller into Auto-Volume mode 
			  (ARCCONF/BIOS) is not supported if the configuration 
			  includes any logical device type other than Simple 
			  Volume, including a maxCache Device. The mode switch 
			  from RAID mode to Auto-Volume mode is blocked if any 
			  other type of logical volume exists (including 
			  maxCache). After switching to Auto-Volume mode, 
			  you can create and delete Simple Volumes 
			  only in maxView Storage Manager and ARCCONF.
				
			o In Auto-Volume mode, only the first 128 RAW drives 
			  are converted to Simple Volumes; the rest of the 
			  RAW drives remain unchanged. If you uninitialize 
			  a Ready drive while the controller is in Auto-Volume 
			  mode, the firmware converts the drive automatically 
			  until the Simple Volume count reaches the maximum.
				
		4.2.10. Hot-Removing Disk Drives on Xenserver Guest OS
		
			XenServer does not support "hot-removal" of disk 
			drives from a partitioned logical drive. As a result, 
			if you hot remove a disk from a logical drive, 
			the Guest OS becomes inaccessible because the drive 
			partition remains visible to the OS instead of being cleared.
			
			WORKAROUND: Reboot the XenServer host, detach the 
			failed partition, then restart the VM.
			
		4.2.11. Changing Read and Write Cache Settings for 
			Logical Drive
		
			maxView Storage Manager does not allow you to change 
			the read-cache and write-cache settings for a logical drive 
			in one step. You must click OK after each change.
			
	4.3. Limitations Specific to Smart Family Controllers
	
		4.3.1. SES Passthrough Commands to Expanders
		
			SES passthrough commands to expanders fail.
			
		4.3.2 Firmware Upgrade Issues
			
			For systems using Adaptec HBA 1000 with an Adaptec 
			SAS Expander 82885T card, where the ARCCONF utility 
			is used to upgrade the expander firmware, ARCCONF 
			may crash if 64-bit chunk sizes are used.  
			
			WORKAROUND: Use 32-bit chunk sizes to upgrade/downgrade 
			the expander firmware.



Copyright 2016 Microsemi Corporation. All rights reserved. 
Microsemi and the Microsemi logo are trademarks of Microsemi 
Corporation. All other trademarks and service marks are 
the property of their respective owners.

PMC-2153191, Issue 2

Microsemi Corporation (Nasdaq: MSCC) offers a comprehensive 
portfolio of semiconductor and system solutions for communications, 
defense and security, aerospace, and industrial markets. 
Products include high-performance and radiation-hardened 
analog mixed-signal integrated circuits, FPGAs, SoCs, and 
ASICs; power management products; timing and synchronization 
devices and precise time solutions; voice processing devices; 
RF solutions; discrete components; enterprise storage and 
communications solutions; security technologies and scalable 
anti-tamper products; Ethernet solutions; Power-over-Ethernet 
ICs and midspans; custom design capabilities and services. 
Microsemi is headquartered in Aliso Viejo, California and has 
approximately 4,800 employees world-wide. 
Learn more at www.microsemi.com.

Microsemi makes no warranty, representation, or guarantee 
regarding the information contained herein or the suitability 
of its products and services for any particular purpose, 
nor does Microsemi assume any liability whatsoever arising 
out of the application or use of any product or circuit. 
The products sold hereunder and any other products sold 
by Microsemi have been subject to limited testing and should 
not be used in conjunction with mission-critical equipment 
or applications. Any performance specific ations are believed 
to be reliable but are not verified, and Buyer must conduct 
and complete all performance and other testing of the products, 
alone and together with, or installed in, any end-products. 
Buyer shall not rely on any data and performance specifications 
or parameters provided by Microsemi. It is the Buyer's 
responsibility to independently determine suitability of 
any products and to test and verify the same. The information 
provided by Microsemi hereunder is provided as is, where is 
and with all faults, and the entire risk associated with such 
information is entirely with the Buyer. Microsemi does not 
grant, explicitly or implicitly, to any party any patent 
rights, licenses, or any other IP rights, whether with regard 
to such information itself or anything described by 
such information. Information provided in this document is 
proprietary to Microsemi, and Microsemi reserves the right 
to make any changes to the information in this document or 
to any products and services at any time without notice.

The technology discussed in this document may be protected by 
one or more patent grants.

 
 
