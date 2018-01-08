storage-system-monitoring-for-windows
==========================

*Read this in: [Russian](README.md), [English](README.en.md).*

Welcome, dear FastVPS Eesti OU customer! :) You've got here because we really care about you and your data safety!

You may find an open code of our disk subsystem diagnose system for your server.

How to install the monitoring script?

- Download the installer https://github.com/FastVPSEestiOu/storage-system-monitoring-for-windows/raw/master/installer/fastvps_monitoring_install.exe
- Run it and follow the installation instructions

You may also download and run the installer by executing only one PowerShell command line:
```bash
wget https://github.com/FastVPSEestiOu/storage-system-monitoring-for-windows/raw/master/installer/fas
tvps_monitoring_install.exe -OutFile C:\Users\Administrator\Downloads\fastvps_monitoring_install.exe; & C:\Users\Adminis
trator\Downloads\fastvps_monitoring_install.exe
```

- The script works via an ecrypted channel (https, ssl)
- The script doesn't open any ports in the system (which excludes a chance of intrusion from outside)
- The script doesn't update itself automatically (which excludes adding vulnerabilities)
- The script has an open code (which gives you a chance to read its content)


What files in this repo are responsible for?

- FastvpsMonitoring.ps1 - the script itself that collects the data about disks and arrays.
- storage-monitoring-installer.NSI - NSIS utility configuration file that compiles the installer.
- installer/fastvps_monitoring_install.exe - compiled installer by NSIS utility.
- utilities/arcconf - arcconf utility files that are used to work with Adaptec controllers.
- utilities/megacli - megacli utility files that are used to work with LSI controllers.
- utilities/smartmontools - smartctl utility files that are userd to get data from physical devices.

Where does it send all data?

- The data is send to https://fastcheck24.com via an ecrypted channel

What do we do with the data?

- We analyze it with a special software that uses various alogorythms to predict a disk subsystem failure
- In the event of detecting a potentially destructive promlems with the disk subsystem we shall contact you in any available way

Which types of RAID are being suppored by the monitoring?

- Adaptec
- LSI
- DELL PERC (LSI)

What does the script do?

- Sends VritualDisk data hourly
- Sends hardware RAID data and disks data connected to RAID hourly. 
- Sends smartctl output regarding all disks in the system

What the scrip does NOT do?

- The script does not run any additional modules
- The script does not update itself automatically
- The script does not send any information except what is listed above 

Which operating systems are supported:

- Windws Server 2012 r2
- Correct operation of the script was not tested on other OS Windows versions and can not be guaranteed.

Which program language the script was written in?

- PowerShell (monitoring script)
- NSIS (installer)

What changes will be made in the system?

- The script creates a schedule task with "FastVPS Monitoring" that runs every hour.
- We place arcconf, megaraid and storage_system_fastvps_monitoring.pl script in a folder set during installation. It is C:\FASTVPS\StorageMonitoring\ by default.

Who may use the software?

- Any FastVPS Eesti OU customer

What kind of software do we install on the server and why?

- smartmontools - a package of utilities for obtaining S.M.A.R.T. information from the device
- arcconf - Adaptec vendor utilitiy
- megacli - LSI vendor utilities

May I use the program locally to check an array status?

- Sure, but you loose all the features of our S.M.A.R.T. analyze system and other metrics. Only array condition can be checked. Moreover you will not get any notifications when a disk fails

Is XXX YYY support available?

- Of course, patches are welcome!

Is it possible to see the data collected by the script?

- In order to do that you need to run the script with -Test key. All the data collected will appear on the screen.
```bash
C:\FASTVPS\StorageMonitoring\FastvpsMonitoring.ps1 -Test
```

Can I compile the script by myself?

- Download the archive with files that are included into the installer - https://github.com/FastVPSEestiOu/storage-system-monitoring-for-windows/archive/master.zip
- Download the utility to compile the installer in exe format - http://nsis.sourceforge.net/Download
- Run NSIS utility. Choose storage-monitoring-installer.NSI as a configuration file.
- Wait when compilation is complete and check the installer.

How to remove the monitoring script from the system?

- Simply run C:\FASTVPS\StorageMonitoring\uninstall.exe file. All programms related to the script and the scheduler task will be removed.
