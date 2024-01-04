---
layout: post
title: Windows Forensics - Registry
date: '2023-10-09 13:43:16 +0300'
image: /assets/img/cover_images/28.png
categories: [Forensics, Windows]
tags: [Windows, Registry, Hives]
---

## Windows Registry
The Windows Registry is a collection of databases that contains the system's configuration data. The Windows registry consists of Keys and Values. A Registry Hive is a group of Keys, subkeys, and values stored in a single file on the disk. 5 root keys

```
HKEY_CURRENT_USER Contains the root of the configuration information for the user who is currently logged on.

HKEY_USERS Contains all the actively loaded user profiles on the computer

HKEY_LOCAL_MACHINE(HKLM) Contains configuration information particular to the computer.

HKEY_CLASSES_ROOT The information that is stored here makes sure that the correct program opens when you open a file by using Windows Explorer. This key is sometimes abbreviated as HKCR

HKEY_CURRENT_CONFIG Contains information about the hardware profile that is used by the local computer at system startup.
```

## Registry hives
### Major hives
```
C:\Windows\System32\Config
```
```
DEFAULT
SAM
SECURITY
SOFTWARE
SYSTEM
```
### USRCLASS.DAT
```
C:\Users\<username>\AppData\Local\Microsoft\Windows
```
### NTUSER.DAT
```
C:\Users\<username>\
```
### AMCACHE
The Amcache hive saves information on programs that were recently run on the system
```
C:\Windows\AppCompat\Programs\Amcache.hve
```
### TRANSACTION LOGS
```
 C:\Windows\System32\Config
```
### REGISTRY BACKUPS
```
C:\Windows\System32\Config\RegBack
```

## System Information and accounts
### Os version
```
SOFTWARE\Microsoft\Windows NT\CurrentVersion
```
### Current control set
```
HKLM\SYSTEM\CurrentControlSet
SYSTEM\Select\Current
SYSTEM\Select\LastKnownGood
```
### Computer Name
```
SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName 
```
### Time Zone Information
```
SYSTEM\CurrentControlSet\Control\TimeZoneInformation
```
### Network Interfaces, Past Networks, VPN and Wireless access points
```
SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces
SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\
SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles
```
### Autostart Programs (Autoruns)
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce
SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run
SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```
### Services
```
SYSTEM\CurrentControlSet\Services
```
### SAM hive and user information
```
SAM\Domains\Account\Users
```
### Login activities
```
SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Winlogon
```
## Files and Folders
### Browser opened files
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU
```
### Shared File
```
SYSTEM\CurrentControlSet\Services\LanmanServer\Shares
```
### Recent Opened Files
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.pdf
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.jpg
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.docx
```
### Office Recent Files
```
NTUSER.DAT\Software\Microsoft\Office\VERSION
NTUSER.DAT\Software\Microsoft\Office\15.0\Word
NTUSER.DAT\Software\Microsoft\Office\VERSION\UserMRU\LiveID_####\FileMRU
```
### ShellBags
```
USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags
USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU
NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags
```
### Open/Save and LastVisited Dialog MRUs
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMRU
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
```
### Windows Explorer Address/Search Bars/File Explorer Search/Commands
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### Opened Urls using Internet explorer
```
NTUSER.DAT\Software\Microsoft\Internet\Explorer\TypedURLs
```
## Execution
### UserAssist
These keys contain information about the programs launched, the time of their launch, and the number of times they were executed.
```
NTUSER.DAT\Software\Microsoft\Windows\Currentversion\Explorer\UserAssist\{GUID}\Count
```
### ShimCache/Application Compatibility Cache (AppCompatCache)
its main purpose in Windows is to ensure backward compatibility of applications
```
SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
```
### AmCache
This performs a similar function to ShimCache, and stores additional data related to program executions
```
C:\Windows\appcompat\Programs\Amcache.hve
Amcache.hve\Root\File\{Volume GUID}\
```
### BAM/DAM
Background Activity Monitor keeps a tab on the activity of background applications.Desktop Activity Moderator optimizes the power consumption of the device.
```
SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}
SYSTEM\CurrentControlSet\Services\dam\UserSettings\{SID}
```
## External/ USB device
### Device identification
The following locations keep track of USB keys plugged into a system
```
SYSTEM\CurrentControlSet\Enum\USBSTOR
SYSTEM\CurrentControlSet\Enum\USB
```
### First/Last Times
First time the device was connected,last time connected and last time removed from the system.
```
SYSTEM\CurrentControlSet\Enum\USBSTOR\Ven_Prod_Version\USBSerial#\Properties\{83da6326-97a6-4088-9453-a19231573b29}\####
```
### USB device Volume Name
Device name of the connected drive 
```
SOFTWARE\Microsoft\Windows Portable Devices\Devices
```