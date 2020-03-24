# All the other settings can be tweaked by editing the !defines at the top of this script
!define APPNAME "StorageMonitoring"
!define COMPANYNAME "FASTVPS"
!define DESCRIPTION "Storage monitoring by FASTVPS."
# These three must be integers
!define VERSIONMAJOR 1
!define VERSIONMINOR 1
!define VERSIONBUILD 1

!define !IfExist `!insertmacro _!IfExist ""`
!define !IfNExist `!insertmacro _!IfExist "n"`
!define OldScriptPath 'C:\perl64\fastvps_monitoring.pl'

 
RequestExecutionLevel admin ;Require admin rights on NT6+ (When UAC is turned on)
 
InstallDir "C:\${COMPANYNAME}\${APPNAME}"
 
# This will be in the installer/uninstaller's title bar
Name "${COMPANYNAME} - ${APPNAME}"
outFile "fastvps_monitoring_install.exe"
 
!include LogicLib.nsh
 
Page directory
Page instfiles
 
!macro VerifyUserIsAdmin
UserInfo::GetAccountType
pop $0
${If} $0 != "admin" ;Require admin rights on NT4+
        messageBox mb_iconstop "Administrator rights required!"
        setErrorLevel 740 ;ERROR_ELEVATION_REQUIRED
        quit
${EndIf}
!macroend

function .onInit
    setShellVarContext all
    !insertmacro VerifyUserIsAdmin
functionEnd

section "preinstall"
    IfFileExists ${OldScriptPath} file_found file_not_found
    file_found:
        StrCpy $0 "Old script was found"
        Delete ${OldScriptPath}
        ExecWait 'schtasks /DELETE /TN "FastVPS Monitoring" /F'
        goto end_of_test 
    file_not_found:
        StrCpy $0 "Old script was NOT found"
    end_of_test:
sectionEnd

section "install"
    # Path for unpack files during installation.
    setOutPath $INSTDIR
    # Files and directories that will be included in the installer and unpacked when it is launched.
    file /r "utilities"
    file "FastvpsMonitoring.ps1"

    # Add task to schedule.
    ExecWait 'schtasks /CREATE /F /SC HOURLY /TN "FastVPS Monitoring" /TR "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy RemoteSigned -File $INSTDIR\FastvpsMonitoring.ps1" /RU "NT Authority\System"'
    ExecWait 'schtasks /RUN /TN "FastVPS Monitoring"'
    
    # Uninstaller file path.
    writeUninstaller "$INSTDIR\uninstall.exe"
 
    # Start Menu
    createDirectory "$SMPROGRAMS\${COMPANYNAME}"
 
    # Registry information for add/remove programs
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "DisplayName" "${COMPANYNAME} - ${APPNAME} - ${DESCRIPTION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "QuietUninstallString" "$\"$INSTDIR\uninstall.exe$\" /S"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "InstallLocation" "$\"$INSTDIR$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "Publisher" "$\"${COMPANYNAME}$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "DisplayVersion" "$\"${VERSIONMAJOR}.${VERSIONMINOR}.${VERSIONBUILD}$\""
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "VersionMajor" ${VERSIONMAJOR}
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "VersionMinor" ${VERSIONMINOR}
    
    # There is no option for modifying or repairing the install
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "NoRepair" 1
sectionEnd
 
# Uninstaller
 
function un.onInit
    SetShellVarContext all
 
    #Verify the uninstaller - last chance to back out
    MessageBox MB_OKCANCEL "Permanantly remove ${APPNAME}?" IDOK next
        Abort
    next:
    !insertmacro VerifyUserIsAdmin
functionEnd
 
section "uninstall"

    # Remove task from schedule.
    Exec 'schtasks /DELETE /TN "FastVPS Monitoring" /F'
 
    # Try to remove dir with files.
    rmDir /r $INSTDIR
 
    # Remove uninstaller information from the registry
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}"
sectionEnd
