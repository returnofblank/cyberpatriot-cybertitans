@echo off

:: Change the maximum password age to 90 days
net accounts /maxpwage:90

:: Change the secure lockout threshold to 10 attempts
net accounts /lockoutthreshold:10

:: Create Minimum Password age of 10 Days
net accounts /minpwage:10

:: Disable Guest Account
net user Guest /active:no

:: Stop and Disable FTP service
sc stop ftpsvc
sc config ftpsvc start=disabled

:: Enable Limit local use of blank passwords to console only
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f

:: Enable Do not allow anonymous enumeration of SAM accounts
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f

:: Disable Remote Desktop
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f

:: Disable Remote Assistance
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f

:: Turn on Windows Firewall
netsh advfirewall set allprofiles state on

:: Open Group Policy Editor
start gpedit

:: Open Windows Update Settings
start ms-settings:windowsupdate

:: Open Control Panel
start control

:: Open User Manager
lusrmgr.msc
