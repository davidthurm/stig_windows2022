## ChatGPT Dec 15 2022 Version
## https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_STIGViewer_2-17_Win64.zip
## https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/scc-5.6_Windows_bundle.zip
## https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2022_V1R0-1_STIG_SCAP_1-2_DraftBenchmark.zip
## https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2022_V1R1_STIG.zip
## Server Manager add feature Group Policy Management
### Get-ChildItem -Path "C:\Windows\System32\GroupPolicy"


$fancyDate = (Get-Date -f 'yyyy-MM-dd_HH-mm-ss') 
Start-Transcript -Path "$($env:USERPROFILE)\Documents\MyScriptLog_$($fancyDate).txt" -NoClobber -Force


# Windows Server 2022 account lockout duration must be configured to 15 minutes or greater.
## This code does not clear the error.
net accounts /lockoutduration:30
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LockoutDuration -Type DWord -Value 900000

net accounts /MINPWLEN:14
net accounts /MAXPWAGE:60
net accounts /MINPWAGE:1
net accounts /UNIQUEPW:24


# Windows Server 2022 account lockout duration must be configured to 15 minutes or greater.
## This code does not clear the error.
net accounts /lockoutduration:30
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LockoutDuration -Type DWord -Value 900000

# Windows Server 2022 must have the number of allowed bad logon attempts configured to three or less. 

# Windows Server 2022 must have the period of time before the bad logon counter is reset configured to 15 minutes or greater. 

# Windows Server 2022 password history must be configured to 24 passwords remembered. 

net accounts /uniquepw:24

# Windows Server 2022 must be configured to audit Account Logon - Credential Validation failures. 
AuditPol /set /subcategory:"Credential Validation" /failure:enable

# Windows Server 2022 must be configured to audit Account Management - User Account Management failures. 
AuditPol /set /subcategory:"User Account Management" /failure:enable

# Windows Server 2022 must be configured to audit Detailed Tracking - Process Creation successes. 
AuditPol /set /subcategory:"Process Creation" /success:enable

# Windows Server 2022 must be configured to audit Logon/Logoff - Account Lockout failures. 
AuditPol /set /subcategory:"Account Lockout" /failure:enable

# Windows Server 2022 must be configured to audit Object Access - Other Object Access Events successes. 
AuditPol /set /subcategory:"Other Object Access Events" /success:enable

# Windows Server 2022 must be configured to audit Object Access - Other Object Access Events failures. 
AuditPol /set /subcategory:"Other Object Access Events" /failure:enable

# Windows Server 2022 must be configured to audit Policy Change - Authorization Policy Change successes. 
AuditPol /set /subcategory:"Authorization Policy Change" /success:enable

# Windows Server 2022 must be configured to audit Privilege Use - Sensitive Privilege Use successes. 
AuditPol /set /subcategory:"Sensitive Privilege Use" /success:enable

# Windows Server 2022 must be configured to audit Privilege Use - Sensitive Privilege Use failures. 
AuditPol /set /subcategory:"Sensitive Privilege Use" /failure:enable

# Windows Server 2022 must be configured to audit System - IPsec Driver failures. 
AuditPol /set /subcategory:"IPsec Driver" /failure:enable

# Windows Server 2022 must be configured to audit System - Security System Extension successes. 
AuditPol /set /subcategory:"Security System Extension" /success:enable

# Windows Server 2022 must prevent the display of slide shows on the lock screen. 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenSlideshow" -Type DWord -Value 1

# Windows Server 2022 must have WDigest Authentication disabled. 
## FAILS
New-Item -force "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest" -Type DWord -Value 0

# Windows Server 2022 Internet Protocol version 6 (IPv6) source routing must be configured to the highest protection level to prevent IP source routing. 
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Type DWord -Value 2

# Windows Server 2022 source routing must be configured to the highest protection level to prevent Internet Protocol (IP) source routing. 
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Type DWord -Value 2

# Windows Server 2022 must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF)-generated routes. 
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Type DWord -Value 0

# Windows Server 2022 must be configured to ignore NetBIOS name release requests except from WINS servers. 
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" -Name "NoNameReleaseOnDemand" -Type DWord -Value 1

# Windows Server 2022 insecure logons to an SMB server must be disabled.
## It is Disabled but the scanner does not pick it up.
### New-Item -force "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -Type DWord -Value 0
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
Set-SmbServerConfiguration -EnableSMB2Protocol $false
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB2 -Type DWORD -Value 0 -Force
Set-SmbServerConfiguration –EncryptData $true
Set-SmbServerConfiguration –RejectUnencryptedAccess $false

# Windows Server 2022 command line data must be included in process creation events. 
## New-Item -force "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ProcessCreationIncludeCmdLine_Enabled" -Type DWord -Value 1
New-Item -force "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\" -Name "ProcessCreationIncludeCmdLine_Enabled" -Type DWord -Value 1

# Windows Server 2022 must be configured to enable Remote host allows delegation of nonexportable credentials. 

# Windows Server 2022 group policy objects must be reprocessed even if they have not changed. 

# Windows Server 2022 downloading print driver packages over HTTP must be turned off. 

# Windows Server 2022 printing over HTTP must be turned off. 

# Windows Server 2022 network selection user interface (UI) must not be displayed on the logon screen. 

# Windows Server 2022 users must be prompted to authenticate when the system wakes from sleep (on battery). 

# Windows Server 2022 users must be prompted to authenticate when the system wakes from sleep (plugged in). 
# SRG-OS-000095-GPOS-00049
# Windows Server 2022 Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft. 
# SRG-OS-000368-GPOS-00154
# Windows Server 2022 Autoplay must be turned off for nonvolume devices. 
# SRG-OS-000368-GPOS-00154
# Windows Server 2022 default AutoRun behavior must be configured to prevent AutoRun commands. 
# SRG-OS-000368-GPOS-00154
# Windows Server 2022 AutoPlay must be disabled for all drives. 
# SRG-OS-000134-GPOS-00068
# Windows Server 2022 administrator accounts must not be enumerated during elevation. 
# SRG-OS-000480-GPOS-00227
# Windows Server 2022 Windows Update must not obtain updates from other PCs on the internet. 
# SRG-OS-000341-GPOS-00132
# Windows Server 2022 Application event log size must be configured to 32768 KB or greater. 
# SRG-OS-000095-GPOS-00049
# Windows Server 2022 Microsoft Defender antivirus SmartScreen must be enabled. 
# SRG-OS-000373-GPOS-00156
# Windows Server 2022 must not save passwords in the Remote Desktop Client. 
# SRG-OS-000138-GPOS-00069
# Windows Server 2022 Remote Desktop Services must prevent drive redirection. 
# SRG-OS-000373-GPOS-00156
# Windows Server 2022 Remote Desktop Services must always prompt a client for passwords upon connection. 
# SRG-OS-000033-GPOS-00014
# Windows Server 2022 Remote Desktop Services must require secure Remote Procedure Call (RPC) communications. 
# SRG-OS-000033-GPOS-00014
# Windows Server 2022 Remote Desktop Services must be configured with the client connection encryption set to High Level. 
# SRG-OS-000480-GPOS-00227
# Windows Server 2022 must prevent attachments from being downloaded from RSS feeds. 
# SRG-OS-000095-GPOS-00049
# Windows Server 2022 must prevent Indexing of encrypted files. 
# SRG-OS-000362-GPOS-00149
# Windows Server 2022 must prevent users from changing installation options. 
# SRG-OS-000362-GPOS-00149
# Windows Server 2022 must disable the Windows Installer Always install with elevated privileges option. 
# SRG-OS-000042-GPOS-00020
# Windows Server 2022 PowerShell script block logging must be enabled. 
# SRG-OS-000125-GPOS-00065
# Windows Server 2022 Windows Remote Management (WinRM) client must not use Basic authentication. 
# SRG-OS-000393-GPOS-00173
# Windows Server 2022 Windows Remote Management (WinRM) client must not allow unencrypted traffic. 
# SRG-OS-000125-GPOS-00065
# Windows Server 2022 Windows Remote Management (WinRM) client must not use Digest authentication. 
# SRG-OS-000125-GPOS-00065
# Windows Server 2022 Windows Remote Management (WinRM) service must not use Basic authentication. 
# SRG-OS-000393-GPOS-00173
# Windows Server 2022 Windows Remote Management (WinRM) service must not allow unencrypted traffic. 
# SRG-OS-000373-GPOS-00156
# Windows Server 2022 Windows Remote Management (WinRM) service must not store RunAs credentials. 
# SRG-OS-000041-GPOS-00019
# Windows Server 2022 must have PowerShell Transcription enabled. 
# SRG-OS-000379-GPOS-00164
# Windows Server 2022 must restrict unauthenticated Remote Procedure Call (RPC) clients from connecting to the RPC server on domain-joined member servers and standalone or nondomain-joined systems. 
# SRG-OS-000324-GPOS-00125
# Windows Server 2022 must restrict remote calls to the Security Account Manager (SAM) to Administrators on domain-joined member servers and standalone or nondomain-joined systems. 
# SRG-OS-000080-GPOS-00048
# Windows Server 2022 Deny log on locally user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and from unauthenticated access on all systems. 
# SRG-OS-000066-GPOS-00034
# Windows Server 2022 must have the DoD Root Certificate Authority (CA) certificates installed in the Trusted Root Store. 
# SRG-OS-000066-GPOS-00034
# Windows Server 2022 must have the DoD Interoperability Root Certificate Authority (CA) cross-certificates installed in the Untrusted Certificates Store on unclassified systems. 
# SRG-OS-000066-GPOS-00034
# Windows Server 2022 must have the US DoD CCEB Interoperability Root CA cross-certificates in the Untrusted Certificates Store on unclassified systems. 
# SRG-OS-000480-GPOS-00227
# Windows Server 2022 built-in administrator account must be renamed. 
# SRG-OS-000480-GPOS-00227
# Windows Server 2022 built-in guest account must be renamed. 
# SRG-OS-000480-GPOS-00227
# Windows Server 2022 Smart Card removal option must be configured to Force Logoff or Lock Workstation. 
# SRG-OS-000423-GPOS-00187
# Windows Server 2022 setting Microsoft network client: Digitally sign communications (always) must be configured to Enabled. 
# SRG-OS-000423-GPOS-00187
# Windows Server 2022 setting Microsoft network server: Digitally sign communications (always) must be configured to Enabled. 
# SRG-OS-000138-GPOS-00069
# Windows Server 2022 must not allow anonymous enumeration of shares. 
# SRG-OS-000480-GPOS-00227
# Windows Server 2022 must prevent NTLM from falling back to a Null session. 
# SRG-OS-000480-GPOS-00227
# Windows Server 2022 must prevent PKU2U authentication using online identities. 
# SRG-OS-000120-GPOS-00061
# Windows Server 2022 Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites. 
# SRG-OS-000480-GPOS-00227
# Windows Server 2022 LAN Manager authentication level must be configured to send NTLMv2 response only and to refuse LM and NTLM. 
# SRG-OS-000480-GPOS-00227
# Windows Server 2022 session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption. 
# SRG-OS-000478-GPOS-00223
# Windows Server 2022 must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing. 
# SRG-OS-000373-GPOS-00156
# Windows Server 2022 User Account Control (UAC) approval mode for the built-in Administrator must be enabled. 
# SRG-OS-000373-GPOS-00156
# Windows Server 2022 User Account Control (UAC) must automatically deny standard user requests for elevation. 
# SRG-OS-000080-GPOS-00048
# Windows Server 2022 Allow log on locally user right must only be assigned to the Administrators group. 
# SRG-OS-000324-GPOS-00125
# Windows Server 2022 back up files and directories user right must only be assigned to the Administrators group. 
# SRG-OS-000324-GPOS-00125
# Windows Server 2022 restore files and directories user right must only be assigned to the Administrators group. 
