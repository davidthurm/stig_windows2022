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
## NONE OF THESE FIXED THE SCAN
### New-Item -force "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -Type DWord -Value 0
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
Set-SmbServerConfiguration -EnableSMB1Protocol $false
Set-SmbServerConfiguration -EnableSMB2Protocol $false
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB2 -Type DWORD -Value 0 -Force
Set-SmbServerConfiguration –EncryptData $true
Set-SmbServerConfiguration –RejectUnencryptedAccess $false
Set-SmbServerConfiguration –AuditSmb1Access $true
Set-SmbClientConfiguration -EnableInsecureGuestLogons $false -Confirm:$false 
Set-SmbServerConfiguration -EncryptionCiphers "AES_128_GCM, AES_256_GCM" -Confirm:$false

# Windows Server 2022 command line data must be included in process creation events. 
## NONE OF THESE FIXED THE SCAN
New-Item -force "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ProcessCreationIncludeCmdLine_Enabled" -Type DWord -Value 1
New-Item -force "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Type Dword -Value 1

#####################################################
# Windows Server 2022 must be configured to enable Remote host allows delegation of nonexportable credentials. 
## NONE OF THESE FIXED THE SCAN
New-Item -force "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowProtectedCreds" -Type DWord -Value 1
New-Item -force "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SOFTWARE\Microsoft\PolicyManager\default\CredentialsDelegation\RemoteHostAllowsDelegationOfNonExportableCredentials" -Name "AllowProtectedCreds" -Type DWord -Value 1


# Windows Server 2022 group policy objects must be reprocessed even if they have not changed. 
## NONE OF THESE FIXED THE SCAN
New-Item -force "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoGPOListChanges" -Type DWord -Value 0

# Windows Server 2022 downloading print driver packages over HTTP must be turned off. 
## NONE OF THESE FIXED THE SCAN
New-Item -force "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -Type DWord -Value 1

# Windows Server 2022 printing over HTTP must be turned off.
## NONE OF THESE FIXED THE SCAN
New-Item -force "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableHTTPPrinting" -Type DWord -Value 1


# Windows Server 2022 network selection user interface (UI) must not be displayed on the logon screen. 
## NONE OF THESE FIXED THE SCAN
New-Item -force "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Type DWord -Value 1

# Windows Server 2022 users must be prompted to authenticate when the system wakes from sleep (on battery). 
New-Item -force "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name "DCSettingIndex" -Type DWord -Value 1
## NONE OF THESE FIXED THE SCAN

# Windows Server 2022 users must be prompted to authenticate when the system wakes from sleep (plugged in). 
## NONE OF THESE FIXED THE SCAN
New-Item -force "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name "ACSettingIndex" -Type DWord -Value 1

# Windows Server 2022 Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft. 
## NONE OF THESE FIXED THE SCAN
New-Item -force "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name "EnumerateAdministrators" -Type DWord -Value 0

# Windows Server 2022 Autoplay must be turned off for nonvolume devices. 

# Windows Server 2022 default AutoRun behavior must be configured to prevent AutoRun commands. 

# Windows Server 2022 AutoPlay must be disabled for all drives. 

# Windows Server 2022 administrator accounts must not be enumerated during elevation. 
## NONE OF THESE FIXED THE SCAN
New-Item -force "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name "EnumerateAdministrators" -Type DWord -Value 0

# Windows Server 2022 Windows Update must not obtain updates from other PCs on the internet. 

# Windows Server 2022 Application event log size must be configured to 32768 KB or greater. 

# Windows Server 2022 Microsoft Defender antivirus SmartScreen must be enabled. 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 1

###############################
### Remote Desktop Services ###
###############################

# Windows Server 2022 must not save passwords in the Remote Desktop Client. 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving" -Type DWord -Value 1

# Windows Server 2022 Remote Desktop Services must prevent drive redirection. 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -Type DWord -Value 1

# Windows Server 2022 Remote Desktop Services must always prompt a client for passwords upon connection. 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fPromptForPassword" -Type DWord -Value 1

# Windows Server 2022 Remote Desktop Services must require secure Remote Procedure Call (RPC) communications. 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEncryptRPCTraffic" -Type DWord -Value 1

# Windows Server 2022 Remote Desktop Services must be configured with the client connection encryption set to High Level. 
## NONE OF THESE FIXED THE SCAN
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel" -Type DWord -Value 4

# Windows Server 2022 must prevent attachments from being downloaded from RSS feeds. 
## NONE OF THESE FIXED THE SCAN
New-Item -force "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name "DisableEnclosureDownload" -Type DWord -Value 1

# Windows Server 2022 must prevent Indexing of encrypted files. 
## NONE OF THESE FIXED THE SCAN
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Search\AllowIndexingEncryptedStoresOrItems" -Name "(Default)" -Type String -Value 0


# Windows Server 2022 must prevent users from changing installation options. 
## NONE OF THESE FIXED THE SCAN
New-Item -force "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "EnableUserControl" -Type DWord -Value 0

# Windows Server 2022 must disable the Windows Installer Always install with elevated privileges option. 

# Windows Server 2022 PowerShell script block logging must be enabled. 
## NONE OF THESE FIXED THE SCAN
New-Item -force "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Type DWord -Value 1

#########################################
### Windows Remote Management (WinRM) ###
#########################################

# Windows Server 2022 Windows Remote Management (WinRM) client must not use Basic authentication. 
## NONE OF THESE FIXED THE SCAN
### Check the config:  winrm get winrm/config/client/auth
winrm set WinRM/Config/Client/Auth '@{Basic="false";Digest="false";Kerberos="false";Negotiate="true";Certificate="true";CredSSP="false"}'
winrm get winrm/config/client/auth

# Windows Server 2022 Windows Remote Management (WinRM) client must not allow unencrypted traffic. 
## Set Above 

# Windows Server 2022 Windows Remote Management (WinRM) client must not use Digest authentication. 
## Set Above 

# Windows Server 2022 Windows Remote Management (WinRM) service must not allow unencrypted traffic. 
## Set Above 

# Windows Server 2022 Windows Remote Management (WinRM) service must not store RunAs credentials. 
## NONE OF THESE FIXED THE SCAN
New-Item -force "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "DisableRunAs" -Type DWord -Value 1
New-Item -force "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "DisableRunAsCredSorage" -Type DWord -Value 1

##########################################
# Windows Server 2022 must have PowerShell Transcription enabled.
## NONE OF THESE FIXED THE SCAN
New-Item -force "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Type DWord -Value 1

# Windows Server 2022 must restrict unauthenticated Remote Procedure Call (RPC) clients from connecting to the RPC server on domain-joined member servers and standalone or nondomain-joined systems. 
## NONE OF THESE FIXED THE SCAN
New-Item -force "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "RestrictRemoteClients" -Type DWord -Value 1

# Windows Server 2022 must restrict remote calls to the Security Account Manager (SAM) to Administrators on domain-joined member servers and standalone or nondomain-joined systems. 
## NONE OF THESE FIXED THE SCAN
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictRemoteSAM" -Type String -Value "O:BAG:BAD:(A;;RC;;;BA)"

# Windows Server 2022 Deny log on locally user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and from unauthenticated access on all systems. 

# Windows Server 2022 must have the DoD Root Certificate Authority (CA) certificates installed in the Trusted Root Store. 

# $certUrl = "https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/certificates_pkcs7_DoD.zip"
# $certificateFile = "$env:TEMP\certificates_pkcs7_DoD.zip"

# Invoke-WebRequest -Uri $certUrl -OutFile $certificateFile

# ## Import the certificates
# Import-Certificate -FilePath $certificateFile -CertStoreLocation Cert:\LocalMachine\Root


# # Windows Server 2022 must have the DoD Interoperability Root Certificate Authority (CA) cross-certificates installed in the Untrusted Certificates Store on unclassified systems. 

# # Windows Server 2022 must have the US DoD CCEB Interoperability Root CA cross-certificates in the Untrusted Certificates Store on unclassified systems. 

# # Windows Server 2022 built-in administrator account must be renamed. 
# $newName = "root"

# Rename-LocalUser -Name "Administrator" -NewName $newName

# $description = "administrator account"

# Set-LocalUser -Name $newName -Description $description

# # Windows Server 2022 built-in guest account must be renamed.
# $newName = "newguest"

# Rename-LocalUser -Name "Guest" -NewName $newName

# $description = "guest account"

# Set-LocalUser -Name $newName -Description $description

# Windows Server 2022 Smart Card removal option must be configured to Force Logoff or Lock Workstation. 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "scremoveoption" -Type String -Value "2"

# Windows Server 2022 setting Microsoft network client: Digitally sign communications (always) must be configured to Enabled. 
## NONE OF THESE FIXED THE SCAN
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Type DWord -Value 1

# Windows Server 2022 must not allow anonymous enumeration of shares. 

# Windows Server 2022 must prevent NTLM from falling back to a Null session. 
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" -Name "allownullsessionfallback" -Type DWord -Value 0

# Windows Server 2022 must prevent PKU2U authentication using online identities. 
## NONE OF THESE FIXED THE SCAN
New-Item -force "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u" -Name "AllowOnlineID" -Type DWord -Value 0

# Windows Server 2022 Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites. 

# Windows Server 2022 LAN Manager authentication level must be configured to send NTLMv2 response only and to refuse LM and NTLM. 

# Windows Server 2022 session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption. 
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinServerSec" -Type DWord -Value 0x20080000

# Windows Server 2022 must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing. 
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy" -Name "Enabled" -Type DWord -Value 1

# Windows Server 2022 User Account Control (UAC) approval mode for the built-in Administrator must be enabled. 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Type DWord -Value 1

# Windows Server 2022 User Account Control (UAC) must automatically deny standard user requests for elevation. 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Type DWord -Value 0

# Windows Server 2022 Allow log on locally user right must only be assigned to the Administrators group. 

# Windows Server 2022 back up files and directories user right must only be assigned to the Administrators group. 

# Windows Server 2022 restore files and directories user right must only be assigned to the Administrators group. 


Stop-Transcript
