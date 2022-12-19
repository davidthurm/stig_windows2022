## ChatGPT Dec 15 2022 Version
## https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_STIGViewer_2-17_Win64.zip
## https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/scc-5.6_Windows_bundle.zip
## https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2022_V1R0-1_STIG_SCAP_1-2_DraftBenchmark.zip
## https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2022_V1R1_STIG.zip
## Server Manager add feature Group Policy Management
### Get-ChildItem -Path "C:\Windows\System32\GroupPolicy"


Import-Module GroupPolicy

# Disabling Autoplay
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoAutoplayfornonVolume -Type DWord -Value 1
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoCDBurning -Type DWord -Value 1
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoDriveTypeAutoRun -Type DWord -Value 145

# Disable the "Always install with elevated privileges"
## [Broken] Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -Type DWord -Value 0
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\ -Name MSIAlwaysInstallWithElevatedPrivileges -Type DWord -Value 0

# Windows Server 2022 Windows Remote Management (WinRM) client must not use Basic authentication.
Set-Item WSMan:\localhost\Client\Auth\Basic -Value $false

# Windows Server 2022 Windows Remote Management (WinRM) service must not use Basic authentication.
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false

# Windows Server 2022 must not allow anonymous enumeration of shares.
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -Name RestrictAnonymous -Type DWord -Value 2
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name ResetLockoutCount -Type DWord -Value 900000


# Windows Server 2022 LAN Manager authentication level must be configured to send NTLMv2 response only and to refuse LM and NTLM.
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LmCompatibilityLevel -Type DWord -Value 5

#  Windows Server 2022 account lockout duration must be configured to 15 minutes or greater.
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LockoutDuration -Type DWord -Value 900000

# Windows Server 2022 must have the number of allowed bad logon attempts configured to three or less.
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LockoutThreshold -Type DWord -Value 3

# Windows Server 2022 must have the period of time before the bad logon counter is reset configured to 15 minutes or greater.
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name ResetLockoutCount -Type DWord -Value 900000

# Windows Server 2022 password history must be configured to 24 passwords remembered.
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name PasswordHistorySize -Type DWord -Value 24

# Windows Server 2022 minimum password age must be configured to at least one day.
# Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name MinPasswordAge -Type DWord -Value 86400
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name MinPasswordAge -Type DWord -Value 14
Set-GPRegistryValue -Name "Machine" -Key "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "MinimumPasswordAge" -Type DWord -Value 14

################
# Set the minimum password age to 60 days
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "MinimumPasswordAge" -Value 60 -Type DWord

# Enable the policy
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "PasswordAgeDays" -Value 1 -Type DWord

#################


# Windows Server 2020 minimum password length must be configured to 14 characters.
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name MinPasswordLength -Type DWord -Value 14

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

###########################################
### CAUSES SCRIPT TO CRASH VIA DEFENDER ###
###########################################

# Windows Server 2022 must have WDigest Authentication disabled.
## Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Type DWord -Value 1

# Windows Server 2022 insecure logons to an SMB server must be disabled.
## Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\LanmanWorkstation\EnableInsecureGuestLogons" -Name EnableInsecureGuestLogons -Type DWord -Value 0

# Windows Server 2022 command line data must be included in process creation events.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ProcessCreationIncludeCmdLine_Enabled" -Type DWord -Value 1

#####################################################
# There isn't really a registry key fitting this. ###
#####################################################

# Windows Server 2022 must be configured to enable Remote host allows delegation of nonexportable credentials.
## Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowProtectedCreds" -Type DWord -Value 1
### Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SOFTWARE\Microsoft\PolicyManager\default\CredentialsDelegation\RemoteHostAllowsDelegationOfNonExportableCredentials" -Name "AllowProtectedCreds" -Type DWord -Value 1

###################################
### Registry Permissions Denied ###
###################################

# Windows Server 2022 group policy objects must be reprocessed even if they have not changed.
## Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoGPOListChanges" -Type DWord -Value 0
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{0ACDD40C-75AC-47ab-BAA0-BF6DE7E7FE63}" -Name "NoGPOListChanges" -Type DWord -Value 0

###########################
### Not in the registry ###
###########################

# Windows Server 2022 downloading print driver packages over HTTP must be turned off.
## Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -Type DWord -Value 1

###########################
### Not in the registry ###
###########################

# Windows Server 2022 printing over HTTP must be turned off.
## Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableHTTPPrinting" -Type DWord -Value 1

# Windows Server 2022 network selection user interface (UI) must not be displayed on the logon screen.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Type DWord -Value 1

###########################
### Not in the registry ###
###########################

# Windows Server 2022 users must be prompted to authenticate when the system wakes from sleep (on battery).
## Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name "DCSettingIndex" -Type DWord -Value 1

###########################
### Not in the registry ###
###########################

# Windows Server 2022 users must be prompted to authenticate when the system wakes from sleep (plugged in).
## Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name "ACSettingIndex" -Type DWord -Value 1

###########################
### Not in the registry ###
###########################

# Windows Server 2022 administrator accounts must not be enumerated during elevation.
## Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name "EnumerateAdministrators" -Type DWord -Value 0

######################
### This is broken ###
######################

# Windows Server 2022 Application event log size must be configured to 32768 KB or greater.
## Get-EventLog -LogName Application | Set-EventLog -MaximumSize 32768KB

####
# Windows Defender
######

# Windows Server 2022 Microsoft Defender antivirus SmartScreen must be enabled.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 1

# Windows Server 2022 must not save passwords in the Remote Desktop Client.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving" -Type DWord -Value 1

# Windows Server 2022 Remote Desktop Services must prevent drive redirection.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -Type DWord -Value 1

# Windows Server 2022 Remote Desktop Services must always prompt a client for passwords upon connection.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fPromptForPassword" -Type DWord -Value 1

# Windows Server 2022 Remote Desktop Services must require secure Remote Procedure Call (RPC) communications.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEncryptRPCTraffic" -Type DWord -Value 1

#####################################################
### Changed it to 4 from 3 to get FIPS encryption ###
#####################################################

# Windows Server 2022 Remote Desktop Services must be configured with the client connection encryption set to High Level.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel" -Type DWord -Value 4
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel" -Name "(Default)" -Type String -Value 0


###########################
### Not in the registry ###
###########################

# Windows Server 2022 must prevent attachments from being downloaded from RSS feeds.
## Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name "DisableEnclosureDownload" -Type DWord -Value 1

##################
### Start Here ###
##################

# Windows Server 2022 must prevent Indexing of encrypted files.
## Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowIndexingEncryptedStoresOrItems" -Type DWord -Value 0
## Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Search\AllowIndexingEncryptedStoresOrItems" -Name "(Default)" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Search\AllowIndexingEncryptedStoresOrItems" -Name "(Default)" -Type String -Value 0


# Windows Server 2022 must prevent users from changing installation options.
## Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "EnableUserControl" -Type DWord -Value 0

# Windows Server 2022 PowerShell script block logging must be enabled.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Type DWord -Value 1

# Windows Server 2022 Windows Remote Management (WinRM) client must not allow unencrypted traffic.
## Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowUnencryptedTraffic" -Type DWord -Value 0

# Windows Server 2022 Windows Remote Management (WinRM) client must not use Digest authentication.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest" -Type DWord -Value 0

# Windows Server 2022 Windows Remote Management (WinRM) service must not allow unencrypted traffic.
## Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic" -Type DWord -Value 0

#####
# It looks like the stig intructions are wrong here.  I added what I thought is the right command and remarked the one STIG wanted.
#####

# Windows Server 2022 Windows Remote Management (WinRM) service must not store RunAs credentials.
###  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "DisableRunAs" -Type DWord -Value 1
## Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "DisableRunAsCredSorage" -Type DWord -Value 1

# Windows Server 2022 must have PowerShell Transcription enabled.
## Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Type DWord -Value 1

# Windows Server 2022 must restrict unauthenticated Remote Procedure Call (RPC) clients from connecting to the RPC server on domain-joined member servers and standalone or nondomain-joined systems.
## Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "RestrictRemoteClients" -Type DWord -Value 1

# Windows Server 2022 must restrict remote calls to the Security Account Manager (SAM) to Administrators on domain-joined member servers and standalone or nondomain-joined systems.
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictRemoteSAM" -Type String -Value "O:BAG:BAD:(A;;RC;;;BA)"

###################################################
### This needs customization to create the GPO. ###
###################################################

###  Windows Server 2022 Deny log on locally user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and from unauthenticated access on all systems.

# Import-Module GroupPolicy
# $GPO = New-Object System.DirectoryServices.DirectoryEntry("LDAP://cn={GPO Name},cn=policies,cn=system,DC=domain,DC=com")

# $GPO.psbase.Invoke("SetSecurityDescriptorSddlForm",("O:BAG:BAD:(A;;CC;;;EA)(A;;CC;;;DA)(A;;CC;;;BA)(A;;CC;;;S-1-5-32-546)"))
# $GPO.psbase.CommitChanges()

# $GPO.psbase.Invoke("SetSecurityDescriptorSddlForm",("O:BAG:BAD:(A;;CC;;;EA)(A;;CC;;;DA)(A;;CC;;;BA)(A;;CC;;;S-1-5-32-546)(A;;CC;;;S-1-5-32-546)"))
# $GPO.psbase.CommitChanges()

# Windows Server 2022 must have the DoD Root Certificate Authority (CA) certificates installed in the Trusted Root Store.
## Download the DOD Certificates
### $certUrl = "https://dodpki.c3pki.chamb.disa.mil/rootca.p7b"
### $certificateFile = "$env:TEMP\dod_root_ca_certificates.p7b"

$certUrl = "https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/certificates_pkcs7_DoD.zip"
$certificateFile = "$env:TEMP\certificates_pkcs7_DoD.zip"

Invoke-WebRequest -Uri $certUrl -OutFile $certificateFile

## Import the certificates
Import-Certificate -FilePath $certificateFile -CertStoreLocation Cert:\LocalMachine\Root

######
### Need to verify this one.
######

# Windows Server 2022 must have the DoD Interoperability Root Certificate Authority (CA) cross-certificates installed in the Untrusted Certificates Store on unclassified systems.
## Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"} | FL Subject, Issuer, Thumbprint, NotAfter

# Windows Server 2022 must have the US DoD CCEB Interoperability Root CA cross-certificates in the Untrusted Certificates Store on unclassified systems.
# Get-ChildItem -Path Cert:Localmachine\disallowed | Where Issuer -Like "*CCEB Interoperability*" | FL Subject, Issuer, Thumbprint, NotAfter

#################################################
### This needs customization for your systems ###
#################################################

# Windows Server 2022 built-in administrator account must be renamed.
$newName = "newadmin"

Rename-LocalUser -Name "Administrator" -NewName $newName

$description = "Built-in administrator account"

Set-LocalUser -Name $newName -Description $description

# Windows Server 2022 built-in guest account must be renamed.
$newName = "newguest"

Rename-LocalUser -Name "Guest" -NewName $newName

$description = "Built-in guest account"

Set-LocalUser -Name $newName -Description $description

# Windows Server 2022 Smart Card removal option must be configured to Force Logoff or Lock Workstation.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "scremoveoption" -Type String -Value "2"

# Windows Server 2022 setting Microsoft network client: Digitally sign communications (always) must be configured to Enabled
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Type DWord -Value 1

# Windows Server 2022 must prevent NTLM from falling back to a Null session.
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" -Name "allownullsessionfallback" -Type DWord -Value 0

# Windows Server 2022 must prevent PKU2U authentication using online identities
## Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u" -Name "AllowOnlineID" -Type DWord -Value 0

######
### The STIG Suggestion is wrong.  This fixes it.
#####

# Windows Server 2022 Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.
## Set-GPRegistryValue -Name "Network security: Configure encryption types allowed for Kerberos" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -ValueName "SupportedEncryptionTypes" -Type DWORD -Value 0x80000034

# Windows Server 2022 session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption.
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinServerSec" -Type DWord -Value 0x20080000

# Windows Server 2022 must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing.
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy" -Name "Enabled" -Type DWord -Value 1

# Windows Server 2022 User Account Control (UAC) approval mode for the built-in Administrator must be enabled.
## Set-GPRegistryValue -Name "User Account Control: Admin Approval Mode for the built-in Administrator account" -Key "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "FilterAdministratorToken" -Type DWORD -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Type DWord -Value 1

# Windows Server 2022 User Account Control (UAC) must automatically deny standard user requests for elevation
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Type DWord -Value 0

# Windows Server 2022 Allow log on locally user right must only be assigned to the Administrators group.
## Add-LocalGroupMember -Group "Allow log on locally" -Member "Administrators"

#######
### This one probably doesn't work.
#########

# Windows Server 2022 back up files and directories user right must only be assigned to the Administrators group.
## Add-LocalGroupMember -Group "Back up files and directories" -Member "Administrators"

#######
### This one probably doesn't work.
#########

# Windows Server 2022 restore files and directories user right must only be assigned to the Administrators group.
## Remove-LocalGroupMember -Group "Restore files and directories" -Member "Administrators"

# Windows Server 2022 Internet Protocol version 6 (IPv6) source routing must be configured to the highest protection level to prevent IP source routing.
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Type DWord -Value 2

# Windows Server 2022 source routing must be configured to the highest protection level to prevent Internet Protocol (IP) source routing.
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -Type DWord -Value 0

# Windows Server 2022 must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF)-generated routes.
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Type DWord -Value 0

# Windows Server 2022 must be configured to ignore NetBIOS name release requests except from WINS servers.
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" -Name "NoNameReleaseOnDemand" -Type DWord -Value 1

# Windows Server 2022 Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "Inventory" -Type DWord -Value 0

# Windows Server 2022 Windows Update must not obtain updates from other PCs on the internet.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "AllowPeerToPeer" -Type DWord -Value 0
