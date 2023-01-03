}

Function Set-SecPol($Object, $CfgFile){
   $SecPool.psobject.Properties.GetEnumerator() | %{
        "[$($_.Name)]"
        $_.Value | %{
            $_.psobject.Properties.GetEnumerator() | %{
                "$($_.Name)=$($_.Value)"
            }
        }
    } | out-file $CfgFile -ErrorAction Stop
    secedit /configure /db c:\windows\security\local.sdb /cfg "$CfgFile" /areas SECURITYPOLICY
}


$SecPool = Parse-SecPol -CfgFile ./Test.cgf

## Update Password Policy
$SecPool.'System Access'.PasswordComplexity = 1
$SecPool.'System Access'.MinimumPasswordLength = 14
$SecPool.'System Access'.MaximumPasswordAge = 60
$SecPool.'System Access'.MinimumPasswordAge = 1
$SecPool.'System Access'.PasswordHistorySize = 24

## Account Account Policies
$SecPool.'System Access'.LockoutBadCount = 3
$SecPool.'System Access'.LockoutDuration = 15
$SecPool.'System Access'.ResetLockoutCount = 15


## Enable AUdit Events -Success and Failure
$SecPool.'Event Audit'.AuditSystemEvents=3
$SecPool.'Event Audit'.AuditLogonEvents=3
$SecPool.'Event Audit'.AuditPrivilegeUse=3
$SecPool.'Event Audit'.AuditPolicyChange=3
$SecPool.'Event Audit'.AuditAccountLogon=3
$SecPool.'Event Audit'.AuditAccountManage=3


Set-SecPol -Object $SecPool -CfgFile ./Test.cfg
