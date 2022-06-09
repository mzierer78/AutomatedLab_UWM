# Create Lab Environment for Ivanti Advantage Learning Course "User Workspace Management"
#region Define Variables
#Lab related Variables
$TestLabAdminUser = "Administrator"
$TestLabAdminPassword = "Pa55word"
$TestLabDomain = "FBN.local"
$TestLabName = "UWM"
$TestLabSecUser = "FBN\Administrator"
$TestLabSecPwd = "Pa55word"
$TestLabVMPath = "C:\TestLabs\UWM"

#Network related Variables
#$TestLabIPScope = "192.168.12.0/24"
#$TestLabDHCPScope = "192.168.12.0"
#$TestLabDHCPScopeStart = "192.168.12.50"
#$TestLabDHCPScopeEnd = "192.168.12.60"
#$TestLabDHCPScopeMask = "255.255.255.0"
#$TestLabDHCPScopeDNSSRV = "192.168.12.3"

#endregion

#Define TestLab
New-LabDefinition -Name UWM -DefaultVirtualizationEngine HyperV -VmPath C:\TestLabs\UWM

#Define TestLab Settings
Add-LabDomainDefinition -Name FBN.local -AdminUser Administrator -AdminPassword Pa55word
Set-LabInstallationCredential -Username Administrator -Password Pa55word
Add-LabIsoImageDefinition -Name SQLServer2016 -Path $LabSources\ISOs\en_sql_server_2016_standard_with_service_pack_1_x64_dvd_9540929.iso

#create DC
Add-LabMachineDefinition -Name DC01 -OperatingSystem 'Windows Server 2019 STANDARD (Desktop Experience)' -Roles RootDC -DomainName FBN.local

#create Memberserver
Add-LabMachineDefinition -Name SERVER01 -OperatingSystem 'Windows Server 2019 STANDARD (Desktop Experience)' -Roles SQLServer2016 -DomainName FBN.local -Memory 2GB -MinMemory 512MB -MaxMemory 4GB
Add-LabMachineDefinition -Name TS01 -OperatingSystem 'Windows Server 2019 STANDARD (Desktop Experience)' -DomainName FBN.local
Add-LabMachineDefinition -Name PC01 -OperatingSystem 'Windows 8.1 Pro' -DomainName FBN.local
Add-LabMachineDefinition -Name PC10 -OperatingSystem 'Windows 10 Enterprise' -DomainName FBN.local

#Ensure Windows Defender does not slow down LAB build
Write-ScreenInfo -Message 'Setting Windows Defender Exclusions'
Set-MpPreference -ExclusionProcess dism.exe,code.exe,powershell.exe

#start building lab
Install-Lab

#region Actions for DC01
#Install software
Install-LabSoftwarePackage -ComputerName DC01 -Path $labSources\SoftwarePackages\FirefoxSetup78.4.1esr.msi -CommandLine /qn

#Create Shared Printers
Invoke-LabCommand -ActivityName "Add Printer Driver" -ComputerName DC01 -ScriptBlock {
    Add-PrinterDriver -Name "Generic / Text Only"
} -Credential $creds

Invoke-LabCommand -ActivityName "Add Printer FinancePrinter1" -ComputerName DC01 -ScriptBlock {
    Add-Printer -Name "FinancePrinter1" -DriverName "Generic / Text Only" -PortName "FILE:" -Shared
} -Credential $creds

Invoke-LabCommand -ActivityName "Add Printer FinancePrinter2" -ComputerName DC01 -ScriptBlock {
    Add-Printer -Name "FinancePrinter2" -DriverName "Generic / Text Only" -PortName "FILE:" -Shared
} -Credential $creds

Invoke-LabCommand -ActivityName "Add Printer HRPrinter1" -ComputerName DC01 -ScriptBlock {
    Add-Printer -Name "HRPrinter1" -DriverName "Generic / Text Only" -PortName "FILE:" -Shared
} -Credential $creds

#Prepare AD Credentials
$secpasswd = ConvertTo-SecureString Pa55word -AsPlainText -Force
$secuser = "FBN\Administrator"
$creds = New-Object System.Management.Automation.PSCredential ($secuser, $secpasswd)

#Create AD OU's
Invoke-LabCommand -ActivityName "Add OU Test" -ComputerName DC01 -ScriptBlock {
    New-ADOrganizationalUnit -Name "Test" -Path "DC=FBN,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds

Invoke-LabCommand -ActivityName "Add OU Accounts" -ComputerName DC01 -ScriptBlock {
    New-ADOrganizationalUnit -Name "Accounts" -Path "OU=Test,DC=FBN,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds

Invoke-LabCommand -ActivityName "Add OU Finance" -ComputerName DC01 -ScriptBlock {
    New-ADOrganizationalUnit -Name "Finance" -Path "OU=Accounts,OU=Test,DC=FBN,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds

Invoke-LabCommand -ActivityName "Add OU HR" -ComputerName DC01 -ScriptBlock {
    New-ADOrganizationalUnit -Name "HR" -Path "OU=Accounts,OU=Test,DC=FBN,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds

Invoke-LabCommand -ActivityName "Add OU Windows 8.1" -ComputerName DC01 -ScriptBlock {
    New-ADOrganizationalUnit -Name "Windows 8.1" -Path "OU=Test,DC=FBN,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds

Invoke-LabCommand -ActivityName "Add OU Windows 10" -ComputerName DC01 -ScriptBlock {
    New-ADOrganizationalUnit -Name "Windows 10" -Path "OU=Test,DC=FBN,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds

Invoke-LabCommand -ActivityName "Add OU TS" -ComputerName DC01 -ScriptBlock {
    New-ADOrganizationalUnit -Name "TS" -Path "OU=Test,DC=FBN,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds

#Move Computers to OU's
Invoke-LabCommand -ActivityName "Move PC01" -ComputerName DC01 -ScriptBlock {
    Move-ADObject -Identity "CN=PC01,CN=Computers,DC=FBN,DC=local" -TargetPath "OU=Windows 8.1,OU=Test,DC=FBN,DC=local"
} -Credential $creds

Invoke-LabCommand -ActivityName "Move PC10" -ComputerName DC01 -ScriptBlock {
    Move-ADObject -Identity "CN=PC10,CN=Computers,DC=FBN,DC=local" -TargetPath "OU=Windows 10,OU=Test,DC=FBN,DC=local"
} -Credential $creds

Invoke-LabCommand -ActivityName "Move TS01" -ComputerName DC01 -ScriptBlock {
    Move-ADObject -Identity "CN=TS01,CN=Computers,DC=FBN,DC=local" -TargetPath "OU=TS,OU=Test,DC=FBN,DC=local"
} -Credential $creds

#create additional users
Invoke-LabCommand -ActivityName "CreateUser SQL-Creator" -ComputerName DC01 -ScriptBlock {
    Import-Module ActiveDirectory
    $secpwd = ConvertTo-SecureString "Pa55word" -AsPlainText -Force
    New-ADUser -Name SQL-Creator -AccountPassword $secpwd -Enabled $true -ChangePasswordAtLogon $false
} -Credential $creds

Invoke-LabCommand -ActivityName "CreateUser SQL-Acct" -ComputerName DC01 -ScriptBlock {
    Import-Module ActiveDirectory
    $secpwd = ConvertTo-SecureString "Pa55word" -AsPlainText -Force
    New-ADUser -Name SQL-Acct -AccountPassword $secpwd -Enabled $true -ChangePasswordAtLogon $false
} -Credential $creds

Invoke-LabCommand -ActivityName "CreateUser Support1" -ComputerName DC01 -ScriptBlock {
    Import-Module ActiveDirectory
    $secpwd = ConvertTo-SecureString "Pa55word" -AsPlainText -Force
    New-ADUser -Name Support1 -AccountPassword $secpwd -Enabled $true -ChangePasswordAtLogon $false
} -Credential $creds

Invoke-LabCommand -ActivityName "CreateUser Support2" -ComputerName DC01 -ScriptBlock {
    Import-Module ActiveDirectory
    $secpwd = ConvertTo-SecureString "Pa55word" -AsPlainText -Force
    New-ADUser -Name Support2 -AccountPassword $secpwd -Enabled $true -ChangePasswordAtLogon $false
} -Credential $creds

Invoke-LabCommand -ActivityName "CreateUser JTester" -ComputerName DC01 -ScriptBlock {
    Import-Module ActiveDirectory
    $secpwd = ConvertTo-SecureString "Pa55word" -AsPlainText -Force
    New-ADUser -Name JTester -AccountPassword $secpwd -Enabled $true -ChangePasswordAtLogon $false
} -Credential $creds

Invoke-LabCommand -ActivityName "CreateUser Finance1" -ComputerName DC01 -ScriptBlock {
    Import-Module ActiveDirectory
    $secpwd = ConvertTo-SecureString "Pa55word" -AsPlainText -Force
    New-ADUser -Name Finance1 -AccountPassword $secpwd -Enabled $true -ChangePasswordAtLogon $false
} -Credential $creds

Invoke-LabCommand -ActivityName "CreateUser HR1" -ComputerName DC01 -ScriptBlock {
    Import-Module ActiveDirectory
    $secpwd = ConvertTo-SecureString "Pa55word" -AsPlainText -Force
    New-ADUser -Name HR1 -AccountPassword $secpwd -Enabled $true -ChangePasswordAtLogon $false
} -Credential $creds

#Create AD Groups
Invoke-LabCommand -ActivityName "Create Group Finance" -ComputerName DC01 -ScriptBlock {
    New-ADObject -Name "Finance" -Type Group -Path "OU=Finance,OU=Accounts,OU=Test,DC=FBN,DC=LOCAL"
} -Credential $creds

Invoke-LabCommand -ActivityName "Add Members to Group Finance" -ComputerName DC01 -ScriptBlock {
    Add-ADGroupMember -Identity "CN=Finance,OU=Finance,OU=Accounts,OU=Test,DC=FBN,DC=LOCAL" -Members Finance1
} -Credential $creds

Invoke-LabCommand -ActivityName "Create Group HR" -ComputerName DC01 -ScriptBlock {
    New-ADObject -Name "HR" -Type Group -Path "OU=HR,OU=Accounts,OU=Test,DC=FBN,DC=LOCAL"
} -Credential $creds

Invoke-LabCommand -ActivityName "Add Members to Group HR" -ComputerName DC01 -ScriptBlock {
    Add-ADGroupMember -Identity "CN=HR,OU=HR,OU=Accounts,OU=Test,DC=FBN,DC=LOCAL" -Members HR1
} -Credential $creds
#endregion

#region Actions for SERVER01
#Install software
Install-LabSoftwarePackage -ComputerName SERVER01 -Path $labSources\SoftwarePackages\GoogleChromeStandaloneEnterprise64.msi -CommandLine /qn

#Populate local Administrators
Invoke-LabCommand -ActivityName "Add SQL-Creator to Administrators" -ComputerName SERVER01 -ScriptBlock {
    Add-LocalGroupMember -Group "Administrators" -Member "FBN\SQL-Creator"
} -Credential $creds

#Create additional Folders
Invoke-LabCommand -ActivityName "CreateFolder Home" -ComputerName SERVER01 -ScriptBlock {
    New-Item -Path C:\ -Name Home -ItemType Directory
} -Credential $creds

#Copy files
Write-ScreenInfo -Message 'Copying files to SERVER01' -TaskStart
Write-ProgressIndicator
Copy-LabFileItem -Path $LabSources\Labs\UWM\User_Workspace_Manager -ComputerName SERVER01 -DestinationFolderPath C:\PostInstall
Copy-LabFileItem -Path $LabSources\Labs\UWM\License -ComputerName SERVER01 -DestinationFolderPath C:\PostInstall
Copy-LabFileItem -Path $LabSources\Labs\UWM\Module3 -ComputerName SERVER01 -DestinationFolderPath C:\PostInstall
Copy-LabFileItem -Path $LabSources\Labs\UWM\Resources -ComputerName SERVER01 -DestinationFolderPath C:\
Copy-LabFileItem -Path $LabSources\Labs\UWM\Wallpapers -ComputerName SERVER01 -DestinationFolderPath C:\PostInstall
Write-ProgressIndicatorEnd
Write-ScreenInfo -Message 'File copy finished' -TaskEnd

#Create Shares
Invoke-LabCommand -ActivityName "CreateShare Home" -ComputerName SERVER01 -ScriptBlock {
    New-SmbShare -Name "Home" -Path "C:\Home" -FullAccess "EVERYONE"
} -Credential $creds

Invoke-LabCommand -ActivityName "CreateShare PostInstall" -ComputerName SERVER01 -ScriptBlock {
    New-SmbShare -Name "PostInstall" -Path "C:\PostInstall" -FullAccess "EVERYONE"
} -Credential $creds

Invoke-LabCommand -ActivityName "CreateShare Resources" -ComputerName SERVER01 -ScriptBlock {
    New-SmbShare -Name "Resources" -Path "C:\Resources" -FullAccess "EVERYONE"
} -Credential $creds
#endregion

#region Actions for PC01
#Copy files
Write-ScreenInfo -Message 'Copying files to PC01' -TaskStart
Write-ProgressIndicator
Copy-LabFileItem -Path $LabSources\SoftwarePackages\Office2010ProPlusx86ENU -ComputerName PC01 -DestinationFolderPath C:\PostInstall
Copy-LabFileItem -Path $LabSources\Labs\UWM\Wallpapers -ComputerName PC01 -DestinationFolderPath C:\PostInstall
Copy-LabFileItem -Path $LabSources\Labs\UWM\Module5 -ComputerName PC01 -DestinationFolderPath C:\PostInstall
Copy-LabFileItem -Path $LabSources\Labs\UWM\Module6 -ComputerName PC01 -DestinationFolderPath C:\PostInstall
Write-ProgressIndicatorEnd
Write-ScreenInfo -Message 'File copy finished' -TaskEnd

#Install software
Install-LabSoftwarePackage -ComputerName PC01 -Path $labSources\SoftwarePackages\ndp48-x86-x64-allos-enu.exe -CommandLine /quiet
Install-LabSoftwarePackage -ComputerName PC01 -Path $labSources\SoftwarePackages\GoogleChromeStandaloneEnterprise64.msi -CommandLine /qn
Install-LabSoftwarePackage -ComputerName PC01 -Path $labSources\SoftwarePackages\FirefoxSetup78.4.1esr.msi -CommandLine /qn
Install-LabSoftwarePackage -ComputerName PC01 -Path $labSources\SoftwarePackages\FoxitReader101_enu_Setup.msi -CommandLine /qn
Write-ScreenInfo -Message 'Installing Office 2010' -TaskStart
Install-LabSoftwarePackage -ComputerName PC01 -LocalPath C:\PostInstall\Office2010ProPlusx86ENU\setup.exe
Write-ScreenInfo -Message 'Installing Office 2010 done'
#endregion

#region Actions for PC10
#Copy files
Write-ScreenInfo -Message 'Copying files to PC10' -TaskStart
Write-ProgressIndicator
Copy-LabFileItem -Path $LabSources\SoftwarePackages\Office2013ProPlusx86ENU -ComputerName PC10 -DestinationFolderPath C:\PostInstall
Copy-LabFileItem -Path $LabSources\Labs\UWM\Wallpapers -ComputerName PC10 -DestinationFolderPath C:\PostInstall
Write-ProgressIndicatorEnd
Write-ScreenInfo -Message 'File copy finished' -TaskEnd

#Install software
Install-LabSoftwarePackage -ComputerName PC10 -Path $labSources\SoftwarePackages\FirefoxSetup78.4.1esr.msi -CommandLine /qn
Install-LabSoftwarePackage -ComputerName PC10 -Path $labSources\SoftwarePackages\GoogleChromeStandaloneEnterprise64.msi -CommandLine /qn
Install-LabSoftwarePackage -ComputerName PC10 -Path $labSources\SoftwarePackages\FoxitReader101_enu_Setup.msi -CommandLine /qn
Write-ScreenInfo -Message 'Installing Office 2013' -TaskStart
Install-LabSoftwarePackage -ComputerName PC10 -LocalPath C:\PostInstall\Office2013ProPlusx86ENU\setup.exe
Write-ScreenInfo -Message 'Installing Office 2013 done'
#endregion

#region Actions for TS01
#Copy files
Write-ScreenInfo -Message 'Copying files to TS01' -TaskStart
Write-ProgressIndicator
Copy-LabFileItem -Path $LabSources\SoftwarePackages\Office2010ProPlusx86ENU -ComputerName TS01 -DestinationFolderPath C:\PostInstall
Copy-LabFileItem -Path $LabSources\Labs\UWM\Wallpapers -ComputerName TS01 -DestinationFolderPath C:\PostInstall
Write-ProgressIndicatorEnd
Write-ScreenInfo -Message 'File copy finished' -TaskEnd

#Install software
Install-LabSoftwarePackage -ComputerName TS01 -Path $labSources\SoftwarePackages\GoogleChromeStandaloneEnterprise64.msi -CommandLine /qn
Install-LabSoftwarePackage -ComputerName TS01 -Path $labSources\SoftwarePackages\FirefoxSetup78.4.1esr.msi -CommandLine /qn
Install-LabSoftwarePackage -ComputerName TS01 -Path $labSources\SoftwarePackages\FoxitReader101_enu_Setup.msi -CommandLine /qn
Write-ScreenInfo -Message 'Installing Office 2010' -TaskStart
Install-LabSoftwarePackage -ComputerName TS01 -LocalPath C:\PostInstall\Office2010ProPlusx86ENU\setup.exe
Write-ScreenInfo -Message 'Installing Office 2010 done'
#endregion

#Post Installation tasks
Write-ScreenInfo -Message 'Disable AutoLogon & Reboot Machines'
Disable-LabAutoLogon -ComputerName DC01,SERVER01,TS01,PC01,PC10
Restart-LabVM -ComputerName DC01,SERVER01,TS01,PC01,PC10

Write-ScreenInfo -Message 'Removing Windows Defender Exclusions'
Remove-MpPreference -ExclusionProcess code.exe,powershell.exe

Show-LabDeploymentSummary 