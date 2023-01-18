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

#region AutomatedLab Actions
#Copy ISO Files to C:\Labsources\ISOs
Write-ScreenInfo -Message 'Copying required ISO Files to C:\LabSources\ISOs Folder'
#hier variable einsetzen
robocopy.exe "C:\LabSources\Labs\$TestLabName\ISO" 'C:\LabSources\ISOs'

#Define TestLab
New-LabDefinition -Name $TestLabName -DefaultVirtualizationEngine HyperV -VmPath $TestLabVMPath -ReferenceDiskSizeInGB 100

#Define TestLab Settings
Add-LabDomainDefinition -Name $TestLabDomain -AdminUser $TestLabAdminUser -AdminPassword $TestLabAdminPassword
Add-LabVirtualNetworkDefinition -Name $TestLabName -AddressSpace $TestLabIPScope
Set-LabInstallationCredential -Username $TestLabAdminUser -Password $TestLabAdminPassword

#prepare lab computer names
#$DC = $TestLabName + "DC01"
#$SRV01 = $TestLabName + "FS01"
#$PC01 = $TestLabName + "W10"
#$PC02 = $TestLabName + "W701"
$DC = "DC01"
$SRV01 = "Server01"
$PC01 = "TS01"
$PC02 = "PC10"
$PC03 = "PC11"

#create DC
Add-LabMachineDefinition -Name $DC -OperatingSystem 'Windows Server 2019 STANDARD (Desktop Experience)' -Roles RootDC -DomainName $TestLabDomain -TimeZone "W. Europe Standard Time"

#create Memberserver
Add-LabMachineDefinition -Name $SRV01 -OperatingSystem 'Windows Server 2019 STANDARD (Desktop Experience)' -DomainName $TestLabDomain -TimeZone "W. Europe Standard Time" -Memory 2GB -MinMemory 512MB -MaxMemory 8GB -Processors 4
Add-LabMachineDefinition -Name $PC01 -OperatingSystem 'Windows Server 2019 STANDARD (Desktop Experience)' -DomainName $TestLabDomain -TimeZone "W. Europe Standard Time" -Memory 1GB -MinMemory 512MB -MaxMemory 2GB
Add-LabMachineDefinition -Name $PC02 -OperatingSystem 'Windows 10 Enterprise' -DomainName $TestLabDomain -TimeZone "W. Europe Standard Time" -Memory 1GB -MinMemory 512MB -MaxMemory 2GB
Add-LabMachineDefinition -Name $PC03 -OperatingSystem 'Windows 11 Enterprise' -DomainName $TestLabDomain -TimeZone "W. Europe Standard Time" -Memory 1GB -MinMemory 512MB -MaxMemory 2GB

#Ensure Windows Defender does not slow down LAB build
Write-ScreenInfo -Message 'Setting Windows Defender Exclusions'
Set-MpPreference -ExclusionProcess dism.exe,code.exe,powershell.exe,powershell_ise.exe

#start building lab
Install-Lab

#endregion

#region Actions for Domain Controller ($DC)
Write-ScreenInfo -Message "Starting Actions for $DC"
#Prepare AD Credentials
$secpasswd = ConvertTo-SecureString $TestLabSecPwd -AsPlainText -Force
$secuser = $TestLabSecUser
$creds = New-Object System.Management.Automation.PSCredential ($secuser, $secpasswd)

#Create AD OU's
Write-ScreenInfo -Message "start creating OU's"
$TestLabName = 'Test'
$TestLabDomainName = 'FBN'
Invoke-LabCommand -ActivityName "Add OU $TestLabName" -ComputerName $DC -ScriptBlock {
    New-ADOrganizationalUnit -Name "$TestLabName" -Path "DC=$TestLabDomainName,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds -Variable (Get-Variable -Name TestLabName),(Get-Variable -Name TestLabDomainName)

$TestLabOUName = 'Accounts'
Invoke-LabCommand -ActivityName "Add OU $TestLabOUName" -ComputerName $DC -ScriptBlock {
    New-ADOrganizationalUnit -Name $TestLabOUName -Path "OU=$TestLabName,DC=$TestLabDomainName,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds -Variable (Get-Variable -Name TestLabOUName),(Get-Variable -Name TestLabName),(Get-Variable -Name TestLabDomainName)
Remove-Variable -Name TestLabOUName

$TestLabOUName = 'Finance'
Invoke-LabCommand -ActivityName "Add OU $TestLabOUName" -ComputerName $DC -ScriptBlock {
    New-ADOrganizationalUnit -Name $TestLabOUName -Path "OU=$TestLabName,DC=$TestLabDomainName,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds -Variable (Get-Variable -Name TestLabOUName),(Get-Variable -Name TestLabName),(Get-Variable -Name TestLabDomainName)
Remove-Variable -Name TestLabOUName

$TestLabOUName = 'HR'
Invoke-LabCommand -ActivityName "Add OU $TestLabOUName" -ComputerName $DC -ScriptBlock {
    New-ADOrganizationalUnit -Name $TestLabOUName -Path "OU=$TestLabName,DC=$TestLabDomainName,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds -Variable (Get-Variable -Name TestLabOUName),(Get-Variable -Name TestLabName),(Get-Variable -Name TestLabDomainName)
Remove-Variable -Name TestLabOUName

$TestLabOUName = 'Windows 10'
Invoke-LabCommand -ActivityName "Add OU $TestLabOUName" -ComputerName $DC -ScriptBlock {
    New-ADOrganizationalUnit -Name $TestLabOUName -Path "OU=$TestLabName,DC=$TestLabDomainName,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds -Variable (Get-Variable -Name TestLabOUName),(Get-Variable -Name TestLabName),(Get-Variable -Name TestLabDomainName)
Remove-Variable -Name TestLabOUName

$TestLabOUName = 'Windows 11'
Invoke-LabCommand -ActivityName "Add OU $TestLabOUName" -ComputerName $DC -ScriptBlock {
    New-ADOrganizationalUnit -Name $TestLabOUName -Path "OU=$TestLabName,DC=$TestLabDomainName,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds -Variable (Get-Variable -Name TestLabOUName),(Get-Variable -Name TestLabName),(Get-Variable -Name TestLabDomainName)
Remove-Variable -Name TestLabOUName

$TestLabOUName = 'TS'
Invoke-LabCommand -ActivityName "Add OU $TestLabOUName" -ComputerName $DC -ScriptBlock {
    New-ADOrganizationalUnit -Name $TestLabOUName -Path "OU=$TestLabName,DC=$TestLabDomainName,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds -Variable (Get-Variable -Name TestLabOUName),(Get-Variable -Name TestLabName),(Get-Variable -Name TestLabDomainName)
Remove-Variable -Name TestLabOUName

Write-ScreenInfo -Message "creating OU's finished"

#Move Computers to OU's
Write-Screeninfo -Message "start moving Computers"

$Identity = "CN=$PC01,CN=Computers,DC=$TestLabDomainName,DC=local"
$TargetPath = "OU=TS,OU=$TestLabName,DC=$TestLabDomainName,DC=local"
Invoke-LabCommand -ActivityName "Move $Identity to $TargetPath" -ComputerName $DC -ScriptBlock {
    Move-ADObject -Identity $Identity -TargetPath $TargetPath
} -Credential $creds -Variable (Get-Variable -Name Identity),(Get-Variable -Name TargetPath)
Remove-Variable -Name Identity
Remove-Variable -Name TargetPath

$Identity = "CN=$PC02,CN=Computers,DC=$TestLabDomainName,DC=local"
$TargetPath = "OU=Windows 10,OU=$TestLabName,DC=$TestLabDomainName,DC=local"
Invoke-LabCommand -ActivityName "Move $Identity to $TargetPath" -ComputerName $DC -ScriptBlock {
    Move-ADObject -Identity $Identity -TargetPath $TargetPath
} -Credential $creds -Variable (Get-Variable -Name Identity),(Get-Variable -Name TargetPath)
Remove-Variable -Name Identity
Remove-Variable -Name TargetPath

$Identity = "CN=$PC03,CN=Computers,DC=$TestLabDomainName,DC=local"
$TargetPath = "OU=Windows 11,OU=$TestLabName,DC=$TestLabDomainName,DC=local"
Invoke-LabCommand -ActivityName "Move $Identity to $TargetPath" -ComputerName $DC -ScriptBlock {
    Move-ADObject -Identity $Identity -TargetPath $TargetPath
} -Credential $creds -Variable (Get-Variable -Name Identity),(Get-Variable -Name TargetPath)
Remove-Variable -Name Identity
Remove-Variable -Name TargetPath

Write-ScreenInfo -Message "end moving computers"

#create additional users
Write-ScreenInfo -Message "start creating Users"

$Pwd = 'Pa55word'
$User = 'SQL-Creator'
Invoke-LabCommand -ActivityName "CreateUser $User" -ComputerName $DC -ScriptBlock {
    Import-Module ActiveDirectory
    $secpwd = ConvertTo-SecureString $Pwd -AsPlainText -Force
    New-ADUser -Name $User -AccountPassword $secpwd -Enabled $true -ChangePasswordAtLogon $false
} -Credential $creds -Variable (Get-Variable -Name User),(Get-Variable -Name Pwd)
Remove-Variable -Name User

$User = 'SQL-Acct'
Invoke-LabCommand -ActivityName "CreateUser $User" -ComputerName $DC -ScriptBlock {
    Import-Module ActiveDirectory
    $secpwd = ConvertTo-SecureString $Pwd -AsPlainText -Force
    New-ADUser -Name $User -AccountPassword $secpwd -Enabled $true -ChangePasswordAtLogon $false
} -Credential $creds -Variable (Get-Variable -Name User),(Get-Variable -Name Pwd)
Remove-Variable -Name User

$User = 'Support1'
Invoke-LabCommand -ActivityName "CreateUser $User" -ComputerName $DC -ScriptBlock {
    Import-Module ActiveDirectory
    $secpwd = ConvertTo-SecureString $Pwd -AsPlainText -Force
    New-ADUser -Name $User -AccountPassword $secpwd -Enabled $true -ChangePasswordAtLogon $false
} -Credential $creds -Variable (Get-Variable -Name User),(Get-Variable -Name Pwd)
Remove-Variable -Name User

$User = 'Support2'
Invoke-LabCommand -ActivityName "CreateUser $User" -ComputerName $DC -ScriptBlock {
    Import-Module ActiveDirectory
    $secpwd = ConvertTo-SecureString $Pwd -AsPlainText -Force
    New-ADUser -Name $User -AccountPassword $secpwd -Enabled $true -ChangePasswordAtLogon $false
} -Credential $creds -Variable (Get-Variable -Name User),(Get-Variable -Name Pwd)
Remove-Variable -Name User

$User = 'JTester'
Invoke-LabCommand -ActivityName "CreateUser $User" -ComputerName $DC -ScriptBlock {
    Import-Module ActiveDirectory
    $secpwd = ConvertTo-SecureString $Pwd -AsPlainText -Force
    New-ADUser -Name $User -AccountPassword $secpwd -Enabled $true -ChangePasswordAtLogon $false
} -Credential $creds -Variable (Get-Variable -Name User),(Get-Variable -Name Pwd)
Remove-Variable -Name User

$User = 'Finance1'
Invoke-LabCommand -ActivityName "CreateUser $User" -ComputerName $DC -ScriptBlock {
    Import-Module ActiveDirectory
    $secpwd = ConvertTo-SecureString $Pwd -AsPlainText -Force
    New-ADUser -Name $User -AccountPassword $secpwd -Enabled $true -ChangePasswordAtLogon $false
} -Credential $creds -Variable (Get-Variable -Name User),(Get-Variable -Name Pwd)
Remove-Variable -Name User

$User = 'HR1'
Invoke-LabCommand -ActivityName "CreateUser $User" -ComputerName $DC -ScriptBlock {
    Import-Module ActiveDirectory
    $secpwd = ConvertTo-SecureString $Pwd -AsPlainText -Force
    New-ADUser -Name $User -AccountPassword $secpwd -Enabled $true -ChangePasswordAtLogon $false
} -Credential $creds -Variable (Get-Variable -Name User),(Get-Variable -Name Pwd)
Remove-Variable -Name User


#Install software
Install-LabSoftwarePackage -ComputerName $DC -Path $labSources\Labs\UWM\SoftwarePackages\MicrosoftEdgeEnterpriseX64.msi -CommandLine /qn

#endregion

#region Actions for SERVER ($SRV01)
Write-ScreenInfo -Message "start Actions for $SRV01"

#Populate local Administrators
$Member = "FBN\SQL-Creator"
Invoke-LabCommand -ActivityName "Add $Member to Administrators" -ComputerName $SRV01 -ScriptBlock {
    Add-LocalGroupMember -Group "Administrators" -Member $Member
} -Credential $creds -Variable (Get-Variable -Name Member)
Remove-Variable -Name Member

#Create additional Folders
$FolderName = "Home"
$FolderPath = "C:\"
Invoke-LabCommand -ActivityName "CreateFolder $FolderName" -ComputerName $SRV01 -ScriptBlock {
    New-Item -Path $FolderPath -Name $FolderName -ItemType Directory
} -Credential $creds -Variable (Get-Variable -Name FolderPath),(Get-Variable -Name FolderName)
Remove-Variable -Name FolderName
Remove-Variable -Name FolderPath

#Copy files
Write-ScreenInfo -Message 'Copying files to SERVER01' -TaskStart
Write-ProgressIndicator
Copy-LabFileItem -Path $LabSources\Labs\UWM\User_Workspace_Manager -ComputerName $SRV01 -DestinationFolderPath C:\PostInstall
Copy-LabFileItem -Path $LabSources\Labs\UWM\License -ComputerName $SRV01 -DestinationFolderPath C:\PostInstall
Copy-LabFileItem -Path $LabSources\Labs\UWM\Module3 -ComputerName $SRV01 -DestinationFolderPath C:\PostInstall
Copy-LabFileItem -Path $LabSources\Labs\UWM\Resources -ComputerName $SRV01 -DestinationFolderPath C:\
Copy-LabFileItem -Path $LabSources\Labs\UWM\Wallpapers -ComputerName $SRV01 -DestinationFolderPath C:\PostInstall
Copy-LabFileItem -Path $LabSources\Labs\UWM\SQL -ComputerName $SRV01 -DestinationFolderPath C:\PostInstall
Write-ProgressIndicatorEnd
Write-ScreenInfo -Message 'File copy finished' -TaskEnd

#Extract Archives
Invoke-LabCommand -ActivityName "Extract SQL files" -ComputerName $SRV01 -ScriptBlock {
    Expand-Archive -Path "C:\PostInstall\SQL\SQLEXP_2019_x64_ENU.zip" -DestinationPath "c:\PostInstall\SQL"
} -Credential $creds
Invoke-LabCommand -ActivityName "Remove SQL archive" -ComputerName $SRV01 -ScriptBlock {
    Remove-Item -Path "C:\PostInstall\SQL\SQLEXP_2019_x64_ENU.zip" -Force
} -Credential $creds

#Create Shares
$ShareName = "Home"
$SharePath = "C:\Home"
Invoke-LabCommand -ActivityName "CreateShare $ShareName" -ComputerName $SRV01 -ScriptBlock {
    New-SmbShare -Name $ShareName -Path $SharePath -FullAccess "EVERYONE"
} -Credential $creds -Variable (Get-Variable -Name ShareName),(Get-Variable -Name SharePath)

$ShareName = "PostInstall"
$SharePath = "C:\Postinstall"
Invoke-LabCommand -ActivityName "CreateShare $ShareName" -ComputerName $SRV01 -ScriptBlock {
    New-SmbShare -Name $ShareName -Path $SharePath -FullAccess "EVERYONE"
} -Credential $creds -Variable (Get-Variable -Name ShareName),(Get-Variable -Name SharePath)

$ShareName = "Resources"
$SharePath = "C:\Resources"
Invoke-LabCommand -ActivityName "CreateShare $ShareName" -ComputerName $SRV01 -ScriptBlock {
    New-SmbShare -Name $ShareName -Path $SharePath -FullAccess "EVERYONE"
} -Credential $creds -Variable (Get-Variable -Name ShareName),(Get-Variable -Name SharePath)

#Install software
Install-LabSoftwarePackage -ComputerName $SRV01 -Path $labSources\Labs\UWM\SoftwarePackages\MicrosoftEdgeEnterpriseX64.msi -CommandLine /qn
Install-LabSoftwarePackage -ComputerName $SRV01 -Path $labSources\Labs\UWM\SoftwarePackages\SSMS-Setup-ENU.exe -CommandLine '/install /quiet /norestart'
Install-LabSoftwarePackage -ComputerName $SRV01 -LocalPath C:\PostInstall\SQL\setup.exe -CommandLine '/ConfigurationFile=C:\PostInstall\SQL\ConfigurationFile.ini'

Write-ScreenInfo -Message "end actions for $SRV01"
#endregion

#region Actions for PC01
#Copy files
Write-ScreenInfo -Message 'Copying files to $PC01' -TaskStart
Write-ProgressIndicator
Copy-LabFileItem -Path $LabSources\Labs\UWM\SoftwarePackages\Office2010ProPlusx86ENU -ComputerName $PC01 -DestinationFolderPath C:\PostInstall
Copy-LabFileItem -Path $LabSources\Labs\UWM\Wallpapers -ComputerName $PC01 -DestinationFolderPath C:\PostInstall
Copy-LabFileItem -Path $LabSources\Labs\UWM\Module5 -ComputerName $PC01 -DestinationFolderPath C:\PostInstall
Copy-LabFileItem -Path $LabSources\Labs\UWM\Module6 -ComputerName $PC01 -DestinationFolderPath C:\PostInstall
Write-ProgressIndicatorEnd
Write-ScreenInfo -Message 'File copy finished' -TaskEnd

#Extract Archives
Invoke-LabCommand -ActivityName "Extract Office2010 files" -ComputerName $PC01 -ScriptBlock {
    Expand-Archive -Path "C:\PostInstall\Office2010ProPlusx86ENU\Office2010ProPlusx86ENU.zip" -DestinationPath "c:\PostInstall" -Force
} -Credential $creds
Invoke-LabCommand -ActivityName "Remove Office2010 archive" -ComputerName $PC01 -ScriptBlock {
    Remove-Item -Path "C:\PostInstall\Office2010ProPlusx86ENU\Office2010ProPlusx86ENU.zip" -Force
} -Credential $creds

#Install software
Install-LabSoftwarePackage -ComputerName $PC01 -Path $labsources\Labs\UWM\SoftwarePackages\GoogleChromeStandaloneEnterprise64.msi -CommandLine /qn
Install-LabSoftwarePackage -ComputerName $PC01 -Path $labsources\Labs\UWM\SoftwarePackages\FirefoxSetup91.10.0esr.msi -CommandLine /qn
Install-LabSoftwarePackage -ComputerName $PC01 -Path $labsources\Labs\UWM\SoftwarePackages\FoxitPDFReader1122_enu_Setup.msi -CommandLine /qn
Write-ScreenInfo -Message 'Installing Office 2010' -TaskStart
Install-LabSoftwarePackage -ComputerName $PC01 -LocalPath C:\PostInstall\Office2010ProPlusx86ENU\setup.exe
Write-ScreenInfo -Message 'Installing Office 2010 done'
#endregion

#region Actions for PC02
#Copy files
Write-ScreenInfo -Message 'Copying files to $PC02' -TaskStart
Write-ProgressIndicator
Copy-LabFileItem -Path $LabSources\Labs\UWM\SoftwarePackages\Office2013ProPlusx86ENU -ComputerName $PC02 -DestinationFolderPath C:\PostInstall
Copy-LabFileItem -Path $LabSources\Labs\UWM\Wallpapers -ComputerName $PC02 -DestinationFolderPath C:\PostInstall
Write-ProgressIndicatorEnd
Write-ScreenInfo -Message 'File copy finished' -TaskEnd

#Extract Archives
Invoke-LabCommand -ActivityName "Extract Office2013 files" -ComputerName $PC02 -ScriptBlock {
    Expand-Archive -Path "C:\PostInstall\Office2013ProPlusx86ENU\Office2013ProPlusx86ENU.zip" -DestinationPath "c:\PostInstall" -Force
} -Credential $creds
Invoke-LabCommand -ActivityName "Remove Office2013 archive" -ComputerName $PC02 -ScriptBlock {
    Remove-Item -Path "C:\PostInstall\Office2013ProPlusx86ENU\Office2013ProPlusx86ENU.zip" -Force
} -Credential $creds

#Install software
Install-LabSoftwarePackage -ComputerName $PC02 -Path $labsources\Labs\UWM\SoftwarePackages\GoogleChromeStandaloneEnterprise64.msi -CommandLine /qn
Install-LabSoftwarePackage -ComputerName $PC02 -Path $labsources\Labs\UWM\SoftwarePackages\FirefoxSetup91.10.0esr.msi -CommandLine /qn
Install-LabSoftwarePackage -ComputerName $PC02 -Path $labsources\Labs\UWM\SoftwarePackages\FoxitPDFReader1122_enu_Setup.msi -CommandLine /qn
Write-ScreenInfo -Message 'Installing Office 2013' -TaskStart
Install-LabSoftwarePackage -ComputerName $PC02 -LocalPath C:\PostInstall\Office2013ProPlusx86ENU\setup.exe -Timeout 20
Write-ScreenInfo -Message 'Installing Office 2013 done'
#endregion

#region Actions for PC03
#Copy files
Write-ScreenInfo -Message 'Copying files to $PC03' -TaskStart
Write-ProgressIndicator
Copy-LabFileItem -Path $LabSources\Labs\UWM\SoftwarePackages\Office2010ProPlusx86ENU -ComputerName $PC03 -DestinationFolderPath C:\PostInstall
Copy-LabFileItem -Path $LabSources\Labs\UWM\Wallpapers -ComputerName $PC03 -DestinationFolderPath C:\PostInstall
Copy-LabFileItem -Path $LabSources\Labs\UWM\Module5 -ComputerName $PC03 -DestinationFolderPath C:\PostInstall
Copy-LabFileItem -Path $LabSources\Labs\UWM\Module6 -ComputerName $PC03 -DestinationFolderPath C:\PostInstall
Write-ProgressIndicatorEnd
Write-ScreenInfo -Message 'File copy finished' -TaskEnd

#Extract Archives
Invoke-LabCommand -ActivityName "Extract Office2010 files" -ComputerName $PC03 -ScriptBlock {
    Expand-Archive -Path "C:\PostInstall\Office2010ProPlusx86ENU\Office2010ProPlusx86ENU.zip" -DestinationPath "c:\PostInstall" -Force
} -Credential $creds
Invoke-LabCommand -ActivityName "Remove Office2010 archive" -ComputerName $PC03 -ScriptBlock {
    Remove-Item -Path "C:\PostInstall\Office2010ProPlusx86ENU\Office2010ProPlusx86ENU.zip" -Force
} -Credential $creds

#Install software
Install-LabSoftwarePackage -ComputerName $PC03 -Path $labsources\Labs\UWM\SoftwarePackages\FoxitPDFReader1122_enu_Setup.msi -CommandLine /qn
Install-LabSoftwarePackage -ComputerName $PC03 -Path $labsources\Labs\UWM\SoftwarePackages\GoogleChromeStandaloneEnterprise64.msi -CommandLine /qn
Install-LabSoftwarePackage -ComputerName $PC03 -Path $labsources\Labs\UWM\SoftwarePackages\FirefoxSetup91.10.0esr.msi -CommandLine /qn
Write-ScreenInfo -Message 'Installing Office 2010' -TaskStart
Install-LabSoftwarePackage -ComputerName $PC03 -LocalPath C:\PostInstall\Office2010ProPlusx86ENU\setup.exe
Write-ScreenInfo -Message 'Installing Office 2010 done'

#endregion

#region Post Installation tasks
Write-ScreenInfo -Message 'Disable AutoLogon & Reboot Machines'
Disable-LabAutoLogon -ComputerName DC01,SERVER01,TS01,PC01,PC10
Restart-LabVM -ComputerName DC01,SERVER01,TS01,PC01,PC10

Write-ScreenInfo -Message 'Removing Windows Defender Exclusions'
Remove-MpPreference -ExclusionProcess code.exe,powershell.exe,powershell_ise.exe

Show-LabDeploymentSummary

#endregion