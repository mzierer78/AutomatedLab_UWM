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

#Ensure Windows Defender does not slow down LAB build
Write-ScreenInfo -Message 'Setting Windows Defender Exclusions'
Set-MpPreference -ExclusionProcess dism.exe,code.exe,powershell.exe

#endregion

#region Domain Controller Actions
#Create AD OU's
$TestLabName = 'Test'
$TestLabDomainName = 'FBN'
#Create Parent OU
Invoke-LabCommand -ActivityName "Add OU $TestLabName" -ComputerName $DC -ScriptBlock {
    New-ADOrganizationalUnit -Name "$TestLabName" -Path "DC=$TestLabDomainName,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds -Variable (Get-Variable -Name TestLabName),(Get-Variable -Name TestLabDomainName)

#Create Child OU's
$TestLabOUName = 'Accounts'
Invoke-LabCommand -ActivityName "Add OU $TestLabOUName" -ComputerName $DC -ScriptBlock {
    New-ADOrganizationalUnit -Name $TestLabOUName -Path "OU=$TestLabName,DC=$TestLabDomainName,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds -Variable (Get-Variable -Name TestLabOUName),(Get-Variable -Name TestLabName),(Get-Variable -Name TestLabDomainName)
Remove-Variable -Name TestLabOUName

#Move Computers to OU's
$Identity = 'CN=PC02,CN=Computers,$TestLabDomainName,DC=local'
$TargetPath = 'OU=Windows 10,OU=$TestLabName,$TestLabDomainName,DC=local'
Invoke-LabCommand -ActivityName "Move $Identity to $TargetPath" -ComputerName $DC -ScriptBlock {
    Move-ADObject -Identity $Identity -TargetPath $TargetPath
} -Credential $creds -Variable (Get-Variable -Name Identity),(Get-Variable -Name TargetPath)
Remove-Variable -Name Identity
Remove-Variable -Name TargetPath

#create additional users
$User = 'SQL-Creator'
$Pwd = 'Pa55word'
Invoke-LabCommand -ActivityName "CreateUser $User" -ComputerName $DC -ScriptBlock {
    Import-Module ActiveDirectory
    $secpwd = ConvertTo-SecureString $Pwd -AsPlainText -Force
    New-ADUser -Name $User -AccountPassword $secpwd -Enabled $true -ChangePasswordAtLogon $false
} -Credential $creds -Variable (Get-Variable -Name User),(Get-Variable -Name Pwd)
Remove-Variable -Name User

#endregion

#region Member Actions

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


#endregion