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

#Copy ISO Files to C:\Labsources\ISOs
Write-ScreenInfo -Message 'Copying required ISO Files to C:\LabSources\ISOs Folder'
#hier variable einsetzen
robocopy.exe "C:\LabSources\Labs\$TestLabName\ISO" 'C:\LabSources\ISOs'

#Ensure Windows Defender does not slow down LAB build
Write-ScreenInfo -Message 'Setting Windows Defender Exclusions'
Set-MpPreference -ExclusionProcess dism.exe,code.exe,powershell.exe

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