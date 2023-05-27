# Function to show the current audit policy
function Show-AuditPolicy {
    auditpol /get /category:"Detailed Tracking"
}

# Function to show the current Powershell log settings
function Show-PowershellLogSettings {
    Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
    Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
}

# Function to show the current Process Creation settings
function Show-ProcessCreationSettings {
    Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled
}

# Output current logging settings
Write-Host "Before changes:"
Show-AuditPolicy
Show-PowershellLogSettings
Show-ProcessCreationSettings

# Enable Windows Event ID 4688
auditpol /set /subcategory:"Process Creation" /success:enable

# Enable Command Line Auditing
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit -Name ProcessCreationIncludeCmdLine_Enabled -Value 1

# Enable Powershell Module Logging
New-Item -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell -Name ModuleLogging -Force
Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging -Name EnableModuleLogging -Value 1

# Enable Powershell Script Block Logging
New-Item -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell -Name ScriptBlockLogging -Force
Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 1

# Output new logging settings
Write-Host "After changes:"
Show-AuditPolicy
Show-PowershellLogSettings
Show-ProcessCreationSettings

# Download Sysmon from the official Microsoft website
Invoke-WebRequest -Uri "https://live.sysinternals.com/Sysmon64.exe" -OutFile "C:\Temp\Sysmon64.exe"

# Download the SwiftOnSecurity Sysmon configuration from their GitHub repository
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Temp\sysmonconfig-export.xml"

# Navigate to the directory where you downloaded Sysmon
Set-Location -Path "C:\Temp"

# Install Sysmon with the SwiftOnSecurity configuration
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
