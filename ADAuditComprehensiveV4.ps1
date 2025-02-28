######################################################################################
# ADComprehensiveMerged.ps1
# ------------------------------------------------------------------------------------
# Merges your original "ADAuditComprehensiveV2.ps1" script with selected, non-duplicated
# functions from "ADAudit.ps1" (phillips321.co.uk).
#
# Notably, it adds:
#   - SYSVOL GPP cpassword check
#   - LAPS status check
#   - OU perms check
#   - SPN kerberoast check
#   - AS-REP roastable check
#   - DC ownership check
#   - LDAP security check
#
# All references to Nessus output have been removed.
# The rest of the original "ADAuditComprehensiveV2.ps1" is retained, including:
#   - your DNS reverse lookup vs Sites/Subnets check
#   - your menu-based approach and BPA scanning
#   - your "Invoke-DiscoveryScript", "Invoke-ForestHealthCheck", etc.
#
# Usage:
#   1) Copy this entire script to a .ps1 file, e.g. ADComprehensiveMerged.ps1.
#   2) Run in an elevated PowerShell with modules: ActiveDirectory, GroupPolicy,
#      BestPractices, DSInternals, etc. installed as needed.
#   3) Select the menu item that corresponds to each check you want to run.
#
######################################################################################


######################################################################################
# SECTION 1: UTILITY / SHARED FUNCTIONS
######################################################################################

function Write-Both {
    param([string] $Message)
    $basePath = "C:\ADHealthCheck"
    if (!(Test-Path $basePath)) {
        New-Item -ItemType Directory -Path $basePath | Out-Null
    }
    $logFile = Join-Path $basePath "consolelog.txt"
    Write-Host $Message
    Add-Content -Path $logFile -Value $Message
}

function Pause {
    Write-Host ""
    Write-Host "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Write-Header {
    param([string]$Text)
    Write-Both "========================================="
    Write-Both " $Text "
    Write-Both "========================================="
}

function Ensure-Folder {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -ItemType Directory | Out-Null
    }
}

######################################################################################
# SECTION 2: ORIGINAL CONTENT FROM "ADAuditComprehensiveV2.ps1"
######################################################################################

#region Helper Functions from original

function Invoke-ScanGPOsUnknownAccounts {
    <#
        Scans all GPOs for unresolved SIDs in security settings.
    #>
    Write-Header "Scanning GPOs for Orphand SIDs"
    Import-Module GroupPolicy -ErrorAction SilentlyContinue | Out-Null
     # Check if the Get-GPO command is available.
     if (-not (Get-Command Get-GPO -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-GPO command was not found. Please ensure the GroupPolicy module is installed."
        Pause
        Show-MainMenu
        return
    }
    $OutPath = "C:\ADHealthCheck\GPOswithOrphandSIDS"
    Ensure-Folder -Path $OutPath

    $GPOsWithIssues = @()
    foreach ($GPO in Get-GPO -All -ErrorAction SilentlyContinue) {
        $xmlContent = try {
            [xml](Get-GPOReport -Guid $GPO.Id -ReportType Xml -ErrorAction Goto Pause | Out-Null)
        } catch {
            $null
        }
        if ($xmlContent -and $xmlContent.GPO.Computer.ExtensionData.Extension.SecuritySettings) {
            foreach ($setting in $xmlContent.GPO.Computer.ExtensionData.Extension.SecuritySettings.ChildNodes) {
                if ($setting.'Trustee-SID' -and -not $setting.'Trustee-Name') {
                    $GPOsWithIssues += [PSCustomObject]@{
                        GPOName = $GPO.DisplayName
                        SID     = $setting.'Trustee-SID'
                        Setting = $setting.LocalizedName
                    }
                }
            }
        }
    }
    if ($GPOsWithIssues.Count -gt 0) {
        $GPOsWithIssues | Format-Table -AutoSize
        $OutputFile = Join-Path $OutPath "GPOsWithUnknownAccounts.csv"
        $GPOsWithIssues | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Both "Results exported to $OutputFile"
    } else {
        Write-Both "No unknown (orphaned) accounts found in GPOs."
    }
    Pause
    Show-MainMenu
}

function Invoke-ScanGPOPasswordPolicies {
    <#
        Evaluates all GPOs for password policy settings.
    #>
    Write-Header "Scanning GPOs for Password Policies"
    Import-Module GroupPolicy -ErrorAction SilentlyContinue | Out-Null
     # Check if the Get-GPO command is available.
     if (-not (Get-Command Get-GPO -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-GPO command was not found. Please ensure the GroupPolicy module is installed."
        Pause
        Show-MainMenu
        return
    }
    $OutPath = "C:\ADHealthCheck\GPOPasswordPolicies"
    Ensure-Folder -Path $OutPath

    function Get-PolicyValue {
        param(
            [xml]$XmlContent,
            [string]$PolicyName
        )
        $policy = $XmlContent.GPO.Computer.ExtensionData.Extension.Account | Where-Object { $_.Name -eq $PolicyName }
        if ($policy -and $policy.SettingNumber) {
            return $policy.SettingNumber
        }
        else {
            return $null
        }
    }

    $results = @()
    foreach ($gpo in Get-GPO -All) {
        $xmlContent = try {
            [xml](Get-GPOReport -Guid $gpo.Id -ReportType Xml)
        } catch {
            $null
        }
        if ($xmlContent) {
            $maxAge    = Get-PolicyValue -XmlContent $xmlContent -PolicyName "MaximumPasswordAge"
            $minLength = Get-PolicyValue -XmlContent $xmlContent -PolicyName "MinimumPasswordLength"
            $history   = Get-PolicyValue -XmlContent $xmlContent -PolicyName "PasswordHistorySize"
            if ($maxAge -or $minLength -or $history) {
                $results += [PSCustomObject]@{
                    GPOName             = $gpo.DisplayName
                    MaxPasswordAge      = $maxAge
                    MinPasswordLength   = $minLength
                    PasswordHistorySize = $history
                }
            }
        }
    }
    if ($results.Count -gt 0) {
        $results | Format-Table -AutoSize
        $OutputFile = Join-Path $OutPath "GPO_Password_Policies.csv"
        $results | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Both "Results exported to $OutputFile"
    } else {
        Write-Both "No GPO-level password policy settings detected or none found."
    }
    Pause
}

function Invoke-GPOPolicyOverlapScan {
    <#
        Scans for overlapping GPO settings across domain controllers.
    #>
    Write-Header "Overlapping GPO Policy Settings Scan"
    Import-Module GroupPolicy -ErrorAction SilentlyContinue | Out-Null
     # Check if the Get-GPO command is available.
     if (-not (Get-Command Get-GPO -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-GPO command was not found. Please ensure the GroupPolicy module is installed."
        Pause
        Show-MainMenu
        return
    }
    $OutPath = "C:\ADHealthCheck\OverlapGPO"
    Ensure-Folder -Path $OutPath

    foreach ($gpo in Get-GPO -All) {
        $xmlPath = Join-Path $OutPath ("{0}.xml" -f ($gpo.DisplayName -replace '[\\/:*?"<>|]', '_'))
        Get-GPOReport -Guid $gpo.Id -ReportType Xml -Path $xmlPath
    }
    $summaries = @()
    foreach ($file in Get-ChildItem "$OutPath\*.xml") {
        [xml]$xmlContent = Get-Content $file.FullName
        if ($xmlContent.GPO.Computer.ExtensionData.Extension.Policy) {
            foreach ($setting in $xmlContent.GPO.Computer.ExtensionData.Extension.Policy) {
                $summaries += [PSCustomObject]@{
                    GPOName = $xmlContent.GPO.Name
                    Policy  = $setting.Name
                    State   = $setting.State
                    Value   = $setting.Value
                }
            }
        }
    }
    if ($summaries.Count -gt 0) {
        $CSVPath = Join-Path $OutPath "GPOSummary.csv"
        $summaries | Export-Csv -Path $CSVPath -NoTypeInformation
        Write-Both "GPO Summary exported to $CSVPath"
    } else {
        Write-Both "No GPO policy data collected or no extension data found."
    }
    Pause
}

function Invoke-ReviewBaseSecurity {
    <#
        Reviews base security settings on the DC.
    #>
    Write-Header "Reviewing Base Security Settings"

    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Both "Run this script as an Administrator!"
        Pause
        return
    }

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Both "Active Directory module not available. Install RSAT-AD-PowerShell."
        Pause
        return
    }
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADUser command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    $OutPath = "C:\ADHealthCheck\BaseSecurity"
    Ensure-Folder -Path $OutPath

    try {
        $osInfo = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
    } catch {
        Write-Both "Failed to retrieve OS information: $_"
        Pause
        return
    }

    try {
        $domainPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
    } catch {
        Write-Both "Failed to retrieve domain password policy: $_"
        $domainPolicy = $null
    }

    $groupsToCheck = @("Domain Admins", "Enterprise Admins", "Schema Admins")
    $groupMemberships = @{}

    foreach ($grp in $groupsToCheck) {
        try {
            $members = (Get-ADGroupMember -Identity $grp -ErrorAction Stop).Name -join ', '
            $groupMemberships["$grp Members"] = $members
        } catch {
            $groupMemberships["$grp Members"] = "Error retrieving members"
        }
    }

    if ((Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue)) {
        try {
            $smb1 = Get-WindowsFeature FS-SMB1
        } catch {
            $smb1 = $null
        }
    } else {
        $smb1 = $null
    }

    try {
        $isRODC = (Get-ADDomainController -Identity $env:computername -ErrorAction Stop).IsReadOnly
    } catch {
        $isRODC = $false
    }

    try {
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            $installedFeatures = (Get-WindowsFeature | Where-Object { $_.Installed }).Name -join ', '
        } else {
            $installedFeatures = "N/A"
        }
    } catch {
        $installedFeatures = "Error retrieving features"
    }

    $result = [PSCustomObject]@{
        "Operating System"         = "$($osInfo.Caption), SP:$($osInfo.ServicePackMajorVersion).$($osInfo.ServicePackMinorVersion)"
        "Last Boot "           = $osInfo.LastBootUp
        "Min Password Length"      = if ($domainPolicy) { $domainPolicy.MinPasswordLength } else { "N/A" }
        "Password History Count"   = if ($domainPolicy) { $domainPolicy.PasswordHistoryCount } else { "N/A" }
        "Max Password Age (Days)"  = if ($domainPolicy) { $domainPolicy.MaxPasswordAge.Days } else { "N/A" }
        "Reversible Encryption"    = if ($domainPolicy) { $domainPolicy.ReversibleEncryptionEnabled } else { "N/A" }
        "SMBv1 Installed"          = if ($smb1 -and $smb1.Installed) { "Yes" } else { "No" }
        "DC Type"                  = if ($isRODC) { "Read-Only" } else { "Writable" }
        "Installed Features"       = $installedFeatures
    } + $groupMemberships

    $result | Format-Table -AutoSize
    $OutputFile = Join-Path $OutPath "BaseSecurityReview.csv"
    $result | Export-Csv -Path $OutputFile -NoTypeInformation
    Write-Both "Data exported to $OutputFile"
    Pause
}

function Invoke-DCEventErrorSummary {
    <#
        Summarizes error and warning events from key logs.
    #>
    Write-Header "DC Event Errors Summary"

    $OutPath = "C:\ADHealthCheck\EventErrors"
    Ensure-Folder -Path $OutPath

    $logs = @("System","Application","Directory Service","DNS Server","File Replication Service")
    $eventStats = @{}

    foreach ($log in $logs) {
        $events = Get-WinEvent -LogName $log -MaxEvents 1000 | Where-Object { $_.LevelDisplayName -in @("Error","Warning") }
        foreach ($e in $events) {
            $key = "$log-$($e.LevelDisplayName)-$($e.Id)"
            if ($eventStats.ContainsKey($key)) {
                $eventStats[$key].Count++
            } else {
                $eventStats[$key] = [PSCustomObject]@{
                    Count         = 1
                    LogName       = $log
                    Level         = $e.LevelDisplayName
                    EventID       = $e.Id
                    SampleMessage = ($e.Message.Split("`n"))[0]
                }
            }
        }
    }

    $summary = $eventStats.GetEnumerator() | ForEach-Object {
        [PSCustomObject]@{
            LogName       = $_.Value.LogName
            Level         = $_.Value.Level
            EventID       = $_.Value.EventID
            Count         = $_.Value.Count
            SampleMessage = $_.Value.SampleMessage
        }
    } | Sort-Object Count -Descending

    if ($summary.Count -gt 0) {
        $summary | Format-Table -AutoSize
        $OutputFile = Join-Path $OutPath "EventLogSummary.csv"
        $summary | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Both "Event log summary exported to $OutputFile"
    } else {
        Write-Both "No Error/Warning events found or no events retrieved."
    }
    Pause
}

function Invoke-AllDCDiagTests {
    <#
        Runs a full suite of dcdiag tests on all domain controllers.
    #>
    Write-Header "Running DCDiag Tests"
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADDomainController command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    $OutPath = "C:\ADHealthCheck\DCDiag"
    Ensure-Folder -Path $OutPath

    $results = @()
    $dcs = Get-ADDomainController -Filter *
    foreach ($dc in $dcs) {
        Write-Both "Running dcdiag on $($dc.HostName)"
        $testOutput = (& dcdiag /s:$($dc.HostName)) | Out-String
        $results += [PSCustomObject]@{
            DCName       = $dc.HostName
            DCDiagOutput = $testOutput
        }
    }
    $OutputFile = Join-Path $OutPath "DCDiagResults.csv"
    $results | Export-Csv -Path $OutputFile -NoTypeInformation
    Write-Both "DCDiag results exported to $OutputFile"
    Pause
    Show-MainMenu
}

function Invoke-ForestHealthCheck {
    <#
        Performs an AD forest health check.
    #>
    Write-Header "AD Forest Health Check"
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADForest -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADForest command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    $OutPath = "C:\ADHealthCheck\ForestHealthCheck"
    Ensure-Folder -Path $OutPath

    $forest = Get-ADForest
    $domains = $forest.Domains | ForEach-Object { Get-ADDomain -Identity $_ }
    $fsmoRoles = netdom query fsmo
    $repData = Get-ADReplicationUpToDatenessVectorTable -Scope Forest -Target $forest.Name
    $staleData = $repData | Where-Object { $_.LastReplicationSuccess -lt (Get-Date).AddDays(-7) }

    $review = [PSCustomObject]@{
        ForestName             = $forest.Name
        ForestFunctionalLevel  = $forest.ForestMode
        ChildDomains           = ($forest.Domains -join ', ')
        GlobalCatalogs         = ($forest.GlobalCatalogs -join ', ')
        UPNSuffixes            = ($forest.UPNSuffixes -join ', ')
        SPNSuffixes            = ($forest.SPNSuffixes -join ', ')
        DomainFunctionalLevels = ($domains | ForEach-Object { "$($_.Name): $($_.DomainMode)" }) -join '; '
        SchemaVersion          = $forest.ObjectVersion
        FSMORoles              = $fsmoRoles -join "`r`n"
        SiteNames              = ($forest.Sites -join ', ')
    }

    $ForestCSV = Join-Path $OutPath "ADForestReview.csv"
    $StaleCSV  = Join-Path $OutPath "StaleReplicationData.csv"

    $review | Export-Csv -Path $ForestCSV -NoTypeInformation
    $staleData | Export-Csv -Path $StaleCSV -NoTypeInformation

    Write-Both "Forest review exported to $ForestCSV"
    Write-Both "Stale replication data exported to $StaleCSV"
    Pause
}

function Invoke-MoveFSMORoles {
    <#
        Moves all FSMO roles to a specified new DC.
    #>
    Write-Header "Moving FSMO Roles"
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Move-ADDirectoryServerOperationMasterRole -ErrorAction SilentlyContinue)) {
        Write-Both "The Move-ADDirectoryServerOperationMasterRole command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    $OutPath = "C:\ADHealthCheck\FSMOMoves"
    Ensure-Folder -Path $OutPath

    $TargetDC = Read-Host "Enter the FQDN of the target DC for FSMO roles"
    $Server = Get-ADDomainController -Identity $TargetDC
    Move-ADDirectoryServerOperationMasterRole -Identity $Server -OperationMasterRole SchemaMaster,DomainNamingMaster,PDCEmulator,RIDMaster,InfrastructureMaster
    Write-Both "FSMO roles moved to $TargetDC."
    Pause
}

function Invoke-GetDCEgressWANIPs {
    <#
        Retrieves the external WAN IPs for all domain controllers.
    #>
    Write-Header "DC External WAN IPs"
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADDomainController command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    $OutPath = "C:\ADHealthCheck\ExternalWANIPs"
    Ensure-Folder -Path $OutPath

    function Get-LocalExternalIP {
        try {
            return (Invoke-RestMethod -Uri 'https://ipinfo.io/json' -UseBasicParsing).ip
        } catch {
            return "Failed to get external IP"
        }
    }

    $results = @()
    $DCs = Get-ADDomainController -Filter *
    foreach ($dc in $DCs) {
        $scriptBlock = ${function:Get-LocalExternalIP}
        $wanIP = Invoke-Command -ComputerName $dc.HostName -ScriptBlock $scriptBlock -ErrorAction SilentlyContinue
        $results += [PSCustomObject]@{
            DCName = $dc.HostName
            WANIP  = $wanIP
        }
        Write-Both "External IP for $($dc.HostName): $wanIP"
    }
    $OutputFile = Join-Path $OutPath "DCExternalWANIPs.csv"
    $results | Export-Csv -Path $OutputFile -NoTypeInformation
    Write-Both "Results exported to $OutputFile"
    Pause
}

function Invoke-LDAPLDAPSCheck {
    <#
        Checks LDAP and LDAPS connectivity on all domain controllers.
    #>
    Write-Header "LDAP/LDAPS Connectivity Check"
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADDomainController command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    $OutPath = "C:\ADHealthCheck\LDAPLDAPSCheck"
    Ensure-Folder -Path $OutPath

    function Test-LDAPPort {
        param([string]$Server,[int]$Port)
        try {
            $conn = [ADSI]"LDAP://$Server`:$Port"
            $conn.Close()
            return $true
        } catch {
            return $_.Exception.Message
        }
    }

    $allDCs = (Get-ADDomainController -Filter *).HostName
    $results = foreach ($dc in $allDCs) {
        $ldapStatus  = Test-LDAPPort -Server $dc -Port 389
        $ldapsStatus = Test-LDAPPort -Server $dc -Port 636
        [PSCustomObject]@{
            ComputerName = $dc
            LDAPStatus   = if ($ldapStatus -eq $true) {"OK"} else {"Failed: $ldapStatus"}
            LDAPSStatus  = if ($ldapsStatus -eq $true) {"OK"} else {"Failed: $ldapsStatus"}
        }
    }
    $OutputFile = Join-Path $OutPath "DomainControllers_LDAPS_Status.csv"
    $results | Export-Csv -Path $OutputFile -NoTypeInformation
    $results | Format-Table -AutoSize
    Write-Both "LDAP/LDAPS results exported to $OutputFile"
    Pause
}

function Invoke-DiscoveryScript {
    <#
        Collects detailed software, hardware, and network info from DCs.
    #>
    Write-Header "Running Discovery Script"
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADDomainController command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    $OutPath = "C:\ADHealthCheck\Discovery"
    Ensure-Folder -Path $OutPath

    $swFile = Join-Path $OutPath "DC_Software_Report.csv"
    $hwFile = Join-Path $OutPath "DC_Hardware_Report.csv"
    $nwFile = Join-Path $OutPath "DC_Network_Report.csv"

    $swResults = @(); $hwResults = @(); $nwResults = @()
    $onlineDCs = Get-ADDomainController -Filter * | Where-Object { Test-Connection -ComputerName $_.HostName -Count 1 -Quiet }

    foreach ($dc in $onlineDCs) {
        # Software
        try {
            $regPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            $reg = [wmiclass]"\\$($dc.HostName)\root\cimv2:StdRegProv"
            $subKeys = $reg.EnumKey(2147483650, $regPath)
            foreach ($key in $subKeys.sNames) {
                $name = $reg.GetStringValue(2147483650, "$regPath\$key", "DisplayName").sValue
                if ($name) {
                    $swResults += [PSCustomObject]@{
                        DCName      = $dc.HostName
                        DisplayName = $name
                    }
                }
            }
        } catch {
            Write-Both "Error retrieving software info for $($dc.HostName)"
        }
        # Hardware
        try {
            $comp = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $dc.HostName
            $cpu  = Get-WmiObject -Class Win32_Processor -ComputerName $dc.HostName
            $os   = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $dc.HostName
            $disks = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" -ComputerName $dc.HostName
            foreach ($disk in $disks) {
                $hwResults += [PSCustomObject]@{
                    DCName        = $dc.HostName
                    Manufacturer  = $comp.Manufacturer
                    Model         = $comp.Model
                    CPU           = $cpu.Name
                    TotalMemoryGB = [Math]::Round($os.TotalVisibleMemorySize / 1MB,2)
                    DiskDrive     = $disk.DeviceID
                    TotalSizeGB   = [Math]::Round($disk.Size / 1GB,2)
                    FreeSpaceGB   = [Math]::Round($disk.FreeSpace / 1GB,2)
                }
            }
        } catch {
            Write-Both "Error retrieving hardware info for $($dc.HostName)"
        }
        # Network
        try {
            $configs = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE" -ComputerName $dc.HostName
            foreach ($cfg in $configs) {
                $nwResults += [PSCustomObject]@{
                    DCName         = $dc.HostName
                    IPAddress      = ($cfg.IPAddress -join ', ')
                    SubnetMask     = ($cfg.IPSubnet -join ', ')
                    DefaultGateway = ($cfg.DefaultIPGateway -join ', ')
                    DNSServers     = ($cfg.DNSServerSearchOrder -join ', ')
                    MACAddress     = $cfg.MACAddress
                }
            }
        } catch {
            Write-Both "Error retrieving network info for $($dc.HostName)"
        }
    }
    $swResults | Export-Csv -Path $swFile -NoTypeInformation
    $hwResults | Export-Csv -Path $hwFile -NoTypeInformation
    $nwResults | Export-Csv -Path $nwFile -NoTypeInformation
    Write-Both "Discovery reports exported to $OutPath"
    Pause
}

function Invoke-ProtectOUs {
    <#
        Protects all OUs from accidental deletion.
    #>
    Write-Header "Protecting All OUs"
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADOrganizationalUnit -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADOrganizationalUnit command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    Get-ADOrganizationalUnit -Filter * | ForEach-Object {
        Set-ADOrganizationalUnit $_ -ProtectedFromAccidentalDeletion $true
    }
    Write-Both "All OUs have been protected from accidental deletion."
    Pause
}

function Invoke-QuietAuditRedTeam {
    <#
        Performs a quiet audit for red team operations (example from original).
    #>
    Write-Header "Quiet Red Team Audit"
    $OutPath = "C:\ADHealthCheck\QuietAuditRedTeam"
    Ensure-Folder -Path $OutPath

    function Install-Tools {
        Write-Both "Installing Chocolatey and required AD tools..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
        choco install ldapexplorer -y
    }
    Install-Tools

    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null

    Get-ADDomain | Select-Object DistinguishedName,DNSRoot,DomainMode | Export-Csv -Path (Join-Path $OutPath "AD_DomainInfo.csv") -NoTypeInformation
    Get-ADDomainController -Filter * | Select-Object Name,IPv4Address,Site | Export-Csv -Path (Join-Path $OutPath "AD_DomainControllers.csv") -NoTypeInformation
    Get-ADUser -Filter * | Select-Object Name,SamAccountName,Enabled | Export-Csv -Path (Join-Path $OutPath "AD_Users.csv") -NoTypeInformation
    Get-ADGroup -Filter * | Select-Object Name,GroupCategory,GroupScope | Export-Csv -Path (Join-Path $OutPath "AD_Groups.csv") -NoTypeInformation
    Get-ADOrganizationalUnit -Filter * | Select-Object DistinguishedName,Name | Export-Csv -Path (Join-Path $OutPath "AD_OrganizationalUnits.csv") -NoTypeInformation
    Write-Both "Quiet audit completed. Files exported to $OutPath"
    Pause
}

function Invoke-BestPracticeDNSSiteSubnetCheck {
    <#
        Checks DNS reverse lookup zones vs AD Sites and Services subnets. (From original)
    #>
    Write-Header "DNS Subnet and AD Sites/Services Best Practices Check"
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADReplicationSubnet -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADReplicationSubnet command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    if (-not (Get-Module -ListAvailable -Name DNSServer)) {
        Write-Both "DNSServer module not available. DNS reverse lookup check will be limited."
    } else {
        Import-Module DNSServer
    }

    $OutPath = "C:\ADHealthCheck\SubnetConnectivity"
    Ensure-Folder -Path $OutPath

    function Log-Message {
        param (
            [string]$Message,
            [string]$Type = "Info"
        )
        $stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Both "$stamp [$Type] $Message"
    }

    function Get-ReverseZoneName {
        param([string]$Subnet)
        # Expecting subnet in CIDR form e.g. 192.168.1.0/24
        $parts = $Subnet -split '/'
        if ($parts.Count -lt 2) { return "" }
        $ip = $parts[0]
        $cidr = [int]$parts[1]
        $ipOctets = $ip -split '\.'
        switch ($cidr) {
            8  { return "$($ipOctets[0]).in-addr.arpa" }
            16 { return "$($ipOctets[1]).$($ipOctets[0]).in-addr.arpa" }
            24 { return "$($ipOctets[2]).$($ipOctets[1]).$($ipOctets[0]).in-addr.arpa" }
            default {
                # fallback
                $fullOctets = [int]($cidr / 8)
                $reverseParts = @()
                for ($i = $fullOctets -1; $i -ge 0; $i--) {
                    $reverseParts += $ipOctets[$i]
                }
                return ($reverseParts -join '.') + ".in-addr.arpa"
            }
        }
    }

    function Get-IPsFromSubnet {
        param(
            [string]$Subnet,
            [int]$Count
        )
        $baseIP,$cidr = $Subnet -split '/'
        if (-not $cidr) { return }
        $baseOctets = $baseIP -split '\.'
        [int]$lastOctet = $baseOctets[3]
        1..$Count | ForEach-Object {
            "$($baseOctets[0]).$($baseOctets[1]).$($baseOctets[2]).$($lastOctet + $_)"
        }
    }

    function Test-ADSubnetConnectivity {
        param(
            [string]$RemoteDC,
            [int]$IPsToTestPerSubnet = 3,
            [int]$Pingout = 2,
            [string]$OutputCsvPath = (Join-Path $OutPath 'SubnetConnectivityReport.csv')
        )

        $results = @()
        $sites = Get-ADReplicationSite -Filter *
        $siteSubnets = @{}

        foreach ($site in $sites) {
            $subnets = Get-ADReplicationSubnet -Filter {Site -eq $site.Name}
            $siteSubnets[$site.Name] = $subnets
        }

        foreach ($site in $siteSubnets.Keys) {
            foreach ($subnet in $siteSubnets[$site]) {
                # Check DNS reverse lookup if DNSServer module is available
                if (Get-Module -Name DNSServer) {
                    $reverseZoneName = Get-ReverseZoneName -Subnet $subnet.Range
                    if ($reverseZoneName) {
                        try {
                            $dnsZone = Get-DnsServerZone -Name $reverseZoneName -ErrorAction Stop
                            Log-Message "Reverse lookup zone '$reverseZoneName' exists for $($subnet.Range) in site $site" "Info"
                        } catch {
                            Log-Message "Reverse zone '$reverseZoneName' NOT found for $($subnet.Range) in site $site" "Error"
                        }
                    }
                } else {
                    Log-Message "Skipping DNS reverse zone check for $($subnet.Range) in site $site. No DNSServer module" "Warning"
                }

                $IPsToTest = Get-IPsFromSubnet -Subnet $subnet.Range -Count $IPsToTestPerSubnet
                if ($IPsToTest) {
                    foreach ($ip in $IPsToTest) {
                        try {
                            $localPing = Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue -outSeconds $Pingout
                            $remotePing = Invoke-Command -ComputerName $RemoteDC -ScriptBlock {
                                param($ip,$Pingout)
                                Test-Connection -ComputerName $ip -Count 1 -Quiet -outSeconds $Pingout
                            } -ArgumentList $ip,$Pingout -ErrorAction SilentlyContinue

                            $results += [PSCustomObject]@{
                                Stamp    = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                                Site         = $site
                                Subnet       = $subnet.Range
                                TestedIP     = $ip
                                LocalDCPing  = $localPing
                                RemoteDC     = $RemoteDC
                                RemotePing   = $remotePing
                            }
                        } catch {
                            Log-Message "Error pinging $ip $_" "Error"
                        }
                    }
                }
            }
        }
        if ($results) {
            $results | Export-Csv -Path $OutputCsvPath -NoTypeInformation
            Write-Both "Subnet connectivity report generated at $OutputCsvPath"
        } else {
            Write-Both "No results produced for connectivity test or no subnets found."
        }
    }

    $remoteDC = Read-Host "Enter the name of a remote DC to use for ping tests"
    Test-ADSubnetConnectivity -RemoteDC $remoteDC
    Pause
}

function Invoke-ADTimeFix {
    <#
        Updates time settings on the PDC emulator and configures other domain controllers
        to sync with it (from original script).
    #>
    Write-Header "AD Time Fix Process"
    try {
        $fsmo = netdom query fsmo | Out-String
        $pdcLine = $fsmo.Split("`r`n") | Where-Object { $_ -match "^PDC\s" }
        if (-not $pdcLine) {
            Write-Both "PDC role not found in FSMO query output."
            Pause
            return
        }
        $tokens = $pdcLine -split "\s+"
        $pdcName = $tokens[1]
        Write-Both "PDC Emulator: $pdcName"

        $localComp = $env:COMPUTERNAME
        if ($localComp -ieq $pdcName) {
            Write-Both "Running locally on PDC, applying time config here."
            w32tm /config /syncfromflags:manual
            w32tm /config /manualpeerlist:"0.pool.ntp.org,1.pool.ntp.org,2.pool.ntp.org,3.pool.ntp.org"
            w32tm /config /reliable:yes
            net stop w32time; net start w32time
        } else {
            Write-Both "Remotely configuring PDC time on $pdcName"
            $pdcBlock = {
                w32tm /config /syncfromflags:manual
                w32tm /config /manualpeerlist:"0.pool.ntp.org,1.pool.ntp.org,2.pool.ntp.org,3.pool.ntp.org"
                w32tm /config /reliable:yes
                net stop w32time; net start w32time
            }
            Invoke-Command -ComputerName $pdcName -ScriptBlock $pdcBlock
        }
        Import-Module ActiveDirectory
        if (-not (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue)) {
            Write-Both "The Get-ADDomainController command was not found. Please ensure the ActiveDirectory module is installed."
            Pause
            Show-MainMenu
            return
        }
        # Now configure other DCs to sync from domain hierarchy
        $otherDCs = Get-ADDomainController -Filter * | Where-Object { $_.Name -ine $pdcName }
        foreach ($dc in $otherDCs) {
            Write-Both "Configuring time on $($dc.Name)"
            $dcBlock = {
                w32tm /config /syncfromflags:domhier
                w32tm /resync /force
            }
            Invoke-Command -ComputerName $dc.Name -ScriptBlock $dcBlock -ErrorAction SilentlyContinue
        }
        Write-Both "AD Time Fix completed."
    } catch {
        Write-Both "Error in ADTimeFix: $_"
    }
    Pause
}

function Invoke-BPALocalScan {
    <#
        Runs BPA models related to AD roles on the local DC.
    #>
    Write-Header "Running Local BPA Scan"
    Import-Module BestPractices -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-BPAModel -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-BPAModel command was not found. Please ensure the BPA module is installed and this is running on a Domain Controller."
        Pause
        Show-MainMenu
        return
    }
    $models = Get-BpaModel | Where-Object { $_.Id -match "DirectoryServices|DNSServer|DHCPServer|CertificateServices" }
    $results = @()
    foreach ($m in $models) {
        Write-Both "Invoking BPA model: $($m.Id)"
        Invoke-BpaModel $m.Id | Out-Null
        $r = Get-BpaResult $m.Id
        $results += $r
    }
    $outputDir = "C:\ADHealthCheck\BPA"
    Ensure-Folder -Path $outputDir
    $outfile = Join-Path $outputDir "BPA_LocalScanResults.csv"
    $results | Export-Csv -Path $outfile -NoTypeInformation
    Write-Both "Local BPA scan results exported to $outfile"
    Pause
}
function start-gpozaurr {
    $outputDir = "C:\ADHealthCheck\GPOZaurr"
    Ensure-Folder -Path $outputDir

    # 3) Check if GPOZaurr is installed
    if (-not (Get-Module -ListAvailable -Name 'GPOZaurr')) {
        Write-Host "Installing GPOZaurr from PSGallery..." -ForegroundColor Magenta
        try {
            Install-Module GPOZaurr -Force -Verbose
        }
        catch {
            Write-Error "Failed to install GPOZaurr: $_"
            Show-MainMenu
            return
        }
    }

    # 6) Example usage: Invoking GPOZaurr
    Write-Host "Running GPOZaurr" -ForegroundColor Green
        Invoke-GPOZaurr -Verbose 
    Write-Host "GPOZaurr tasks completed. Data is in $outputPath" -ForegroundColor Green
    Show-MainMenu
    return
}

function Invoke-GPOBPASetup {

    <#
    .SYNOPSIS
        Sets up Policy Analyzer plus STIG and Microsoft baseline GPO packages,
        then optionally runs Policy Analyzer.
    
    .DESCRIPTION
        - Checks if the local machine is a Domain Controller.
        - Backs up domain GPOs if on a DC and converts them into a .PolicyRules file.
        - Clears any old .PolicyRules files and downloads the latest STIG GPO package.
        - Downloads and extracts Microsoft baseline packages.
        - Merges STIG GPO backups into a single STIG_GPOs.PolicyRules file.
        - Optionally prompts to launch Policy Analyzer.
        - Now uses C:\ADHealthCheck\PolicyAnalyzer for all operations.
    
    .PARAMETER None
        This function takes no parameters and performs all actions automatically.
    
    .NOTES
        Requires PowerShell 5+ (for Expand-Archive).
        Relies on GPO2PolicyRules.exe from the PolicyAnalyzer.zip package.
    #>
    
        [CmdletBinding()]
        param()
    
        # ----------------------------
        # 1. Define core paths
        # ----------------------------
        $basePath          = 'C:\ADHealthCheck\PolicyAnalyzer'
        $policyAnalyzerPath = Join-Path (Join-Path $basePath 'PolicyAnalyzer_40') 'PolicyAnalyzer.exe'
        $policyRulesFolder  = Join-Path (Join-Path $basePath 'PolicyAnalyzer_40') 'Policy Rules'
        $gpo2PolicyExe      = Join-Path (Join-Path $basePath 'PolicyAnalyzer_40') 'GPO2PolicyRules.exe'
    
        # ----------------------------
        # 2. Ensure main folders exist
        # ----------------------------
        if (!(Test-Path $basePath)) {
            New-Item -ItemType Directory -Path $basePath | Out-Null
            Write-Host "Created folder: $basePath" -ForegroundColor Green
        }
        if (!(Test-Path $policyRulesFolder)) {
            New-Item -ItemType Directory -Path $policyRulesFolder | Out-Null
            Write-Host "Created policy rules folder: $policyRulesFolder" -ForegroundColor Green
        }
    
        # ----------------------------
        # 3. Check Domain Controller & backup GPOs
        # ----------------------------
        function Is-DC {
            try {
                # DomainRole: 4 = Backup DC, 5 = Primary DC
                $domainRole = (Get-WmiObject Win32_ComputerSystem).DomainRole
                return ($domainRole -eq 4 -or $domainRole -eq 5)
            }
            catch {
                Write-Warning "Could not determine Domain Controller role: $_"
                return $false
            }
        }
    
        if (Is-DC) {
            Write-Host "Domain Controller detected. Backing up GPOs..." -ForegroundColor Magenta
            try {
                Import-Module GroupPolicy -ErrorAction Stop
                $allGPOs = Get-GPO -All
                if ($allGPOs) {
                    Write-Host "Found $($allGPOs.Count) GPO(s). Backing them up..." -ForegroundColor Cyan
                    foreach ($gpo in $allGPOs) {
                        Backup-GPO -Name $gpo.DisplayName -Path $policyRulesFolder -ErrorAction Stop
                        Write-Host "Backed up: $($gpo.DisplayName)" -ForegroundColor Green
                    }
                } else {
                    Write-Warning "No GPOs found for backup."
                }
            } catch {
                Write-Warning "Failed to backup GPOs: $_"
            }
        }
        else {
            Write-Host "Not a Domain Controller, skipping GPO backup." -ForegroundColor Yellow
        }
    
        # ----------------------------
        # 4. Download & Extract PolicyAnalyzer FIRST
        # ----------------------------
        $allBaselines = @(
            'https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%20Server%202025%20Security%20Baseline.zip',
            'https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Microsoft%20365%20Apps%20for%20Enterprise%202412.zip',
            'https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20v24H2%20Security%20Baseline.zip',
            'https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20v23H2%20Security%20Baseline.zip',
            'https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20version%2022H2%20Security%20Baseline.zip',
            'https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20Security%20Baseline.zip',
            'https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20Version%201809%20and%20Windows%20Server%202019%20Security%20Baseline.zip'
        )
    
        # Known direct link for PolicyAnalyzer
        $policyAnalyzerLink = 'https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/PolicyAnalyzer.zip'
        Write-Host "`n(1) Downloading and extracting PolicyAnalyzer.zip first..." -ForegroundColor Magenta
    
        $policyAnalyzerZip = Join-Path $basePath 'PolicyAnalyzer.zip'
        try {
            Write-Host "Downloading PolicyAnalyzer.zip..." -ForegroundColor Cyan
            Invoke-WebRequest -Uri $policyAnalyzerLink -OutFile $policyAnalyzerZip
    
            Write-Host "Extracting PolicyAnalyzer to $($basePath + '\PolicyAnalyzer')" -ForegroundColor Cyan
            $paExtractPath = $basePath
            if (!(Test-Path $paExtractPath)) {
                New-Item -ItemType Directory -Path $paExtractPath | Out-Null
            }
    
            Expand-Archive -Path $policyAnalyzerZip -DestinationPath $paExtractPath -Force
            Write-Host "Policy Analyzer extracted." -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to download/extract PolicyAnalyzer.zip: $_"
        }
    
        # ----------------------------
        # 5. Clear out old .PolicyRules AFTER extracting
        # ----------------------------
        Write-Host "`n(2) Clearing out old .PolicyRules files..." -ForegroundColor Magenta
        if (Test-Path $policyRulesFolder) {
            Get-ChildItem -Path $policyRulesFolder -Filter *.PolicyRules -File -ErrorAction SilentlyContinue | Remove-Item -Force
            Write-Host "Cleared old .PolicyRules in: $policyRulesFolder" -ForegroundColor Yellow
        } else {
            New-Item -ItemType Directory -Path $policyRulesFolder | Out-Null
            Write-Host "Created missing folder: $policyRulesFolder" -ForegroundColor Green
        }
    
        # ----------------------------
        # 6. Convert DC GPO backups (if any) using GPO2PolicyRules
        # ----------------------------
        if (Is-DC) {
            if (Test-Path $gpo2PolicyExe) {
                Write-Host "Converting Domain GPO backups to Domain_GPOs.PolicyRules..." -ForegroundColor Magenta
                $outputPolicyFile = Join-Path $policyRulesFolder 'Domain_GPOs.PolicyRules'
                & $gpo2PolicyExe $policyRulesFolder $outputPolicyFile
                if (Test-Path $outputPolicyFile) {
                    Write-Host "Created: $outputPolicyFile" -ForegroundColor Green
                } else {
                    Write-Warning "Failed to create Domain_GPOs.PolicyRules"
                }
            } else {
                Write-Warning "GPO2PolicyRules.exe not found after extraction."
            }
        }
    
        # ----------------------------
        # 7. Find the latest STIG GPO zip & prepare for downloads
        # ----------------------------
        Write-Host "`n(3) Checking for latest STIG GPO zip..." -ForegroundColor Magenta
        $stigBaseUrl = 'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/'
        $defaultStigLink = 'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_STIG_GPO_Package_January_2025.zip'
    
        $global:downloadList = New-Object System.Collections.ArrayList
        [void]$global:downloadList.AddRange($allBaselines)
    
        try {
            $listing = Invoke-WebRequest -Uri $stigBaseUrl -UseBasicParsing -ErrorAction Stop
            $regex   = 'U_STIG_GPO_Package_.*?\.zip'
            $files   = $listing.Links | Where-Object { $_.href -match $regex } | ForEach-Object { $_.href }
    
            if (!$files) {
                Write-Warning "No STIG GPO zip files found at $stigBaseUrl"
                Write-Host "Using fallback STIG link: $defaultStigLink" -ForegroundColor Yellow
                [void]$global:downloadList.Add($defaultStigLink)
            } else {
                $latestStig = $files | Sort-Object | Select-Object -Last 1
                if ($latestStig) {
                    $fullStigUrl = $stigBaseUrl + $latestStig
                    Write-Host "Latest STIG GPO zip: $fullStigUrl" -ForegroundColor Cyan
                    [void]$global:downloadList.Add($fullStigUrl)
                }
            }
        }
        catch {
            Write-Warning "Failed to parse STIG zip listing: $_"
            Write-Host "Using fallback STIG link: $defaultStigLink" -ForegroundColor Yellow
            [void]$global:downloadList.Add($defaultStigLink)
        }
    
        # ----------------------------
        # 8. Download/extract the baselines + STIG
        # ----------------------------
        Write-Host "`n(4) Downloading and extracting baselines + STIG if found..." -ForegroundColor Magenta
        foreach ($url in $global:downloadList) {
            try {
                $originalFileName = Split-Path -Path $url -Leaf
                $cleanFileName    = $originalFileName -replace '%20', '_'
                $destinationZip   = Join-Path $basePath $cleanFileName
    
                Write-Host "`nDownloading $cleanFileName ..." -ForegroundColor Magenta
                Invoke-WebRequest -Uri $url -OutFile $destinationZip
    
                $folderName      = [System.IO.Path]::GetFileNameWithoutExtension($cleanFileName)
                $baselinesFolder = Join-Path (Join-Path $basePath 'PolicyAnalyzer_40') 'Baselines'
                if (!(Test-Path $baselinesFolder)) {
                    New-Item -ItemType Directory -Path $baselinesFolder | Out-Null
                }
                $extractPath = Join-Path $baselinesFolder $folderName
    
                Write-Host "Extracting $cleanFileName to $extractPath" -ForegroundColor Cyan
                Expand-Archive -Path $destinationZip -DestinationPath $extractPath -Force
    
                # If STIG GPO package, convert to STIG_GPOs.PolicyRules
                if ($cleanFileName -match '^U_STIG_GPO_Package_.*\.zip$') {
                    if (Test-Path $gpo2PolicyExe) {
                        Write-Host "Converting STIG GPO backups to STIG_GPOs.PolicyRules..." -ForegroundColor Magenta
                        $stigOutputPolicyFile = Join-Path $policyRulesFolder 'STIG_GPOs.PolicyRules'
                        & $gpo2PolicyExe $extractPath $stigOutputPolicyFile
                        if (Test-Path $stigOutputPolicyFile) {
                            Write-Host "Created STIG .PolicyRules: $stigOutputPolicyFile" -ForegroundColor Green
                        } else {
                            Write-Warning "Failed to create STIG_GPOs.PolicyRules"
                        }
                    } else {
                        Write-Warning "Could not find GPO2PolicyRules.exe. Skipping STIG conversion."
                    }
                }
    
                # Copy any .PolicyRules files from the extracted folder
                $allPolicyRules = Get-ChildItem -Path $extractPath -Recurse -Include *.PolicyRules -File -ErrorAction SilentlyContinue
                if ($allPolicyRules) {
                    Write-Host "Found PolicyRules files in $extractPath" -ForegroundColor Green
                    foreach ($ruleFile in $allPolicyRules) {
                        Write-Host "  Copying '$($ruleFile.FullName)'" -ForegroundColor Green
                        $destination = Join-Path $policyRulesFolder $ruleFile.Name
                        Copy-Item $ruleFile.FullName -Destination $destination -Force
                    }
                } else {
                    Write-Host "No .PolicyRules files found under $extractPath" -ForegroundColor Yellow
                }
    
                Write-Host "Done processing $cleanFileName" -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed to process $url. Error: $_"
            }
        }
    
        Write-Host "`nAll baseline/STIG downloads and extractions complete!" -ForegroundColor Green
        Start-Sleep 2
    
        # ----------------------------
        # 9. Prompt to launch Policy Analyzer
        # ----------------------------
        if (Test-Path $policyAnalyzerPath) {
            $userChoice = Read-Host "`nWould you like to run Policy Analyzer now? (Y/N)"
            if ($userChoice -match '^(Y|y)$') {
                Write-Host "Launching Policy Analyzer..." -ForegroundColor Magenta
                Start-Process $policyAnalyzerPath
            } else {
                Write-Host "Policy Analyzer launch skipped." -ForegroundColor Yellow
            }
        } else {
            Write-Host "Policy Analyzer.exe not found at $policyAnalyzerPath" -ForegroundColor Red
        }
    }
    
function Invoke-BPARemoteScan {
    <#
        Runs BPA models for AD roles on each DC remotely.
    #>
    Write-Header "Running Remote BPA Scan on All DCs"
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    Import-Module BestPractices -ErrorAction SilentlyContinue | Out-Null

    $modelFilter = "DirectoryServices|DNSServer|DHCPServer|CertificateServices"
    $dcResults = @()
    $allDCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName

    foreach ($dc in $allDCs) {
        Write-Both "Scanning DC: $dc"
        try {
            $remoteResults = Invoke-Command -ComputerName $dc -ScriptBlock {
                param($modelFilter)
                Import-Module BestPractices -ErrorAction SilentlyContinue | Out-Null
                $localResults = @()
                $filteredModels = Get-BpaModel | Where-Object { $_.Id -match $modelFilter }
                foreach ($mod in $filteredModels) {
                    Invoke-BpaModel $mod.Id | Out-Null
                    $localResults += Get-BpaResult $mod.Id
                }
                return $localResults
            } -ArgumentList $modelFilter -ErrorAction Stop
            foreach ($r in $remoteResults) {
                $r | Add-Member -MemberType NoteProperty -Name "DC" -Value $dc -Force
                $dcResults += $r
            }
        } catch {
            Write-Both "Failed scanning $dc $_"
        }
    }
    $outputDir = "C:\ADHealthCheck\BPA"
    Ensure-Folder -Path $outputDir
    $outfile = Join-Path $outputDir "BPA_RemoteCombinedScanResults.csv"
    $dcResults | Export-Csv -Path $outfile -NoTypeInformation
    Write-Both "Remote BPA scan results combined and exported to $outfile"
    Pause
    Show-MainMenu
    return
}

#endregion

######################################################################################
# SECTION 3: NON-DUPLICATED FUNCTIONS FROM ADAudit.ps1
# (Renamed as "Invoke-" style for consistency)
######################################################################################

function Invoke-SYSVOLGPPPasswordCheck {
    <#
      Original "Get-SYSVOLXMLS" renamed to "Invoke-SYSVOLGPPPasswordCheck"
      Checks SYSVOL for GPP cpassword in XML files.
    #>
    Write-Header "Check SYSVOL for cpassword in GPP XMLs"
    $outputDir = "C:\ADHealthCheck\SYSVOL"
    Ensure-Folder -Path $outputDir

    $xmlFiles = Get-ChildItem -Path "\\$env:USERDNSDOMAIN\SYSVOL" -Recurse -ErrorAction SilentlyContinue -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml'
    if ($xmlFiles) {
        $foundCount = 0
        foreach ($file in $xmlFiles) {
            $xml = try { [xml](Get-Content -Path $file.FullName) } catch { $null }
            if ($xml -and ($xml.InnerXml -like "*cpassword*" -and $xml.InnerXml -notlike '*cpassword=""*')) {
                $destName = $file.Name + "_" + (Get-Date -Format "yyyyMMddHHmmss")
                Copy-Item -Path $file.FullName -Destination (Join-Path $outputDir $destName) -Force
                Write-Both "[!] Found cpassword in: $($file.FullName). Copied to $destName"
                $foundCount++
            }
        }
        if ($foundCount -eq 0) {
            Write-Both "No cpassword entries found in discovered GPP XMLs."
        }
    }
    else {
        Write-Both "No GPP XML files or cannot read SYSVOL."
    }
    Pause
}

function Invoke-LAPSStatusCheck {
    <#
      Original "Get-LAPSStatus"
      Checks if LAPS is installed, which machines are missing ms-Mcs-AdmPwd, etc.
    #>
    Write-Header "Check for LAPS usage"
    $outputDir = "C:\ADHealthCheck\LAPS"
    Ensure-Folder -Path $outputDir

    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADObject -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADObject command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    try {
        Get-ADObject "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,$((Get-ADDomain).DistinguishedName)" -ErrorAction Stop | Out-Null
        Write-Both "[+] LAPS attribute found (ms-Mcs-AdmPwd)."
    } catch {
        Write-Both "[!] LAPS Not Installed or not detected in schema."
    }

    if (Get-Module -ListAvailable -Name "AdmPwd.PS") {
        Import-Module AdmPwd.PS -Force
        $missing = Get-ADComputer -Filter { ms-Mcs-AdmPwd -notlike "*" }
        if ($missing) {
            $missing | Select-Object -ExpandProperty Name | Out-File (Join-Path $outputDir "laps_missing-computers.txt")
            Write-Both "[!] Some computers do not have LAPS password set, see laps_missing-computers.txt"
        } else {
            Write-Both "All discovered computers appear to store LAPS password."
        }
    } else {
        Write-Both "AdmPwd.PS module not found, skipping advanced LAPS checks."
    }
    Pause
}

function Invoke-OUPermsCheck {
    <#
      Original "Get-OUPerms"
      Checks for non-standard ACL perms on OUs for Authenticated Users, Domain Users, Everyone.
    #>
    Write-Header "Check for non-standard OU permissions"
    $outputDir = "C:\ADHealthCheck\OUperms"
    Ensure-Folder -Path $outputDir
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADObject -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADObject command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    try {
        $count = 0
        $objects = Get-ADObject -Filter * -SearchBase (Get-ADDomain).DistinguishedName
        foreach ($obj in $objects) {
            try {
                $acl = Get-Acl ("AD:\" + $obj.DistinguishedName)
                $perm = $acl.Access | Where-Object {
                    ($_.IdentityReference -match "Authenticated Users" -or
                     $_.IdentityReference -match "Everyone" -or
                     $_.IdentityReference -match "Domain Users" -or
                     $_.IdentityReference -match "BUILTIN\\Users") -and
                    ($_.ActiveDirectoryRights -notin 'GenericRead','GenericExecute','ExtendedRight','ReadControl','ReadProperty','ListObject','ListChildren','ListChildren, ReadProperty, ListObject','ReadProperty, GenericExecute') -and
                    ($_.AccessControlType -ne 'Deny')
                }
                if ($perm) {
                    Add-Content -Path (Join-Path $outputDir "ou_permissions.txt") -Value "OU: $($obj.DistinguishedName)"
                    Add-Content -Path (Join-Path $outputDir "ou_permissions.txt") -Value "   Rights: $($perm.IdentityReference) $($perm.ActiveDirectoryRights) $($perm.AccessControlType)"
                    $count++
                }
            } catch {}
        }
        if ($count -gt 0) {
            Write-Both "[!] Found $count OU(s) with suspicious ACL entries. See ou_permissions.txt"
        } else {
            Write-Both "No suspicious OU ACL perms found."
        }
    } catch {
        Write-Both "[!] Error enumerating OUs: $_"
    }
    Pause
}

function Invoke-SPNsCheck {
    <#
      Original "Get-SPNs"
      Checks for potential high-value kerberoastable SPN accounts in Domain Admins or Enterprise Admins.
    #>
    Write-Header "Check for high-value kerberoastable SPN accounts"
    $outputDir = "C:\ADHealthCheck\SPNs"
    Ensure-Folder -Path $outputDir

    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADUser command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    $allUsers = Get-ADUser -Filter { ServicePrincipalName -like "*" } -Properties ServicePrincipalName,MemberOf
    $results = @()
    foreach ($u in $allUsers) {
        $grpNames = $u.MemberOf | ForEach-Object {
            (Get-ADGroup $_ -ErrorAction SilentlyContinue).SamAccountName
        }
        if ($grpNames -contains "Domain Admins" -or $grpNames -contains "Enterprise Admins") {
            $results += "$($u.SamAccountName) ($($u.Name))"
        }
    }

    if ($results) {
        $results | Out-File (Join-Path $outputDir "HighValueSPNs.txt")
        Write-Both "[!] Found potential high-value kerberoastable accounts. See HighValueSPNs.txt"
    } else {
        Write-Both "No high-value SPNs found or enumeration incomplete."
    }
    Pause
}

function Invoke-ASREPCheck {
    <#
      Original "Get-ADUsersWithoutPreAuth"
      Lists AS-REP roastable (DoesNotRequirePreAuth= True).
    #>
    Write-Header "Check for AS-REP roastable accounts"
    $outputDir = "C:\ADHealthCheck\ASREP"
    Ensure-Folder -Path $outputDir

    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADUser command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    $users = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true -and Enabled -eq $true } -Properties DoesNotRequirePreAuth
    if ($users) {
        $users | Select-Object SamAccountName,Name | Out-File (Join-Path $outputDir "ASREPAccounts.txt")
        Write-Both "[!] Found $($users.Count) user(s) that do not require pre-auth. See ASREPAccounts.txt"
    } else {
        Write-Both "No AS-REP roastable accounts found."
    }
    Pause
}

function Invoke-DCsOwnershipCheck {
    <#
      Original "Get-DCsNotOwnedByDA"
      Quick check if DC objects are not owned by the Domain Admins group.
    #>
    Write-Header "Check if DC machine accounts are not owned by Domain Admins group"
    $outputDir = "C:\ADHealthCheck\DCsOwnership"
    Ensure-Folder -Path $outputDir

    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADComputer -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADComputer command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    $results = @()
    $dcs = Get-ADComputer -Filter { PrimaryGroupID -eq 516 -or PrimaryGroupID -eq 521 } -Properties nTSecurityDescriptor
    foreach ($dc in $dcs) {
        $owner = $dc.nTSecurityDescriptor.Owner
        if ($owner -notmatch "Domain Admins") {
            $results += "$($dc.Name) is owned by $owner"
        }
    }
    if ($results) {
        $results | Out-File (Join-Path $outputDir "dcs_not_owned_by_da.txt")
        Write-Both "[!] Found DCs not owned by Domain Admins group. See dcs_not_owned_by_da.txt"
    } else {
        Write-Both "All DCs appear properly owned by Domain Admins."
    }
    Pause
}

function Invoke-LDAPSecurityCheck {
    <#
      Original "Get-LDAPSecurity"
      Checks LDAP signing, LDAPS usage, channel binding, attempts an anonymous LDAP bind
    #>
    Write-Header "Check for LDAP Security Settings"
    $outputDir = "C:\ADHealthCheck\LDAPSecurity"
    Ensure-Folder -Path $outputDir

    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
        Write-Both "The Get-ADUser command was not found. Please ensure the ActiveDirectory module is installed."
        Pause
        Show-MainMenu
        return
    }
    # 1) LDAP signing (LDAPServerIntegrity)
    try {
        $ldapSigning = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -ErrorAction Stop).LDAPServerIntegrity
        if ($ldapSigning -eq 2) {
            Write-Both "LDAP signing enforced."
        } else {
            Write-Both "[!] LDAP signing not fully enforced. Value: $ldapSigning"
        }
    } catch {
        Write-Both "[!] Could not read LDAP signing registry value."
    }

    # 2) LDAPS cert check
    try {
        $serverAuthOid = '1.3.6.1.5.5.7.3.1'
        $ldapsCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
            $_.Extensions | Where-Object { $_.Oid.Value -eq $serverAuthOid }
        }
        if ($ldapsCert) {
            Write-Both "LDAPS certificate found in local machine store."
        } else {
            Write-Both "[!] No server auth cert found for LDAPS."
        }
    } catch {
        Write-Both "[!] Error enumerating LDAPS cert."
    }

    # 3) Channel binding
    try {
        $channelBind = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -ErrorAction Stop).LdapEnforceChannelBinding
        if ($channelBind -eq 2) {
            Write-Both "LDAPS channel binding enforced."
        } else {
            Write-Both "[!] LDAPS channel binding not enforced. Value: $channelBind"
        }
    } catch {
        Write-Both "[!] Could not read channel binding registry value."
    }

    # 4) Attempt anonymous bind
    try {
        Add-Type -AssemblyName System.DirectoryServices.Protocols
        $dc = (Get-ADDomainController -Discover).HostName
        $conn = New-Object System.DirectoryServices.Protocols.LdapConnection("$dc:389")
        $conn.Timeout = [TimeSpan]::FromSeconds(5)
        $anonCred = New-Object System.Net.NetworkCredential("","")
        $conn.Bind($anonCred)
        Write-Both "[!] Anonymous LDAP bind succeeded on $dc:389"
    } catch [System.DirectoryServices.Protocols.LdapException] {
        Write-Both "Null LDAP bind not allowed on $dc:389"
    } catch {
        Write-Both "[!] Error testing anonymous bind: $_"
    }
    Pause
}
function Configure-MDIEnvironment {
    <#
    .SYNOPSIS
        Presents a menu to run key DefenderForIdentity commands.

    .DESCRIPTION
        Ensures that the DefenderForIdentity module is installed or updated.
        Then it displays a menu with options for running:
            - Get-MDIConfiguration
            - New-MDIConfigurationReport
            - New-MDIDSA
            - Set-MDIConfiguration -Mode Domain -Configuration All -Identity MDIgMSAsvc01 (or user-specified)
            - Test-MDIConfiguration -Mode Domain -Configuration All
            - Test-MDIDSA -Identity "MDIgMSAsvc01" (or user-specified) -Detailed
            - Test-MDISensorApiConnection
        Lets the user pick from a menu to execute each command, optionally
        prompting for a service account name.

    .EXAMPLE
        PS> Configure-MDIEnvironment
        # Displays the menu and prompts user for input.
    #>

    [CmdletBinding()]
    param()

    # 1. Ensure DefenderForIdentity module is installed or updated
    $moduleName = "DefenderForIdentity"

    Write-Host "Checking if $moduleName module is installed..."
    $moduleCheck = Get-Module -ListAvailable -Name $moduleName | Select-Object -First 1
    if (-not $moduleCheck) {
        Write-Host "Module '$moduleName' not found. Installing..." -ForegroundColor Yellow
        try {
            Install-Module -Name $moduleName -Force -ErrorAction Stop
        }
        catch {
            Write-Error "Failed to install $moduleName $_"
            return
        }
    }
    else {
        Write-Host "Module '$moduleName' found. Attempting to update to latest version..." -ForegroundColor Yellow
        try {
            Update-Module -Name $moduleName -ErrorAction SilentlyContinue
        } catch {
            Write-Warning "Could not update $moduleName $_"
        }
    }

    # Import the module
    try {
        Import-Module $moduleName -ErrorAction Stop
        Write-Host "Imported module $moduleName successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to import $moduleName after installation: $_"
        return
    }

    Write-Host "`nWelcome to the Microsoft Defender for Identity Configuration Menu." -ForegroundColor Cyan

    do {
        Write-Host "`nPlease choose from the following options:" -ForegroundColor Cyan
        Write-Host "1) Get MDI Configuration"
        Write-Host "2) Generate MDI Configuration Report"
        Write-Host "3) Create New MDI DSA (Default: MDIgMSAsvc01)"
        Write-Host "4) Set MDI Configuration (Domain, All) for MDIgMSAsvc01 or user choice"
        Write-Host "5) Test MDI Configuration (Domain, All)"
        Write-Host "6) Test MDI DSA (Default: MDIgMSAsvc01) -Detailed"
        Write-Host "7) Test MDI Sensor API Connection"
        Write-Host "0) Exit"

        $choice = Read-Host "Enter your selection (0 to exit)"

        switch ($choice) {
            "1" {
                Write-Host "`nRunning: Get-MDIConfiguration..." -ForegroundColor Yellow
                try {
                    $conf = Get-MDIConfiguration
                    if ($conf) {
                        $conf | Format-Table -AutoSize
                    } else {
                        Write-Host "No MDI configuration found or command returned nothing." -ForegroundColor Red
                    }
                } catch {
                    Write-Host "Error executing Get-MDIConfiguration: $_" -ForegroundColor Red
                }
            }
            "2" {
                Write-Host "`nRunning: New-MDIConfigurationReport..." -ForegroundColor Yellow
                $outputFolder = Read-Host "Specify the folder path where you'd like the MDI report generated"
                if (-not (Test-Path $outputFolder)) {
                    try {
                        New-Item -ItemType Directory -Path $outputFolder | Out-Null
                    } catch {
                        Write-Host "Could not create directory '$outputFolder': $_" -ForegroundColor Red
                        break
                    }
                }
                try {
                    New-MDIConfigurationReport -OutputFolder $outputFolder -HtmlReportName "MDI_Config.html" -JsonReportName "MDI_Config.json"
                    Write-Host "MDI configuration report generated at $outputFolder" -ForegroundColor Green
                } catch {
                    Write-Host "Error executing New-MDIConfigurationReport: $_" -ForegroundColor Red
                }
            }
            "3" {
                Write-Host "`nRunning: New-MDIDSA..." -ForegroundColor Yellow
                $svcAccount = Read-Host "Enter the MDI service account name (press ENTER to use default 'MDIgMSAsvc01')"
                if ([string]::IsNullOrWhiteSpace($svcAccount)) {
                    $svcAccount = "MDIgMSAsvc01"
                }
                try {
                    New-MDIDSA -SamAccountName $svcAccount
                    Write-Host "Successfully created MDI DSA '$svcAccount'." -ForegroundColor Green
                } catch {
                    Write-Host "Error executing New-MDIDSA: $_" -ForegroundColor Red
                }
            }
            "4" {
                Write-Host "`nRunning: Set-MDIConfiguration -Mode Domain -Configuration All..." -ForegroundColor Yellow
                $svcAccount = Read-Host "Enter the MDI service account name (press ENTER to use default 'MDIgMSAsvc01')"
                if ([string]::IsNullOrWhiteSpace($svcAccount)) {
                    $svcAccount = "MDIgMSAsvc01"
                }
                try {
                    Set-MDIConfiguration -Mode Domain -Configuration All -Identity $svcAccount
                    Write-Host "MDI Configuration set successfully for '$svcAccount'." -ForegroundColor Green
                } catch {
                    Write-Host "Error executing Set-MDIConfiguration: $_" -ForegroundColor Red
                }
            }
            "5" {
                Write-Host "`nRunning: Test-MDIConfiguration -Mode Domain -Configuration All..." -ForegroundColor Yellow
                try {
                    $testResults = Test-MDIConfiguration -Mode Domain -Configuration All
                    $testResults | Format-Table -AutoSize
                } catch {
                    Write-Host "Error executing Test-MDIConfiguration: $_" -ForegroundColor Red
                }
            }
            "6" {
                Write-Host "`nRunning: Test-MDIDSA -Detailed..." -ForegroundColor Yellow
                $svcAccount = Read-Host "Enter the MDI service account name (press ENTER to use default 'MDIgMSAsvc01')"
                if ([string]::IsNullOrWhiteSpace($svcAccount)) {
                    $svcAccount = "MDIgMSAsvc01"
                }
                try {
                    $dsaTest = Test-MDIDSA -Identity $svcAccount -Detailed
                    $dsaTest | Format-List
                } catch {
                    Write-Host "Error executing Test-MDIDSA: $_" -ForegroundColor Red
                }
            }
            "7" {
                Write-Host "`nRunning: Test-MDISensorApiConnection..." -ForegroundColor Yellow
                try {
                    $apiResult = Test-MDISensorApiConnection
                    $apiResult | Format-List
                } catch {
                    Write-Host "Error executing Test-MDISensorApiConnection: $_" -ForegroundColor Red
                }
            }
            "0" {
                Write-Host "Exiting..." -ForegroundColor Cyan
            }
            default {
                Write-Host "Invalid choice, please try again." -ForegroundColor Red
            }
        }
    } while ($choice -ne '0')
      Pause
      Show-MainMenu
      return
}

function Show-MainMenu {
    Clear-Host

    #
    # QUISITIVE ASCII ART + "AD AUDIT TOOL"
    #
    Write-Host " / __ \      (_)   (_) | (_)" -ForegroundColor Green
    Write-Host "| |  | |_   _ _ ___ _| |_ ___   _____ " -ForegroundColor Green
    Write-Host "| |  | | | | | / __| | __| \ \ / / _ \" -ForegroundColor Green
    Write-Host "| |__| | |_| | \__ \ | |_| |\ V /  __/" -ForegroundColor Green
    Write-Host " \___\_\\__,_|_|___/_|\__|_| \_/ \___|" -ForegroundColor Green

    Write-Host "======================================================" -ForegroundColor Cyan
    Write-Host " Comprehensive AD Audit Script" -ForegroundColor Cyan
    Write-Host "======================================================" -ForegroundColor Cyan
    Write-Host ""

    # -- GPO & Policy Checks (1-6) --
    Write-Host "==== GPO & Policy Checks ====" -ForegroundColor Green
    Write-Host "  1) Scan GPOs for Unknown (Orphaned) Accounts"            -ForegroundColor Cyan
    Write-Host "  2) Scan GPOs for Password Policies"                      -ForegroundColor Cyan
    Write-Host "  3) Scan Overlapping GPO Policy Settings Scan"            -ForegroundColor Cyan
    Write-Host "  4) SYSVOL GPP cpassword Check (from ADAudit)"            -ForegroundColor Cyan
    Write-Host "  5) Install and Launch GPOZaurr"                          -ForegroundColor Cyan
    Write-Host "  6) Microsoft Policy Analyzer Setup and Ready"            -ForegroundColor Cyan

    Write-Host ""

    # -- Base Security & DC Health (7-19) --
    Write-Host "==== Base Security & DC Health ===="                       -ForegroundColor Green
    Write-Host "  7)  Review Base Security Settings"                       -ForegroundColor Cyan
    Write-Host "  8)  Summarize DC Event Errors"                           -ForegroundColor Cyan
    Write-Host "  9)  All DCs DCDiag Tests"                                -ForegroundColor Cyan
    Write-Host " 10)  AD Forest Health Check"                              -ForegroundColor Cyan
    Write-Host " 11)  DC Egress (WAN) IPs"                                 -ForegroundColor Cyan
    Write-Host " 12)  LDAP/LDAPS Connectivity Check"                       -ForegroundColor Cyan
    Write-Host " 13)  Best Practice DNS vs AD Sites/Subnets Check"         -ForegroundColor Cyan
    Write-Host " 14)  LAPS Status Check (from ADAudit)"                    -ForegroundColor Cyan
    Write-Host " 15)  OU Permissions Check (from ADAudit)"                 -ForegroundColor Cyan
    Write-Host " 16)  SPN (Kerberoast) Check (from ADAudit)"               -ForegroundColor Cyan
    Write-Host " 17)  AS-REP (DoesNotRequirePreAuth) Check (from ADAudit)" -ForegroundColor Cyan
    Write-Host " 18)  DC Ownership Check (from ADAudit)"                   -ForegroundColor Cyan
    Write-Host " 19)  LDAP Security Check (from ADAudit)"                  -ForegroundColor Cyan

    Write-Host ""

    # -- BPA Scans & Discovery (20-23) --
    Write-Host "==== BPA Scans & Discovery ===="                          -ForegroundColor Yellow
    Write-Host " 20) DC Discovery Script (Hardware/Software/NIC Info)"    -ForegroundColor Cyan
    Write-Host " 21) BPA Scan (Local) - AD Roles"                         -ForegroundColor Cyan
    Write-Host " 22) BPA Scan (Remote) - AD Roles"                        -ForegroundColor Cyan
    Write-Host " 23) AD Recon Quiet Audit from Member Server orDesktop (Red Team)"  -ForegroundColor Cyan

    Write-Host ""

    # -- Administration Scripts - These make changes so use carefully. (24-26) --
    Write-Host "==== AD Maintenance / FSMO / OU Protection ===="          -ForegroundColor Yellow
    Write-Host " 24) Move FSMO Roles"                                     -ForegroundColor Cyan
    Write-Host " 25) Protect OUs from Accidental Deletion"                -ForegroundColor Cyan
    Write-Host " 26) Fix AD Time Settings on Domain Controllers"          -ForegroundColor Cyan
    Write-Host " 27) Prepare AD for MDI Deployment"                       -ForegroundColor Cyan
    Write-Host ""
    Write-Host " 28) Exit"
    Write-Host ""
}

do {
    Show-MainMenu
    $choice = Read-Host "Enter selection (1-28)"

    switch ($choice) {

        # -- GPO & Policy Checks (1-6) --
        1 { Invoke-ScanGPOsUnknownAccounts }
        2 { Invoke-ScanGPOPasswordPolicies }
        3 { Invoke-GPOPolicyOverlapScan }
        4 { Invoke-SYSVOLGPPPasswordCheck }
        5 { start-gpozaurr }  # ← New function
        6 { Invoke-GPOBPASetup }  # ← New function

        # -- Base Security & DC Health (7-19) --
        7  { Invoke-ReviewBaseSecurity }
        8  { Invoke-DCEventErrorSummary }
        9  { Invoke-AllDCDiagTests }
        10 { Invoke-ForestHealthCheck }
        11 { Invoke-GetDCEgressWANIPs }
        12 { Invoke-LDAPLDAPSCheck }
        13 { Invoke-BestPracticeDNSSiteSubnetCheck }
        14 { Invoke-LAPSStatusCheck }
        15 { Invoke-OUPermsCheck }
        16 { Invoke-SPNsCheck }
        17 { Invoke-ASREPCheck }
        18 { Invoke-DCsOwnershipCheck }
        19 { Invoke-LDAPSecurityCheck }

        # -- BPA Scans & Discovery (20-23) --
        20 { Invoke-DiscoveryScript }
        21 { Invoke-BPALocalScan }
        22 { Invoke-BPARemoteScan }
        23 { Invoke-QuietAuditRedTeam }

        # -- AD Maintenance / FSMO / OU (24-26) --
        24 { Invoke-MoveFSMORoles }
        25 { Invoke-ProtectOUs }
        26 { Invoke-ADTimeFix }
        27 { Configure-MDIEnvironment }

        28 {
            Write-Host "Exiting..."
            break
        }

        default {
            Write-Host "Invalid choice."
            Pause
        }
    }
} while ($choice -ne 28)

Write-Host "Done, Thank you for using, we enjoy feedback and suggestions please drop us a line." -ForegroundColor Green
