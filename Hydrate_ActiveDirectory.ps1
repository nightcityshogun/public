<#
.SYNOPSIS
    This PowerShell script is to be used as a last resort for hydrating a clean-built Active Directory Domain Services (AD DS) environment from Microsoft Entra ID following a systemic identity compromise or ransomware attack.

.DESCRIPTION
    The script performs the following actions:
    - Connects to Microsoft Entra ID and exports user information to a CSV file.
    - Uses the exported user data to create accounts in Active Directory Domain Services (AD DS).
    - Dynamically discovers the Active Directory domain and organisational unit (OU) structure, ensuring accounts are placed in the correct OUs.
    - Generates unique user accounts in AD DS, ensuring no duplicates are created.
    - Generates secure, random passwords for each new account, ensuring compliance with password complexity standards (lowercase, uppercase, numbers, and special characters).
    - Updates the ms-DS-ConsistencyGuid in AD DS with the Object GUID to facilitate account linking between AD DS and Microsoft Entra ID.
    - Logs all operations to a log file, including successes, warnings, and errors.
    - Provides a menu-driven interface to choose between exporting users, hydrating Active Directory, updating the Immutable ID, or exiting the script.

.PARAMETER PasswordLength
    Specifies the length of the randomly generated password. Default is 24 characters.

.NOTES
    Author: NightCityShogun
    Name: Hydrate_ActiveDirectory
    Version: 1.5
    Date: 2023-12-15
#>

# ------------------------------------------------------------------------------------------------------------------------

# Add PasswordLength parameter with default value of 24
param (
    [int]$PasswordLength = 24
)

# Variables
$modules = @(
  "Microsoft.Graph.Authentication",
  "Microsoft.Graph.Identity.DirectoryManagement",
  "Microsoft.Graph.Identity.Governance",
  "Microsoft.Graph.Users"
)

# Microsoft Graph API Scope and Permissions
$Scopes = @("Directory.Read.All",
"User.ReadBasic.All",
"User.Read.All")

# Microsoft Graph Environment Options
$validEnvironments = @("China", "Global", "USGov", "USGovDoD")

# Password Configuration
$Lowercase = "abcdefghijkmnopqrstuvwxyz"
$Uppercase = "ABCDEFGHJKLMNOPQRSTUVWXYZ"
$Numbers = "0123456789"
$Symbols = '@#$%^&*-_=+[]{}|:,''.?/`~";()<>'
$AllChars = $Lowercase + $Uppercase + $Numbers + $Symbols

# Organisational Unit Empty Array
$uniqueOUPaths = @{}
$createdOUs = @{}
$ouData = @{}

# NCS Log File Path
$logDirectory = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Temp\NCS"
$logFilePath = Join-Path -Path $logDirectory -ChildPath ("NCS_Log_" + (Get-Date -Format "yyyyMMdd") + ".log")

# Export File Path
$csvFilePath = Join-Path -Path $PSScriptRoot -ChildPath ("Hydrate_ActiveDirectory_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".csv")

# Import Data for Hydration
$csvFilePattern = "hydrate_ActiveDirectory_*.csv"

# ------------------------------------------------------------------------------------------------------------------------

# Ensure the NCS Log Directory Exists in $env:LOCALAPPDATA\Temp
if (!(Test-Path -Path $logDirectory)) {
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
}

# Function to Write Log File Entries
function Write-Log {
    param (
        [string]$Message,
        [ValidateSet("SOS", "ERROR", "INFO", "WARNING", "IMPORTANT")]
        [string]$Level = "INFO",
        [bool]$LogOnly = $false  
    )

    $logEntry = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Add-Content -Path $logFilePath -Value $logEntry

    if (-not $LogOnly) {
        # Define colors for each log level
        $logColor = @{
            "SOS"        = [System.ConsoleColor]::Green
            "ERROR"      = [System.ConsoleColor]::Red
            "INFO"       = [System.ConsoleColor]::White
            "WARNING"    = [System.ConsoleColor]::Yellow
            "IMPORTANT"  = [System.ConsoleColor]::Cyan
        }[$Level]

        # Write the log entry to the console with the specified color
        Write-Host -ForegroundColor $logColor $logEntry
    }
}

# Mark the Start of the Script
Write-Log -Message "[SCRIPT] Start of Hydrate_ActiveDirectory Script." -Level "SOS"

# Function: Check OS Architecture
function Check-OSArchitecture {
    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $architecture = $osInfo.OSArchitecture

        if ($architecture -match "ARM") {
            Write-Log -Message "[UNSUPPORTED] This script requires x64 or x86 architecture to install RSAT tools." -Level "ERROR"
            exit
        } else {
            Write-Log -Message "[SUPPORTED] OS architecture detected: $architecture." -Level "IMPORTANT"
        }
    } catch {
        Write-Log -Message "[UNKNOWN] Failed to determine OS architecture. Error: $_" -Level "ERROR"
        exit
    }
}

# Function: Install RSAT Tools
function Install-RSAT {
    try {
        Write-Log -Message "Starting RSAT installation and module import." -Level "INFO"
        $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $IsClientOS = ($OSInfo.ProductType -eq 1)

        # Check if the OS is a Workstation (Windows 10/11)
        if ($IsClientOS) {
            $rsatCapability = Get-WindowsCapability -Name "Rsat.ActiveDirectory*" -Online -ErrorAction SilentlyContinue
            if (-not $rsatCapability -or $rsatCapability.State -ne "Installed") {
                Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ErrorAction Stop
                Write-Log -Message "RSAT tools installed successfully on client OS." -Level "INFO"
            } else {
                Write-Log -Message "RSAT tools are already installed." -Level "INFO"
            }
        } else {
        # Check if the OS is a Server (Windows Server)
            $rsatFeature = Get-WindowsFeature -Name "RSAT-AD-PowerShell" -ErrorAction SilentlyContinue
            if (-not $rsatFeature -or -not $rsatFeature.Installed) {
                Install-WindowsFeature -Name "RSAT-AD-PowerShell" -ErrorAction Stop
                Write-Log -Message "RSAT tools installed successfully on server OS." -Level "INFO"
            } else {
                Write-Log -Message "RSAT tools are already installed." -Level "INFO"
            }
        }
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Log -Message "Active Directory Module Loaded." -Level "INFO"
    } catch {
        Write-Log -Message "Failed to install RSAT tools. Error: $_" -Level "ERROR"
        exit
    }
}

# Modules For Microsoft Graph
function Initialize-MicrosoftGraphEnvironment {
    # Ensure NuGet provider is installed and imported
    Write-Log -Message "Checking for NuGet provider..." -Level "INFO"
    $nugetProvider = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue

    if (-not $nugetProvider) {
        Write-Log -Message "NuGet provider not found. Installing..." -Level "INFO"
        try {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -ErrorAction Stop
            Write-Log -Message  "NuGet provider installed successfully."
        } catch {
            Write-Log -Message  "Failed to install the NuGet provider. Error: $_" -Level "ERROR"
            exit
        }
    } else {
        Write-Log -Message "NuGet provider is already installed." -Level "INFO"
    }

    # Import NuGet provider
    Import-PackageProvider -Name NuGet -ErrorAction SilentlyContinue

    # Install and Import Microsoft Graph modules
    foreach ($module in $Modules) {
        try {
            if (!(Get-Module -ListAvailable -Name $module)) {
                Write-Log -Message "Module $module not found. Installing..." -Level "INFO"
                Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser -ErrorAction SilentlyContinue 3>$null
            }
            Import-Module -Name $module -Force -ErrorAction SilentlyContinue 3>$null
            Write-Log -Message "Module $module imported successfully." -Level "INFO"
        } catch {
            Write-Log -Message "Error installing/importing module ${module}: $($_.Exception.Message)" -Level "ERROR"
            exit
        }
    }
}

# Function to connect to Microsoft Graph
function Connect-MSGraph {

    # Function to prompt for TenantId and validate user's confirmation only if a TenantId is provided
    function Get-TenantId {
        do {
            $TenantId = Read-Host "Enter the Tenant ID (leave blank to skip)"
            if ($TenantId) {
                do {
                    $confirmTenantId = Read-Host "You have entered: $TenantId. Is this correct? (Yes/No)"
                    if ($confirmTenantId -match '^(yes|y)$') {
                        return $TenantId  # Return TenantId if confirmed
                    } elseif ($confirmTenantId -match '^(no|n)$' -or -not $confirmTenantId) {
                        Write-Host "Proceeding without a Tenant ID." -ForegroundColor Yellow
                        return ""  # Return empty string to skip TenantId
                    } else {
                        Write-Host "Invalid input. Please answer Yes or No." -ForegroundColor Red
                    }
                } while ($true)
            } else {
                Write-Host "You have decided to proceed without a Tenant ID." -ForegroundColor Yellow
                return ""
            }
        } while ($true)
    }

    # Function to prompt for Environment and ensure valid input
    function Get-Environment {
        do {
            $Environment = Read-Host "Enter the Environment (China, Global, USGov, USGovDoD). Leave blank for 'Global'"
            if (-not $Environment) {
                Write-Host "No environment specified, defaulting to 'Global'." -ForegroundColor Yellow
                return "Global"
            } elseif ($validEnvironments -contains $Environment) {
                return $Environment
            } else {
                Write-Host "Invalid environment specified. Please enter one of the valid options: China, Global, USGov, USGovDoD." -ForegroundColor Red
            }
        } while ($true)
    }

    # Prompt for and validate TenantId and Environment
    $TenantId = Get-TenantId
    $Environment = Get-Environment

    # Attempt Microsoft Graph Connection
    try {
        $params = @{
            Scopes    = $Scopes
            NoWelcome = $true
            Environment = $Environment
        }

        if ($TenantId) {
            $params.TenantId = $TenantId
        }

        # Connect to Microsoft Graph
        Connect-MgGraph @params

        Write-Log -Message "Successfully connected to Microsoft Graph in the '$Environment' environment." -Level "SOS"
    } catch {
        Write-Log -Message "Failed to connect to Microsoft Graph. Error: $($_.Exception.Message)" -Level "ERROR"
        exit
    }
}

# Function to disconnect from Microsoft Graph
function Disconnect-MSGraph {
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Log -Message "Disconnected from Microsoft Graph" -Level "INFO"
    } catch {
        Write-Log -Message "Error disconnecting from Microsoft Graph: $_" -Level "ERROR"
    }
}

# Check License
function Check-License {
    try {
        $license = (Get-MgSubscribedSku).ServicePlans | Where-Object { $_.ServicePlanName -eq 'AAD_PREMIUM_P2' -and $_.ProvisioningStatus -eq 'Success' }
        if (-not $license) {
            $errorMessage = "Required AAD_PREMIUM_P2 license with 'Success' status not found."
            Write-Log -Message $errorMessage -Level "ERROR"
            exit
        }
        Write-Log -Message "Required AAD_PREMIUM_P2 license found with 'Success' status." -Level "INFO"
    } catch {
        Write-Log -Message "Error: $_" -Level "ERROR"
        exit
    }
}

# Main Script Execution Flow

# Validate x86 Architecture
Check-OSArchitecture > $null

# Import Microsoft Graph Modules
Initialize-MicrosoftGraphEnvironment

# Install Remote Server Administration Tools
Install-RSAT > $null

Connect-MSGraph
Check-License

SLEEP 2
CLS

# ------------------------------------------------------------------------------------------------------------------------

# Create a Random Password for Hydrated Users
function Generate-RandomPassword {
    param (
        [int]$PasswordLength = 24
    )
    # Ensure password starts with one character from each set for complexity
    $Password = [System.Text.StringBuilder]::new()
    $Password.Append($Lowercase[(Get-Random -Maximum $Lowercase.Length)]) | Out-Null
    $Password.Append($Uppercase[(Get-Random -Maximum $Uppercase.Length)]) | Out-Null
    $Password.Append($Numbers[(Get-Random -Maximum $Numbers.Length)]) | Out-Null
    $Password.Append($Symbols[(Get-Random -Maximum $Symbols.Length)]) | Out-Null

    # Fill the remaining password length with random characters from all sets
    for ($i = $Password.Length; $i -lt $PasswordLength; $i++) {
        $randomChar = $AllChars[(Get-Random -Maximum $AllChars.Length)]
        $Password.Append($randomChar) | Out-Null
    }

    # Shuffle the password to randomize the order of characters
    $PasswordString = $Password.ToString()
    $CharArray = $PasswordString.ToCharArray()
    $ShuffledArray = $CharArray | Get-Random -Count $CharArray.Length
    $ShuffledPassword = -join $ShuffledArray

    return $ShuffledPassword
}

# Function to Export All Users and Properties from Microsoft Entra ID
Function Export-EntraIDUsers {
    process {
        try {
            Write-Log -Message "Collecting all Microsoft Entra ID Users" -Level "INFO"

            # Set the properties to retrieve
            $selectProperties = @(
                'onPremisesLastSyncDateTime',
                'onPremisesSamAccountName',
                'onPremisesSecurityIdentifier',
                'onPremisesSyncEnabled',
                'onPremisesUserPrincipalName',
                'onPremisesDistinguishedName',
                'onPremisesDomainName',
                'createdDateTime',
                'accountEnabled',
                'displayName',
                'givenName',
                'surname',
                'mail',
                'id',
                'UserPrincipalName',
                'proxyAddresses'
            )

            # Get enabled, disabled, or both users
            switch ($enabled) {
                "true" { $filter = "accountEnabled eq true and userType eq 'member' and onPremisesSyncEnabled eq true" }
                "false" { $filter = "accountEnabled eq false and userType eq 'member' and onPremisesSyncEnabled eq true" }
                "both" { $filter = "userType eq 'member' and onPremisesSyncEnabled eq true" }
            }

            # Retrieve users
            $users = Get-MgUser -Filter $filter -All -Select $selectProperties | ForEach-Object {
                $ou = if ($_.onPremisesDistinguishedName) { 
                    ($_.onPremisesDistinguishedName -split ',', 2)[1]
                }

                [pscustomobject]@{
                    "Name" = $_.displayName
                    "GivenName" = $_.givenName
                    "SurName" = $_.surname
                    "Domain" = $_.OnPremisesDomainName
                    "DistinguishedName" = $_.OnPremisesDistinguishedName
                    "UserPrincipalName" = $_.UserPrincipalName
                    "ID" = $_.Id
                    "Emailaddress" = $_.mail
                    "ProxyAddress" = $_.proxyAddresses -join '; '
                    "Enabled" = if ($_.accountEnabled) {"enabled"} else {"disabled"}
                    "OU" = $ou
                    "Account Created on" = $_.createdDateTime
                    "LastSyncDateTime" = $_.onPremisesLastSyncDateTime
                    "SamAccountName" = $_.onPremisesSamAccountName
                    "SecurityIdentifier" = $_.onPremisesSecurityIdentifier
                    "SyncEnabled" = $_.onPremisesSyncEnabled
                    "OnPremisesUserPrincipalName" = $_.onPremisesUserPrincipalName
                }
            }

            # Filter users matching specific criteria
            $filteredUsers = $users | Where-Object {
                $_.SyncEnabled -eq "True" -and
                $_.DistinguishedName -ne $null -and
                $_.SecurityIdentifier -ne $null
            }

            # Check if there are any matched users
            if ($null -eq $filteredUsers -or $filteredUsers.Count -eq 0) {
                Write-Log -Message "No Matched Users - Exiting Function" -Level "WARNING"
            } else {
                # Export the collected data to a CSV file
                $filteredUsers | Export-Csv -Path $csvFilePath -NoTypeInformation
                Write-Log -Message "User data exported successfully to $csvFilePath" -Level "INFO"
            }

            SLEEP 2
            CLS
        }
        catch {
            Write-Log -Message "Error occurred: $_" -Level "ERROR"
        }
    }
}

# Function to Hydrate Active Directory
function Create-ADHydratedUsers {
    # Define CSV file search criteria and import CSV data
    $csvFiles = Get-ChildItem -Path $PSScriptRoot -Filter $csvFilePattern | Sort-Object LastWriteTime -Descending

    if ($csvFiles.Count -eq 0) {
        Write-Host "No CSV file found matching the pattern '$csvFilePattern'."
        $choice = Read-Host "Do you want to enter the path to the CSV file manually (Y/N)?"
        if ($choice -eq "Y" -or $choice -eq "y") {
            $csvFilePath = Read-Host "Enter the path to the CSV file containing user data"
        } else {
            Write-Log -Message "No CSV file found. Exiting the script." -Level "INFO"
            return
        }
    } else {
        $csvFilePath = $csvFiles[0].FullName
    }

    # Attempt to retrieve domain information and check if the current user is a Domain Admin
    try {
        # Explicitly query the domain without confusion
        $domain = Get-ADDomain -ErrorAction Stop
        $domainDN = $domain.DistinguishedName
        $domainRoot = $domain.DNSRoot

        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $domainAdmins = Get-ADGroupMember -Identity 'Domain Admins' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SamAccountName

        if (-not ($domainAdmins -contains $currentUser.Split('\')[-1])) {
            Write-Host "The current user '$currentUser' is not a member of the Domain Admins group. Exiting script..."
            Write-Log -Message "The current user '$currentUser' does not have Domain Admin privileges. Exiting." -Level "ERROR"
            return
        }
    } catch {
        Write-Host "Unable to locate the domain or verify Domain Admin credentials. Please ensure you are connected to the correct domain environment."
        Write-Log -Message "Error: Unable to locate domain or verify Domain Admin credentials. $_" -Level "ERROR"
        return
    }

    # Import CSV data with filtering
    $csvData = Import-Csv -Path $csvFilePath | Where-Object { $_.SyncEnabled -eq $true -and $_.DistinguishedName -ne "" -and $_.Domain -eq $domainRoot }

    # Collect unique OU paths and sort them in reverse (parent OUs before child OUs)
    $uniqueOUPaths = $csvData | Select-Object -ExpandProperty OU | Sort-Object -Descending
    foreach ($ouPath in $uniqueOUPaths) {
        if (-not (Test-Path "AD:\$ouPath")) {
            Create-ADHydratedOU -OUPath $ouPath -DomainDN $domainDN
        }
    }

    # Now that OUs are created, sort the user list based on the OU path to ensure orderly processing
    $sortedUsers = $csvData | Sort-Object OU

    # Create users
    foreach ($row in $sortedUsers) {
        $userExists = Get-ADUser -Filter "UserPrincipalName -eq '$($row.OnPremisesUserPrincipalName)'" -ErrorAction SilentlyContinue
        if (-not $userExists) {
            $userPassword = Generate-RandomPassword

            $givenName = $row.GivenName
            $surName = $row.SurName

            # Use OnPremisesUserPrincipalName for Name, GivenName, SurName, and SamAccountName if they are blank
            if ([string]::IsNullOrWhiteSpace($givenName) -or [string]::IsNullOrWhiteSpace($surName) -or [string]::IsNullOrWhiteSpace($row.Name) -or [string]::IsNullOrWhiteSpace($row.SamAccountName)) {
                $nameParts = $row.OnPremisesUserPrincipalName.Split('@')[0].Split('.')
                $givenName = $nameParts[0]
                $surName = $nameParts[1]
                $row.Name = "$givenName $surName"
                $row.SamAccountName = $nameParts -join '.'
            }

            $newUserParams = @{
                sAMAccountName         = $row.SamAccountName
                UserPrincipalName      = $row.OnPremisesUserPrincipalName
                Name                   = $row.Name
                GivenName              = $givenName
                Surname                = $surName
                Enabled                = $true
                AccountPassword        = (ConvertTo-SecureString -AsPlainText $userPassword -Force)
                Path                   = $row.OU
                PasswordNeverExpires   = $false
                ChangePasswordAtLogon  = $false
            }

            # Conditionally add EmailAddress if it exists in CSV
            if (-not [string]::IsNullOrWhiteSpace($row.Emailaddress)) {
                $newUserParams["EmailAddress"] = $row.Emailaddress
            } else {
                $newUserParams["EmailAddress"] = $row.OnPremisesUserPrincipalName
            }

            # Conditionally add proxyAddresses if it exists in CSV
            if (-not [string]::IsNullOrWhiteSpace($row.ProxyAddress)) {
                $newUserParams["OtherAttributes"] = @{'proxyAddresses' = $row.ProxyAddress}
            } else {
                if ([string]::IsNullOrWhiteSpace($row.ProxyAddress)) {
                    $newUserParams["OtherAttributes"] = @{'proxyAddresses' = "smtp:" + $row.OnPremisesUserPrincipalName}
                }
            }

            try {
                $newUser = New-ADUser @newUserParams -PassThru
                # Refresh the user object to retrieve the objectGUID
                $newUser = Get-ADUser -Identity $newUser -Properties objectGUID
                $guidByteArray = $newUser.objectGUID

                # Update the msDS-ConsistencyGuid with the user's objectGUID byte array
                Set-ADUser -Identity $newUser -Replace @{ 'ms-DS-ConsistencyGuid' = $guidByteArray }
                Write-Log -Message "[USER] Successfully created and updated $($row.OnPremisesUserPrincipalName) with $guidByteArray" -Level "INFO"
            } catch {
                Write-Log -Message "[USER] Error creating $($row.Name): $_" -Level "ERROR"
            }
        } else {
            Write-Log -Message "[USER] $($row.Name) already exists. Skipping." -Level "INFO"
        }
    }

    Write-Log -Message "[USER] Completed User Creation..." -Level "INFO"
    Start-Sleep -Seconds 2
    Clear-Host
}

# Function to Create Org Units
function Create-ADHydratedOU {
    param (
        [Parameter(Mandatory=$true)]
        [string] $OUPath,
        [string] $DomainDN
    )

    # Check if base OU is being created
    if ($OUPath -eq $DomainDN) {
        Write-Log -Message "[OU] $OUPath cannot be created as it is the base domain." -Level "ERROR"
        return
    }

    # Extract OU names and DC component from OUPath and create in reverse order (parent before child)
    $ouNames = @()
    $ouPattern = 'OU=([^,]+)'
    $matches = [regex]::Matches($OUPath, $ouPattern)
    if ($matches.Count -gt 0) {
        foreach ($match in $matches) {
            $ouNames += $match.Groups[1].Value
        }
    }

    # Reverse the order of OU names to ensure parent is created first
    [array]::Reverse($ouNames)

    # Create the OU hierarchy
    $parentPath = $DomainDN
    foreach ($ouName in $ouNames) {
        $ouFullPath = "OU=$ouName,$parentPath"
        if (-not (Test-Path "AD:\$ouFullPath")) {
            try {
                New-ADOrganizationalUnit -Name $ouName -Path $parentPath -ProtectedFromAccidentalDeletion $false
                Write-Log -Message "[OU] Created $ouFullPath" -Level "INFO"
            } catch {
                Write-Log -Message "[OU] Error creating '$ouName': $_" -Level "ERROR"
                return
            }
        }
        $parentPath = $ouFullPath
    }
}

# Function to Update the Immutable ID in Microsoft Entra ID
function Update-ImmutableID {
    # Define CSV file search criteria and import CSV data
    $csvFilePattern = "hydrate_ActiveDirectory_*.csv"
    $csvFiles = Get-ChildItem -Path $PSScriptRoot -Filter $csvFilePattern | Sort-Object LastWriteTime -Descending

    if ($csvFiles.Count -eq 0) {
        Write-Host "No CSV file found matching the pattern '$csvFilePattern'."
        $choice = Read-Host "Do you want to enter the path to the CSV file manually (Y/N)?"
        if ($choice -eq "Y" -or $choice -eq "y") {
            $csvFilePath = Read-Host "Enter the path to the CSV file containing user data"
        } else {
            Write-Log -Message "No CSV file found. Exiting the script." -Level "INFO"
            exit
        }
    } else {
        $csvFilePath = $csvFiles[0].FullName
    }

    $domainRoot = (Get-ADDomain).DNSRoot
    $csvData = Import-Csv -Path $csvFilePath | Where-Object { $_.SyncEnabled -eq $true -and $_.DistinguishedName -ne "" -and $_.Domain -eq $domainRoot }

    # Iterate through each user in the filtered CSV data
    foreach ($user in $csvData) {
        # Fetch the user's ms-DS-ConsistencyGuid from Active Directory
        try {
            $adUser = Get-ADUser -Filter "UserPrincipalName -eq '$($user.OnPremisesUserPrincipalName)'" -Properties "ms-DS-ConsistencyGuid"
            if ($adUser -ne $null -and $adUser."ms-DS-ConsistencyGuid" -ne $null) {
                # Since ms-DS-ConsistencyGuid is a byte array, directly convert it to Base64
                $b64GUID = [System.Convert]::ToBase64String($adUser."ms-DS-ConsistencyGuid")
            } else {
                Write-Log -Message "[USER] ms-DS-ConsistencyGuid not found for $($user.OnPremisesUserPrincipalName)" -Level "WARNING"
                continue
            }
        } catch {
            Write-Log -Message "[USER] Error retrieving ms-DS-ConsistencyGuid for $($user.OnPremisesUserPrincipalName): $_" -Level "ERROR"
            continue
        }

        # Fetch the user using Get-MgUser with the UPN
        try {
            $mgUser = Get-MgUser -Filter "userPrincipalName eq '$($user.OnPremisesUserPrincipalName)'"
        } catch {
            Write-Log -Message "[USER] Error fetching $($user.OnPremisesUserPrincipalName) from Microsoft Graph: $_" -Level "ERROR"
            continue
        }

        # Check if user exists in Microsoft Entra
        if ($null -ne $mgUser) {
            # Define parameters for updating user
            $params = @{
                OnPremisesImmutableId = $b64GUID
            }
            # Update user with provided parameters in Microsoft Graph
            try {
                Update-MgUser -UserId $mgUser.Id -BodyParameter $params
                Write-Log -Message "[USER] ImmutableID updated for $($user.OnPremisesUserPrincipalName) with GUID $b64GUID" -Level "INFO"
            } catch {
                Write-Log -Message "[USER] Error updating ImmutableID for $($user.OnPremisesUserPrincipalName): $_" -Level "ERROR"
            }
        } else {
            Write-Log -Message "[USER] $($user.OnPremisesUserPrincipalName) has been skipped as does not exist in Microsoft Entra ID" -Level "WARNING"
        }
    } 
SLEEP 2
CLS
}

# Menu Function
function Show-Menu {
    do {
        Write-Host ""
        Write-Host "----------------------------------------------------------------------------------"
        Write-Host "HYDRATE ACTIVE DIRECTORY FROM MICROSOFT ENTRA ID."                                   -ForegroundColor Cyan
        Write-Host "----------------------------------------------------------------------------------"
        Write-Host ""
        Write-Host "Options:"
        Write-Host "[1] Export Microsoft Entra ID Users"
        Write-Host "[2] Hydrate Active Directory"
        Write-Host "[3] Update Cloud Immutable ID"
        Write-Host "[4] Exit"
        Write-Host ""
        Write-Host "----------------------------------------------------------------------------------"
        $choice = Read-Host "Enter your choice"

        switch ($choice) {
            1 { 
                Export-EntraIDUsers
                SLEEP 2
                CLS 
            }
            2 { 
                Create-ADHydratedUsers
                SLEEP 2
                CLS 
            }
            3 { 
                Update-ImmutableID
                SLEEP 2
                CLS 
            }
            4 {
                Write-Host "Exiting the script..." -ForegroundColor Yellow
                # Exit Microsoft Graph Session
                Disconnect-MSGraph > $Null
                # Mark The End of the Script
                Write-Log -Message "[SCRIPT] End of Hydrate_ActiveDirectory Script." -Level "SOS"
                SLEEP 2
                CLS
                Exit
            }
            default { 
                Write-Host "Invalid choice. Please select again." 
            }
        }
    } while ($true)
}

# Display the Menu
Show-Menu

# ------------------------------------------------------------------------------------------------------------------------

# (C) NightCityShogun 2025
