# CrowdStrike Management Module
# Version 1.1 - Added Custom Config Path Support

#region Encryption Functions
function Protect-String {
    param(
        [string]$PlainText,
        [string]$Password
    )
    
    $salt = [byte[]]::new(32)
    [System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($salt)
    
    $key = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($Password, $salt, 10000)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $key.GetBytes(32)
    $aes.GenerateIV()
    
    $encryptor = $aes.CreateEncryptor()
    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
    
    $result = [byte[]]::new($salt.Length + $aes.IV.Length + $encryptedBytes.Length)
    [System.Buffer]::BlockCopy($salt, 0, $result, 0, $salt.Length)
    [System.Buffer]::BlockCopy($aes.IV, 0, $result, $salt.Length, $aes.IV.Length)
    [System.Buffer]::BlockCopy($encryptedBytes, 0, $result, $salt.Length + $aes.IV.Length, $encryptedBytes.Length)
    
    return [Convert]::ToBase64String($result)
}

function Unprotect-String {
    param(
        [string]$EncryptedText,
        [string]$Password
    )
    
    try {
        $encryptedBytes = [Convert]::FromBase64String($EncryptedText)
        
        $salt = [byte[]]::new(32)
        $iv = [byte[]]::new(16)
        $encrypted = [byte[]]::new($encryptedBytes.Length - 48)
        
        [System.Buffer]::BlockCopy($encryptedBytes, 0, $salt, 0, 32)
        [System.Buffer]::BlockCopy($encryptedBytes, 32, $iv, 0, 16)
        [System.Buffer]::BlockCopy($encryptedBytes, 48, $encrypted, 0, $encrypted.Length)
        
        $key = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($Password, $salt, 10000)
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key.GetBytes(32)
        $aes.IV = $iv
        
        $decryptor = $aes.CreateDecryptor()
        $decryptedBytes = $decryptor.TransformFinalBlock($encrypted, 0, $encrypted.Length)
        
        return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
    }
    catch {
        throw "Decryption failed. Invalid password or corrupted data."
    }
}
#endregion

#region Configuration Management
function New-EncryptedConfig {
    Write-Host "=====Config Encryption Setup=====" -ForegroundColor Cyan
    
    $configPath = ".\config.json"
    $encryptedConfigPath = ".\config.enc"
    
    if (Test-Path $configPath) {
        Write-Host "Found existing config.json file" -ForegroundColor Yellow
        $encrypt = Read-Host "Do you want to encrypt this file? (Y/N)"
        
        if ($encrypt -eq 'Y' -or $encrypt -eq 'y') {
            $masterPassword = Read-Host "Enter master password" -AsSecureString
            $confirmPassword = Read-Host "Confirm master password" -AsSecureString
            
            $pass1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($masterPassword))
            $pass2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmPassword))
            
            if ($pass1 -ne $pass2) {
                Write-Host "Passwords do not match! Please try again." -ForegroundColor Red
                return $false
            }
            
            $configContent = Get-Content $configPath -Raw
            $encryptedContent = Protect-String -PlainText $configContent -Password $pass1
            
            $encryptedContent | Out-File -FilePath $encryptedConfigPath -Encoding UTF8
            
            Write-Host "Config encrypted successfully!" -ForegroundColor Green
            
            $delete = Read-Host "`nDelete the plain config.json file? (Y/N)"
            if ($delete -eq 'Y' -or $delete -eq 'y') {
                Remove-Item $configPath -Force
                Write-Host "Plain config file deleted" -ForegroundColor Yellow
            }
            
            $pass1 = $null
            $pass2 = $null
            [System.GC]::Collect()
            
            return $true
        }
    }
    else {
        Write-Host "No config.json found. Please create a config.json file first." -ForegroundColor Red
        Write-Host "Example format:" -ForegroundColor Yellow
        Write-Host @"
{
    "ClientA": {
        "client_id": "your_client_id",
        "client_secret": "your_client_secret"
    },
    "ClientB": {
        "client_id": "your_client_id",
        "client_secret": "your_client_secret"
    }
}
"@ -ForegroundColor Gray
        return $false
    }
}

function Get-ConfigurationAndAuthenticate {
    param(
        [string]$ConfigPath
    )
    
    # Determine config file paths
    if ($ConfigPath) {
        # Use provided config path
        $encryptedConfigPath = $ConfigPath
        $plainConfigPath = $ConfigPath
        
        # If provided path doesn't have extension, try both
        if ([System.IO.Path]::GetExtension($ConfigPath) -eq "") {
            $encryptedConfigPath = $ConfigPath + ".enc"
            $plainConfigPath = $ConfigPath + ".json"
        }
    } else {
        # Use default paths
        $encryptedConfigPath = ".\config.enc"
        $plainConfigPath = ".\config.json"
    }
    
    $config = $null

    # Load configuration
    if (Test-Path $encryptedConfigPath) {
        Write-Host "Encrypted configuration detected: $encryptedConfigPath" -ForegroundColor Yellow
        
        # Check if password is already stored in session
        if (-not $global:CrowdStrikePassword) {
            $masterPassword = Read-Host "Enter master password" -AsSecureString
            $global:CrowdStrikePassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($masterPassword))
        } else {
            Write-Host "Using cached password" -ForegroundColor Green
        }
        
        try {
            $encryptedContent = Get-Content $encryptedConfigPath -Raw
            $decryptedContent = Unprotect-String -EncryptedText $encryptedContent -Password $global:CrowdStrikePassword
            $config = $decryptedContent | ConvertFrom-Json
            Write-Host "Configuration decrypted successfully" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to decrypt configuration: $($_.Exception.Message)" -ForegroundColor Red
            # Clear cached password on failure
            $global:CrowdStrikePassword = $null
            return $null
        }
    }
    elseif (Test-Path $plainConfigPath) {
        Write-Host "Plain configuration file detected: $plainConfigPath" -ForegroundColor Yellow
        if (-not $ConfigPath) {
            $useEncryption = Read-Host "Would you like to encrypt your configuration for security? (Y/N)"
            
            if ($useEncryption -eq 'Y' -or $useEncryption -eq 'y') {
                if (New-EncryptedConfig) {
                    Write-Host "Configuration encrypted. Please run the script again." -ForegroundColor Yellow
                    return $null
                }
            }
        }
        
        $config = Get-Content $plainConfigPath | ConvertFrom-Json
        Write-Host "Using unencrypted configuration" -ForegroundColor Yellow
    }
    else {
        Write-Host "No configuration file found!" -ForegroundColor Red
        if ($ConfigPath) {
            Write-Host "Specified path: $ConfigPath" -ForegroundColor Red
        } else {
            Write-Host "Default paths: .\config.json or .\config.enc" -ForegroundColor Red
        }
        Write-Host "Please create a config.json file or specify a valid path" -ForegroundColor Yellow
        return $null
    }

    # Display available clients and get selection
    Write-Host "`n=====Available Clients=====" -ForegroundColor Cyan
    $clientNames = $config.PSObject.Properties.Name
    $clientNames | ForEach-Object { Write-Host "  - $_" -ForegroundColor Green }

    # Prompt for client name
    Write-Host "`n"
    $clientName = Read-Host "Select client for this session"

    # Validate client exists in config
    if (-not ($config.PSObject.Properties.Name -contains $clientName)) {
        Write-Host "Error: Client '$clientName' not found in configuration" -ForegroundColor Red
        return $null
    }

    # Extract credentials for selected client
    $clientConfig = $config.$clientName
    if (-not $clientConfig.client_id -or -not $clientConfig.client_secret) {
        Write-Host "Error: Missing client_id or client_secret for client '$clientName'" -ForegroundColor Red
        return $null
    }

    # Authenticate to CrowdStrike API
    Write-Host "`n=====Authenticating to CrowdStrike API=====" -ForegroundColor Cyan
    $url = "https://api.crowdstrike.com/oauth2/token"
    $body = "client_id=$($clientConfig.client_id)&client_secret=$($clientConfig.client_secret)"

    try {
        $authResponse = Invoke-RestMethod -Method Post -Uri $url -Body $body -ContentType "application/x-www-form-urlencoded"
        Write-Host "Authentication successful for client: $clientName" -ForegroundColor Green
        
        $headers = @{
            Authorization = "Bearer $($authResponse.access_token)"
        }
        
        # Clean up config data but keep password cached
        $config = $null
        $clientConfig = $null
        $body = $null
        [System.GC]::Collect()
        
        return @{
            Headers = $headers
            ClientName = $clientName
        }
    } catch {
        Write-Host "Authentication failed:" -ForegroundColor Red
        Write-Host $_.Exception.Message
        return $null
    }
}
#endregion

#region CrowdStrike Operations
function Invoke-DAAccountsReport {
    param(
        [hashtable]$Headers,
        [string]$ClientName
    )
    
    Write-Host "`n=====Domain Admin Accounts Report=====" -ForegroundColor Cyan
    Write-Host "Client: $ClientName" -ForegroundColor Green

    try {
        Write-Host "=====Retrieving Domain Admin Accounts====="
        $response = Invoke-RestMethod -Method Get -Uri "https://api.crowdstrike.com/discover/queries/accounts/v1?filter=admin_privileges:'Yes'%2Baccount_type:'Domain'" -Headers $Headers
    }
    catch {
        Write-Host "Request failed:" -ForegroundColor Red
        Write-Host "Status Code: $($_.Exception.Response.StatusCode.value__)"
        Write-Host "Message: $($_.Exception.Message)"
        return
    }

    $da_accounts = $response.resources
    
    if ($da_accounts.Count -eq 0) {
        Write-Host "No domain admin accounts found." -ForegroundColor Yellow
        return
    }

    $account_data = @()

    Write-Host "Retrieving account details..." -ForegroundColor Yellow
    $counter = 0
    ForEach ($item in $da_accounts) {
        $counter++
        Write-Progress -Activity "Retrieving account details" -Status "Processing $counter of $($da_accounts.Count)" -PercentComplete (($counter / $da_accounts.Count) * 100)
        
        $Url = "https://api.crowdstrike.com/discover/entities/accounts/v1?ids=" + $item
        $Umd = Invoke-RestMethod -Method 'get' -Uri $url -Headers $Headers
        $account_data += $Umd.resources
    }

    Write-Progress -Activity "Retrieving account details" -Completed
    Write-Host "=====Data Retrieved====="

    # Export to CSV with improved path handling
    $defaultPath = ".\DA_Accounts_Report_${clientName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $exportPath = Read-Host "Enter the full path to save the file (or press Enter for default: $defaultPath)"
    
    if ([string]::IsNullOrWhiteSpace($exportPath)) {
        $exportPath = $defaultPath
    } else {
        # Check if the provided path is a directory or missing extension
        if ((Test-Path $exportPath -PathType Container) -or 
            ([System.IO.Path]::GetExtension($exportPath) -eq "")) {
            
            # It's a directory or path without extension, append filename
            if (Test-Path $exportPath -PathType Container) {
                $exportPath = Join-Path $exportPath "DA_Accounts_Report_${clientName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            } else {
                # Path doesn't exist and has no extension, add .csv
                $exportPath = $exportPath + "_DA_Accounts_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            }
        }
        
        # Ensure the directory exists
        $directory = [System.IO.Path]::GetDirectoryName($exportPath)
        if (-not (Test-Path $directory)) {
            try {
                New-Item -ItemType Directory -Path $directory -Force | Out-Null
                Write-Host "Created directory: $directory" -ForegroundColor Yellow
            } catch {
                Write-Host "Failed to create directory: $directory" -ForegroundColor Red
                Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
                $exportPath = $defaultPath
                Write-Host "Falling back to default path: $exportPath" -ForegroundColor Yellow
            }
        }
    }

    try {
        $account_data | Select-Object -Property account_name, username, password_last_set_timestamp, admin_privileges | Export-csv -path $exportPath -NoTypeInformation
        Write-Host "`n=====File Exported Successfully=====" -ForegroundColor Green
        Write-Host "Client: $clientName" -ForegroundColor White
        Write-Host "Total DA accounts found: $($account_data.Count)" -ForegroundColor White
        Write-Host "File saved to: $exportPath" -ForegroundColor White
    }
    catch {
        Write-Host "Failed to export file: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Attempted path: $exportPath" -ForegroundColor Yellow
        
        # Try saving to current directory as fallback
        $fallbackPath = ".\DA_Accounts_Report_${clientName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        try {
            $account_data | Select-Object -Property account_name, username, password_last_set_timestamp, admin_privileges | Export-csv -path $fallbackPath -NoTypeInformation
            Write-Host "File saved to fallback location: $fallbackPath" -ForegroundColor Green
        }
        catch {
            Write-Host "Fallback save also failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

function Invoke-EOLDevicesReport {
    param(
        [hashtable]$Headers,
        [string]$ClientName
    )
    
    Write-Host "`n=====End-of-Life OS Devices Report=====" -ForegroundColor Cyan
    Write-Host "Client: $ClientName" -ForegroundColor Green

    try {
        Write-Host "=====Retrieving Outdated OS-builds Devices====="
        $response = Invoke-RestMethod -Method Get -Uri "https://api.crowdstrike.com/discover/queries/hosts/v1?filter=os_is_eol:'Yes'&facet=system_insights%2Bkernel_version:'*'" -Headers $Headers
        Write-Host "Found $($response.resources.Count) devices with EOL OS" -ForegroundColor Yellow
    } catch {
        Write-Host "Request failed:" -ForegroundColor Red
        Write-Host "Status Code: $($_.Exception.Response.StatusCode.value__)"
        Write-Host "Message: $($_.Exception.Message)"
        return
    }

    $os_builds = $response.resources

    if ($os_builds.Count -eq 0) {
        Write-Host "No EOL devices found for client: $clientName" -ForegroundColor Green
        Write-Host "All devices are running supported OS versions." -ForegroundColor Green
        return
    }

    $Allhostdetails = @()

    Write-Host "Retrieving detailed information for each host..." -ForegroundColor Yellow
    $counter = 0
    ForEach ($item in $os_builds) {
        $counter++
        Write-Progress -Activity "Retrieving host details" -Status "Processing $counter of $($os_builds.Count)" -PercentComplete (($counter / $os_builds.Count) * 100)
        
        $hostUrl = "https://api.crowdstrike.com/discover/entities/hosts/v1?ids=" + $item
        try {
            $UCdet = Invoke-RestMethod -Method 'get' -Uri $hostUrl -Headers $Headers
            $Allhostdetails += $UCdet.resources
        } catch {
            Write-Host "`nFailed to retrieve details for host ID: $item" -ForegroundColor Red
        }
    }

    Write-Progress -Activity "Retrieving host details" -Completed
    Write-Host "Data retrieved successfully" -ForegroundColor Green

    # Export to CSV with improved path handling
    $defaultPath = ".\EOL_OS_Report_${clientName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $exportPath = Read-Host "Enter the full path to save the file (or press Enter for default: $defaultPath)"

    if ([string]::IsNullOrWhiteSpace($exportPath)) {
        $exportPath = $defaultPath
    } else {
        # Check if the provided path is a directory or missing extension
        if ((Test-Path $exportPath -PathType Container) -or 
            ([System.IO.Path]::GetExtension($exportPath) -eq "")) {
            
            # It's a directory or path without extension, append filename
            if (Test-Path $exportPath -PathType Container) {
                $exportPath = Join-Path $exportPath "EOL_OS_Report_${clientName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            } else {
                # Path doesn't exist and has no extension, add .csv
                $exportPath = $exportPath + "_EOL_OS_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            }
        }
        
        # Ensure the directory exists
        $directory = [System.IO.Path]::GetDirectoryName($exportPath)
        if (-not (Test-Path $directory)) {
            try {
                New-Item -ItemType Directory -Path $directory -Force | Out-Null
                Write-Host "Created directory: $directory" -ForegroundColor Yellow
            } catch {
                Write-Host "Failed to create directory: $directory" -ForegroundColor Red
                Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
                $exportPath = $defaultPath
                Write-Host "Falling back to default path: $exportPath" -ForegroundColor Yellow
            }
        }
    }

    try {
        $Allhostdetails | Select-Object -Property hostname, form_factor, os_version, kernel_Version, os_is_eol, machine_domain, product_type_desc | Export-Csv -Path $exportPath -NoTypeInformation
        Write-Host "`n=====File Exported Successfully=====" -ForegroundColor Green
        Write-Host "Client: $clientName" -ForegroundColor White
        Write-Host "Total EOL devices found: $($Allhostdetails.Count)" -ForegroundColor White
        Write-Host "Report saved to: $exportPath" -ForegroundColor White
    } catch {
        Write-Host "Failed to export file: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Attempted path: $exportPath" -ForegroundColor Yellow
        
        # Try saving to current directory as fallback
        $fallbackPath = ".\EOL_OS_Report_${clientName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        try {
            $Allhostdetails | Select-Object -Property hostname, form_factor, os_version, kernel_Version, os_is_eol, machine_domain, product_type_desc | Export-Csv -Path $fallbackPath -NoTypeInformation
            Write-Host "File saved to fallback location: $fallbackPath" -ForegroundColor Green
        }
        catch {
            Write-Host "Fallback save also failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

function Invoke-UnencryptedDevicesReport {
    param(
        [hashtable]$Headers,
        [string]$ClientName
    )
    
    Write-Host "`n=====Unencrypted Devices Report=====" -ForegroundColor Cyan
    Write-Host "Client: $ClientName" -ForegroundColor Green

    try {
        Write-Host "=====Retrieving Unencrypted Devices====="
        $response = Invoke-RestMethod -Method Get -Uri "https://api.crowdstrike.com/discover/queries/hosts/v1?filter=form_factor:'Laptop'%2Bencryption_status%3A'Unencrypted'&facet=system_insights" -Headers $Headers
    }
    catch {
        Write-Host "Request failed:" -ForegroundColor Red
        Write-Host "Status Code: $($_.Exception.Response.StatusCode.value__)"
        Write-Host "Message: $($_.Exception.Message)"
        return
    }

    $Unencrypted_devices = $response.resources
    
    if ($Unencrypted_devices.Count -eq 0) {
        Write-Host "No unencrypted devices found for client: $clientName" -ForegroundColor Green
        return
    }

    $Allhostdetails = @()

    Write-Host "Retrieving detailed information for each host..." -ForegroundColor Yellow
    $counter = 0
    ForEach ($item in $Unencrypted_devices) {
        $counter++
        Write-Progress -Activity "Retrieving host details" -Status "Processing $counter of $($Unencrypted_devices.Count)" -PercentComplete (($counter / $Unencrypted_devices.Count) * 100)
        
        $Url = "https://api.crowdstrike.com/discover/entities/hosts/v1?ids=" + $item
        $UCdet = Invoke-RestMethod -Method 'get' -Uri $url -Headers $Headers
        $Allhostdetails += $UCdet.resources
    }

    Write-Progress -Activity "Retrieving host details" -Completed
    Write-Host "=====Data Retrieved====="

    # Export to CSV with improved path handling
    $defaultPath = ".\Unencrypted_Devices_Report_${clientName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $exportPath = Read-Host "Enter the full path to save the file (or press Enter for default: $defaultPath)"

    if ([string]::IsNullOrWhiteSpace($exportPath)) {
        $exportPath = $defaultPath
    } else {
        # Check if the provided path is a directory or missing extension
        if ((Test-Path $exportPath -PathType Container) -or 
            ([System.IO.Path]::GetExtension($exportPath) -eq "")) {
            
            # It's a directory or path without extension, append filename
            if (Test-Path $exportPath -PathType Container) {
                $exportPath = Join-Path $exportPath "Unencrypted_Devices_Report_${clientName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            } else {
                # Path doesn't exist and has no extension, add .csv
                $exportPath = $exportPath + "_Unencrypted_Devices_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            }
        }
        
        # Ensure the directory exists
        $directory = [System.IO.Path]::GetDirectoryName($exportPath)
        if (-not (Test-Path $directory)) {
            try {
                New-Item -ItemType Directory -Path $directory -Force | Out-Null
                Write-Host "Created directory: $directory" -ForegroundColor Yellow
            } catch {
                Write-Host "Failed to create directory: $directory" -ForegroundColor Red
                Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
                $exportPath = $defaultPath
                Write-Host "Falling back to default path: $exportPath" -ForegroundColor Yellow
            }
        }
    }

    try {
        $Allhostdetails | Select-Object -Property hostname, encryption_status, form_factor, os_version, machine_domain, product_type_desc | Export-csv -path $exportPath -NoTypeInformation
        Write-Host "`n=====File Exported Successfully=====" -ForegroundColor Green
        Write-Host "Client: $clientName" -ForegroundColor White
        Write-Host "Total unencrypted devices found: $($Allhostdetails.Count)" -ForegroundColor White
        Write-Host "File saved to: $exportPath" -ForegroundColor White
    }
    catch {
        Write-Host "Failed to export file: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Attempted path: $exportPath" -ForegroundColor Yellow
        
        # Try saving to current directory as fallback
        $fallbackPath = ".\Unencrypted_Devices_Report_${clientName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        try {
            $Allhostdetails | Select-Object -Property hostname, encryption_status, form_factor, os_version, machine_domain, product_type_desc | Export-csv -path $fallbackPath -NoTypeInformation
            Write-Host "File saved to fallback location: $fallbackPath" -ForegroundColor Green
        }
        catch {
            Write-Host "Fallback save also failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

function Invoke-UnmanagedDevicesReport {
    param(
        [hashtable]$Headers,
        [string]$ClientName
    )
    
    Write-Host "`n=====Unmanaged Devices Report=====" -ForegroundColor Cyan
    Write-Host "Client: $ClientName" -ForegroundColor Green

    try {
        Write-Host "=====Retrieving Unmanaged Devices====="
        $response = Invoke-RestMethod -Method Get -Uri "https://api.crowdstrike.com/discover/queries/hosts/v1?filter=entity_type:'unmanaged'%2Blast_seen_timestamp:>'now-47d'%2Bconfidence:>=5%2Bdiscoverer_count:>=3" -Headers $Headers
    }
    catch {
        Write-Host "Request failed:" -ForegroundColor Red
        Write-Host "Status Code: $($_.Exception.Response.StatusCode.value__)"
        Write-Host "Message: $($_.Exception.Message)"
        return
    }

    $Unmanaged_devices = $response.resources
    
    if ($Unmanaged_devices.Count -eq 0) {
        Write-Host "No unmanaged devices found for client: $clientName" -ForegroundColor Green
        return
    }

    $allhost_data = @()

    Write-Host "Retrieving detailed information for each host..." -ForegroundColor Yellow
    $counter = 0
    $DetailedProperties = ForEach ($item in $Unmanaged_devices) {
        $counter++
        Write-Progress -Activity "Retrieving host details" -Status "Processing $counter of $($Unmanaged_devices.Count)" -PercentComplete (($counter / $Unmanaged_devices.Count) * 100)
        
        $Url = "https://api.crowdstrike.com/discover/entities/hosts/v1?ids=" + $item
        $Umd = Invoke-RestMethod -Method 'get' -Uri $url -Headers $Headers
        $allhost_data += $Umd.resources
        foreach ($item2 in $umd.resources){ 
            [PSCustomObject]@{
                hostname = $item2.last_discoverer_hostname
                unmanaged = $item2.entity_type
                mac_address = $item2.network_interfaces.mac_address
                local_IP = $item2.network_interfaces.local_ip
                Data_Providers = $item2.data_providers -join 'Active Directory,Falcon passive discovery'
                System_manufacturer = $item2.system_manufacturer
                First_seen = $item2.first_seen_timestamp
                Last_seen = $item2.last_seen_timestamp
                confidence = $item2.confidence
            }
        }
    }

    Write-Progress -Activity "Retrieving host details" -Completed
    Write-Host "=====Data Retrieved====="

    # Export to CSV with improved path handling
    $defaultPath = ".\Unmanaged_Devices_Report_${clientName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $exportPath = Read-Host "Enter the full path to save the file (or press Enter for default: $defaultPath)"

    if ([string]::IsNullOrWhiteSpace($exportPath)) {
        $exportPath = $defaultPath
    } else {
        # Check if the provided path is a directory or missing extension
        if ((Test-Path $exportPath -PathType Container) -or 
            ([System.IO.Path]::GetExtension($exportPath) -eq "")) {
            
            # It's a directory or path without extension, append filename
            if (Test-Path $exportPath -PathType Container) {
                $exportPath = Join-Path $exportPath "Unmanaged_Devices_Report_${clientName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            } else {
                # Path doesn't exist and has no extension, add .csv
                $exportPath = $exportPath + "_Unmanaged_Devices_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            }
        }
        
        # Ensure the directory exists
        $directory = [System.IO.Path]::GetDirectoryName($exportPath)
        if (-not (Test-Path $directory)) {
            try {
                New-Item -ItemType Directory -Path $directory -Force | Out-Null
                Write-Host "Created directory: $directory" -ForegroundColor Yellow
            } catch {
                Write-Host "Failed to create directory: $directory" -ForegroundColor Red
                Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
                $exportPath = $defaultPath
                Write-Host "Falling back to default path: $exportPath" -ForegroundColor Yellow
            }
        }
    }

    try {
        $DetailedProperties | Export-csv -path $exportPath -NoTypeInformation
        Write-Host "`n=====File Exported Successfully=====" -ForegroundColor Green
        Write-Host "Client: $clientName" -ForegroundColor White
        Write-Host "Total unmanaged devices found: $($DetailedProperties.Count)" -ForegroundColor White
        Write-Host "File saved to: $exportPath" -ForegroundColor White
    }
    catch {
        Write-Host "Failed to export file: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Attempted path: $exportPath" -ForegroundColor Yellow
        
        # Try saving to current directory as fallback
        $fallbackPath = ".\Unmanaged_Devices_Report_${clientName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        try {
            $DetailedProperties | Export-csv -path $fallbackPath -NoTypeInformation
            Write-Host "File saved to fallback location: $fallbackPath" -ForegroundColor Green
        }
        catch {
            Write-Host "Fallback save also failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}
#endregion

#region Menu System
function Show-MainMenu {
    param(
        [string]$ClientName
    )
    
    Clear-Host
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "    CrowdStrike Management Console" -ForegroundColor Cyan
    Write-Host "             Version 1.2" -ForegroundColor Gray
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Active Client: $ClientName" -ForegroundColor Green
    Write-Host ""
    Write-Host "Please select an option:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  A) Domain Admin Accounts Report" -ForegroundColor White
    Write-Host "  B) End-of-Life OS Devices Report" -ForegroundColor White
    Write-Host "  C) Unencrypted Devices Report" -ForegroundColor White
    Write-Host "  D) Unmanaged Devices Report" -ForegroundColor White
    Write-Host ""
    Write-Host "  Q) Quit" -ForegroundColor Red
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Cyan
}

function Start-CrowdStrikeManager {
    param(
        [string]$ConfigPath
    )
    
    # Authenticate once at startup
    Write-Host "Starting CrowdStrike Management Console..." -ForegroundColor Green
    Write-Host "Initializing authentication..." -ForegroundColor Yellow
    
    $authResult = Get-ConfigurationAndAuthenticate -ConfigPath $ConfigPath
    if (-not $authResult) {
        Write-Host "Failed to authenticate. Exiting..." -ForegroundColor Red
        return
    }
    
    $headers = $authResult.Headers
    $clientName = $authResult.ClientName
    
    Write-Host "`nAuthentication successful! Ready to generate reports." -ForegroundColor Green
    Write-Host "Selected Client: $clientName" -ForegroundColor Green
    Start-Sleep -Seconds 2
    
    # Main menu loop with pre-authenticated session
    do {
        Show-MainMenu -ClientName $clientName
        $choice = Read-Host "Enter your choice"
        
        switch ($choice.ToUpper()) {
            'A' {
                Invoke-DAAccountsReport -Headers $headers -ClientName $clientName
                Write-Host "`nPress any key to return to main menu..." -ForegroundColor Yellow
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            'B' {
                Invoke-EOLDevicesReport -Headers $headers -ClientName $clientName
                Write-Host "`nPress any key to return to main menu..." -ForegroundColor Yellow
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            'C' {
                Invoke-UnencryptedDevicesReport -Headers $headers -ClientName $clientName
                Write-Host "`nPress any key to return to main menu..." -ForegroundColor Yellow
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            'D' {
                Invoke-UnmanagedDevicesReport -Headers $headers -ClientName $clientName
                Write-Host "`nPress any key to return to main menu..." -ForegroundColor Yellow
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            'Q' {
                Write-Host "`nCleaning up session..." -ForegroundColor Yellow
                
                # Clear cached password and authentication data
                $global:CrowdStrikePassword = $null
                $headers = $null
                [System.GC]::Collect()
                
                Write-Host "Thank you for using CrowdStrike Management Console!" -ForegroundColor Green
                return
            }
            default {
                Write-Host "`nInvalid selection. Please choose A, B, C, D, or Q." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
    } while ($true)
}
#endregion

# Export functions
Export-ModuleMember -Function Start-CrowdStrikeManager, New-EncryptedConfig

# Module cleanup when removed
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
    # Clear cached password when module is unloaded
    if ($global:CrowdStrikePassword) {
        $global:CrowdStrikePassword = $null
        [System.GC]::Collect()
        Write-Host "Cleared cached authentication data" -ForegroundColor Yellow
    }
}
