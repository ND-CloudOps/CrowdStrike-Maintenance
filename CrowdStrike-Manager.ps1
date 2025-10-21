# CrowdStrike Management Console Launcher
# Version 1.1 - Added Custom Config Path Support
# 
# This script provides a centralized interface for running CrowdStrike reports
# with support for encrypted configuration files and multiple client environments

param(
    [switch]$SetupConfig,
    [switch]$Help,
    [string]$ConfigPath
)

# Help function
function Show-Help {
    Write-Host @"
CrowdStrike Management Console
==============================

DESCRIPTION:
    A PowerShell module for managing CrowdStrike reports across multiple client environments.
    Supports encrypted configuration storage for secure credential management.

USAGE:
    .\CrowdStrike-Manager.ps1 [parameters]

PARAMETERS:
    -SetupConfig    : Run configuration setup to create/encrypt config file
    -ConfigPath     : Specify custom path to config file (supports .json or .enc files)
    -Help          : Show this help message

EXAMPLES:
    .\CrowdStrike-Manager.ps1                                    # Start - will prompt for config if needed
    .\CrowdStrike-Manager.ps1 -ConfigPath "C:\Configs\cs.json"   # Use specific config file
    .\CrowdStrike-Manager.ps1 -ConfigPath "\\Server\cs.enc"      # Use network config file
    .\CrowdStrike-Manager.ps1 -SetupConfig                       # Set up encrypted configuration
    .\CrowdStrike-Manager.ps1 -Help                              # Show this help

INTERACTIVE CONFIG SELECTION:
    If no default config is found, you'll be prompted to:
    - Create a new config.json file, or
    - Specify the path to your existing config file
    
    If default config files exist, you can choose to:
    - Use the default config files, or
    - Specify a custom config file path

REQUIREMENTS:
    - PowerShell 5.1 or later
    - CrowdStrike API credentials
    - Network access to api.crowdstrike.com

"@ -ForegroundColor White
}

# Check if help was requested
if ($Help) {
    Show-Help
    exit 0
}

# Import the module
$ModulePath = Join-Path $PSScriptRoot "CrowdStrike-Manager_module.psm1"

if (-not (Test-Path $ModulePath)) {
    Write-Host "Error: Module file not found at: $ModulePath" -ForegroundColor Red
    Write-Host "Please ensure CrowdStrike-Manager_module.psm1 is in the same directory as this script." -ForegroundColor Yellow
    exit 1
}

try {
    Import-Module $ModulePath -Force
    Write-Host "CrowdStrike Management Module loaded successfully" -ForegroundColor Green
}
catch {
    Write-Host "Error loading module: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Handle setup configuration parameter
if ($SetupConfig) {
    Write-Host "Starting configuration setup..." -ForegroundColor Cyan
    New-EncryptedConfig
    exit 0
}

# Determine config file paths
if ($ConfigPath) {
    # Custom config path provided via parameter
    if (-not (Test-Path $ConfigPath)) {
        Write-Host "Error: Specified config file not found at: $ConfigPath" -ForegroundColor Red
        exit 1
    }
    
    $finalConfigPath = $ConfigPath
    $configExists = $true
    Write-Host "Using custom config file: $ConfigPath" -ForegroundColor Green
} else {
    # Check if default configs exist
    $defaultConfigExists = (Test-Path ".\config.json") -or (Test-Path ".\config.enc")
    
    if ($defaultConfigExists) {
        # Default config found, ask if they want to use it or specify custom path
        Write-Host "=====Configuration File Selection=====" -ForegroundColor Cyan
        
        if (Test-Path ".\config.enc") {
            Write-Host "Found: .\config.enc (encrypted)" -ForegroundColor Green
        }
        if (Test-Path ".\config.json") {
            Write-Host "Found: .\config.json (plain text)" -ForegroundColor Green
        }
        
        Write-Host "Options:" -ForegroundColor White
        Write-Host "  1) Use default config file(s) found above" -ForegroundColor White
        Write-Host "  2) Specify a custom config file path" -ForegroundColor White
        
        $choice = Read-Host "Select option (1 or 2)"
        
        if ($choice -eq '2') {
            $customPath = Read-Host "Enter the full path to your config file"
            
            if ([string]::IsNullOrWhiteSpace($customPath)) {
                Write-Host "No path provided. Using default config files." -ForegroundColor Yellow
                $finalConfigPath = $null
            } elseif (-not (Test-Path $customPath)) {
                Write-Host "Error: Config file not found at: $customPath" -ForegroundColor Red
                Write-Host "Falling back to default config files." -ForegroundColor Yellow
                $finalConfigPath = $null
            } else {
                $finalConfigPath = $customPath
                Write-Host "Using custom config file: $customPath" -ForegroundColor Green
            }
        } else {
            $finalConfigPath = $null
            Write-Host "Using default config files" -ForegroundColor Green
        }
        
        $configExists = $true
    } else {
        # No default config found, prompt for custom path
        Write-Host "=====No Default Configuration Found=====" -ForegroundColor Yellow
        Write-Host "No config.json or config.enc found in the current directory." -ForegroundColor Yellow
        Write-Host ""
        
        $createOrSpecify = Read-Host "Choose an option:  1) Create a new config.json file in current directory  2) Specify path to existing config file Enter choice (1 or 2)"
        
        if ($createOrSpecify -eq '2') {
            $customPath = Read-Host "Enter the full path to your existing config file"
            
            if ([string]::IsNullOrWhiteSpace($customPath)) {
                Write-Host "No path provided. Cannot continue without configuration." -ForegroundColor Red
                $configExists = $false
                $finalConfigPath = $null
            } elseif (-not (Test-Path $customPath)) {
                Write-Host "Error: Config file not found at: $customPath" -ForegroundColor Red
                $configExists = $false
                $finalConfigPath = $null
            } else {
                $finalConfigPath = $customPath
                $configExists = $true
                Write-Host "Using config file: $customPath" -ForegroundColor Green
            }
        } else {
            $configExists = $false
            $finalConfigPath = $null
        }
    }
}

if (-not $configExists) {

    $createNow = Read-Host "Would you like to create a sample config.json file now? (Y/N)"
    
    if ($createNow -eq 'Y' -or $createNow -eq 'y') {
        $sampleConfig = @{
            "ExampleClient1" = @{
                "client_id" = "your_client_id_here"
                "client_secret" = "your_client_secret_here"
            }
            "ExampleClient2" = @{
                "client_id" = "another_client_id"
                "client_secret" = "another_client_secret"
            }
        }
        
        try {
            $sampleConfig | ConvertTo-Json -Depth 3 | Out-File -FilePath "C:\Users\ndunne\Documents\config.json" -Encoding UTF8
            Write-Host "Sample config.json created successfully!" -ForegroundColor Green
            Write-Host "Please edit this file with your actual CrowdStrike API credentials." -ForegroundColor Yellow
            Write-Host "Then run this script again to begin using the tool." -ForegroundColor Yellow
        }
        catch {
            Write-Host "Error creating config file: $($_.Exception.Message)" 
        }
    }
    
    exit 0
}

# Start the main application
try {
    Write-Host "Starting CrowdStrike Management Console..." -ForegroundColor Green
    Start-Sleep -Seconds 1
    if ($finalConfigPath) {
        Start-CrowdStrikeManager -ConfigPath $finalConfigPath
    } else {
        Start-CrowdStrikeManager
    }
}
catch {
    Write-Host "Error running CrowdStrike Manager: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
}
finally {
    # Clean up
    Remove-Module CrowdStrike-Manager -ErrorAction SilentlyContinue
}