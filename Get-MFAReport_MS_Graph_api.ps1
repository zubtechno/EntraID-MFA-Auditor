<#
.Synopsis
  Get MFA Status, Admin Status, and Contact Details (Phone/Email) using Microsoft Graph.
  INCLUDES FIX FOR: "Function capacity exceeded" error.

.NOTES
  Name: Get-MFAStatus-Final
  Updated by: Gemini AI
#>

[CmdletBinding(DefaultParameterSetName="Default")]
param(
    [Parameter(Mandatory = $false, ParameterSetName = "UserPrincipalName", Position = 0)]
    [string[]]$UserPrincipalName,

    [Parameter(Mandatory = $false, ParameterSetName = "AdminsOnly")]
    [switch]$adminsOnly = $false,

    [Parameter(Mandatory = $false, ParameterSetName = "AllUsers")]
    [int]$MaxResults = 10000,

    [Parameter(Mandatory = $false, ParameterSetName = "Licensed")]
    [switch]$IsLicensed = $true,

    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = "withOutMFAOnly")]
    [switch]$withOutMFAOnly = $false,

    [Parameter(Mandatory = $false)]
    [switch]$listAdmins = $true
)

# -------------------------------------------------------------------------
# 0. CLEANUP (Fix for "Function Capacity Exceeded")
# -------------------------------------------------------------------------
# We actively remove the functions if they exist from a previous run to free up slots.
$Funcs = @("Get-MgUserLegacyMFAState", "Process-UserMFA")
foreach ($F in $Funcs) {
    if (Test-Path "Function:\$F") { Remove-Item "Function:\$F" -Force -ErrorAction SilentlyContinue }
}

# -------------------------------------------------------------------------
# 1. CONNECT TO MICROSOFT GRAPH
# -------------------------------------------------------------------------
$Scopes = @("User.Read.All", "UserAuthenticationMethod.Read.All", "RoleManagement.Read.Directory", "Policy.Read.All")

try {
    $CurrentContext = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $CurrentContext) {
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
        Connect-MgGraph -Scopes $Scopes -NoWelcome
    }
}
catch {
    Write-Error "Could not connect. Please restart PowerShell and run again."
    return
}

# -------------------------------------------------------------------------
# 2. HELPER FUNCTIONS
# -------------------------------------------------------------------------

Function Get-MgUserLegacyMFAState {
    param ($UserId)
    # Queries the Beta endpoint to find if user is Enforced/Enabled
    try {
        $Uri = "https://graph.microsoft.com/beta/users/$UserId/authentication/requirements"
        $Result = Invoke-MgGraphRequest -Method GET -Uri $Uri -ErrorAction Stop
        if ($Result.perUserMfaState) {
            return $Result.perUserMfaState.Substring(0,1).ToUpper() + $Result.perUserMfaState.Substring(1)
        }
        return "Disabled"
    }
    catch {
        # 404 usually means not in the list (Disabled)
        if ($_.Exception.Message -match "Not Found" -or $_.Exception.Message -match "404") { return "Disabled" }
        return "Unknown"
    }
}

Function Process-UserMFA {
    param ($UserObj, $AdminIdList)

    Write-Host "Processing: $($UserObj.UserPrincipalName)" -NoNewline

    # A. Get Legacy MFA State
    $LegacyState = Get-MgUserLegacyMFAState -UserId $UserObj.Id
    
    # B. Get General Methods (To check if ANY MFA exists)
    try {
        $AllMethods = Get-MgUserAuthenticationMethod -UserId $UserObj.Id -ErrorAction SilentlyContinue
    } catch { $AllMethods = $null }

    # C. Get SPECIFIC Phone/Email Details (Using dedicated endpoints)
    $PhoneStr = "-"
    $EmailStr = "-"
    
    try {
        # Force retrieve phone methods
        $PhoneMethods = Get-MgUserAuthenticationPhoneMethod -UserId $UserObj.Id -ErrorAction SilentlyContinue
        if ($PhoneMethods) {
            $PhoneStr = ($PhoneMethods.PhoneNumber | Select-Object -Unique) -join ", "
        }
    } catch {}

    try {
        # Force retrieve email methods
        $EmailMethods = Get-MgUserAuthenticationEmailMethod -UserId $UserObj.Id -ErrorAction SilentlyContinue
        if ($EmailMethods) {
            $EmailStr = ($EmailMethods.EmailAddress | Select-Object -Unique) -join ", "
        }
    } catch {}

    # D. Is Admin?
    $IsAdmin = if ($AdminIdList -and $AdminIdList.Contains($UserObj.Id)) { $true } else { "-" }

    # E. MFA Enabled Calculation
    # User is "MFA Ready" if they have methods registered OR are enforced
    $MfaEnabledBool = if (($AllMethods.Count -gt 0) -or ($LegacyState -eq "Enforced")) { $true } else { $false }
    
    # Display small status in console
    if ($LegacyState -eq "Enforced") { Write-Host " [Enforced]" -ForegroundColor Green }
    elseif ($MfaEnabledBool) { Write-Host " [Enabled]" -ForegroundColor Cyan }
    else { Write-Host " [Disabled]" -ForegroundColor Gray }

    # F. Create Result Object
    [PSCustomObject]@{
        DisplayName        = $UserObj.DisplayName
        UserPrincipalName  = $UserObj.UserPrincipalName
        "Is Admin"         = $IsAdmin
        "MFA Status"       = $LegacyState      # Enforced/Enabled/Disabled
        "MFA Active"       = $MfaEnabledBool   # Has methods registered?
        "Registered Phone" = $PhoneStr
        "Registered Email" = $EmailStr
    }
}

# -------------------------------------------------------------------------
# 3. GATHER DATA
# -------------------------------------------------------------------------

# PRE-FETCH ADMINS (Using HashSet for fast lookup)
$AdminIds = New-Object System.Collections.Generic.HashSet[string]
if ($listAdmins -or $adminsOnly) {
    Write-Host "Fetching Admin Roles..." -ForegroundColor Cyan
    $Roles = Get-MgDirectoryRole | Where-Object { $_.MemberCount -gt 0 }
    foreach ($Role in $Roles) {
        $Members = Get-MgDirectoryRoleMember -DirectoryRoleId $Role.Id
        $Members | ForEach-Object { 
            if ($_.AdditionalProperties['@odata.type'] -eq "#microsoft.graph.user") {
                 $null = $AdminIds.Add($_.Id)
            }
        }
    }
}

# SELECT USERS TO PROCESS
$UsersToProcess = @()

if ($PSBoundParameters.ContainsKey('UserPrincipalName')) {
    foreach ($upn in $UserPrincipalName) {
        try { $UsersToProcess += Get-MgUser -UserId $upn -ErrorAction Stop } catch { Write-Warning "$upn not found" }
    }
}
elseif ($adminsOnly) {
    Write-Host "Filtering for Admins only..." -ForegroundColor Cyan
    foreach ($id in $AdminIds) { 
        try { $UsersToProcess += Get-MgUser -UserId $id -ErrorAction SilentlyContinue } catch {} 
    }
}
else {
    Write-Host "Fetching All Users (Max $MaxResults)..." -ForegroundColor Cyan
    $UsersToProcess = Get-MgUser -All -Top $MaxResults -Property Id, DisplayName, UserPrincipalName, AssignedLicenses
    if ($IsLicensed) {
        $UsersToProcess = $UsersToProcess | Where-Object { $_.AssignedLicenses.Count -gt 0 }
    }
}

# -------------------------------------------------------------------------
# 4. RUN AND OUTPUT
# -------------------------------------------------------------------------

$Results = @()
Write-Host "Starting Analysis..." -ForegroundColor Cyan

foreach ($User in $UsersToProcess) {
    $ResultObj = Process-UserMFA -UserObj $User -AdminIdList $AdminIds
    
    if ($withOutMFAOnly) {
        if ($ResultObj."MFA Active" -eq $false) {
            $Results += $ResultObj
        }
    }
    else {
        $Results += $ResultObj
    }
}

Write-Host "`nAnalysis Complete." -ForegroundColor Cyan
$Results | Format-Table -AutoSize

$Path = "C:\Temp\MFA_Status_Report_{0:yyyyMMdd_HHmmss}.csv" -f (Get-Date)
$Results | Export-Csv -Path $Path -NoTypeInformation

Write-Host "Report saved to: $Path" -ForegroundColor Green