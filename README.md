# EntraID-MFA-Auditor
# 🛡️ Entra ID MFA Status Report (Microsoft Graph)

A modern PowerShell script to audit Multi-Factor Authentication (MFA) status across your Microsoft Entra ID (formerly Azure AD) tenant.

## 🚀 Why this script?
With the deprecation of the `MSOnline` (v1) module, many legacy MFA scripts no longer work or require old protocols. This script is built entirely on the **Microsoft Graph PowerShell SDK**.

## 📊 Features
- **Legacy MFA Status:** Detects if users are Enforced, Enabled, or Disabled.
- **Modern "MFA Capable" Check:** Verifies if a user has actual methods registered (Authenticator App, Phone, Key) even if their legacy state is "Disabled" (common for Conditional Access environments).
- **Contact Details:** Fetches registered phone numbers and email addresses.
- **Auto-Cleanup:** Handles PowerShell function capacity limits automatically.

## ⚙️ Prerequisites
You must have the Microsoft Graph module installed:
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser

🏃 How to Run
Download Get-MFAStatus.ps1

Run in PowerShell:
Get-MFAReport_MS_Graph_api.ps1

Options
Check a specific user: .\Get-MFAStatus.ps1 -UserPrincipalName user@domain.com

Check only Admins: .\Get-MFAStatus.ps1 -AdminsOnly

Export to CSV: .\Get-MFAStatus.ps1 | Export-Csv "MFA_Report.csv" -NoTypeInformation

🔐 Permissions
The script will request the following Graph permissions upon first login:

User.Read.All

UserAuthenticationMethod.Read.All

Policy.Read.All (Required for Legacy MFA state)

RoleManagement.Read.Directory


---

### Step 2: The LinkedIn Post
I have taken your draft and polished it to maximize readability and engagement. I added a "Technical Note" section to highlight that you built this for the modern era (Graph SDK), which is a great selling point for your skills.

**Post Text:**

**Headline:** 📉 The Silent Killer of Identity Security: Configuration Drift.

Setting up MFA is the easy part of Identity Management. Keeping it consistently enforced across your tenant? That’s where things fall apart.

When multiple administrators can modify authentication settings, "Configuration Drift" becomes almost guaranteed. Over time, a perfectly designed security posture starts to degrade without anyone noticing.

**Why Routine MFA Verification Matters:**

✅ **Consistency:** Ensures policies implemented by architects don’t get unintentionally overridden by Help Desk or junior admins.
✅ **Compliance:** Many cyber-insurance carriers now require 100% MFA coverage. One missed user can void an entire claim.
✅ **Security Exposure:** Attackers only need one MFA-less account to get in and pivot.

**My Recommendation:**
Stop relying on tribal knowledge or “I thought someone set that up.” Implement a weekly audit.

You need visibility into:
1. Who *should* have MFA.
2. Who *actually* has MFA.
3. Who slipped through the cracks.

To solve this, I wrote a custom PowerShell script.

**Technical Note:**
Microsoft is deprecating the old `MSOnline` module, breaking many classic audit scripts. I built this utilizing the modern **Microsoft Graph PowerShell SDK**. It audits Legacy State (Enforced/Enabled) AND actual registered methods (Phone/Authenticator App) to give you the full picture.

📂 **Grab the script on my GitHub:**
[INSERT YOUR GITHUB LINK HERE]

#PowerShell #MicrosoftGraph #EntraID #CyberSecurity #MFA #SysAdmin #IdentityManagement

---

### One final check before you post:
Make sure you copied the **last** script I gave you (the one with the `function capacity` fix and the `IsAdmin` HashSet logic). It is the most robust version.

**Would you like me to generate a dummy CSV example of what the output looks like so you can
