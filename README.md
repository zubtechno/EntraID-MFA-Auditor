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
