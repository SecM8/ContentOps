# Detection inventory

_Generated 2026-06-03T11:26:00Z by ContentOps powered by SecM8._

## Summary

| Metric | Value |
|---|---:|
| Total detections | **148** |
| Production | 146 |
| Experimental | 1 |
| Deprecated | 1 |
| Tactic coverage | **86%** (12 / 14) |
| Technique coverage | **20%** (45 / 222) |
| Sub-technique coverage | **3%** (16 / 475) |

## Detections

| Title | Status | Severity | Kind | Tactics | Techniques | Owner | Merge | Deploy | Last review | Last PR |
|---|---|---|---|---|---|---|---|---|---|---|
| Detection of Attempts to Disable Microsoft Defender<br>`detection-of-attempts-to-disable-microsoft-defender` | production | medium | Defender XDR Custom Detection | Defense Evasion | T1562.001 | — | 2026-05-17 | — | — | — |
| Detection of Connections to Newly Registered Domains (DeviceNetworkEvents)<br>`detection-of-connections-to-newly-registered-domains-devicenetworkevents` | production | high | Defender XDR Custom Detection | Command And Control | — | — | 2026-05-17 | — | — | — |
| Detection of Connections to Newly Registered Domains (UrlClickEvents)<br>`detection-of-connections-to-newly-registered-domains-urlclickevents` | production | high | Defender XDR Custom Detection | Command And Control | — | — | 2026-05-17 | — | — | — |
| Detection of Hidden PowerShell Child Process Performing Network Activity<br>`detection-of-hidden-powershell-child-process-performing-network-activity` | production | medium | Defender XDR Custom Detection | Command And Control | T1105 | — | 2026-05-17 | — | — | — |
| Detection of Hidden PowerShell Network Activity for Potential Tool Transfer<br>`detection-of-hidden-powershell-network-activity-for-potential-tool-transfer` | production | high | Defender XDR Custom Detection | Command And Control | T1105 | — | 2026-05-17 | — | — | [#296](https://github.com/KustoKing/SIEMContent/pull/296) |
| Detection of High Volume of Unique DNS Queries Within One Hour<br>`detection-of-high-volume-of-unique-dns-queries-within-one-hour` | production | medium | Defender XDR Custom Detection | Command And Control | T1071.004 | — | 2026-05-17 | — | — | — |
| Detection of Low Prevalence DLL Sideloading Attempts in OneDrive Directory<br>`detection-of-low-prevalence-dll-sideloading-attempts-in-onedrive-directory` | production | high | Defender XDR Custom Detection | Persistence | T1574.002 | — | 2026-05-17 | — | — | [#299](https://github.com/KustoKing/SIEMContent/pull/299) |
| Detection of Malicious Process Injection Events with Untrusted or Rare Initiating Processes<br>`detection-of-malicious-process-injection-events-with-untrusted-or-rare-initiatin` | production | medium | Defender XDR Custom Detection | Defense Evasion, Privilege Escalation | T1055 | — | 2026-05-17 | — | — | [#300](https://github.com/KustoKing/SIEMContent/pull/300) |
| Detection of Microsoft Defender Disabling<br>`detection-of-microsoft-defender-disabling` | production | high | Defender XDR Custom Detection | Defense Evasion | T1562.001 | — | 2026-05-17 | — | — | — |
| Detection of Outbound POST Requests with Unusual Characteristics<br>`detection-of-outbound-post-requests-with-unusual-characteristics` | production | medium | Defender XDR Custom Detection | Command And Control | T1071.001 | — | 2026-05-17 | — | — | [#296](https://github.com/KustoKing/SIEMContent/pull/296) |
| Detection of Process Injection via Mavinject.exe<br>`detection-of-process-injection-via-mavinject-exe` | production | medium | Defender XDR Custom Detection | Defense Evasion, Privilege Escalation | T1055.001 | — | 2026-05-17 | — | — | [#300](https://github.com/KustoKing/SIEMContent/pull/300) |
| Detection of Remote WMI Shadow Copy Deletion<br>`detection-of-remote-wmi-shadow-copy-deletion` | production | medium | Defender XDR Custom Detection | Execution | — | — | 2026-05-17 | — | — | — |
| Detection of Rundll32.exe Execution Without Arguments<br>`detection-of-rundll32-exe-execution-without-arguments` | production | medium | Defender XDR Custom Detection | Defense Evasion | T1218.011 | — | 2026-05-17 | — | — | [#296](https://github.com/KustoKing/SIEMContent/pull/296) |
| Detection of RunOnce.exe Spawning Child Processes<br>`detection-of-runonce-exe-spawning-child-processes` | production | medium | Defender XDR Custom Detection | Persistence, Privilege Escalation | T1547 | — | 2026-05-17 | — | — | — |
| Detection of Suspicious Application Reading Clipboard<br>`detection-of-suspicious-application-reading-clipboard` | production | medium | Defender XDR Custom Detection | Collection | T1115 | — | 2026-05-17 | — | — | — |
| Detection of Suspicious Certificate File Creation by Scripting and Utility Tools<br>`detection-of-suspicious-certificate-file-creation-by-scripting-and-utility-tools` | production | medium | Defender XDR Custom Detection | Credential Access | T1649 | — | 2026-05-17 | — | — | — |
| Detection of Suspicious DLL Injections via InprocServer32 Registry Modifications<br>`detection-of-suspicious-dll-injections-via-inprocserver32-registry-modifications` | production | high | Defender XDR Custom Detection | Defense Evasion, Persistence | T1112 | — | 2026-05-17 | — | — | [#300](https://github.com/KustoKing/SIEMContent/pull/300) |
| Detection of Suspicious File Creation by ntoskrnl.exe<br>`detection-of-suspicious-file-creation-by-ntoskrnl-exe` | production | medium | Defender XDR Custom Detection | Lateral Movement | T1570 | — | 2026-05-17 | — | — | — |
| Detection of Suspicious LDAP Searches by Non-System Processes<br>`detection-of-suspicious-ldap-searches-by-non-system-processes` | production | medium | Defender XDR Custom Detection | Discovery | T1087 | — | 2026-05-17 | — | — | — |
| Detection of Suspicious or Unsigned Applications Accessing Cloud Storage APIs<br>`detection-of-suspicious-or-unsigned-applications-accessing-cloud-storage-apis` | deprecated | medium | Defender XDR Custom Detection | Exfiltration | T1567.001, T1567.002 | — | 2026-05-17 | — | — | [#300](https://github.com/KustoKing/SIEMContent/pull/300) |
| Detection of Suspicious Outbound MSHTA Traffic<br>`detection-of-suspicious-outbound-mshta-traffic` | production | high | Defender XDR Custom Detection | Defense Evasion | T1218.005 | — | 2026-05-17 | — | — | [#296](https://github.com/KustoKing/SIEMContent/pull/296) |
| Detection of Suspicious Outbound WScript or CScript Network Activity<br>`detection-of-suspicious-outbound-wscript-or-cscript-network-activity` | production | medium | Defender XDR Custom Detection | Execution | T1059.005 | — | 2026-05-17 | — | — | — |
| Detection of Suspicious PsExec Service Executing Files<br>`detection-of-suspicious-psexec-service-executing-files` | production | medium | Defender XDR Custom Detection | Lateral Movement | T1570 | — | 2026-05-17 | — | — | — |
| Detection of Suspicious User Account Creation Outside of Domain Controllers<br>`detection-of-suspicious-user-account-creation-outside-of-domain-controllers` | production | low | Defender XDR Custom Detection | Persistence | T1136.001 | — | 2026-05-17 | — | — | — |
| Detection of Suspicious WMI Activity Over RPC<br>`detection-of-suspicious-wmi-activity-over-rpc` | production | medium | Defender XDR Custom Detection | Lateral Movement | T1028 | — | 2026-05-17 | — | — | — |
| Detection of Unauthorized Modifications to the Hosts File<br>`detection-of-unauthorized-modifications-to-the-hosts-file` | production | medium | Defender XDR Custom Detection | Impact | — | — | 2026-05-17 | — | — | — |
| Detection of Unusual Connections to Domain Controllers Over Kerberos Port 88<br>`detection-of-unusual-connections-to-domain-controllers-over-kerberos-port-88` | production | medium | Defender XDR Custom Detection | Lateral Movement | T1550 | — | 2026-05-17 | — | — | — |
| Detection of Unusual Processes Taking Screenshots<br>`detection-of-unusual-processes-taking-screenshots` | production | low | Defender XDR Custom Detection | Collection | T1113 | — | 2026-05-17 | — | — | [#296](https://github.com/KustoKing/SIEMContent/pull/296) |
| Detection of WinRM Connections Over Port 5985<br>`detection-of-winrm-connections-over-port-5985` | production | medium | Defender XDR Custom Detection | Lateral Movement | T1028 | — | 2026-05-17 | — | — | — |
| [DEV] Processes spawned by VMware Tools (vmtoolsd.exe)<br>`dev-processes-spawned-by-vmware-tools-vmtoolsd-exe` | production | medium | Defender XDR Custom Detection | Execution | T1059 | — | 2026-05-17 | — | — | — |
| [DEV] Remote Thread Execution via QueueUserAPC API Call<br>`dev-remote-thread-execution-via-queueuserapc-api-call` | production | high | Defender XDR Custom Detection | Defense Evasion, Privilege Escalation | T1055 | — | 2026-05-17 | — | — | — |
| [DEV] Service Creation from a network share<br>`dev-service-creation-from-a-network-share` | production | low | Defender XDR Custom Detection | — | — | — | 2026-05-17 | — | — | — |
| [DEV]VMware Command Execution from Hypervisor<br>`dev-vmware-command-execution-from-hypervisor` | production | low | Defender XDR Custom Detection | — | — | — | 2026-05-17 | — | — | — |
| [DEV] WMI Provider Host spawning high-risk executables<br>`dev-wmi-provider-host-spawning-high-risk-executables` | production | high | Defender XDR Custom Detection | Execution | T1047 | — | 2026-05-17 | — | — | — |
| [DxBP][D0A0H1][MDE] ASR Executable Office Content<br>`dxbp-d0a0h1-mde-asr-executable-office-content` | production | low | Defender XDR Custom Detection | Persistence | T1137 | — | 2026-05-17 | — | — | [#300](https://github.com/KustoKing/SIEMContent/pull/300) |
| Out-of-Date Microsoft Security Intelligence Updates Detection<br>`out-of-date-microsoft-security-intelligence-updates-detection` | production | informational | Defender XDR Custom Detection | Defense Evasion | — | — | 2026-05-17 | — | — | — |
| Registry Key Analysis for Potential LoLBAS Persistence<br>`registry-key-analysis-for-potential-lolbas-persistence` | production | medium | Defender XDR Custom Detection | Persistence, Privilege Escalation | T1037 | — | 2026-05-17 | — | — | [#296](https://github.com/KustoKing/SIEMContent/pull/296) |
| Successful Login Post-URL Click Detection (1)<br>`successful-login-post-url-click-detection-1` | production | high | Defender XDR Custom Detection | Credential Access | — | — | 2026-05-17 | — | — | — |
| Successful Login Post-URL Click Detection<br>`successful-login-post-url-click-detection` | production | high | Defender XDR Custom Detection | Credential Access | — | — | 2026-05-17 | — | — | — |
| Suspicious commands over WMI<br>`suspicious-commands-over-wmi` | production | medium | Defender XDR Custom Detection | Execution | T1047 | — | 2026-05-17 | — | — | — |
| Suspicious LDAP Queries<br>`suspicious-ldap-queries` | production | medium | Defender XDR Custom Detection | Discovery | — | — | 2026-05-17 | — | — | — |
| Suspicious LDAP Search performed<br>`suspicious-ldap-search-performed` | production | medium | Defender XDR Custom Detection | Discovery | T1018, T1069.001, T1069.002, T1087, T1087.002, T1482 | — | 2026-05-17 | — | — | — |
| Suspicisadfasous Process Injection Detected<br>`suspicisadfasous-process-injection-detected` | production | high | Defender XDR Custom Detection | Defense Evasion, Privilege Escalation | T1055, T1055.001, T1055.002, T1055.004 | — | 2026-05-17 | — | — | — |
| T1018 Remote System Discovery<br>`t1018-remote-system-discovery` | production | medium | Defender XDR Custom Detection | Discovery | T1018 | — | 2026-05-17 | — | — | — |
| T1087.001 Account Discovery: Local Account<br>`t1087-001-account-discovery-local-account` | production | medium | Defender XDR Custom Detection | Discovery | T1087.001 | — | 2026-05-17 | — | — | — |
| T1087.002 Account Discovery: Domain Account<br>`t1087-002-account-discovery-domain-account` | production | medium | Defender XDR Custom Detection | Discovery | T1087.002 | — | 2026-05-17 | — | — | — |
| A User added an account to a privileged role<br>`a-user-added-an-account-to-a-privileged-role` | production | medium | Sentinel Analytic | — | — | — | 2026-05-17 | — | — | — |
| A User Registered an MFA Device while being at Risk<br>`a-user-registered-an-mfa-device-while-being-at-risk` | production | medium | Sentinel Analytic | Credential Access, Persistence | T1098, T1111 | — | 2026-05-17 | — | — | — |
| A User registred a new MFA Device<br>`a-user-registred-a-new-mfa-device` | production | high | Sentinel Analytic | Persistence | T1098 | — | 2026-05-17 | — | — | — |
| AA-Administrator modified the retention time<br>`aa-administrator-modified-the-retention-time` | production | medium | Sentinel Analytic | — | — | — | 2026-05-17 | — | — | — |
| AA-Azure Active Directory Hybrid Health AD FS New Server<br>`aa-azure-active-directory-hybrid-health-ad-fs-new-server` | production | medium | Sentinel Analytic | Defense Evasion | T1578 | — | 2026-05-17 | — | — | — |
| AA-Azure Active Directory Hybrid Health AD FS Service Delete<br>`aa-azure-active-directory-hybrid-health-ad-fs-service-delete` | production | medium | Sentinel Analytic | Defense Evasion | T1578 | — | 2026-05-17 | — | — | — |
| AA-Azure Active Directory Hybrid Health AD FS Suspicious Application<br>`aa-azure-active-directory-hybrid-health-ad-fs-suspicious-application` | production | medium | Sentinel Analytic | Credential Access, Defense Evasion | T1528, T1550 | — | 2026-05-17 | — | — | — |
| AA-Azure VM Run Command operation executed during suspicious login window<br>`aa-azure-vm-run-command-operation-executed-during-suspicious-login-window` | production | high | Sentinel Analytic | Credential Access, Lateral Movement | T1570 | — | 2026-05-17 | — | — | — |
| AA-Light house connection has modified<br>`aa-light-house-connection-has-modified` | production | high | Sentinel Analytic | — | — | — | 2026-05-17 | — | — | — |
| AA-Mass Cloud resource deletions Time Series Anomaly<br>`aa-mass-cloud-resource-deletions-time-series-anomaly` | production | medium | Sentinel Analytic | Impact | T1485 | — | 2026-05-17 | — | — | — |
| AA-New CloudShell User<br>`aa-new-cloudshell-user` | production | low | Sentinel Analytic | Execution | T1059 | — | 2026-05-17 | — | — | — |
| AA-Rare subscription-level operations in Azure<br>`aa-rare-subscription-level-operations-in-azure` | production | low | Sentinel Analytic | Credential Access, Persistence | T1003, T1098 | — | 2026-05-17 | — | — | — |
| AA-Suspicious granting of permissions to an account<br>`aa-suspicious-granting-of-permissions-to-an-account` | production | medium | Sentinel Analytic | Persistence, Privilege Escalation | T1098 | — | 2026-05-17 | — | — | — |
| AA-TI map Email entity to AzureActivity<br>`aa-ti-map-email-entity-to-azureactivity` | production | medium | Sentinel Analytic | Impact | — | — | 2026-05-17 | — | — | — |
| AA-TI map IP entity to AzureActivity<br>`aa-ti-map-ip-entity-to-azureactivity` | production | medium | Sentinel Analytic | Impact | — | — | 2026-05-17 | — | — | — |
| AAD-A User used PIM to request permisisons outside office hours<br>`aad-a-user-used-pim-to-request-permisisons-outside-office-hours` | production | low | Sentinel Analytic | — | — | — | 2026-05-17 | — | — | — |
| AAD-A User used SSPR outside office hours<br>`aad-a-user-used-sspr-outside-office-hours` | production | medium | Sentinel Analytic | — | — | — | 2026-05-17 | — | — | — |
| AAD-Account Created and Deleted in Longer Timeframe<br>`aad-account-created-and-deleted-in-longer-timeframe` | production | medium | Sentinel Analytic | — | — | — | 2026-05-17 | — | — | — |
| AAD-Account Created and Deleted in Short Timeframe<br>`aad-account-created-and-deleted-in-short-timeframe` | production | high | Sentinel Analytic | Initial Access | T1078 | — | 2026-05-17 | — | — | — |
| AAD-Account created or deleted by non-approved user<br>`aad-account-created-or-deleted-by-non-approved-user` | production | medium | Sentinel Analytic | Initial Access | T1078 | — | 2026-05-17 | — | — | — |
| AAD-Admin promotion after Role Management Application Permission Grant<br>`aad-admin-promotion-after-role-management-application-permission-grant` | production | high | Sentinel Analytic | Persistence, Privilege Escalation | — | — | 2026-05-17 | — | — | — |
| AAD-Anomalous sign-in location by user account and authenticating application<br>`aad-anomalous-sign-in-location-by-user-account-and-authenticating-application` | production | medium | Sentinel Analytic | Initial Access | T1078 | — | 2026-05-17 | — | — | — |
| AAD-Attempts to sign in to disabled accounts<br>`aad-attempts-to-sign-in-to-disabled-accounts` | production | medium | Sentinel Analytic | Initial Access | T1078 | — | 2026-05-17 | — | — | — |
| AAD-Azure Active Directory PowerShell accessing non-AAD resources<br>`aad-azure-active-directory-powershell-accessing-non-aad-resources` | production | low | Sentinel Analytic | Initial Access | T1078 | — | 2026-05-17 | — | — | — |
| AAD-Azure AD Role Management Permission Grant<br>`aad-azure-ad-role-management-permission-grant` | production | high | Sentinel Analytic | Persistence, Privilege Escalation | — | — | 2026-05-17 | — | — | — |
| AAD-Brute force attack against Azure Portal<br>`aad-brute-force-attack-against-azure-portal` | production | medium | Sentinel Analytic | Credential Access | T1110 | — | 2026-05-17 | — | — | — |
| AAD-Bulk Changes to Privileged Account Permissions<br>`aad-bulk-changes-to-privileged-account-permissions` | production | high | Sentinel Analytic | Privilege Escalation | T1078 | — | 2026-05-17 | — | — | — |
| AAD-Correlate Unfamiliar sign-in properties and atypical travel alerts<br>`aad-correlate-unfamiliar-sign-in-properties-and-atypical-travel-alerts` | production | high | Sentinel Analytic | Initial Access | T1078 | — | 2026-05-17 | — | — | — |
| AAD-Credential added after admin consented to Application<br>`aad-credential-added-after-admin-consented-to-application` | production | medium | Sentinel Analytic | Credential Access | — | — | 2026-05-17 | — | — | — |
| AAD-Detect PIM Alert Disabling activity<br>`aad-detect-pim-alert-disabling-activity` | production | medium | Sentinel Analytic | Persistence, Privilege Escalation | T1078, T1098 | — | 2026-05-17 | — | — | — |
| AAD-External guest invitations by default guest followed by Azure AD powershell signin<br>`aad-external-guest-invitations-by-default-guest-followed-by-azure-ad-powershell` | production | medium | Sentinel Analytic | Discovery, Initial Access, Persistence | — | — | 2026-05-17 | — | — | — |
| AAD-Failed login attempts to Azure Portal<br>`aad-failed-login-attempts-to-azure-portal` | production | low | Sentinel Analytic | Credential Access | T1110 | — | 2026-05-17 | — | — | — |
| AAD-Failed MFA<br>`aad-failed-mfa` | production | medium | Sentinel Analytic | — | — | — | 2026-05-17 | — | — | — |
| AAD-First access credential added to Application or Service Principal where no credential was present<br>`aad-first-access-credential-added-to-application-or-service-principal-where-no-c` | production | high | Sentinel Analytic | Defense Evasion | T1550 | — | 2026-05-17 | — | — | — |
| AAD-Mail.Read Permissions Granted to Application<br>`aad-mail-read-permissions-granted-to-application` | production | medium | Sentinel Analytic | Persistence | T1098 | — | 2026-05-17 | — | — | — |
| AAD-MFA disabled for a user<br>`aad-mfa-disabled-for-a-user` | production | medium | Sentinel Analytic | Credential Access | — | — | 2026-05-17 | — | — | — |
| AAD-Modified domain federation trust settings<br>`aad-modified-domain-federation-trust-settings` | production | high | Sentinel Analytic | Credential Access | — | — | 2026-05-17 | — | — | — |
| AAD-New access credential added to Application or Service Principal<br>`aad-new-access-credential-added-to-application-or-service-principal` | production | medium | Sentinel Analytic | Defense Evasion | T1550 | — | 2026-05-17 | — | — | — |
| AAD-New Legacy App<br>`aad-new-legacy-app` | production | high | Sentinel Analytic | — | — | — | 2026-05-17 | — | — | — |
| AAD-New Security Device Registered<br>`aad-new-security-device-registered` | production | high | Sentinel Analytic | — | — | — | 2026-05-17 | — | — | — |
| AAD-PIM Elevation Request Rejected<br>`aad-pim-elevation-request-rejected` | production | high | Sentinel Analytic | Persistence | T1078 | — | 2026-05-17 | — | — | — |
| AAD-Rare application consent<br>`aad-rare-application-consent` | production | medium | Sentinel Analytic | Collection, Lateral Movement, Persistence | T1136 | — | 2026-05-17 | — | — | — |
| AAD-Successfull SignIn from an IP address which blocked an account before<br>`aad-successfull-signin-from-an-ip-address-which-blocked-an-account-before` | production | medium | Sentinel Analytic | — | — | — | 2026-05-17 | — | — | — |
| AAD-Suspicious application consent for offline access<br>`aad-suspicious-application-consent-for-offline-access` | production | low | Sentinel Analytic | Credential Access | T1528 | — | 2026-05-17 | — | — | — |
| AAD-Suspicious application consent similar to O365 Attack Toolkit<br>`aad-suspicious-application-consent-similar-to-o365-attack-toolkit` | production | high | Sentinel Analytic | Credential Access, Defense Evasion | T1528, T1550 | — | 2026-05-17 | — | — | — |
| AAD-Suspicious application consent similar to PwnAuth<br>`aad-suspicious-application-consent-similar-to-pwnauth` | production | medium | Sentinel Analytic | Credential Access, Defense Evasion | T1528, T1550 | — | 2026-05-17 | — | — | — |
| AAD-TI map Email entity to SigninLogs<br>`aad-ti-map-email-entity-to-signinlogs` | production | medium | Sentinel Analytic | Impact | — | — | 2026-05-17 | — | — | — |
| AAD-TI map IP entity to SigninLogs<br>`aad-ti-map-ip-entity-to-signinlogs` | production | medium | Sentinel Analytic | Impact | — | — | 2026-05-17 | — | — | — |
| AAD-User added to Azure Active Directory Privileged Groups<br>`aad-user-added-to-azure-active-directory-privileged-groups` | production | medium | Sentinel Analytic | Persistence, Privilege Escalation | T1078, T1098 | — | 2026-05-17 | — | — | — |
| AAD-User added to highly privileged role<br>`aad-user-added-to-highly-privileged-role` | production | high | Sentinel Analytic | — | — | — | 2026-05-17 | — | — | — |
| AAD-User Added to the Partner Tier2 Support Role<br>`aad-user-added-to-the-partner-tier2-support-role` | production | high | Sentinel Analytic | — | — | — | 2026-05-17 | — | — | — |
| AAD-User Assigned Privileged Role<br>`aad-user-assigned-privileged-role` | production | high | Sentinel Analytic | Persistence | T1078 | — | 2026-05-17 | — | — | — |
| Advanced Multistage Attack Detection<br>`advanced-multistage-attack-detection` | production | high | Sentinel Analytic | Collection, Command And Control, Credential Access, Defense Evasion, Discovery, Execution, Exfiltration, Impact, Initial Access, Lateral Movement, Persistence, Privilege Escalation | — | — | 2026-05-17 | — | — | — |
| Create incidents based on Azure Active Directory Identity Protection alerts<br>`create-incidents-based-on-azure-active-directory-identity-protection-alerts` | production | informational | Sentinel Analytic | — | — | — | 2026-05-17 | — | — | — |
| Create incidents based on Azure Defender alerts<br>`create-incidents-based-on-azure-defender-alerts` | production | informational | Sentinel Analytic | — | — | — | 2026-05-17 | — | — | — |
| Detection of Account Disabling by Computer Accounts<br>`detection-of-account-disabling-by-computer-accounts` | production | medium | Sentinel Analytic | — | — | — | 2026-05-17 | — | — | — |
| Detection of Suspicious Outbound MSHTA Traffic<br>`detection-of-suspicious-outbound-mshta-traffic` | production | medium | Sentinel Analytic | Defense Evasion | T1218 | — | 2026-05-17 | — | — | — |
| Detection of Unusual Connections to Domain Controllers Over Kerberos Port 88<br>`detection-of-unusual-connections-to-domain-controllers-over-kerberos-port-88` | production | medium | Sentinel Analytic | Defense Evasion, Lateral Movement | T1550 | — | 2026-05-17 | — | — | — |
| Dummy Detction<br>`dummy-detction` | production | medium | Sentinel Analytic | Credential Access | T1003 | — | 2026-05-17 | — | — | — |
| Gebruiker heeft MFA Device geregistreerd<br>`gebruiker-heeft-mfa-device-geregistreerd` | production | medium | Sentinel Analytic | — | — | — | 2026-05-17 | — | — | — |
| HoneyTokens: KeyVault HoneyToken diagnostic settings deleted or changed<br>`honeytokens-keyvault-honeytoken-diagnostic-settings-deleted-or-changed` | production | high | Sentinel Analytic | Defense Evasion | — | — | 2026-05-17 | — | — | — |
| HoneyTokens: KeyVault HoneyToken key accessed<br>`honeytokens-keyvault-honeytoken-key-accessed` | production | medium | Sentinel Analytic | Discovery | — | — | 2026-05-17 | — | — | — |
| HoneyTokens: KeyVault HoneyToken secret accessed<br>`honeytokens-keyvault-honeytoken-secret-accessed` | production | medium | Sentinel Analytic | Discovery | — | — | 2026-05-17 | — | — | — |
| KW001-AD-Multiple User Account Deleted<br>`kw001-ad-multiple-user-account-deleted` | production | medium | Sentinel Analytic | Impact | T1531 | — | 2026-05-17 | — | — | — |
| MFA registration while at risk<br>`mfa-registration-while-at-risk` | production | medium | Sentinel Analytic | Persistence | T1098 | — | 2026-05-17 | — | — | — |
| MS-Anomalous login followed by Teams action<br>`ms-anomalous-login-followed-by-teams-action` | production | medium | Sentinel Analytic | Initial Access, Persistence | T1078, T1098, T1136, T1199 | — | 2026-05-17 | — | — | — |
| MS-Azure VM Run Command operations executing a unique powershell script<br>`ms-azure-vm-run-command-operations-executing-a-unique-powershell-script-91f8b586` | production | medium | Sentinel Analytic | Credential Access, Lateral Movement | T1570 | — | 2026-05-17 | — | — | — |
| MS-Azure VM Run Command operations executing a unique powershell script<br>`ms-azure-vm-run-command-operations-executing-a-unique-powershell-script-fba46ec6` | production | medium | Sentinel Analytic | Credential Access, Lateral Movement | T1570 | — | 2026-05-17 | — | — | — |
| MS-Detecting Impossible travel with mailbox permission tampering & Privilege Escalation attempt<br>`ms-detecting-impossible-travel-with-mailbox-permission-tampering-privilege-escal` | production | medium | Sentinel Analytic | Initial Access, Privilege Escalation | T1078, T1548 | — | 2026-05-17 | — | — | — |
| MS-DEV-0322 Serv-U related IOCs - July 2021<br>`ms-dev-0322-serv-u-related-iocs-july-2021` | production | high | Sentinel Analytic | Initial Access | T1190 | — | 2026-05-17 | — | — | — |
| MS-Known Barium IP<br>`ms-known-barium-ip` | production | high | Sentinel Analytic | Command And Control | — | — | 2026-05-17 | — | — | — |
| MS-Known IRIDIUM IP<br>`ms-known-iridium-ip` | production | high | Sentinel Analytic | Command And Control | — | — | 2026-05-17 | — | — | — |
| MS-Known Phosphorus group domains-IP<br>`ms-known-phosphorus-group-domains-ip` | production | high | Sentinel Analytic | Command And Control | T1071 | — | 2026-05-17 | — | — | — |
| MS-Log4j vulnerability exploit aka Log4Shell IP IOC<br>`ms-log4j-vulnerability-exploit-aka-log4shell-ip-ioc` | production | high | Sentinel Analytic | Command And Control | — | — | 2026-05-17 | — | — | — |
| MS-Malformed user agent<br>`ms-malformed-user-agent` | production | medium | Sentinel Analytic | Command And Control, Execution, Initial Access | T1071, T1189, T1203 | — | 2026-05-17 | — | — | — |
| MS-Multiple Password Reset by user<br>`ms-multiple-password-reset-by-user` | production | low | Sentinel Analytic | Credential Access, Initial Access | T1078, T1110 | — | 2026-05-17 | — | — | — |
| MS-NOBELIUM - Domain and IP IOCs - March 2021<br>`ms-nobelium-domain-and-ip-iocs-march-2021` | production | medium | Sentinel Analytic | Command And Control | T1102 | — | 2026-05-17 | — | — | — |
| MS-SOURGUM Actor IOC - July 2021<br>`ms-sourgum-actor-ioc-july-2021` | production | high | Sentinel Analytic | Persistence | T1546 | — | 2026-05-17 | — | — | — |
| MS-Suspicious number of resource creation or deployment activities<br>`ms-suspicious-number-of-resource-creation-or-deployment-activities` | production | medium | Sentinel Analytic | Impact | T1496 | — | 2026-05-17 | — | — | — |
| MS-User agent search for log4j exploitation attempt<br>`ms-user-agent-search-for-log4j-exploitation-attempt` | production | high | Sentinel Analytic | Initial Access | — | — | 2026-05-17 | — | — | — |
| MS-Workspace deletion attempt from an infected device<br>`ms-workspace-deletion-attempt-from-an-infected-device` | production | medium | Sentinel Analytic | Impact, Initial Access | T1078, T1489 | — | 2026-05-17 | — | — | — |
| O365-Client Side Forwarding Rule from New IP Address<br>`o365-client-side-forwarding-rule-from-new-ip-address` | production | medium | Sentinel Analytic | Collection | T1114 | — | 2026-05-17 | — | — | — |
| O365-Exchange AuditLog disabled<br>`o365-exchange-auditlog-disabled` | production | medium | Sentinel Analytic | Defense Evasion | T1562 | — | 2026-05-17 | — | — | — |
| O365-Exchange workflow MailItemsAccessed operation anomaly<br>`o365-exchange-workflow-mailitemsaccessed-operation-anomaly` | production | medium | Sentinel Analytic | Collection | T1114 | — | 2026-05-17 | — | — | — |
| O365-External user added and removed in short timeframe<br>`o365-external-user-added-and-removed-in-short-timeframe` | production | low | Sentinel Analytic | Persistence | T1136 | — | 2026-05-17 | — | — | — |
| O365-Known Manganese IP and UserAgent activity<br>`o365-known-manganese-ip-and-useragent-activity` | production | high | Sentinel Analytic | Collection, Initial Access | T1114, T1133 | — | 2026-05-17 | — | — | — |
| O365-Multiple Teams deleted by a single user<br>`o365-multiple-teams-deleted-by-a-single-user` | production | low | Sentinel Analytic | Impact | T1485, T1489 | — | 2026-05-17 | — | — | — |
| O365-Multiple users email forwarded to same destination<br>`o365-multiple-users-email-forwarded-to-same-destination` | production | medium | Sentinel Analytic | Collection, Exfiltration | T1020, T1114 | — | 2026-05-17 | — | — | — |
| O365-Office policy tampering<br>`o365-office-policy-tampering` | production | medium | Sentinel Analytic | Defense Evasion, Persistence | T1098, T1562 | — | 2026-05-17 | — | — | — |
| O365-Possible STRONTIUM attempted credential harvesting - Oct 2020<br>`o365-possible-strontium-attempted-credential-harvesting-oct-2020-7b515f8d` | production | low | Sentinel Analytic | Credential Access | T1110 | — | 2026-05-17 | — | — | — |
| O365-Possible STRONTIUM attempted credential harvesting - Oct 2020<br>`o365-possible-strontium-attempted-credential-harvesting-oct-2020-ab8adcf6` | production | low | Sentinel Analytic | Credential Access | T1110 | — | 2026-05-17 | — | — | — |
| O365-Possible STRONTIUM attempted credential harvesting - Sept 2020<br>`o365-possible-strontium-attempted-credential-harvesting-sept-2020` | production | low | Sentinel Analytic | Credential Access | T1110 | — | 2026-05-17 | — | — | — |
| O365-Rare and potentially high-risk Office operations<br>`o365-rare-and-potentially-high-risk-office-operations` | production | low | Sentinel Analytic | Collection, Persistence | T1098, T1114 | — | 2026-05-17 | — | — | — |
| O365-SharePointFileOperation via devices with previously unseen user agents<br>`o365-sharepointfileoperation-via-devices-with-previously-unseen-user-agents` | production | medium | Sentinel Analytic | Exfiltration | T1030 | — | 2026-05-17 | — | — | — |
| O365-SharePointFileOperation via previously unseen IPs<br>`o365-sharepointfileoperation-via-previously-unseen-ips` | production | medium | Sentinel Analytic | Exfiltration | T1030 | — | 2026-05-17 | — | — | — |
| O365-TI map Email entity to OfficeActivity<br>`o365-ti-map-email-entity-to-officeactivity` | production | medium | Sentinel Analytic | Impact | — | — | 2026-05-17 | — | — | — |
| O365-TI map IP entity to OfficeActivity<br>`o365-ti-map-ip-entity-to-officeactivity` | production | medium | Sentinel Analytic | Impact | — | — | 2026-05-17 | — | — | — |
| O365-TI map URL entity to OfficeActivity data<br>`o365-ti-map-url-entity-to-officeactivity-data` | production | medium | Sentinel Analytic | Impact | — | — | 2026-05-17 | — | — | — |
| (Preview) Microsoft Threat Intelligence Analytics<br>`preview-microsoft-threat-intelligence-analytics` | production | medium | Sentinel Analytic | Lateral Movement, Persistence | — | — | 2026-05-17 | — | — | — |
| Scheduled Task created to launch suspicious file extension<br>`scheduled-task-created-to-launch-suspicious-file-extension` | production | medium | Sentinel Analytic | Persistence, Privilege Escalation | T1053 | — | 2026-05-17 | — | — | — |
| Test<br>`test` | production | medium | Sentinel Analytic | — | — | — | 2026-05-17 | — | — | — |
| Example: Suspicious child process of Office application<br>`example-suspicious-process-tree` · [runbook](https://learn.microsoft.com/en-us/azure/sentinel/hunts) | experimental | medium | Sentinel Hunting | Execution, Defense Evasion | T1059.001, T1218 | detection-engineering | 2026-05-17 | — | 2026-05-17 | [#248](https://github.com/KustoKing/SIEMContent/pull/248) |

