# Security Console 2.0 Beta (Framework Edition)

One enterprise-grade unified endpoint console for **ClamAV, YARA, osquery, Sysmon and Sigma (via Hayabusa)** on Windows 11, with
Real-Time Protection, NIST CSF 2.0 alignment, MITRE ATT&CK matrix mappings, Authenticode trust verification, combined risk scoring, and post-execution response controls.
No WSL, Docker or server needed. Everything is changed from the app - no PowerShell or config editing.

## Quick start
1. Extract to **C:\Build\SecurityConsole** (short path, no spaces).
2. Double-click **INSTALL.bat**, click **Yes**. First run: about 15-20 minutes.
3. Open it with **START Security Console.bat** or the desktop shortcut.

| File | Use it to |
|---|---|
| INSTALL.bat | Complete unified installation (Core + Add-ons: User Activity, Security Checkup, NIST CSF 2.0, VirusTotal) |
| INSTALL-ADDON.bat | Re-apply or update add-ons and UI extensions |
| UPDATE.bat | Install a newer version. Keeps settings, history, blocked programs, mutes and quarantine |
| START Security Console.bat | Open the dashboard (starts the background program if needed) |
| FIX-ClamAV.bat | Reinstall ClamAV only |
| UNINSTALL.bat | Remove it |

## Implemented in 2.0 Beta
- **Hardened API Handshake Authentication:**
  - Ephemeral 30-second one-time code handshake (`/api/auth/code` -> `/api/session`).
  - Access to `/api/auth/code` is locked down using an ACL-restricted bootstrap token (`config/.auth_bootstrap`) readable only by SYSTEM and Administrators.
  - HttpOnly SameSite=Strict session cookie + custom `X-SC-CSRF` header validation.
  - Strict Host header validation (`127.0.0.1:8080`) and Origin/Sec-Fetch-Site enforcement.
- **Windows Defender & ASR Event Ingestion:**
  - Real-time ingestion of `Microsoft-Windows-Windows Defender/Operational` events:
    - Event 1116: Malware / unwanted software detected.
    - Event 1117: Antivirus protective action taken.
    - Event 1121: Exploit Guard Attack Surface Reduction (ASR) blocked operation.
    - Event 1122: Exploit Guard Attack Surface Reduction (ASR) audited operation.
- **Persistence Diff Monitoring (osquery):**
  - Baseline differential monitoring tracking additions and modifications across:
    - Registry Run keys and startup folder (`T1547.001`)
    - Installed Windows services (`T1543.003`)
    - Scheduled tasks (`T1053.005`)
    - Network listening ports (`T1049`)
    - Local Administrators group (`T1098`)
    - Hosts file tampering (`etc_hosts`, `T1565.001`)
- **Curated Production YARA Ruleset:**
  - Dedicated rules targeting infostealers (RedLine, Vidar, LummaC2), ransomware recovery tampering (`vssadmin delete shadows`), credential dumping, and webshell backdoors.
- **Soften Ransomware Canary Traps:**
  - Decoy files deployed in Desktop and Documents.
  - Benign accessors (OneDrive, SearchIndexer, Windows Explorer, Defender, robocopy) are allow-listed.
  - Implements a sliding 30-second strike counter: single access produces a medium alert; only multi-canary rapid modification triggers a critical containment alert.
- **Multi-Factor Combined Risk Scoring Engine:**
  - Weighted algorithmic scoring (0-100+) with clear factor breakdown drawers:
    - AV / YARA signature hit: `+100` (critical alert)
    - Unsigned binary running from Downloads / Temp / AppData: `+25`
    - Internet Mark-of-the-Web (ZoneId: 3) on unsigned executable: `+15`
    - Deceptive double extension (`.pdf.exe`) or Unicode RLO override: `+30`
    - High-entropy packed sections (Shannon entropy > 7.2): `+10`
    - Valid third-party Authenticode signature: `-30`
    - Verified Microsoft system catalog signature: `-50`
- **Authenticode & Catalog Verification:**
  - Real-time signature validation via `WinVerifyTrust` with catalog awareness for Windows system components (`0x800b0100`).
- **MOTW Privacy Sanitization:**
  - Strips tokens, auth headers, and query strings from Zone.Identifier `HostUrl` and `ReferrerUrl` prior to display.
- **Safe Self-Test with EICAR:**
  - Gracefully handles real-time AV write blocking and automatically isolates/resolves self-test alerts so the Threats drawer remains clean.
- **NIST Cybersecurity Framework (CSF 2.0) Posture Assessment:**
  - Maps controls to **Identify**, **Protect**, **Detect**, **Respond**, and **Recover** with interactive progress meters.
- **MITRE ATT&CK® Tactic & Technique Mapping:**
  - Clickable technique deep-links to [attack.mitre.org](https://attack.mitre.org) and tactic filtering.

## 2.0 Roadmap & Upcoming Enhancements
- [ ] **Clean Corpus Benchmarking:** Benchmark false-positive rates and scan times across clean Windows 11 system directories vs. malware corpus to mathematically measure noise reduction.
- [ ] **Remote Signed Manifest Verification for UPDATE.bat:** Verify release package hashes against a remote signed GitHub release manifest over HTTPS.
- [ ] **YARA-Forge Integration:** Automate scheduled pulls from YARA-Forge Core with per-rule license auditing.
- [ ] **Privilege Separation Architecture:** Split backend into a low-privilege user-facing API and a minimal privileged helper service with a strict whitelist of actions.
- [ ] **AppLocker / Software Restriction Policy (SRP):** Outright pre-execution launch prevention rules alongside reactive process termination.

## Threat Model & Honest Disclosures
- **What Security Console DOES:**
  - Provides defense-in-depth visibility, log telemetry, threat hunting, and rapid post-execution containment.
  - Neutralizes known malware, unauthorized startup persistence, suspicious network connections, and anomalous scripts.
  - Sandboxes API access to local processes only, blocking cross-site request forgery, DNS rebinding, and unauthorized LAN snooping.
- **What Security Console CANNOT DO (Keep Microsoft Defender ON):**
  - **No Pre-Execution Kernel Blocking:** Security Console is an agent running in user-space with SYSTEM privileges; it does not deploy a proprietary ELAM (Early Launch Anti-Malware) or minifilter kernel driver. It detects and terminates unauthorized processes within 1-2 seconds of spawn, but cannot prevent the initial memory page allocation. Always keep Microsoft Defender active for kernel-level pre-execution interception.
  - **Admin-Level Malware:** Any adversary executing code with local Administrator or SYSTEM privileges has access to the local machine and could terminate user-mode processes.
- **Data Privacy (What Leaves Your PC):**
  - **Zero Telemetry by Default:** Security Console operates 100% locally on your machine.
  - **VirusTotal (Opt-In Only):** If and only if you provide a VirusTotal API key in Settings, SHA-256 hashes (and optionally sanitized URLs) will be queried against VirusTotal's public API. Query strings and credentials are automatically stripped from URLs before sending.

## Safety Rules
- Report-only by default; nothing is deleted unless you choose "Delete forever" in Quarantine.
- Windows system programs and Security Console's own tools can't be stopped or blocked.
- Real-time detects within seconds but can't block a file before it opens - keep **Microsoft Defender** on.
- The dashboard listens on 127.0.0.1 only.

## Third-Party Licenses & Credits
- **ClamAV**: GPLv2 (Cisco Talos)
- **osquery**: Apache 2.0 (osquery Project)
- **YARA**: BSD-3-Clause (VirusTotal)
- **YARA-Forge**: Apache 2.0 / MIT (YARA-Forge Project)
- **Hayabusa**: AGPLv3 (Yamato Security)
- **Sigma Rules**: Detection Rule License (DRL 1.1)
- **Sysmon**: Sysinternals Software License (Microsoft)
- **Inter Font**: SIL Open Font License 1.1 (Rasmus Andersson)
- **FastAPI / Pydantic / Uvicorn**: MIT License
- **pywin32 / psutil**: BSD / PSF License
- **watchdog**: Apache 2.0 License
