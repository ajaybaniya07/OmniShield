# Security Console add-on 1.9

## New in 1.9: VirusTotal

- **VirusTotal page** (sidebar > Monitor): check a **file** (Browse, or drop it in - only its fingerprint is sent),
  a **folder**, a **link**, a **website or IP address**, or a **fingerprint** (MD5 / SHA-1 / SHA-256).
  Results in plain English: how many security companies flag it, what they call it, details, and buttons to
  quarantine/block, open the full report, upload an unknown file (optional) or ask VirusTotal to scan a new link.
- **"Is this safe?" asks VirusTotal first** (up to 20 files by default, programs and scripts first), then runs the
  local antivirus and pattern rules. Both results appear in one report.
- **Settings > VirusTotal:** API key (stored encrypted with Windows DPAPI), plan (Free = 4/minute, 500/day,
  15,500/month, or Custom), a reserve kept for your own checks, how long to re-use saved results, files per safety
  check, risky file types only, and whether unknown files may be uploaded (off by default).
- **Never goes over your limits:** every lookup is booked before it's sent; per-minute waits are automatic;
  daily/monthly limits stop cleanly with a message; real usage is checked with VirusTotal for free (the
  overall_quotas endpoint doesn't use quota), so lookups made with the same key elsewhere are counted too.
  Saved results are re-used and don't cost anything.
- **Usage meter** in the sidebar ("481 left") and full minute / today / this-month meters on the VirusTotal page.
- Privacy: files are identified only by their SHA-256 fingerprint unless you upload them. Links, websites and IP
  addresses you check are sent to VirusTotal. The free key is for personal, non-commercial use.

# Add-on 1.8

Adds to Security Console 1.7:

- **User activity** (sidebar > Monitor): who signs in to this PC and how (at the PC, unlocking,
  Remote Desktop, over the network), wrong-password attempts, account changes, and the programs each
  person runs - with plain-English findings such as:
  - someone guessing a password (5+ wrong passwords within 10 minutes), especially if a sign-in then succeeds
  - sign-ins at times a person normally doesn't use the PC
  - Remote Desktop sign-ins, especially from the internet
  - new accounts, accounts given administrator rights, passwords reset by someone else, Guest turned on
  - the Security log being cleared
  - new programs run from Downloads or Temp, and hidden (encoded) PowerShell commands
  Each finding says what to do and whether it could be normal. Click a person for their sign-in heatmap,
  sign-in methods, devices they signed in from, programs and a timeline. Serious findings from the last
  24 hours also appear on the Threats page. Updated every 30 minutes.
- **Security checkup** (sidebar > Monitor): Windows and Security Console settings - Defender, Firewall,
  Windows Update, BitLocker, Remote Desktop, Guest account, administrators, accounts without a password,
  SMBv1, real-time protection, virus definitions, recent scan and more - each with a one-click fix.
  Security Console never changes Windows settings itself: fix buttons open the right Windows page.
- **Dashboard:** a "Get started" checklist for new users, a Security checkup summary and a People card.
- **Print / Save as PDF** for the User activity report and the Security checkup.

## Install

1. Extract this zip **into your Security Console 1.7 folder** (works whether or not add-on 1.8 is installed) (for example `C:\Build\SecurityConsole`),
   so `INSTALL-ADDON.bat` sits next to `UPDATE.bat`. Allow it to merge folders.
2. Double-click **INSTALL-ADDON.bat** and click **Yes**. It connects the add-on and runs the normal update
   (your settings, history, quarantine and blocked programs are kept).
3. Open the dashboard and press **Ctrl + F5** once.

Running INSTALL-ADDON.bat again is safe. Running plain UPDATE.bat later keeps the add-on.

## Good to know

- User activity reads the Windows **Security** log (sign-ins) and the **Sysmon** log (programs). Windows 11
  records sign-ins and failed sign-ins by default. Programs per person need Sysmon running.
- The first time a person is seen, the programs they run become their normal baseline; after that, new
  programs are highlighted.
- "Unusual time" compares each sign-in with that person's own pattern (after about 12 sign-ins).
  Before that, only sign-ins between midnight and 5 AM are highlighted.
