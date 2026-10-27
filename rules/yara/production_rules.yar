/*
   Security Console - Production Threat Rules
   Curated rules for Ransomware, Infostealers, Webshells, and Defense Evasion
*/

rule SC_Ransomware_Recovery_Tampering
{
    meta:
        description = "Commands or code that delete volume shadow copies or disable Windows recovery"
        severity = "critical"
        mitre = "T1490 - Inhibit System Recovery"
    strings:
        $vss1 = "vssadmin" nocase ascii wide
        $vss2 = "delete shadows" nocase ascii wide
        $wba1 = "wbadmin" nocase ascii wide
        $wba2 = "delete catalog" nocase ascii wide
        $bcd1 = "bcdedit" nocase ascii wide
        $bcd2 = "recoveryenabled no" nocase ascii wide
        $bcd3 = "bootstatuspolicy ignoreallfailures" nocase ascii wide
        $wmi  = "Win32_ShadowCopy" nocase ascii wide
    condition:
        filesize < 15MB and (
            ($vss1 and $vss2) or
            ($wba1 and $wba2) or
            ($bcd1 and ($bcd2 or $bcd3)) or
            ($wmi and $vss2)
        )
}

rule SC_Credential_Dumping_Mimikatz_Artifacts
{
    meta:
        description = "Signatures and artifacts associated with Mimikatz and LSASS credential dumping"
        severity = "critical"
        mitre = "T1003.001 - LSASS Memory"
    strings:
        $s1 = "sekurlsa::logonpasswords" nocase ascii wide
        $s2 = "lsadump::sam" nocase ascii wide
        $s3 = "lsadump::secrets" nocase ascii wide
        $s4 = "sekurlsa::minidump" nocase ascii wide
        $s5 = "privilege::debug" nocase ascii wide
        $s6 = "kerberos::golden" nocase ascii wide
        $api1 = "MiniDumpWriteDump" ascii
        $api2 = "lsass.exe" nocase ascii wide
    condition:
        filesize < 20MB and (
            2 of ($s1, $s2, $s3, $s4, $s5, $s6) or
            ($api1 and $api2 and $s5)
        )
}

rule SC_Infostealer_Generic_Capabilities
{
    meta:
        description = "Patterns common to browser password and crypto wallet infostealers (RedLine, Lumma, Vidar)"
        severity = "high"
        mitre = "T1555 - Credentials from Password Stores"
    strings:
        $c1 = "Login Data" ascii wide
        $c2 = "Web Data" ascii wide
        $c3 = "Cookies" ascii wide
        $sql = "SELECT action_url, username_value, password_value FROM logins" ascii wide
        $wal1 = "wallet.dat" nocase ascii wide
        $wal2 = "Atomic\\Local Storage" nocase ascii wide
        $wal3 = "Metamask" nocase ascii wide
        $steal1 = "stealer" nocase ascii wide
        $steal2 = "password_grabber" nocase ascii wide
        $steal3 = "exfiltrat" nocase ascii wide
    condition:
        filesize < 10MB and (
            ($sql and 1 of ($wal1, $wal2, $wal3, $steal1, $steal2, $steal3)) or
            (2 of ($c1, $c2, $c3) and 1 of ($wal1, $wal2, $wal3) and 1 of ($steal1, $steal2, $steal3))
        )
}

rule SC_Generic_Webshell_Backdoor
{
    meta:
        description = "Generic webshell backdoor code patterns (PHP, ASPX)"
        severity = "high"
        mitre = "T1505.003 - Web Shell"
    strings:
        $php1 = "eval(" nocase ascii
        $php2 = "base64_decode(" nocase ascii
        $php3 = "system($_" nocase ascii
        $php4 = "shell_exec($_" nocase ascii
        $php5 = "passthru($_" nocase ascii
        $aspx1 = "ProcessStartInfo" nocase ascii
        $aspx2 = "cmd.exe" nocase ascii
        $aspx3 = "RedirectStandardOutput" nocase ascii
        $tag1 = "<%" ascii
        $tag2 = "<?php" nocase ascii
        $tag3 = "<script runat" nocase ascii
    condition:
        filesize < 2MB and (
            ($tag2 and $php1 and $php2 and ($php3 or $php4 or $php5)) or
            (($tag1 or $tag3) and $aspx1 and $aspx2 and $aspx3)
        )
}

rule SC_Deceptive_Executable_Extension
{
    meta:
        description = "Deceptive double extension designed to trick users into running executables disguised as documents"
        severity = "high"
        mitre = "T1036.007 - Double File Extension"
    strings:
        // Right-to-Left Override Unicode char: U+202E
        $rlo = { E2 80 AE }
    condition:
        $rlo
}

rule SC_Obfuscated_Download_Cradle
{
    meta:
        description = "Scripts using certutil, bitsadmin, or mshta to download payloads directly from remote servers"
        severity = "medium"
        mitre = "T1105 - Ingress Tool Transfer"
    strings:
        $c1 = "certutil" nocase ascii wide
        $c2 = "-urlcache" nocase ascii wide
        $c3 = "-split" nocase ascii wide
        $b1 = "bitsadmin" nocase ascii wide
        $b2 = "/transfer" nocase ascii wide
        $m1 = "mshta" nocase ascii wide
        $m2 = "http://" nocase ascii wide
        $m3 = "https://" nocase ascii wide
    condition:
        filesize < 1MB and (
            ($c1 and $c2 and $c3) or
            ($b1 and $b2) or
            ($m1 and ($m2 or $m3))
        )
}

rule SC_Infostealer_RedLine_Artifacts
{
    meta:
        description = "Signatures and WCF serialization artifacts associated with RedLine Stealer"
        severity = "critical"
        mitre = "T1555 - Credentials from Password Stores"
    strings:
        $wcf1 = "NetTcpBinding" ascii wide
        $wcf2 = "EndpointAddress" ascii wide
        $ent1 = "Entity1" ascii wide
        $ent2 = "Entity2" ascii wide
        $ent3 = "RecordHeaderField" ascii wide
        $tok  = "Token" ascii wide
        $tg   = "Telegram" ascii wide
        $dsc  = "Discord" ascii wide
    condition:
        filesize < 10MB and (
            ($wcf1 and $wcf2 and ($ent1 or $ent2 or $ent3)) or
            (3 of ($ent1, $ent2, $ent3, $tok, $tg, $dsc))
        )
}

rule SC_Infostealer_Vidar_Artifacts
{
    meta:
        description = "Artifacts and file output patterns typical of Vidar Infostealer"
        severity = "critical"
        mitre = "T1555 - Credentials from Password Stores"
    strings:
        $v1 = "\\passwords.txt" nocase ascii wide
        $v2 = "\\autofill.txt" nocase ascii wide
        $v3 = "\\cookies.txt" nocase ascii wide
        $v4 = "\\information.txt" nocase ascii wide
        $v5 = "\\history.txt" nocase ascii wide
    condition:
        filesize < 8MB and (3 of ($v1, $v2, $v3, $v4, $v5))
}

rule SC_Infostealer_LummaC2_Patterns
{
    meta:
        description = "Network endpoints and configuration routines specific to LummaC2 Stealer"
        severity = "critical"
        mitre = "T1071.001 - Web Protocols"
    strings:
        $s1 = "/api/" ascii
        $s2 = "lumma" nocase ascii
        $s3 = "Content-Type: multipart/form-data; boundary=" ascii
        $s4 = "attachment; filename=\"file.zip\"" ascii
        $c2_1 = "lummac2" nocase ascii
        $c2_2 = "/api/report" ascii
    condition:
        filesize < 5MB and (
            ($s2 and $s1) or
            ($s2 and $s3 and $s4) or
            (1 of ($c2_1, $c2_2) and $s3)
        )
}

