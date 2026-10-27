rule SC_Test_Marker
{
    meta:
        description = "Harmless test rule - matches files containing the marker text"
        severity = "low"
    strings:
        $a = "SECURITY_CONSOLE_YARA_TEST" ascii wide
    condition:
        $a
}

rule SC_Suspicious_PowerShell_Download
{
    meta:
        description = "Script that downloads and runs code from the internet in memory"
    strings:
        $iex  = "IEX" nocase ascii wide
        $inv  = "Invoke-Expression" nocase ascii wide
        $dl1  = "DownloadString" nocase ascii wide
        $dl2  = "Net.WebClient" nocase ascii wide
        $enc  = "-EncodedCommand" nocase ascii wide
    condition:
        filesize < 2MB and ((($iex or $inv) and ($dl1 or $dl2)) or ($enc and ($dl1 or $dl2)))
}
