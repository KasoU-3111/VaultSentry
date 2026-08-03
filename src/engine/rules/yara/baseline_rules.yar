/*
   VaultSentry - Baseline Demonstration Rules
*/

rule Suspicious_Powershell_Execution
{
    meta:
        description = "Detects embedded PowerShell execution commands in binaries/scripts"
        severity = "High"
    strings:
        $ps1 = "powershell.exe" nocase
        $ps2 = "-ExecutionPolicy Bypass" nocase
        $ps3 = "-EncodedCommand" nocase
        $ps4 = "Invoke-Expression" nocase
    condition:
        any of ($ps*)
}

rule UPX_Packed_Executable
{
    meta:
        description = "Detects UPX executable compression headers"
        severity = "Medium"
    strings:
        $upx1 = "UPX0"
        $upx2 = "UPX1"
        $upx3 = "UPX!"
    condition:
        2 of ($upx*)
}