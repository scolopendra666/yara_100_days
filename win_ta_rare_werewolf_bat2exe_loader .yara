rule win_ta_rare_werewolf_bat2exe_loader : windows file pe
{
    meta:
        description = "Detects Rare Werewolf group Bat2Exe packed batch scripts (loader and main payload)"
        author = "qazaqstanmafia"
        date = "2026-09-01"
        reference = "https://t.me/four_rays/99"
        severity = "high"
        type = "alert"
        campaign = "Rare Werewolf AnyDesk deployment"
        
    strings:
        // Core infrastructure domains
        $domain1 = "aero-bas.store" ascii nocase
        $domain2 = "mail-identification.site" ascii nocase
        $domain3 = "api.ipify.org" ascii nocase
        
        // Critical paths and filenames
        $path1 = "AppData\\wordpress" ascii nocase
        $path2 = "Program Files (x86)\\AnyDesk" ascii nocase
        $file1 = "whatisit.rar" ascii nocase
        $file2 = "settings.reg" ascii nocase
        $file3 = "letter.pdf" ascii nocase
        $file4 = "doc.exe" ascii nocase
        $file5 = "UnRAR.exe" ascii nocase
        
        // Batch script logic patterns
        $cmd1 = "net session" ascii
        $cmd2 = "Start-Process '%~f0' -Verb RunAs" ascii nocase
        $cmd3 = "attrib +h +s" ascii nocase
        $cmd4 = "bitsadmin /transfer" ascii nocase
        $cmd5 = "ZHVtYmFzcw==" ascii  // Base64 encoded password "dumbass"
        $cmd6 = "taskkill /F /IM AnyDesk.exe" ascii nocase
        $cmd7 = "--set-password _unattended_access" ascii nocase
        $cmd8 = "netsh advfirewall firewall add rule name=\"AnyDesk\"" ascii nocase
        
        // Defender evasion patterns
        $defender1 = "Add-MpPreference -ExclusionPath" ascii nocase
        $defender2 = "DisableAntiSpyware" ascii nocase
        $defender3 = "DisableRealTimeMonitoring" ascii nocase
        $defender4 = "Set-MpPreference -DisableRealtimeMonitoring" ascii nocase
        $defender5 = "HKLM\\Software\\Policies\\Microsoft\\Windows Defender" ascii nocase
        $defender6 = "schtasks /Change /TN \"Microsoft\\Windows\\ExploitGuard" ascii nocase
        
        // Scheduled task creation
        $schtask1 = "schtasks /create /tn \"Auto apdate\"" ascii nocase
        $schtask2 = "schtasks /Change /TN \"Microsoft\\Windows\\Windows Defender" ascii nocase
        
        // Unique password and configuration patterns
        $pwd = "QWERTY1234566" ascii
        $json_pattern = "\\\"id\\\":\\\"[ANYDESK_ID]\\\"\\,\\\"ip\\\":\\\"[PUBLIC_IP_ADDRESS]\\\"" ascii
        
        // Bat2Exe indicators
        $bat2exe = "Batch script" ascii nocase
        $temp_pattern = ".tmp\\.tmp\\.bat" ascii
        
    condition:
        uint16(0) == 0x5A4D and                     // MZ header
        uint32(uint32(0x3C)) == 0x00004550 and      // PE signature
        filesize > 50KB and filesize < 10MB and     // Bat2Exe typical size range
        
        // Must have at least one domain indicator
        any of ($domain*) and
        (
            // Main payload indicators
            (
                any of ($path*) and
                any of ($cmd1, $cmd2, $cmd4, $cmd6, $cmd7, $cmd8) and
                filesize > 1MB and filesize < 7MB
            ) or
            // Loader indicators (Defender evasion focus)
            (
                any of ($defender*) and
                any of ($path1, $file4) and
                filesize > 50KB and filesize < 3MB
            ) or
            // Specific combination for loader
            (
                any of ($defender5, $defender2, $defender3) and
                $domain1 and
                $file4 and
                $path1
            )
        ) and
        // Exclude false positives - requires at least 2 unique indicators
        #strings > 2
}