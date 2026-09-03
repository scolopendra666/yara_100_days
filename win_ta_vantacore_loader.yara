rule win_ta_vantacore_loader : windows file pe {
    meta:
        description = "Detects VantaCoreLoader (network propagation tool)"
        author = "qazaqstanmafia"
        date = "2026-09-03"
        reference = "F6 Report - VantaCoreLoader"
        severity = "high"
        type = "alert"

    strings:
        $name = "VantaCoreLoader" ascii wide
        $usage = "Usage: VantaCoreLoader.exe" ascii wide
        $admin = "Admin Shares" ascii wide nocase
        $ldap = "LDAP query" ascii wide nocase
        $ipc = "IPC$" ascii wide
        $psexec = "psexec_netspread" ascii wide nocase
        $service = "CreateService" ascii wide
        $netspread = "netspread" ascii wide nocase
        $agent = "agent.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 50KB and filesize < 2MB and
        (
            $name or
            ($usage and ($admin or $ldap or $ipc)) or
            (3 of ($admin, $ldap, $ipc, $psexec, $service, $netspread))
        )
}