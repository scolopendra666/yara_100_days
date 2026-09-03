rule win_ta_vantacore_rat_go : windows file pe {
    meta:
        description = "Detects VantaCoreRAT (Go backdoor with obfuscation)"
        author = "qazaqstanmafia"
        date = "2026-09-03"
        reference = "F6 Report - VantaCoreRAT"
        severity = "high"
        type = "alert"

    strings:
        $name = "VantaCoreRAT" ascii wide
        $garble = "Garble" ascii wide
        $socks = "socks5" ascii wide nocase
        $shell = "reverse shell" ascii wide nocase
        $proxy = "proxy" ascii wide
        $update = "/api/update" ascii wide
        $config = "config.json" ascii wide
        $go_main = "main.main" ascii wide
        $go_net = "net/http" ascii wide
        $go_runtime = "runtime" ascii wide

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 200KB and filesize < 10MB and
        (
            ($name and ($socks or $shell or $proxy)) or
            ($garble and ($socks or $shell) and $go_runtime) or
            ($name and $go_main and 2 of ($go_net, $update, $config))
        )
}