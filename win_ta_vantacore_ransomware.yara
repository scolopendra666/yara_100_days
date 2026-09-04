rule win_ta_vantacore_ransomware : windows file pe {
    meta:
        description = "Detects VantaCore Ransomware (C++)"
        author = "qazaqstanmafia"
        date = "2026-09-04"
        reference = "F6 Report - VantaCore Ransomware"
        severity = "high"
        type = "alert"

    strings:
        $help1 = "VantaCore Ransomware" ascii wide
        $help2 = "Usage: VantaCore.exe <password>" ascii wide
        $help3 = "ChaCha20-X25519" ascii wide nocase
        $help4 = "X25519 public key" ascii wide nocase
        $help5 = "--password" ascii wide
        $help6 = "Stopping services" ascii wide nocase
        $help7 = "encrypting files" ascii wide nocase
        $ext1 = ".vantacore" ascii wide nocase
        $ext2 = ".vanta" ascii wide nocase
        $note1 = "VantaCore Decryption" ascii wide
        $note2 = "DECRYPT-ID" ascii wide
        $crypto = "ChaCha20" ascii wide

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        filesize > 100KB and filesize < 5MB and
        (
            ($help1 or $help2 or $help3 or $help4) or
            ($help5 and $help6 and $help7) or
            (3 of ($crypto, $ext1, $ext2, $note1, $note2))
        )
}