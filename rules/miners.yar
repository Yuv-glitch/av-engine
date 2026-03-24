rule Cryptominer_Stratum
{
    meta:
        description = "Detects stratum mining protocol usage"
        severity = "high"

    strings:
        $s1 = "stratum+tcp" ascii
        $s2 = "stratum+ssl" ascii
        $s3 = "mining.subscribe" ascii
        $s4 = "mining.authorize" ascii
        $s5 = "mining.notify" ascii

    condition:
        1 of them
}

rule Cryptominer_Binaries
{
    meta:
        description = "Detects common cryptominer binary strings"
        severity = "high"

    strings:
        $s1 = "xmrig" ascii nocase
        $s2 = "minerd" ascii nocase
        $s3 = "cpuminer" ascii nocase
        $s4 = "cryptonight" ascii nocase
        $s5 = "monero" ascii nocase
        $s6 = "randomx" ascii nocase

    condition:
        2 of them
}

rule Cryptominer_Shell_Dropper
{
    meta:
        description = "Detects shell scripts that download and run miners"
        severity = "critical"

    strings:
        $s1 = "wget" ascii
        $s2 = "curl" ascii
        $s3 = "chmod +x" ascii
        $s4 = "xmrig" ascii nocase
        $s5 = "pool." ascii
        $s6 = "nohup" ascii
        $s7 = "crontab" ascii

    condition:
        3 of them
}

rule Cryptominer_Config
{
    meta:
        description = "Detects cryptominer configuration files"
        severity = "medium"

    strings:
        $s1 = "\"pool\"" ascii
        $s2 = "\"wallet\"" ascii
        $s3 = "\"threads\"" ascii
        $s4 = "\"algo\"" ascii
        $s5 = "\"donate-level\"" ascii

    condition:
        3 of them
}
