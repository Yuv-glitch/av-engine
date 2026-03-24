rule Suspicious_Shell_Commands
{
    meta:
        description = "Detects reverse shell and command execution patterns"
        severity = "high"

    strings:
        $s1 = "/bin/sh" ascii
        $s2 = "/bin/bash" ascii
        $s3 = "nc -e" ascii
        $s4 = "bash -i" ascii
        $s5 = "python -c" ascii
        $s6 = "socket.connect" ascii
        $s7 = "os.system" ascii

    condition:
        2 of them
}

rule Base64_Encoded_Payload
{
    meta:
        description = "Detects base64 decode execution patterns"
        severity = "medium"

    strings:
        $s1 = "base64 -d" ascii
        $s2 = "base64 --decode" ascii
        $s3 = "echo " ascii
        $s4 = "| bash" ascii
        $s5 = "| sh" ascii

    condition:
        2 of them
}

rule ELF_Suspicious
{
    meta:
        description = "Detects ELF binaries with suspicious characteristics"
        severity = "high"

    strings:
        $elf_magic = { 7F 45 4C 46 }
        $s1 = "ptrace" ascii
        $s2 = "rootkit" ascii
        $s3 = "hideprocess" ascii
        $s4 = "/proc/self/mem" ascii

    condition:
        $elf_magic at 0 and 1 of ($s1, $s2, $s3, $s4)
}

rule Webshell_PHP
{
    meta:
        description = "Detects common PHP webshell patterns"
        severity = "critical"

    strings:
        $s1 = "eval(base64_decode" ascii
        $s2 = "system($_GET" ascii
        $s3 = "exec($_POST" ascii
        $s4 = "passthru($_REQUEST" ascii
        $s5 = "shell_exec($_" ascii
        $s6 = "assert($_" ascii

    condition:
        1 of them
}

rule Python_Malware
{
    meta:
        description = "Detects suspicious Python scripts"
        severity = "medium"

    strings:
        $s1 = "import socket" ascii
        $s2 = "import subprocess" ascii
        $s3 = "subprocess.Popen" ascii
        $s4 = "pty.spawn" ascii
        $s5 = "chmod" ascii
        $s6 = "reverse" ascii nocase

    condition:
        3 of them
}

rule Credential_Harvesting
{
    meta:
        description = "Detects scripts targeting credential files"
        severity = "critical"

    strings:
        $s1 = "/etc/shadow" ascii
        $s2 = "/etc/passwd" ascii
        $s3 = ".ssh/id_rsa" ascii
        $s4 = "authorized_keys" ascii
        $s5 = "/root/.bash_history" ascii

    condition:
        2 of them
}
