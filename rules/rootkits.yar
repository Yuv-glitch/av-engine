rule Rootkit_Syscall_Hooking
{
    meta:
        description = "Detects syscall hooking techniques used by rootkits"
        severity = "critical"

    strings:
        $s1 = "sys_call_table" ascii
        $s2 = "kallsyms_lookup_name" ascii
        $s3 = "set_memory_rw" ascii
        $s4 = "cr0" ascii
        $s5 = "write_cr0" ascii
        $s6 = "module_hide" ascii

    condition:
        2 of them
}

rule Rootkit_Process_Hiding
{
    meta:
        description = "Detects process and file hiding techniques"
        severity = "critical"

    strings:
        $s1 = "filldir" ascii
        $s2 = "proc_readdir" ascii
        $s3 = "hide_pid" ascii
        $s4 = "list_del_init" ascii
        $s5 = "/proc/net/tcp" ascii
        $s6 = "find_task_by_pid" ascii

    condition:
        2 of them
}

rule Rootkit_LKM
{
    meta:
        description = "Detects suspicious Linux Kernel Module characteristics"
        severity = "critical"

    strings:
        $s1 = "init_module" ascii
        $s2 = "cleanup_module" ascii
        $s4 = "root_backdoor" ascii nocase
        $s5 = "give_root" ascii
        $s6 = "escalate_privs" ascii nocase

    condition:
        ($s1 and $s2) and 1 of ($s4, $s5, $s6)
}

rule Rootkit_Network_Hiding
{
    meta:
        description = "Detects network connection hiding"
        severity = "high"

    strings:
        $s1 = "hide_port" ascii nocase
        $s2 = "packet_rcv" ascii
        $s3 = "nf_hook_ops" ascii
        $s4 = "netfilter" ascii
        $s5 = "raw_socket" ascii

    condition:
        2 of them
}
