rule DangerousPhp
{
    strings:
        $system = "system" fullword  // localroot bruteforcers have a lot of this

        $ = "exec" fullword
        $ = "eval" fullword
        $ = "shell_exec" fullword
        $ = "passthru" fullword
        $ = "posix_getuid" fullword
        $ = "posix_geteuid" fullword
        $ = "posix_getgid" fullword
        $ = "phpinfo" fullword
        $ = "backticks" fullword
        $ = "proc_open" fullword
        $ = "win_shell_execute" fullword
        $ = "win32_create_service" fullword
        $ = "posix_getpwuid" fullword
        $ = "shm_open" fullword
        $ = "assert" fullword
        $ = "fsockopen" fullword
        $ = "function_exists" fullword
        $ = "getmygid" fullword
        $ = "php_uname" fullword
        $ = "socket_create(AF_INET, SOCK_STREAM, SOL_TCP)"
        $ = "fpassthru" fullword
        $ = "posix_setuid" fullword
        $ = "xmlrpc_decode" fullword
        $ = "show_source" fullword
        $ = "pcntl_exec" fullword
        $ = "array_filter" fullword

    condition:
        any of them
}