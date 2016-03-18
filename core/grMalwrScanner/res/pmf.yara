private rule IsPhp
{
    strings:
        $php = /<\?[^x]/

    condition:
        $php and filesize < 5MB
}

private rule IRC
{
    strings:
        $ = "USER" fullword
        $ = "PASS" fullword
        $ = "PRIVMSG" fullword
        $ = "MODE" fullword
        $ = "PING" fullword
        $ = "PONG" fullword
        $ = "JOIN" fullword
        $ = "PART" fullword

    condition:
        5 of them
}

private rule CloudFlareBypass
{
    strings:
        $ = "chk_jschl"
        $ = "jschl_vc"
        $ = "jschl_answer"

    condition:
        2 of them // Better be safe than sorry
}

rule PMF_align
{
    strings:
        $align = /(\$\w+=[^;]*)*;\$\w+=@?\$\w+\(/  //b374k
    condition:
        any of them
}

rule PMF_weevly3
{
    strings:
        $weevely3 = /\$\w=\$[a-zA-Z]\('',\$\w\);\$\w\(\);/  // weevely3 launcher
    condition:
        any of them
}

rule PMF_c99launcher
{
    strings:
        $c99_launcher = /;\$\w+\(\$\w+(,\s?\$\w+)+\);/  // http://bartblaze.blogspot.fr/2015/03/c99shell-not-dead.html
    condition:
        any of them
}

rule PMF_danone
{
    strings:
        $danone = /\$s20=strtoupper\((\$[0-9A-Za-z]{1,4}\[\d+\]\.){2,9}[^\)]*\);if/
    condition:
        any of them
}

rule PMF_oneliner
{
    strings:
        $oneliner = /<\?php\s*\n*\r*\s*(eval|preg_replace|system|exec)\(/
    condition:
        any of them
}

private rule base64
{
    strings:
        $eval = "ZXZhbCg"
        $system = "c3lzdGVt"
        $preg_replace = "cHJlZ19yZXBsYWNl"
        $exec = "ZXhlYyg"
    condition:
        any of them
}

private rule hex
{
    strings:
      $eval = "\\x65\\x76\\x61\\x6C\\x28" nocase
      $exec = "\\x65\\x78\\x65\\x63" nocase
      $system = "\\x73\\x79\\x73\\x74\\x65\\x6d" nocase
      $preg_replace = "\\x70\\x72\\x65\\x67\\x5f\\x72\\x65\\x70\\x6c\\x61\\x63\\x65" nocase
    
    condition:
        any of them
}


rule PMF_DodgyStrings
{
    strings:
        $ = "/etc/passwd"
        $ = "/etc/shadow"
        $ = "/etc/resolv.conf"
        $ = "/etc/syslog.conf"
        $ = "/etc/proftpd.conf"
        $ = "WinExec"
        $ = "uname -a" fullword
        $ = "nc -l" fullword
        $ = "ls -la" fullword
        $ = "cmd.exe" fullword nocase
        $ = "ipconfig" fullword nocase
        $ = "find . -type f" fullword
        $ = "defaced" fullword nocase
        $ = "slowloris" fullword nocase
        $ = "id_rsa" fullword
        $ = "backdoor" fullword nocase
        $ = "webshell" fullword nocase
        $ = "exploit" fullword nocase
        $ = "hacking" fullword nocase
        $ = "/proc/cpuinfo" fullword
        $ = "/bin/sh" fullword
        $ = "/bin/bash" fullword
        $ = "ps -aux" fullword
        $ = "b374k" fullword
        $ = /(reverse|web)\s*shell/ nocase

        $vbs = /language\s*=\s*vbscript/ nocase
        $asp = "scripting.filesystemobject" nocase

    condition:
        IRC or 2 of them
}
