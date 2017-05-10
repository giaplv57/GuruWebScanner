rule GuruWS_adware_regex
{
    strings:                              
        $ = /var [\_0x\d(a-f)(A-F)]* = \[["']([\\\x\d(A-F)(a-f)]*)["']/i
        $ = /document\[[\_0x\d(a-f)(A-F)\[\]]*\]\([\_0x\d(a-f)(A-F)\[\]]*\)/i

    condition:
        any of them
}

rule GuruWS_adware_strings
{
    strings:                              
        $ = "\x3C\x73\x63\x72\x69\x70"
        $ = "\x77\x72\x69\x74\x65"
        
    condition:
        any of them
}
