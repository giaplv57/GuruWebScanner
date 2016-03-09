rule SHELLDETECT_phpemailer_0_2_php
{
    strings:
        $ = {58 52 70 62 79 41 71 49 43 34 33 4e 53 6b 37 44 51 6f 4e 43 69 41 67 49 43 42 6d 62 33 49 67 4b 43 52 70 49 44 30 67 4d 44 73 67 4a 47 6b 67 50 43 41 6b 62 57 4a 66 62 47 56 75 5a 33 52 6f 4f}
    condition:
        any of them
}

rule SHELLDETECT_b374k_28_0_php
{
    strings:
        $ = {47 43 6e 7a 44 6c 76 74 36 55 6f 6e 33 6d 53 30 64 34 51 51 38 32 36 62 43 6b 4a 77 38 66 36 43 46 46 72 45 5a 4b 39 68 70 6d 36 66 71 48 36 32 36 6e 72 76 63 39 56 4b 45 53 6c 51 59 59 78 79}
    condition:
        any of them
}

rule SHELLDETECT_cmd_31_0_php
{
    strings:
        $ = {4f 77 6b 4a 43 51 6f 4b 43 57 52 6c 5a 6d 46 31 62 48 51 36 43 67 6b 4a 63 32 68 76 64 31 39 73 63 79 67 70 4f 77 70 39 43 67 70 6d 64 57 35 6a 64 47 6c 76 62 69 42 7a 61 47 39 33 58 32 78 7a}
    condition:
        any of them
}

rule SHELLDETECT_noname_1_0_php
{
    strings:
        $ = {5a 64 6b 6f 35 54 54 4e 55 52 33 4a 49 4c 32 52 76 56 30 4d 30 57 47 31 42 52 57 74 5a 56 6e 64 42 51 31 56 51 55 57 51 77 52 32 77 30 4e 33 56 45 61 6c 49 69 4c 43 4a 6a 4d 6b 64 79 62 56 52}
    condition:
        any of them
}

rule SHELLDETECT_hiddenshell_0_0_php
{
    strings:
        $ = {32 68 76 49 43 49 4e 43 67 6b 4a 43 51 6b 4e 43 67 6b 4a 49 43 41 67 49 41 6b 38 64 48 49 2b 44 51 6f 4a 43 51 6b 67 49 43 41 67 49 43 41 38 64 47 51 67 64 32 6c 6b 64 47 67 39 4a 7a 45 77 4a}
    condition:
        any of them
}

rule SHELLDETECT_cmd_24_0_pl
{
    strings:
        $ = {63 6d 39 73 4f 69 42 75 62 79 31 6a 59 57 4e 6f 5a 56 78 75 49 6a 73 4e 43 6e 42 79 61 57 35 30 49 43 4a 44 62 32 35 30 5a 57 35 30 4c 58 52 35 63 47 55 36 49 48 52 6c 65 48 51 76 61 48 52 74}
    condition:
        any of them
}

rule SHELLDETECT_s72shell_0_0_php
{
    strings:
        $ = {4a 79 50 67 6f 67 49 43 41 67 49 43 41 67 49 44 78 69 63 69 41 76 50 6a 78 69 63 69 41 76 50 69 41 38 4c 32 5a 76 62 6e 51 2b 43 69 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 50 44}
    condition:
        any of them
}

rule SHELLDETECT_cocacola_shell_0_0_php
{
    strings:
        $ = {47 52 6c 5a 6d 46 31 62 48 52 66 64 58 4e 6c 58 32 46 71 59 58 67 67 50 53 42 30 63 6e 56 6c 4f 79 41 6b 5a 47 56 6d 59 58 56 73 64 46 39 6a 61 47 46 79 63 32 56 30 49 44 30 67 4a 31 64 70 62 6d 52 76 64 33 4d 74 4d 54 49 31 4d 53 63 37 49 47 6c 6d 4b 43 46 6c 62 58 42 30 65 53 67 6b 58 31 4e 46 55 6c 5a 46 55 6c 73 6e 53 46 52 55 55 46 39 56 55 30 56 53 58 30 46 48 52 55 35}
    condition:
        any of them
}

rule SHELLDETECT_shell_uploader_10_0_php
{
    strings:
        $ = {50 45 5a 50 55 6b 30 67 52 55 35 44 56 46 6c 51 52 54 30 69 62 58 56 73 64 47 6c 77 59 58 4a 30 4c 32 5a 76 63 6d 30 74 5a 47 46 30 59 53 49 67 51 55 4e 55 53 55 39 4f 50 53 4a 31 63 47 78 76}
    condition:
        any of them
}

rule SHELLDETECT_cih_0_0_php
{
    strings:
        $ = {57 46 79 5a 32 6c 75 4c 57 78 6c 5a 6e 51 36 4e 58 42 34 4f 79 42 74 59 58 4a 6e 61 57 34 74 63 6d 6c 6e 61 48 51 36 4e 58 42 34 4f 79 63 2b 62 47 39 6e 61 57 34 36 50 43 39 7a 63 47 46 75 50}
    condition:
        any of them
}

rule SHELLDETECT_c99_26_0_php
{
    strings:
        $ = {5a 69 6b 75 49 69 6b 68 50 43 39 69 50 6a 77 76 59 32 56 75 64 47 56 79 50 69 49 37 66 51 30 4b 49 43 42 6c 62 48 4e 6c 49 48 74 6c 59 32 68 76 49 43 49 38 59 32 56 75 64 47 56 79 50 6a 78 69}
    condition:
        any of them
}

rule SHELLDETECT_lamashell_0_0_php
{
    strings:
        $ = {68 62 57 55 6f 4b 53 34 69 58 47 34 69 4f 77 30 4b 50 7a 34 4e 43 6a 78 6f 63 6a 34 38 4c 33 42 79 5a 54 34 4e 43 69 41 67 49 43 41 38 64 47 46 69 62 47 55 2b 50 47 5a 76 63 6d 30 67 62 57 56}
    condition:
        any of them
}

rule SHELLDETECT_jackal_1_0_php
{
    strings:
        $ = {46 55 6c 73 6e 55 6b 56 4e 54 31 52 46 58 30 46 45 52 46 49 6e 58 54 74 6c 59 32 68 76 49 43 49 67 63 32 6c 36 5a 54 30 78 4e 7a 34 38 4c 33 52 6b 50 6a 77 76 64 48 49 2b 50 48 52 79 50 6a 78}
    condition:
        any of them
}

rule SHELLDETECT_cshell_0_0_php
{
    strings:
        $ = {43 67 6b 4a 43 57 46 79 63 6d 46 35 58 33 42 76 63 43 67 6b 5a 58 68 34 4b 54 73 4e 43 67 30 4b 43 51 6b 4a 50 7a 34 4e 43 67 30 4b 43 51 6b 4a 52 47 6c 79 5a 57 4e 30 62 33 4a 35 49 45 4e 76}
    condition:
        any of them
}

rule SHELLDETECT_troyan_0_0_php
{
    strings:
        $ = {61 7a 45 31 4d 43 35 6b 5a 53 39 33 4c 32 52 6b 49 69 6b 37 49 41 30 4b 63 33 6c 7a 64 47 56 74 4b 43 4a 6a 61 47 31 76 5a 43 41 33 4e 7a 63 67 5a 47 51 69 4b 54 73 67 44 51 70 7a 65 58 4e 30}
    condition:
        any of them
}

rule SHELLDETECT_b374k_13_0_php
{
    strings:
        $ = {51 5a 30 6c 53 4e 6e 4a 57 55 46 64 74 52 6a 46 61 56 6d 74 6d 65 48 4a 42 4c 7a 52 48 55 31 45 79 4b 33 5a 48 5a 32 4e 47 57 56 64 61 65 46 5a 69 64 55 6c 78 59 30 77 30 4d 6c 4e 4e 53 54 4a}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_32_0_php
{
    strings:
        $ = {6c 64 47 4d 76 61 48 52 30 63 47 51 75 59 32 39 75 5a 67 30 4b 4c 32 56 30 59 79 39 77 64 58 4a 6c 4c 57 5a 30 63 47 51 75 59 32 39 75 5a 67 30 4b 4c 32 56 30 59 79 39 77 64 58 4a 6c 4c 57 5a}
    condition:
        any of them
}

rule SHELLDETECT_filesman_9_0_php
{
    strings:
        $ = {4c 56 55 6e 4c 43 41 6e 59 33 41 34 4e 6a 59 6e 4b 54 73 4b 43 53 52 76 63 48 52 66 59 32 68 68 63 6e 4e 6c 64 48 4d 67 50 53 41 6e 4a 7a 73 4b 43 57 5a 76 63 6d 56 68 59 32 67 6f 4a 47 4e 6f}
    condition:
        any of them
}

rule SHELLDETECT_cyberspy5_0_0_asp
{
    strings:
        $ = {4f 6e 52 2f 56 55 41 6a 51 43 5a 6b 4e 32 51 69 4b 32 51 79 53 33 67 76 66 79 42 4a 66 30 35 72 54 57 35 65 57 53 78 4b 4e 46 6c 50 64 32 77 6d 53 6d 68 42 61 47 4d 76 57 43 67 72 4c 6c 4a 78}
    condition:
        any of them
}

rule SHELLDETECT_filesman_14_0_php
{
    strings:
        $ = {46 6a 64 47 6c 76 62 6a 30 6e 61 48 52 30 63 44 6f 76 4c 33 64 33 64 79 35 6f 59 58 4e 6f 59 32 68 6c 59 32 74 6c 63 69 35 6b 5a 53 39 6f 59 58 4e 6f 4c 6d 4e 6e 61 54 38 6e 4f 32 52 76 59 33}
    condition:
        any of them
}

rule SHELLDETECT_cmd_18_0_jsp
{
    strings:
        $ = {35 51 56 56 51 67 64 48 6c 77 5a 54 31 7a 64 57 4a 74 61 58 51 67 64 6d 46 73 64 57 55 39 4a 31 4a 31 62 69 63 2b 44 51 6f 38 4c 30 5a 50 55 6b 30 2b 44 51 6f 4e 43 6a 77 6c 51 43 42 77 59 57}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_33_0_php
{
    strings:
        $ = {79 63 57 31 43 63 46 64 46 64 33 56 52 62 55 55 78 4d 30 45 33 62 6c 64 5a 52 57 4a 4e 53 31 64 57 4e 57 34 32 63 6a 42 6c 4e 43 74 36 61 47 52 36 55 6a 63 72 65 45 46 54 65 6b 4a 6b 54 48 64}
    condition:
        any of them
}

rule SHELLDETECT_spam_trustapp_0_1_php
{
    strings:
        $ = {50 47 45 67 61 48 4a 6c 5a 6a 30 69 61 48 52 30 63 44 6f 76 4c 33 64 33 64 79 35 77 62 32 78 70 63 32 68 75 5a 58 64 7a 4c 6d 4e 76 62 53 39 70 62 6d 52 6c 65 43 35 77 61 48 41}
    condition:
        any of them
}

rule SHELLDETECT_arab_black_hat_0_0_pl
{
    strings:
        $ = {5a 58 4d 67 50 54 78 4a 54 6b 5a 50 50 69 41 37 43 6d 4e 73 62 33 4e 6c 4b 45 6c 4f 52 6b 38 70 4f 77 70 7a 65 58 4e 30 5a 57 30 6f 51 47 78 70 62 6d 56 7a 4b 54 73 4b 63 48 4a 70 62 6e 51 6e}
    condition:
        any of them
}

rule SHELLDETECT_indishell_0_0_php
{
    strings:
        $ = {49 44 77 76 64 47 46 69 62 47 55 2b 44 51 6f 67 49 43 41 67 49 43 41 67 49 41 30 4b 44 51 6f 6e 4f 79 41 4e 43 67 30 4b 50 7a 34 4e 43 6a 78 69 62 32 52 35 49 47 4a 6e 59 32 39 73 62 33 49 39}
    condition:
        any of them
}

rule SHELLDETECT_savefile_0_0_php
{
    strings:
        $ = {50 44 39 51 53 46 41 4b 4a 47 5a 70 62 47 55 67 50 53 42 6d 61 57 78 6c 58 32 64 6c 64 46 39 6a 62 32 35 30 5a 57 35 30 63 79 67 69 61 48 52 30 63 44 6f 76 4c 32 68 68 59 32 74 6c 63 6d 78 68}
    condition:
        any of them
}

rule SHELLDETECT_gnyshell_0_0_php
{
    strings:
        $ = {79 63 33 52 68 64 48 56 7a 49 69 6b 37 49 41 30 4b 49 43 41 6b 63 33 46 73 63 58 56 70 59 32 74 73 59 58 56 75 59 32 68 62 58 53 41 39 49 47 46 79 63 6d 46 35 4b 43 4a 54 5a 58 4a 32 5a 58 49}
    condition:
        any of them
}

rule SHELLDETECT_hackerps_0_0_php
{
    strings:
        $ = {63 47 46 75 50 6a 77 76 5a 6d 39 75 64 44 34 38 5a 6d 39 75 64 43 42 6a 62 32 78 76 63 6a 30 69 49 7a 46 45 4d 55 51 78 52 43 49 67 5a 6d 46 6a 5a 54 30 69 56 47 46 6f 62 32 31 68 49 69 42 7a}
    condition:
        any of them
}

rule SHELLDETECT_phpfilemanager_2_2_php
{
    strings:
        $ = {6d 64 30 61 44 6f 67 49 69 41 75 49 48 4e 30 63 6d 78 6c 62 69 67 6b 64 47 68 70 63 79 30 2b 59 58 4a 6a 61 47 6c 32 5a 53 6b 70 4f 77 30 4b 49 43 41 67 49 43 41 67 49 43 42 6f 5a 57 46 6b 5a}
    condition:
        any of them
}

rule SHELLDETECT_joomla_spam_1_1_php
{
    strings:
        $ = {48 67 79 4d 47 5a 63 65 44 49 7a 58 48 67 78 4e 31 78 34 4d 44 46 51 58 48 67 78 4d 7a 46 63 65 44 42 6b 4e 47 5a 63 65 44 4e 6c 53 31 78 34 4d 47 4d 77 57 46 78 34 4d 54 56 63 65 44 45 79 58}
    condition:
        any of them
}

rule SHELLDETECT_jackal_0_0_php
{
    strings:
        $ = {66 55 6b 56 52 56 55 56 54 56 46 73 6e 64 58 4e 6c 63 69 64 64 4b 53 6b 2f 4a 46 39 53 52 56 46 56 52 56 4e 55 57 79 64 31 63 32 56 79 4a 31 30 36 49 69 49 37 44 51 70 70 5a 69 67 68 5a 6d 6c}
    condition:
        any of them
}

rule SHELLDETECT_elmaliseker_0_0_asp
{
    strings:
        $ = {30 4c 6b 5a 76 63 6d 30 6f 49 6d 31 76 5a 47 55 69 4b 53 6b 4b 5a 58 68 70 64 43 42 7a 64 57 49 4b 5a 57 35 6b 49 47 6c 6d 43 6d 56 75 5a 43 42 70 5a 67 6f 4b 53 48 52 74 62 45 68 6c 59 57 52}
    condition:
        any of them
}

rule SHELLDETECT_irc_bot_0_0_pl
{
    strings:
        $ = {62 32 4e 72 5a 58 51 73 49 43 4a 51 55 6b 6c 57 54 56 4e 48 49 43 52 77 63 6d 6c 75 64 47 77 67 4f 69 42 4f 62 57 46 77 49 46 42 76 63 6e 52 54 59 32 46 75 49 44 45 79 4f 69 34 67 4e 48 77 67}
    condition:
        any of them
}

rule SHELLDETECT_cmd_4_0_php
{
    strings:
        $ = {49 43 41 67 49 43 41 67 49 43 42 6c 59 32 68 76 49 43 49 38 63 48 4a 6c 50 69 49 37 43 69 41 67 49 43 41 67 49 43 41 67 4a 47 4e 74 5a 43 41 39 49 43 67 6b 58 31 4a 46 55 56 56 46 55 31 52 62}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_2_0_php
{
    strings:
        $ = {42 49 4b 30 52 58 61 31 45 35 4d 46 5a 71 59 55 74 44 64 56 6c 78 61 6e 42 53 51 6b 35 6a 55 33 56 5a 4d 32 35 59 52 48 5a 61 56 44 6c 69 53 6b 39 79 4d 46 6c 68 51 6d 31 48 62 58 52 71 51 32}
    condition:
        any of them
}

rule SHELLDETECT_teamsql_0_0_php
{
    strings:
        $ = {5a 53 42 70 5a 44 30 69 64 47 46 69 62 47 55 79 49 69 42 7a 64 48 6c 73 5a 54 30 69 59 6d 39 79 5a 47 56 79 4c 57 4e 76 62 47 78 68 63 48 4e 6c 4f 69 42 6a 62 32 78 73 59 58 42 7a 5a 54 73 69}
    condition:
        any of them
}

rule SHELLDETECT_pbot_1_0_php
{
    strings:
        $ = {43 52 31 63 6d 77 67 4b 51 30 4b 43 51 6c 37 44 51 6f 4a 43 51 6b 6b 56 56 4a 4d 63 47 4e 7a 49 44 30 67 4b 43 42 77 59 58 4a 7a 5a 56 39 31 63 6d 77 6f 49 43 52 31 63 6d 77 67 4b 53 41 70 4f}
    condition:
        any of them
}

rule SHELLDETECT_cmd_23_0_php
{
    strings:
        $ = {50 44 39 77 61 48 41 67 61 57 59 6f 61 58 4e 7a 5a 58 51 6f 4a 46 39 53 52 56 46 56 52 56 4e 55 57 79 4a 6a 62 32 31 74 5a 57 35 30 49 6c 30 70 4b 53 42 37 49 47 56 32 59 57 77 6f 59 6d 46 7a}
    condition:
        any of them
}

rule SHELLDETECT_insomnia_0_0_aspx
{
    strings:
        $ = {6c 36 5a 51 6f 67 49 43 41 67 49 43 41 67 49 48 56 70 62 6e 51 67 62 6b 52 6c 5a 6d 46 31 62 48 52 55 61 57 31 6c 54 33 56 30 4c 41 6b 4a 43 51 6b 4a 43 53 38 76 49 48 52 70 62 57 55 74 62 33}
    condition:
        any of them
}

rule SHELLDETECT_antisecshell_0_0_php
{
    strings:
        $ = {59 6a 49 35 63 6d 46 58 56 57 39 4a 62 6c 70 77 59 7a 4a 73 4d 47 4e 35 53 58 4e 4b 53 46 70 77 59 7a 4a 73 4d 46 6b 79 4f 54 46 69 62 6c 46 77 54 33 64 76 64 6b 78 35 51 54 4e 68 52 46 4a 31}
    condition:
        any of them
}

rule SHELLDETECT_cmd_21_0_php
{
    strings:
        $ = {42 49 59 58 5a 6c 62 6d 46 79 5a 43 41 74 4c 54 34 4e 43 6a 77 68 4c 53 30 67 54 57 39 6b 61 57 5a 70 5a 57 51 67 64 47 38 67 64 32 39 79 61 79 42 33 61 58 52 6f 49 44 51 34 4e 44 4e 77 61 48}
    condition:
        any of them
}

rule SHELLDETECT_aspydrv_0_0_vb
{
    strings:
        $ = {36 5a 54 30 69 49 43 59 67 5a 6d 6b 72 4d 79 41 6d 49 43 49 67 63 33 52 35 62 47 55 39 49 69 4a 69 59 57 4e 72 5a 33 4a 76 64 57 35 6b 4c 57 4e 76 62 47 39 79 4f 69 42 79 5a 32 49 6f 4e 44 67}
    condition:
        any of them
}

rule SHELLDETECT_951078biJ_0_0_php
{
    strings:
        $ = {46 53 59 6b 6f 79 54 6e 52 61 51 32 52 6b 55 46 51 77 61 56 70 75 55 6e 64 59 4d 6c 70 77 59 6b 64 57 5a 6d 52 59 51 57 6c 4c 55 30 46 6e 53 55 68 7a 5a 31 46 48 57 6a 42 6a 52 6a 6c 33 5a 46}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_15_0_php
{
    strings:
        $ = {74 42 51 6c 70 34 51 55 68 6d 4e 6b 35 4a 4d 56 52 32 55 32 30 32 62 30 52 34 53 6c 6f 77 51 32 4d 35 62 6c 5a 48 4e 58 42 71 65 47 30 31 57 44 6c 61 52 47 45 79 55 55 4e 46 57 47 45 72 56 45}
    condition:
        any of them
}

rule SHELLDETECT_nstview_0_0_php
{
    strings:
        $ = {43 42 6a 62 32 78 76 63 6a 31 6e 63 6d 56 6c 62 6a 34 6b 5a 43 38 6b 5a 47 56 73 58 32 59 67 52 45 56 4d 52 56 52 46 52 43 45 38 4c 32 5a 76 62 6e 51 2b 50 43 39 69 50 67 30 4b 50 47 4a 79 50}
    condition:
        any of them
}

rule SHELLDETECT_filesman_12_0_php
{
    strings:
        $ = {57 31 77 4c 6e 4e 78 62 43 49 70 4f 77 30 4b 49 43 41 67 49 43 41 67 49 43 42 6f 5a 57 46 6b 5a 58 49 6f 49 6b 4e 76 62 6e 52 6c 62 6e 51 74 56 48 6c 77 5a 54 6f 67 64 47 56 34 64 43 39 77 62}
    condition:
        any of them
}

rule SHELLDETECT_unitxshell_0_0_pl
{
    strings:
        $ = {74 4c 53 30 74 4c 53 30 74 4c 53 30 74 4c 53 30 74 4c 53 30 74 4c 51 70 7a 64 57 49 67 52 47 39 33 62 6d 78 76 59 57 52 47 61 57 78 6c 43 6e 73 4b 43 53 4d 67 61 57 59 67 62 6d 38 67 5a 6d 6c}
    condition:
        any of them
}

rule SHELLDETECT_phpspy_2_0_php
{
    strings:
        $ = {5a 48 59 58 4a 51 5a 6e 4a 6c 4f 58 41 35 4b 32 68 52 56 6e 56 4e 56 54 4e 31 56 6d 68 32 4e 47 56 55 4e 7a 4a 79 55 6b 6c 4c 53 58 70 4e 4c 31 4e 49 65 45 59 34 65 54 64 73 51 7a 6c 4c 5a 54}
    condition:
        any of them
}

rule SHELLDETECT_antisecshell_2_0_php
{
    strings:
        $ = {41 67 49 44 77 76 64 48 49 2b 44 51 6f 67 49 43 41 67 49 43 41 67 49 44 77 76 64 47 46 69 62 47 55 2b 44 51 6f 67 49 43 41 67 49 43 41 67 49 44 78 30 5a 58 68 30 59 58 4a 6c 59 53 42 75 59 57}
    condition:
        any of them
}

rule SHELLDETECT_getlinks_0_1_php
{
    strings:
        $ = {61 48 52 30 63 44 6f 76 4c 7a 6b 31 4c 6a 45 32 4f 43 34 78 4f 54 45 75 4d 54 45 32 4c 30 64 6c 64 45 78 70 62 6d 74 7a 4c 6d 46 7a 61 48 67 2f 61 47 39 7a 64 44 30 3d}
    condition:
        any of them
}

rule SHELLDETECT_imhapftp_0_0_php
{
    strings:
        $ = {61 57 34 67 58 43 4a 62 4a 54 4a 64 58 43 49 36 58 47 35 62 4a 54 46 64 49 69 77 4b 4a 30 74 76 63 48 6c 68 62 47 46 66 5a 6d 6c 73 5a 58 4d 6e 49 44 30 2b 49 43 64 44 62 33 42 70 62 79 42 78}
    condition:
        any of them
}

rule SHELLDETECT_stressbypass_0_0_php
{
    strings:
        $ = {36 4c 32 46 77 63 48 4e 6c 63 6e 59 76 64 33 64 33 4c 33 4e 6f 5a 57 78 73 63 79 38 69 50 67 6f 67 49 43 41 67 49 43 41 67 49 44 78 6d 62 32 35 30 49 47 4e 76 62 47 39 79 50 53 49 6a 52 45 4e}
    condition:
        any of them
}

rule SHELLDETECT_cmd_1_0_asp
{
    strings:
        $ = {30 67 63 33 70 44 54 55 51 73 49 48 4e 36 56 47 56 74 63 45 5a 70 62 47 55 4b 43 6b 39 75 49 45 56 79 63 6d 39 79 49 46 4a 6c 63 33 56 74 5a 53 42 4f 5a 58 68 30 43 67 6f 6e 49 43 30 74 49 47}
    condition:
        any of them
}

rule SHELLDETECT_darkshell_0_0_php
{
    strings:
        $ = {39 74 62 57 46 75 5a 44 6f 67 50 47 6c 75 63 48 56 30 49 47 35 68 62 57 55 67 50 53 41 6e 59 32 31 6b 4a 7a 35 63 62 69 49 37 44 51 6f 67 49 43 41 67 49 43 41 67 49 43 42 6c 59 32 68 76 49 43}
    condition:
        any of them
}

rule SHELLDETECT_configspy_1_0_php
{
    strings:
        $ = {69 63 76 63 48 56 69 62 47 6c 6a 58 32 68 30 62 57 77 76 61 57 35 6a 4c 32 4e 76 62 6d 5a 70 5a 79 35 70 62 6d 4d 75 63 47 68 77 4a 79 77 6b 64 58 4e 6c 63 69 34 6e 4c 54 4d 7a 4c 6e 52 34 64}
    condition:
        any of them
}

rule SHELLDETECT_isko_0_0_php
{
    strings:
        $ = {56 44 42 4e 52 6a 68 45 61 33 4e 78 63 56 4a 6a 56 6c 42 76 54 31 46 6b 55 6d 31 68 63 57 63 33 65 45 78 76 65 47 4d 72 53 31 46 4c 55 48 45 33 4e 33 70 36 4f 56 42 69 65 48 6c 57 59 6c 64 4d}
    condition:
        any of them
}

rule SHELLDETECT_phpfilemanager_4_0_php
{
    strings:
        $ = {74 5a 53 67 67 4a 46 39 47 53 55 78 46 55 31 73 6e 64 58 42 73 62 32 46 6b 5a 57 52 6d 61 57 78 6c 4a 31 31 62 4a 32 35 68 62 57 55 6e 58 53 6b 67 62 33 49 67 5a 47 6c 6c 4b 43 52 6c 63 6e 4a}
    condition:
        any of them
}

rule SHELLDETECT_worse_0_0_php
{
    strings:
        $ = {49 47 35 68 62 57 55 39 58 43 4a 66 59 32 31 6b 58 43 49 67 64 6d 46 73 64 57 55 39 58 43 49 69 4c 69 52 6a 64 58 4a 79 5a 57 35 30 51 30 31 45 4c 69 4a 63 49 6a 34 38 4c 33 52 6b 50 69 49 37}
    condition:
        any of them
}

rule SHELLDETECT_zaco_0_0_php
{
    strings:
        $ = {66 5a 48 56 74 63 43 6b 37 43 6d 56 73 63 32 55 4b 65 77 70 70 5a 69 67 68 4a 48 52 76 58 32 5a 70 62 47 55 70 43 6e 73 4b 61 47 56 68 5a 47 56 79 4b 43 64 44 62 32 35 30 5a 57 35 30 4c 56 52}
    condition:
        any of them
}

rule SHELLDETECT_mysql_6_2_php
{
    strings:
        $ = {6e 49 67 4c 7a 34 69 4f 69 63 6e 4b 53 34 69 50 43 39 30 5a 44 34 69 4f 77 30 4b 49 43 41 67 66 51 30 4b 49 43 41 67 4a 48 4e 78 62 47 52 79 4c 6a 30 69 50 43 39 30 63 6a 35 63 62 69 49 37 44}
    condition:
        any of them
}

rule SHELLDETECT_server_config_0_0_php
{
    strings:
        $ = {54 47 52 44 65 55 73 4e 43 6c 56 52 52 6d 74 6f 59 6d 49 32 54 7a 68 6b 4d 33 51 79 4c 7a 4e 71 55 6c 52 4b 4c 30 6c 78 55 33 64 44 51 55 6c 72 52 56 70 42 52 54 4e 69 4d 57 4a 43 64 54 59 34}
    condition:
        any of them
}

rule SHELLDETECT_crystal_2_0_php
{
    strings:
        $ = {52 73 5a 54 34 4e 43 69 41 38 63 33 52 35 62 47 55 2b 44 51 6f 67 49 43 42 30 5a 43 42 37 44 51 6f 67 49 43 42 6d 62 32 35 30 4c 57 5a 68 62 57 6c 73 65 54 6f 67 64 6d 56 79 5a 47 46 75 59 53}
    condition:
        any of them
}

rule SHELLDETECT_c99_29_0_php
{
    strings:
        $ = {42 6a 4f 54 6c 77 61 48 42 70 59 33 45 75 63 47 68 77 49 44 38 67 61 48 52 30 63 44 6f 76 4c 32 4e 6a 64 47 56 68 62 53 35 75 64 57 74 73 5a 57 39 75 4c 6e 56 7a 44 51 6f 6a 49 79 4d 6a 49 79}
    condition:
        any of them
}

rule SHELLDETECT_cmd_16_0_asp
{
    strings:
        $ = {67 4a 79 41 67 52 6d 6c 73 5a 54 6f 67 49 43 41 67 51 32 31 6b 51 58 4e 77 4c 6d 46 7a 63 41 30 4b 49 43 41 6e 49 43 42 42 64 58 52 6f 62 33 49 36 49 43 42 4e 59 57 4e 6c 62 79 41 38 62 57 46}
    condition:
        any of them
}

rule SHELLDETECT_ahlisyurga_shell_0_0_php
{
    strings:
        $ = {61 55 31 4e 51 32 46 36 61 79 38 31 4e 30 46 6c 62 6e 56 30 62 6a 64 57 54 6c 4e 6b 61 55 46 55 53 58 6c 4e 4c 33 68 6f 65 6b 35 32 59 7a 6b 79 5a 54 46 31 52 56 67 32 55 30 39 33 4e 48 6b 30}
    condition:
        any of them
}

rule SHELLDETECT_wso_0_0_php
{
    strings:
        $ = {34 6b 63 33 52 79 4b 54 73 4e 43 67 6b 4a 43 51 6b 4a 59 6e 4a 6c 59 57 73 37 44 51 6f 4a 43 51 6b 4a 59 32 46 7a 5a 53 41 6e 62 58 6c 7a 63 57 77 6e 4f 67 30 4b 43 51 6b 4a 43 51 6c 79 5a 58}
    condition:
        any of them
}

rule SHELLDETECT_shell_uploader_15_0_php
{
    strings:
        $ = {61 55 74 54 51 6e 5a 6a 61 55 4a 36 5a 45 68 4b 63 47 4d 7a 55 6e 6c 4c 51 31 4a 35 57 6c 64 61 62 47 4e 74 56 6e 6c 4d 51 30 6f 7a 57 6c 64 4b 61 47 4a 49 55 6d 68 4a 61 57 74 6e 59 6a 4e 4a}
    condition:
        any of them
}

rule SHELLDETECT_wso_5_0_php
{
    strings:
        $ = {35 62 31 39 66 78 71 33 30 6a 44 38 64 2f 77 70 35 43 32 6e 43 77 33 47 67 4a 4f 63 31 44 62 45 69 57 4d 6e 54 68 4d 37 39 55 75 53 4a 73 35 4e 46 31 68 67 36 34 57 6c 75 34 75 78 6d 2b 50 76 66 73 2b 4d 58 6c 62 61 46 38 42 70 7a 33 58 64 7a 2b 39 78 47 78 75 6b 30 57 6a 30 4e 68 72 4e 6a 45 61 6c 58 75 41 48 49 57 73 78 36 34 66 2b 34 4c 47 31 73 31 62 71 75 77 4e 6e 35 73 65 64 57 65 52 32 6e 44 2b}
    condition:
        any of them
}

rule SHELLDETECT_batavi4_0_0_php
{
    strings:
        $ = {69 38 76 56 57 35 30 64 57 73 67 62 33 42 30 61 57 31 68 62 47 6c 7a 59 58 4e 70 49 48 56 72 64 58 4a 68 62 69 42 6b 59 57 34 67 61 32 56 6a 5a 58 42 68 64 47 46 75 4c 67 6f 6b 61 57 31 6e 5a}
    condition:
        any of them
}

rule SHELLDETECT_blindshell_0_0_c
{
    strings:
        $ = {41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 42 39 43 69 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 47 52 31 63 44 49 6f 61 57 35 7a 62 32}
    condition:
        any of them
}

rule SHELLDETECT_crystal_1_0_php
{
    strings:
        $ = {62 57 55 67 4c 6d 68 30 63 47 46 7a 63 33 64 6b 49 6a 34 4e 43 67 6b 4a 5a 6d 6c 75 5a 43 42 68 62 47 77 67 4c 6d 68 30 63 47 46 7a 63 33 64 6b 49 47 5a 70 62 47 56 7a 50 43 39 76 63 48 52 70}
    condition:
        any of them
}

rule SHELLDETECT_r3laps3_0_0_php
{
    strings:
        $ = {45 52 52 62 30 70 44 55 57 74 4b 51 31 52 57 61 6d 46 45 53 57 64 68 53 46 4a 30 59 6b 68 4f 64 30 35 58 54 54 42 4e 56 33 68 71 59 55 52 47 65 57 4e 35 61 45 46 61 62 6b 6b 78 54 56 64 52 62}
    condition:
        any of them
}

rule SHELLDETECT_w3dshell_0_0_php
{
    strings:
        $ = {49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 4a 48 5a 32 49 44 30 67 5a 6d 46 73 63 32 55 37 43 69 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67}
    condition:
        any of them
}

rule SHELLDETECT_b374k_6_0_php
{
    strings:
        $ = {6c 59 4b 79 39 74 63 55 51 34 62 32 46 56 61 6c 68 77 62 7a 42 4e 54 6b 30 33 5a 56 55 72 4d 6a 59 34 52 7a 64 57 4f 46 70 30 55 6b 52 75 61 46 70 78 53 44 52 43 4e 47 56 4c 55 33 51 30 5a 46}
    condition:
        any of them
}

rule SHELLDETECT_b374k_4_0_php
{
    strings:
        $ = {56 77 70 6c 59 57 67 30 51 7a 56 4c 64 55 64 74 61 45 30 78 62 56 67 30 62 48 68 4b 55 6b 6f 33 52 44 46 53 64 33 6f 7a 56 6c 6c 75 52 46 42 49 59 6b 35 73 57 58 49 35 56 79 74 78 51 6e 5a 57}
    condition:
        any of them
}

rule SHELLDETECT_albanianshell_0_0_php
{
    strings:
        $ = {64 43 49 37 4c 79 39 6d 62 33 4a 74 59 58 52 76 44 51 6f 6b 53 47 46 34 63 47 78 76 63 6d 56 79 58 32 46 6b 5a 48 49 39 4a 48 4a 6c 62 57 39 30 5a 56 39 68 5a 47 52 79 4c 69 4a 30 62 32 39 73}
    condition:
        any of them
}

rule SHELLDETECT_hostdevil_0_0_pl
{
    strings:
        $ = {73 67 5a 58 68 70 64 44 73 67 66 53 42 6c 62 48 4e 6c 49 48 73 4e 43 67 6b 4a 4a 6e 52 35 63 47 55 6f 4a 47 4e 6f 59 57 34 73 4a 47 4a 31 5a 79 77 6b 5a 47 39 79 61 79 77 69 52 47 56 4e 62 33}
    condition:
        any of them
}

rule SHELLDETECT_420532shell_0_0_php
{
    strings:
        $ = {68 62 48 4e 6c 4b 53 42 37 44 51 6f 4a 43 51 6b 4a 61 57 59 67 4b 43 52 6d 49 43 45 39 49 43 63 75 4a 79 41 6d 4a 69 41 6b 5a 69 41 68 50 53 41 6e 4c 69 34 6e 49 43 59 6d 49 43 46 6b 5a 57 77}
    condition:
        any of them
}

rule SHELLDETECT_server_config_1_0_php
{
    strings:
        $ = {31 70 63 58 51 72 65 45 52 6d 53 7a 4e 42 54 54 64 79 59 57 31 35 51 6b 5a 53 54 55 56 36 59 6b 39 4b 55 6a 42 43 56 7a 4a 6e 64 6a 68 74 62 6b 78 35 62 6b 68 77 4b 33 42 6e 55 57 4e 4b 63 30}
    condition:
        any of them
}

rule SHELLDETECT_php_mailer_0_1_php
{
    strings:
        $ = {59 57 6c 73 4f 6a 77 76 5a 6d 39 75 64 44 34 38 4c 32 52 70 64 6a 34 38 4c 33 52 6b 50 67 30 4b 43 51 6b 4a 50 48 52 6b 49 48 64 70 5a 48 52 6f 50 53 49 78 4f 43 55 69 50 6a 78 6d 62 32 35 30}
    condition:
        any of them
}

rule SHELLDETECT_shell_uploader_11_0_php
{
    strings:
        $ = {4a 35 49 48 52 79 78 72 44 68 75 35 74 6a 49 47 74 6f 61 53 42 69 34 62 71 76 64 43 44 45 6b 65 47 36 70 33 55 67 5a 2b 47 37 72 57 6b 67 64 47 6c 75 49 47 35 6f 34 62 71 76 62 69 42 72 34 62}
    condition:
        any of them
}

rule SHELLDETECT_udpflooder_0_0_php
{
    strings:
        $ = {62 58 42 73 5a 58 52 6c 49 47 46 6d 64 47 56 79 4f 69 42 37 4a 47 56 34 5a 57 4e 66 64 47 6c 74 5a 58 30 67 63 32 56 6a 62 32 35 6b 63 31 78 75 49 6a 73 4e 43 67 30 4b 66 51 30 4b 44 51 70 6c}
    condition:
        any of them
}

rule SHELLDETECT_egyspider_0_0_php
{
    strings:
        $ = {31 4b 30 52 71 4f 45 4d 33 62 6a 56 47 4e 46 5a 61 56 6a 56 5a 56 47 78 68 63 6d 70 44 65 57 78 61 52 54 64 6c 63 6a 45 7a 52 48 52 4b 5a 6c 45 78 63 6d 6c 56 55 6e 4a 6b 62 57 52 59 65 47 70}
    condition:
        any of them
}

rule SHELLDETECT_629788tryag_0_0_php
{
    strings:
        $ = {57 55 69 4f 77 30 4b 43 51 6b 4a 66 51 30 4b 43 51 6b 4a 61 57 59 6f 49 57 6c 7a 58 32 46 79 63 6d 46 35 4b 43 52 70 62 6d 52 6c 65 46 73 6b 61 32 35 68 62 57 56 64 4b 53 6b 67 65 77 30 4b 43}
    condition:
        any of them
}

rule SHELLDETECT_efso2_1_0_asp
{
    strings:
        $ = {41 64 41 44 39 2f 31 55 41 51 41 41 6a 41 45 41 41 4a 67 42 70 41 46 63 41 58 67 41 36 41 45 4d 41 54 67 42 79 41 47 4d 41 63 67 42 49 41 47 6f 41 2f 66 38 37 41 43 41 41 57 51 42 4c 41 46 63}
    condition:
        any of them
}

rule SHELLDETECT_c99_21_0_php
{
    strings:
        $ = {6c 50 56 77 69 64 47 56 34 64 46 77 69 49 47 35 68 62 57 55 39 58 43 4a 68 59 33 52 68 63 6d 4e 69 64 57 5a 6d 58 33 42 68 64 47 68 63 49 69 42 32 59 57 78 31 5a 54 31 63 49 6e 6c 34 58 32 46}
    condition:
        any of them
}

rule SHELLDETECT_phantasma_0_0_php
{
    strings:
        $ = {67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 49 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 5a 6d 46 30 59 57 77 6f 58 43 4a 56 62 6d 46 69 62 47 55 67 64 47 38 67 59 32 68 68 62 6d 64}
    condition:
        any of them
}

rule SHELLDETECT_b374k_12_0_php
{
    strings:
        $ = {6e 5a 75 4e 47 5a 68 65 47 56 5a 57 56 42 30 4e 57 31 57 54 54 42 6f 59 57 78 4e 62 6a 46 77 51 6d 63 32 51 79 39 4f 53 46 4a 57 59 6a 59 78 5a 46 46 49 4e 48 6c 52 54 6e 42 73 53 46 6f 30 64}
    condition:
        any of them
}

rule SHELLDETECT_jspreverse_0_0_jsp
{
    strings:
        $ = {53 49 70 4f 77 30 4b 44 51 6f 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 55 33 52 79 5a 57 46 74 51 32 39 75 62 6d 56 6a 64 47 39 79 49 47 39 31 64 48 42 31 64 45 4e 76 62}
    condition:
        any of them
}

rule SHELLDETECT_c99_19_0_php
{
    strings:
        $ = {66 51 70 6c 62 48 4e 6c 61 57 59 67 4b 43 67 6b 62 57 39 6b 5a 53 41 6d 49 44 42 34 4e 6a 41 77 4d 43 6b 67 50 54 30 39 49 44 42 34 4e 6a 41 77 4d 43 6b 67 65 79 52 30 49 44 30 67 49 6d 49 69}
    condition:
        any of them
}

rule SHELLDETECT_cmd_0_0_php
{
    strings:
        $ = {5a 58 5a 68 62 43 67 69 61 57 59 6f 61 58 4e 7a 5a 58 51 6f 58 43 52 66 55 6b 56 52 56 55 56 54 56 46 73 6e 59 32 67 6e 58 53 6b 67 4a 69 59 67 4b 47 31 6b 4e 53 68 63 4a 46 39 53 52 56 46 56}
    condition:
        any of them
}

rule SHELLDETECT_cmd_3_0_php
{
    strings:
        $ = {2b 43 6a 78 69 63 6a 34 4b 50 47 6c 75 63 48 56 30 49 48 52 35 63 47 55 39 56 45 56 59 56 43 42 75 59 57 31 6c 50 53 49 74 59 32 31 6b 49 69 42 7a 61 58 70 6c 50 54 59 30 49 48 5a 68 62 48 56}
    condition:
        any of them
}

rule SHELLDETECT_phpfilemanager_1_2_php
{
    strings:
        $ = {67 49 43 41 67 49 47 6c 6d 49 43 68 31 62 6d 78 70 62 6d 73 6f 4a 47 5a 70 62 47 55 70 4b 58 73 4e 43 69 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 61 57 59}
    condition:
        any of them
}

rule SHELLDETECT_ajan_0_0_asp
{
    strings:
        $ = {70 61 32 45 75 64 33 4a 70 64 47 55 67 49 6b 4e 76 62 6e 4e 30 49 47 46 6b 55 32 46 32 5a 55 4e 79 5a 57 46 30 5a 55 39 32 5a 58 4a 58 63 6d 6c 30 5a 53 41 39 49 44 49 69 49 43 59 67 64 6d 4a}
    condition:
        any of them
}

rule SHELLDETECT_ipays777_1_0_php
{
    strings:
        $ = {49 43 34 69 49 45 64 43 49 6a 73 67 66 51 30 4b 49 43 41 67 49 47 56 73 63 32 56 70 5a 69 41 6f 49 43 52 7a 61 58 70 6c 49 44 34 39 49 44 45 77 4e 44 67 31 4e 7a 59 67 4b 53 42 37 49 43 52 7a}
    condition:
        any of them
}

rule SHELLDETECT_safemode_1_0_php
{
    strings:
        $ = {78 69 59 58 49 74 5a 47 46 79 61 33 4e 6f 59 57 52 76 64 79 31 6a 62 32 78 76 63 6a 6f 67 63 32 6c 73 64 6d 56 79 4f 77 6f 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 42 7a 59 33 4a 76 62 47}
    condition:
        any of them
}

rule SHELLDETECT_r57_20_0_php
{
    strings:
        $ = {49 43 4d 67 49 43 41 67 49 79 4d 4e 43 69 38 71 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67}
    condition:
        any of them
}

rule SHELLDETECT_shell_uploader_1_0_php
{
    strings:
        $ = {55 32 31 33 56 7a 52 4b 62 46 4e 46 54 30 6c 6b 59 6a 68 47 61 30 6c 54 4b 31 4d 78 54 56 56 31 55 31 64 74 63 54 6c 78 56 47 6f 32 4d 55 4a 73 4f 48 52 54 5a 46 6b 77 4d 57 34 7a 59 33 70 36}
    condition:
        any of them
}

rule SHELLDETECT_r57_17_0_php
{
    strings:
        $ = {79 63 39 50 69 63 6d 49 7a 45 77 4e 54 63 37 4a 69 4d 78 4d 44 67 32 4f 79 59 6a 4d 54 41 33 4f 54 73 6d 49 7a 45 77 4e 7a 59 37 4a 69 4d 78 4d 44 63 79 4f 79 59 6a 4d 54 41 35 4d 44 73 6d 49}
    condition:
        any of them
}

rule SHELLDETECT_c99_9_0_php
{
    strings:
        $ = {6f 67 49 43 41 67 66 51 30 4b 49 43 41 67 66 51 30 4b 49 43 42 39 44 51 6f 67 49 43 52 6f 5a 57 46 6b 57 79 52 72 58 53 41 39 49 43 49 38 59 6a 34 69 4c 69 52 6f 5a 57 46 6b 57 79 52 72 58 53}
    condition:
        any of them
}

rule SHELLDETECT_mahkeme_0_0_php
{
    strings:
        $ = {53 49 70 4f 79 42 6c 65 47 6c 30 4f 79 42 39 43 67 6f 76 4c 30 31 68 61 47 74 6c 62 57 55 67 52 57 74 73 5a 57 35 30 61 58 4e 70 62 6d 55 67 57 57 46 72 59 57 78 68 62 69 59 6a 4d 7a 41 31 4f}
    condition:
        any of them
}

rule SHELLDETECT_rootshell_3_0_php
{
    strings:
        $ = {76 62 6d 63 2b 43 6a 78 69 50 6a 78 31 50 6a 78 6a 5a 57 35 30 5a 58 49 2b 50 44 39 77 61 48 41 67 5a 57 4e 6f 62 79 41 69 56 47 68 70 63 79 42 7a 5a 58 4a 32 5a 58 49 67 61 47 46 7a 49 47 4a}
    condition:
        any of them
}

rule SHELLDETECT_filesman_10_0_php
{
    strings:
        $ = {46 69 59 7a 55 31 59 6a 67 69 4f 79 41 6a 63 6d 39 76 64 41 30 4b 4a 47 4e 76 62 47 39 79 49 44 30 67 49 69 4e 6b 5a 6a 55 69 4f 77 30 4b 4a 47 52 6c 5a 6d 46 31 62 48 52 66 59 57 4e 30 61 57}
    condition:
        any of them
}

rule SHELLDETECT_phpfilemanager_0_2_php
{
    strings:
        $ = {68 62 44 30 6b 5a 47 6c 79 58 32 46 30 64 57 46 73 4a 79 74 68 63 6d 63 72 4a 79 38 6e 4f 77 30 4b 66 51 30 4b 5a 6e 56 75 59 33 52 70 62 32 34 67 63 32 68 76 64 31 39 75 59 57 31 6c 63 79 67}
    condition:
        any of them
}

rule SHELLDETECT_clearshell_0_0_php
{
    strings:
        $ = {57 45 78 44 61 46 56 58 5a 6a 4e 4a 54 6a 52 52 63 31 46 54 52 56 49 34 62 43 74 31 57 55 64 51 5a 6e 46 71 51 32 64 35 56 6a 46 57 4d 46 52 30 59 31 70 51 64 44 4a 56 4d 6e 64 47 61 55 6c 6a}
    condition:
        any of them
}

rule SHELLDETECT_lizozim_1_0_php
{
    strings:
        $ = {77 59 58 4e 7a 64 32 51 38 4c 32 39 77 64 47 6c 76 62 6a 34 4e 43 6a 78 76 63 48 52 70 62 32 34 67 64 6d 46 73 64 57 55 39 49 6d 35 6c 64 48 4e 30 59 58 51 67 4c 57 46 75 49 48 77 67 5a 33 4a}
    condition:
        any of them
}

rule SHELLDETECT_ironshell_2_0_php
{
    strings:
        $ = {70 4f 77 30 4b 49 48 30 4e 43 69 42 70 5a 69 67 6b 58 31 42 50 55 31 52 62 4a 33 42 68 63 33 4d 6e 58 53 41 39 50 53 41 6b 63 47 46 7a 63 33 64 76 63 6d 51 70 44 51 6f 67 65 77 30 4b 49 43 41}
    condition:
        any of them
}

rule SHELLDETECT_al_marhum_0_0_php
{
    strings:
        $ = {59 7a 5a 31 6b 72 56 6e 52 52 51 32 46 4a 52 56 42 68 63 6c 70 6c 64 6a 64 4a 4f 54 4a 57 51 54 4e 6e 53 31 5a 32 5a 56 45 77 4e 6a 68 72 4d 32 35 43 64 6d 4e 6e 53 44 41 79 54 47 39 4a 5a 6d}
    condition:
        any of them
}

rule SHELLDETECT_configspy_3_0_php
{
    strings:
        $ = {4a 6b 5a 58 49 39 4d 54 34 4b 43 6a 78 30 63 69 42 69 5a 32 4e 76 62 47 39 79 50 57 64 79 5a 57 56 75 50 6a 78 30 5a 44 35 6b 4d 47 31 68 61 57 35 7a 50 43 39 30 5a 44 34 38 64 47 51 2b 64 58}
    condition:
        any of them
}

rule SHELLDETECT_lolipop_0_0_php
{
    strings:
        $ = {42 6f 63 47 4a 69 4a 31 30 70 4b 53 41 4b 65 79 41 4b 5a 57 4e 6f 62 79 41 69 50 47 4e 6c 62 6e 52 6c 63 6a 34 38 64 47 46 69 62 47 55 67 59 6d 39 79 5a 47 56 79 50 54 41 67 64 32 6c 6b 64 47}
    condition:
        any of them
}

rule SHELLDETECT_phpbackdoor_0_0_php
{
    strings:
        $ = {56 55 56 54 56 46 73 6e 5a 47 6c 79 4a 31 30 37 43 67 6b 4a 4a 47 5a 75 59 57 31 6c 50 53 52 49 56 46 52 51 58 31 42 50 55 31 52 66 52 6b 6c 4d 52 56 4e 62 4a 32 5a 70 62 47 56 66 62 6d 46 74}
    condition:
        any of them
}

rule SHELLDETECT_devilzshell_0_0_php
{
    strings:
        $ = {4a 79 4f 44 46 34 55 79 39 78 53 45 52 6c 65 6e 4e 4a 4c 32 34 77 4f 53 39 51 63 44 5a 6c 5a 56 67 34 57 69 39 4c 64 6c 51 35 53 69 73 76 5a 56 70 79 4b 30 64 31 59 54 68 77 64 6b 64 74 5a 56}
    condition:
        any of them
}

rule SHELLDETECT_ajax_command_shell_1_0_php
{
    strings:
        $ = {62 57 56 75 64 43 35 6a 63 6d 56 68 64 47 56 46 62 47 56 74 5a 57 35 30 4b 43 4a 77 63 6d 55 69 4b 54 73 4e 43 6c 39 68 4c 6e 4e 30 65 57 78 6c 4c 6d 52 70 63 33 42 73 59 58 6b 39 49 6d 6c 75}
    condition:
        any of them
}

rule SHELLDETECT_nshell_0_0_php
{
    strings:
        $ = {63 47 55 39 64 47 56 34 64 43 49 75 51 43 52 66 55 45 39 54 56 46 73 6e 5a 6d 6c 73 5a 53 64 64 4c 69 49 2b 50 47 4a 79 50 69 49 37 43 6d 56 6a 61 47 38 67 49 6a 78 70 62 6e 42 31 64 43 42 30}
    condition:
        any of them
}

rule SHELLDETECT_spam_2_0_php
{
    strings:
        $ = {47 56 68 5a 47 56 79 49 43 34 39 49 43 49 6b 62 57 56 7a 63 32 46 6e 5a 56 78 79 58 47 34 69 4f 77 30 4b 49 43 41 67 49 43 41 67 53 57 59 67 4b 43 52 6d 61 57 78 6c 58 32 35 68 62 57 55 70 49}
    condition:
        any of them
}

rule SHELLDETECT_connectback2_0_0_pl
{
    strings:
        $ = {4d 6a 45 67 58 47 34 69 4f 79 41 4b 66 53 41 4b 64 58 4e 6c 49 46 4e 76 59 32 74 6c 64 44 73 67 43 6e 56 7a 5a 53 42 47 61 57 78 6c 53 47 46 75 5a 47 78 6c 4f 79 41 4b 63 32 39 6a 61 32 56 30}
    condition:
        any of them
}

rule SHELLDETECT_king511_0_0_pl
{
    strings:
        $ = {70 4f 6e 67 36 4c 32 63 70 65 77 6f 6d 62 47 6c 73 4b 43 51 78 4b 54 73 4b 63 48 4a 70 62 6e 51 67 54 56 6c 47 53 55 78 46 49 43 51 78 4c 69 49 75 64 48 68 30 49 43 49 37 43 6d 5a 76 63 69 67}
    condition:
        any of them
}

rule SHELLDETECT_cristercorp_infocollector_1_0_php
{
    strings:
        $ = {43 67 6b 4a 49 47 6c 6d 49 43 68 7a 64 48 49 75 61 57 35 6b 5a 58 68 50 5a 69 68 6b 62 33 51 73 4b 47 78 68 64 43 73 79 4b 53 6b 39 50 53 30 78 4b 58 73 4b 43 67 6b 4a 49 43 41 67 49 47 46 73}
    condition:
        any of them
}

rule SHELLDETECT_teamsql_1_0_php
{
    strings:
        $ = {58 68 30 50 53 49 6a 4e 32 45 33 59 7a 64 6b 49 6a 34 4e 43 69 41 67 49 43 41 67 49 43 41 38 5a 47 6c 32 49 47 46 73 61 57 64 75 50 53 4a 6a 5a 57 35 30 5a 58 49 69 50 67 30 4b 49 43 41 67 49}
    condition:
        any of them
}

rule SHELLDETECT_smtpd_0_1_py
{
    strings:
        $ = {43 41 67 49 43 41 67 49 43 42 6a 62 32 35 30 59 57 6c 75 61 57 35 6e 49 47 45 67 59 43 34 6e 49 47 5a 76 62 47 78 76 64 32 56 6b 49 47 4a 35 49 47 39 30 61 47 56 79 49 48 52 6c 65 48 51 67 61}
    condition:
        any of them
}

rule SHELLDETECT_dc3shell_0_0_php
{
    strings:
        $ = {4d 47 52 36 59 55 38 31 64 45 68 6a 4d 6d 70 31 59 6c 49 7a 54 6d 38 33 62 54 42 6b 65 6d 45 4b 54 7a 56 30 53 47 4d 79 61 6e 56 69 55 6a 4e 4f 62 7a 64 74 4d 47 52 36 59 55 38 31 64 45 68 6a}
    condition:
        any of them
}

rule SHELLDETECT_dc3shell_1_0_php
{
    strings:
        $ = {67 6b 58 31 42 50 55 31 52 62 4a 32 4e 76 62 57 31 68 62 6d 51 6e 58 53 6b 37 44 51 70 6c 59 32 68 76 49 43 49 38 4c 33 52 6c 65 48 52 68 63 6d 56 68 50 69 49 37 44 51 70 6c 65 47 6c 30 4f 77}
    condition:
        any of them
}

rule SHELLDETECT_cmd_34_0_php
{
    strings:
        $ = {32 55 75 59 32 39 74 43 67 6f 67 49 45 4e 76 63 48 6c 79 61 57 64 6f 64 43 41 6f 59 79 6b 67 4d 6a 41 77 4d 79 42 76 63 30 4e 76 62 57 31 6c 63 6d 4e 6c 43 67 6f 67 49 46 4a 6c 62 47 56 68 63}
    condition:
        any of them
}

rule SHELLDETECT_pzadv_0_1_php
{
    strings:
        $ = {6b 31 70 65 47 77 79 51 55 70 69 54 57 52 6c 55 30 35 4c 64 6b 77 31 51 57 39 68 62 7a 67 33 54 33 70 7a 65 6e 55 78 64 44 59 30 57 6c 52 47 4f 57 56 4b 64 54 52 4a 4e 56 56 43 4e 30 6c 70 4d 47 39 70 4b 30 45 30 4d 55 31 50 54 30 46 4a 4e 33 6b 78 54 56 5a 56 51 6c 59 33 57 47 64 49 54 6b 5a 33 64 54 64 70 62 7a 6b 34 63 57 64 49 4d 30 4e 42 4e 6e 52 6c 63 31 49 32 54 58 56 4a 53 48 49 30 63 53 39 53 4d 56 45}
    condition:
        any of them
}

rule SHELLDETECT_joomla_spam_2_1_php
{
    strings:
        $ = {46 34 4e 45 31 71 52 6b 39 59 53 47 64 36 57 56 5a 34 4e 45 31 48 55 6d 4e 6c 52 45 55 78 57 45 68 6e 64 31 6c 73 65 44 52 4e 56 31 5a 6a 5a 55 52 42 4d 6b 35 45 57 6d 4e 6c 52 45 6c 33 57 45}
    condition:
        any of them
}

rule SHELLDETECT_O0O_0_0_php
{
    strings:
        $ = {61 57 34 67 59 32 39 75 5a 6d 6c 6e 4c 69 6f 67 5a 6d 6c 73 5a 58 4d 75 4c 69 35 63 62 6c 78 75 49 6a 73 67 44 51 70 6d 62 33 4a 6c 59 57 4e 6f 49 43 67 6b 64 58 4e 6c 63 6e 4d 67 59 58 4d 67}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_35_0_php
{
    strings:
        $ = {6d 56 33 49 46 4e 6f 5a 57 78 73 49 45 4a 35 49 43 34 76 54 55 4e 35 59 6d 56 79 54 47 6c 75 61 31 39 51 62 33 4a 30 4d 6a 49 70 49 43 6f 76 49 41 30 4b 4a 47 46 31 64 47 68 66 63 47 46 7a 63}
    condition:
        any of them
}

rule SHELLDETECT_aZRaiL_0_0_php
{
    strings:
        $ = {43 67 6b 5a 47 6c 79 4c 69 49 76 49 69 34 6b 5a 47 6c 7a 62 57 6b 79 4c 43 52 6d 61 57 78 6c 63 47 56 79 62 53 6b 67 50 79 41 69 50 47 5a 76 62 6e 51 67 59 32 39 73 62 33 49 39 4a 79 4d 77 4d}
    condition:
        any of them
}

rule SHELLDETECT_c99_16_0_php
{
    strings:
        $ = {57 43 31 76 49 44 59 74 62 79 42 59 4c 57 38 67 54 79 31 76 49 45 77 74 62 79 42 6c 4c 57 38 67 65 43 31 76 49 46 49 74 62 79 41 30 4c 57 38 67 4b 79 31 76 49 44 59 74 62 79 42 55 4c 57 38 67}
    condition:
        any of them
}

rule SHELLDETECT_stunshell_2_0_php
{
    strings:
        $ = {33 52 33 5a 7a 61 6d 68 57 62 30 4e 58 64 56 55 7a 61 6d 4e 6d 4e 58 68 49 53 57 56 57 52 32 5a 68 4e 44 6c 61 56 54 46 55 55 6c 52 4e 4d 7a 56 75 56 57 78 45 61 57 5a 31 65 45 5a 6a 53 6a 52}
    condition:
        any of them
}

rule SHELLDETECT_perlbot_0_1_pl
{
    strings:
        $ = {4b 49 43 41 6b 52 45 4e 44 65 79 52 6b 59 32 4e 7a 62 32 4e 72 66 58 74 69 65 58 52 6c 63 33 30 67 50 53 41 6b 59 6e 6c 30 5a 58 4d 37 43 69 41 67 4a 45 52 44 51 33 73 6b 5a 47 4e 6a 63 32 39}
    condition:
        any of them
}

rule SHELLDETECT_harauku_0_0_php
{
    strings:
        $ = {7a 49 69 77 69 51 57 78 68 64 6d 6b 69 4c 43 4a 42 62 47 4e 76 63 6d 34 69 4c 43 4a 42 62 47 52 68 49 69 77 4e 43 69 4a 42 62 47 56 72 63 79 49 73 49 6b 46 73 62 47 6c 7a 62 32 34 69 4c 43 4a}
    condition:
        any of them
}

rule SHELLDETECT_b374k_11_0_php
{
    strings:
        $ = {45 74 61 62 44 46 4b 62 47 63 4e 43 6a 56 47 4d 31 56 44 61 6d 78 50 5a 55 64 6f 57 48 70 6b 64 31 6c 54 54 54 6c 75 55 48 70 6e 5a 6c 70 6a 52 45 70 56 59 32 5a 51 57 47 6b 31 59 6b 46 4d 4d}
    condition:
        any of them
}

rule SHELLDETECT_c99_1_0_php
{
    strings:
        $ = {64 48 52 5a 55 6d 46 43 56 32 6c 4d 54 46 56 79 53 48 6c 78 5a 48 4e 35 4d 47 45 35 55 48 52 6e 4c 32 59 77 54 48 4a 78 4e 6e 5a 77 55 57 59 30 4f 47 77 33 4f 44 49 33 59 58 4e 51 65 56 64 53}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_1_0_php
{
    strings:
        $ = {45 74 61 53 42 31 4c 57 6b 67 65 43 31 70 49 46 41 74 61 53 41 30 4c 57 6b 67 4d 69 31 70 49 46 51 74 61 53 42 4b 4c 57 6b 67 54 69 31 70 49 47 51 74 61 53 42 33 4c 57 6b 67 4d 53 31 70 49 48}
    condition:
        any of them
}

rule SHELLDETECT_metasploit_0_0_php
{
    strings:
        $ = {49 47 4a 79 5a 57 46 72 4f 77 70 39 43 6d 6c 6d 49 43 67 68 4a 47 78 6c 62 69 6b 67 65 77 6f 4a 49 79 42 58 5a 53 42 6d 59 57 6c 73 5a 57 51 67 62 32 34 67 64 47 68 6c 49 47 31 68 61 57 34 67}
    condition:
        any of them
}

rule SHELLDETECT_c100_0_0_php
{
    strings:
        $ = {44 30 67 62 58 6c 7a 63 57 78 66 62 47 6c 7a 64 46 39 6b 59 6e 4d 6f 4a 48 4e 78 62 46 39 7a 62 32 4e 72 4b 54 73 4e 43 69 41 67 49 47 6c 6d 49 43 67 68 4a 48 4a 6c 63 33 56 73 64 43 6b 67 65}
    condition:
        any of them
}

rule SHELLDETECT_webmysql_0_0_php
{
    strings:
        $ = {4e 6f 62 79 41 69 52 6d 46 70 62 43 49 37 43 67 6b 4a 43 58 4a 6c 64 48 56 79 62 6a 73 4b 43 51 6c 39 43 67 6b 4a 4a 47 4e 76 62 43 41 39 49 47 31 35 63 33 46 73 58 32 35 31 62 56 39 6d 61 57}
    condition:
        any of them
}

rule SHELLDETECT_backdoor_2_0_php
{
    strings:
        $ = {5a 47 56 7a 49 48 5a 6c 62 6d 46 75 64 43 42 6b 5a 53 42 51 53 46 41 69 4f 77 70 39 43 67 70 70 5a 69 67 6b 62 33 42 30 61 57 39 75 49 44 30 39 49 44 49 70 65 77 6f 67 49 43 41 67 63 48 4a 70}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_8_0_php
{
    strings:
        $ = {62 6b 70 69 5a 44 6b 72 4e 48 46 7a 56 6a 5a 61 57 6b 5a 51 56 31 52 52 59 55 4a 73 59 32 6b 31 53 32 4e 48 61 44 45 33 57 55 35 51 54 6d 78 56 4f 43 49 73 49 6a 56 57 52 55 51 7a 57 6b 74 45}
    condition:
        any of them
}

rule SHELLDETECT_cmd_8_0_php
{
    strings:
        $ = {50 44 39 77 61 48 41 4e 43 6d 6c 6d 4b 43 52 66 55 45 39 54 56 46 73 69 63 47 46 7a 63 79 4a 64 49 44 30 39 49 43 49 79 4e 6a 4e 6a 5a 44 64 68 5a 54 55 77 4e 7a 68 68 4f 44 51 78 5a 54 41 78}
    condition:
        any of them
}

rule SHELLDETECT_wso_19_0_php
{
    strings:
        $ = {52 58 52 7a 54 47 74 32 59 31 64 47 57 57 74 75 4c 31 6c 52 62 32 39 61 4d 54 64 47 61 44 42 49 52 47 56 4e 57 46 42 6a 52 55 4a 55 57 54 67 33 62 30 38 32 57 47 56 4a 53 47 74 31 51 6e 6c 6a}
    condition:
        any of them
}

rule SHELLDETECT_simshell_0_0_php
{
    strings:
        $ = {63 33 51 67 50 53 41 6e 49 69 49 6e 4f 77 6f 67 49 48 30 67 5a 57 78 7a 5a 53 42 37 43 69 41 67 49 43 41 6b 5a 58 4e 6a 59 58 42 6c 5a 43 41 39 49 47 46 79 63 6d 46 35 58 32 31 68 63 43 67 6e}
    condition:
        any of them
}

rule SHELLDETECT_gfs_0_0_php
{
    strings:
        $ = {47 56 79 62 58 4d 39 4a 48 52 35 63 47 56 62 4d 46 30 37 43 69 41 6b 63 47 56 79 62 58 4d 75 50 53 67 6b 62 57 39 6b 5a 53 41 6d 49 44 41 77 4e 44 41 77 4b 53 41 2f 49 43 4a 79 49 69 41 36 49}
    condition:
        any of them
}

rule SHELLDETECT_myshell_0_0_php
{
    strings:
        $ = {37 43 69 41 67 49 43 41 67 49 43 41 67 66 51 6f 67 49 43 41 67 66 51 70 39 43 6a 38 2b 43 6a 78 69 63 6a 34 4b 50 48 52 6c 65 48 52 68 63 6d 56 68 49 47 35 68 62 57 55 39 49 6e 4e 6f 5a 57 78}
    condition:
        any of them
}

rule SHELLDETECT_ntdaddy_0_0_asp
{
    strings:
        $ = {51 70 47 62 32 78 6b 5a 58 4a 42 64 48 52 79 61 57 4a 31 64 47 56 7a 49 44 30 67 49 6c 4e 35 63 33 52 6c 62 53 77 67 52 47 6c 79 5a 57 4e 30 62 33 4a 35 49 67 70 6a 59 58 4e 6c 49 44 49 79 49}
    condition:
        any of them
}

rule SHELLDETECT_mysql_7_0_php
{
    strings:
        $ = {37 44 51 6f 67 49 47 56 6a 61 47 38 67 49 6b 5a 73 64 58 4e 6f 58 47 34 69 4f 77 30 4b 49 43 42 6c 59 32 68 76 49 43 49 38 64 57 77 2b 58 47 34 69 4f 77 30 4b 49 43 42 6c 59 32 68 76 49 43 49}
    condition:
        any of them
}

rule SHELLDETECT_tdshell_1_0_php
{
    strings:
        $ = {31 52 56 4d 45 35 45 54 58 70 4f 56 45 6c 35 57 6b 52 61 62 45 39 45 59 7a 4e 4e 65 6b 45 77 54 31 64 4f 61 56 6b 78 63 32 6c 61 57 47 68 73 57 54 4e 57 4d 46 70 54 53 6d 52 4a 52 44 42 6e 53}
    condition:
        any of them
}

rule SHELLDETECT_filesman_1_0_php
{
    strings:
        $ = {51 31 67 77 56 31 5a 46 56 48 56 36 54 44 4e 35 56 45 31 35 63 56 46 48 59 56 64 45 53 46 4e 61 5a 55 5a 51 4f 57 52 47 52 30 30 32 62 33 64 35 4d 58 4a 68 59 7a 4e 42 4d 32 4e 53 53 6c 46 4e}
    condition:
        any of them
}

rule SHELLDETECT_c99_2_0_php
{
    strings:
        $ = {64 4f 53 45 5a 52 4d 44 6b 76 57 55 64 42 64 47 4a 31 63 58 5a 34 64 48 70 55 63 58 70 34 4f 55 78 4a 4d 56 6b 34 4e 30 6b 79 55 46 52 7a 53 32 35 30 55 45 74 56 56 56 46 6a 51 6c 70 74 53 47}
    condition:
        any of them
}

rule SHELLDETECT_dxshell_1_0_php
{
    strings:
        $ = {6b 56 55 4c 6a 31 6d 5a 32 56 30 63 79 67 6b 5a 69 77 67 4e 44 41 35 4e 69 41 70 4f 77 6f 4a 5a 6d 4e 73 62 33 4e 6c 4b 43 41 6b 5a 69 41 70 4f 77 6f 4b 43 58 42 79 61 57 35 30 49 43 4a 63 62}
    condition:
        any of them
}

rule SHELLDETECT_c99_8_0_php
{
    strings:
        $ = {44 71 38 4f 74 77 36 58 44 72 63 4f 6f 77 36 55 67 77 36 2f 44 73 4d 4f 75 77 36 6a 44 70 38 4f 69 77 36 37 44 71 38 4f 38 77 36 33 44 72 73 4f 6a 77 36 34 67 55 45 68 51 4c 63 4f 71 77 36 37}
    condition:
        any of them
}

rule SHELLDETECT_spyshell_1_0_php
{
    strings:
        $ = {64 6d 46 73 64 57 55 39 49 69 39 6c 64 47 4d 76 63 33 6c 7a 62 47 39 6e 4c 6d 4e 76 62 6d 59 69 50 6c 4e 35 63 32 78 76 5a 79 42 42 65 57 46 79 62 47 46 79 61 54 77 76 62 33 42 30 61 57 39 75}
    condition:
        any of them
}

rule SHELLDETECT_backdoor_1_0_php
{
    strings:
        $ = {4a 63 49 6a 34 69 4c 69 52 32 59 57 78 31 5a 53 34 69 4c 7a 77 76 51 54 34 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 69 4c 6d 52 68 64 47 55 6f 49 6e 49 69 4c 47}
    condition:
        any of them
}

rule SHELLDETECT_c99_27_0_php
{
    strings:
        $ = {69 42 76 64 47 68 6c 63 69 42 6d 63 6d 56 6c 49 47 39 79 49 47 39 77 5a 57 34 67 63 32 39 31 63 6d 4e 6c 49 48 4e 76 5a 6e 52 33 59 58 4a 6c 49 47 78 70 59 32 56 75 63 32 56 7a 4c 67 6f 67 4b}
    condition:
        any of them
}

rule SHELLDETECT_cmd_30_0_php
{
    strings:
        $ = {50 44 39 77 61 48 41 4e 43 6d 56 6a 61 47 38 67 49 6a 78 6f 4d 7a 35 58 62 33 4a 72 63 79 45 67 56 58 4e 68 5a 32 55 36 49 47 63 77 4d 47 34 75 63 47 68 77 50 32 63 77 4d 47 34 39 57 30 4e 4e}
    condition:
        any of them
}

rule SHELLDETECT_hacker_0_0_php
{
    strings:
        $ = {56 30 5a 58 49 6e 4c 41 6f 6e 63 6d 56 7a 5a 58 51 6e 49 44 30 2b 49 43 64 53 77 36 6c 70 62 6d 6c 30 61 57 46 73 61 58 4e 6c 63 69 63 73 43 69 64 79 5a 57 78 68 64 47 6c 32 5a 53 63 67 50 54}
    condition:
        any of them
}

rule SHELLDETECT_cmd_15_0_asp
{
    strings:
        $ = {47 56 79 62 58 4d 4e 43 69 41 67 51 32 46 73 62 43 42 76 55 79 35 53 64 57 34 6f 49 6e 64 70 62 69 35 6a 62 32 30 67 59 32 31 6b 4c 6d 56 34 5a 53 41 76 59 79 42 6a 59 57 4e 73 63 79 35 6c 65}
    condition:
        any of them
}

rule SHELLDETECT_c2007_0_0_php
{
    strings:
        $ = {32 68 6c 63 69 42 73 5a 58 5a 6c 62 48 4d 67 50 43 39 6b 61 58 59 2b 49 41 6f 67 49 43 41 67 50 43 39 6d 62 33 4a 74 50 69 41 4b 49 43 41 67 49 44 77 76 64 47 51 2b 49 41 6f 67 49 44 78 30 5a}
    condition:
        any of them
}

rule SHELLDETECT_wso_7_0_php
{
    strings:
        $ = {64 30 34 79 64 48 5a 57 52 57 68 4c 59 6d 31 6f 61 56 4e 49 62 46 4a 68 56 31 4a 57 59 6c 68 77 61 32 4a 48 64 33 70 57 52 7a 56 34 57 6a 4e 61 64 6c 52 59 61 44 4a 4f 56 33 4e 34 54 6d 73 35}
    condition:
        any of them
}

rule SHELLDETECT_filesman_23_0_php
{
    strings:
        $ = {52 54 56 36 65 48 56 7a 59 54 4d 76 4b 33 52 71 4e 54 4a 61 52 31 5a 6a 61 47 34 35 54 6c 64 71 63 30 6c 79 54 33 63 35 4b 79 39 79 64 57 59 79 52 6e 68 72 4d 56 6c 6b 65 6d 68 69 4e 7a 42 68}
    condition:
        any of them
}

rule SHELLDETECT_indexer_0_0_asp
{
    strings:
        $ = {43 59 75 66 79 38 79 53 33 68 72 4b 31 4a 54 52 47 4a 50 4b 79 78 4b 52 56 73 78 58 46 63 6e 63 6b 70 41 49 30 41 6d 4c 69 74 72 64 31 63 4a 5a 47 35 53 55 30 52 69 57 57 35 51 52 55 56 4d 57}
    condition:
        any of them
}

rule SHELLDETECT_webroot_1_0_php
{
    strings:
        $ = {79 54 7a 68 31 4d 6c 59 34 62 32 68 4b 57 55 4d 72 59 6b 5a 78 53 6d 74 6f 65 56 63 34 62 6a 4a 4b 53 6b 4e 55 59 54 64 48 4e 31 6f 78 59 6e 6f 77 64 6d 56 4c 55 45 35 32 64 6b 4a 47 64 57 56}
    condition:
        any of them
}

rule SHELLDETECT_FaTaLisTiCz_0_0_php
{
    strings:
        $ = {49 38 4c 32 39 77 64 47 6c 76 62 6a 35 63 63 6c 78 75 49 6a 73 4e 43 69 41 67 49 43 42 39 44 51 6f 67 49 48 30 4e 43 69 41 67 5a 57 4e 6f 62 79 41 69 50 43 39 7a 5a 57 78 6c 59 33 51 2b 58 48}
    condition:
        any of them
}

rule SHELLDETECT_r57_14_0_php
{
    strings:
        $ = {41 76 5a 33 4a 6c 63 43 35 30 65 48 51 6e 4c 41 6f 6e 62 47 39 6a 59 58 52 6c 49 47 4e 76 62 6d 5a 70 5a 79 35 77 61 48 41 67 5a 6d 6c 73 5a 58 4d 67 50 6a 34 67 4c 33 52 74 63 43 39 6e 63 6d}
    condition:
        any of them
}

rule SHELLDETECT_b374k_5_0_php
{
    strings:
        $ = {48 70 6a 4d 47 52 6c 43 67 6f 6b 61 6d 46 74 5a 58 4d 77 59 6d 46 7a 64 47 56 79 49 44 30 67 49 6a 64 59 4d 54 64 6c 4f 58 45 30 4f 48 5a 45 5a 6a 4e 6c 5a 6c 6f 33 4e 6b 49 32 59 33 68 69 57}
    condition:
        any of them
}

rule SHELLDETECT_fx0_3_0_php
{
    strings:
        $ = {6b 62 30 34 34 61 6e 64 52 51 57 52 46 56 6c 63 4b 56 6c 6b 78 63 6b 56 51 4f 56 56 71 64 31 4a 6b 57 47 39 30 5a 45 52 42 64 6b 46 6b 52 45 34 30 55 45 6c 30 4e 30 4e 47 55 47 39 78 5a 6a 63}
    condition:
        any of them
}

rule SHELLDETECT_pas_0_0_php
{
    strings:
        $ = {62 62 3a 4a 46 39 66 58 31 39 66 4b 79 73 70 65 79 52 66 58 31 39 66 57 79 52 66 58 31 39 66 58 31 30 39 59 32 68 79 4b 43 67 67 62 33 4a 6b 4b 43 52 66 58 31 39 66 57 79 52 66 58 31 39 66 58 31 30 70 4c 57 39 79 5a 43 67 6b 58 31 39 66 57 79 52 66 58 31 39 66 58 31 30 70 4b 51 3d 3d}
    condition:
        any of them
}

rule SHELLDETECT_gscshell_0_0_php
{
    strings:
        $ = {58 53 6b 37 44 51 6f 67 49 43 41 67 49 43 41 67 49 47 56 6a 61 47 38 67 49 6a 77 76 64 47 56 34 64 47 46 79 5a 57 45 2b 49 6a 73 67 49 43 41 67 5a 47 6c 6c 4b 43 6b 37 44 51 6f 67 49 43 41 67}
    condition:
        any of them
}

rule SHELLDETECT_kadotshell_0_0_php
{
    strings:
        $ = {73 49 43 52 31 63 47 78 76 59 57 52 6d 61 57 78 6c 4b 53 6b 67 65 77 6f 67 49 43 41 67 5a 57 4e 6f 62 79 41 69 31 4f 44 70 36 2b 34 67 38 2f 48 76 35 66 6a 74 37 69 44 6e 34 4f 50 77 38 2b 62}
    condition:
        any of them
}

rule SHELLDETECT_spam_3_0_php
{
    strings:
        $ = {67 49 43 41 67 50 48 52 6b 49 48 64 70 5a 48 52 6f 50 53 49 79 4d 54 6b 69 50 67 30 4b 49 43 41 67 49 43 41 67 49 43 41 38 5a 6d 39 75 64 43 42 7a 61 58 70 6c 50 53 49 74 4d 79 49 67 5a 6d 46}
    condition:
        any of them
}

rule SHELLDETECT_c99_13_0_php
{
    strings:
        $ = {49 77 54 57 70 71 63 54 42 54 64 48 4a 6c 63 47 5a 51 57 55 6f 7a 63 57 39 30 64 6e 6b 7a 61 33 52 4c 61 30 38 33 4e 32 68 57 4f 58 67 32 54 43 38 31 55 6e 55 31 61 30 6c 56 52 57 4a 32 4f 44}
    condition:
        any of them
}

rule SHELLDETECT_c99_17_0_php
{
    strings:
        $ = {65 46 4d 35 4b 33 68 31 64 44 49 77 55 6b 56 45 59 57 5a 72 51 6d 46 4e 61 55 52 30 53 55 4e 45 64 45 31 44 52 48 52 35 53 31 42 4a 64 6d 77 31 52 54 5a 50 65 56 64 59 4d 30 52 47 5a 6e 5a 4b}
    condition:
        any of them
}

rule SHELLDETECT_htaccess_shell_0_0_htaccess
{
    strings:
        $ = {47 46 73 62 47 39 33 4c 47 52 6c 62 6e 6b 4b 49 43 41 67 49 45 46 73 62 47 39 33 49 47 5a 79 62 32 30 67 59 57 78 73 43 6a 77 76 52 6d 6c 73 5a 58 4d 2b 43 67 6f 6a 49 45 31 68 61 32 55 67 4c}
    condition:
        any of them
}

rule SHELLDETECT_c99_25_0_php
{
    strings:
        $ = {67 50 7a 38 2f 50 7a 38 2f 50 7a 38 2f 50 79 42 7a 61 47 56 73 62 43 30 2f 50 7a 38 2f 50 7a 38 67 4b 44 38 2f 50 7a 38 2f 49 44 38 2f 50 7a 38 2f 50 7a 38 73 49 44 38 2f 50 7a 38 2f 49 44 38}
    condition:
        any of them
}

rule SHELLDETECT_kaushell_0_0_php
{
    strings:
        $ = {49 48 5a 68 62 48 56 6c 50 53 4a 46 62 6e 52 6c 63 69 49 2b 43 6a 77 76 64 47 51 2b 50 43 39 30 63 6a 34 4b 4a 48 52 6c 62 6d 51 4b 53 46 52 4e 54 44 73 4b 43 6d 6c 6d 49 43 68 70 63 33 4e 6c}
    condition:
        any of them
}

rule SHELLDETECT_darkshell_1_0_php
{
    strings:
        $ = {47 39 45 4d 44 42 4f 54 6e 4a 57 54 32 5a 4f 64 46 6b 72 65 48 46 35 4e 30 34 7a 51 57 64 6d 53 56 64 69 61 30 73 32 65 6b 6b 76 59 31 6c 51 5a 33 4a 31 56 6e 70 58 65 6b 73 78 4e 46 4a 6f 4f}
    condition:
        any of them
}

rule SHELLDETECT_stressbypass_1_0_php
{
    strings:
        $ = {67 50 48 52 6b 49 48 64 70 5a 48 52 6f 50 53 49 31 4d 43 55 69 49 47 68 6c 61 57 64 6f 64 44 30 69 4d 53 49 67 64 6d 46 73 61 57 64 75 50 53 4a 30 62 33 41 69 49 47 4a 6e 59 32 39 73 62 33 49}
    condition:
        any of them
}

rule SHELLDETECT_madspot_0_0_php
{
    strings:
        $ = {79 49 46 4e 6c 63 6e 5a 6c 63 69 42 70 62 6e 52 79 64 58 4e 70 62 32 34 38 4c 32 39 77 64 47 6c 76 62 6a 34 4e 43 6a 78 76 63 48 52 70 62 32 34 67 64 6d 46 73 64 57 55 39 49 6a 45 31 49 69 41}
    condition:
        any of them
}

rule SHELLDETECT_filesman_0_0_php
{
    strings:
        $ = {54 54 5a 70 55 6b 67 7a 56 55 56 51 64 44 5a 7a 5a 43 39 5a 63 57 46 59 59 6a 68 76 62 54 41 7a 65 47 4a 31 63 55 5a 4e 61 57 39 51 59 33 6c 56 64 6b 74 51 4e 6e 5a 54 55 6e 70 6a 63 57 31 70}
    condition:
        any of them
}

rule SHELLDETECT_elmaliseker_0_0_vbs
{
    strings:
        $ = {4e 6c 49 47 59 75 59 58 52 30 63 6d 6c 69 64 58 52 6c 63 77 30 4b 59 32 46 7a 5a 53 41 77 44 51 70 47 62 32 78 6b 5a 58 4a 42 64 48 52 79 61 57 4a 31 64 47 56 7a 49 44 30 67 49 6b 35 76 63 6d}
    condition:
        any of them
}

rule SHELLDETECT_c99_20_0_php
{
    strings:
        $ = {68 5a 44 64 34 63 53 38 30 4e 79 74 69 5a 30 6c 78 54 31 4d 78 64 6d 5a 70 63 57 64 34 61 6d 74 7a 4d 45 46 45 4e 6b 6c 49 59 32 68 6b 4d 33 70 56 57 44 63 35 64 6e 46 77 56 46 64 6c 55 7a 5a}
    condition:
        any of them
}

rule SHELLDETECT_r57_18_0_php
{
    strings:
        $ = {53 69 73 34 61 32 31 36 59 6b 78 6c 62 6d 5a 42 65 6e 42 48 63 54 5a 6c 56 69 74 71 64 6b 64 71 64 6b 38 34 54 30 4a 4e 55 6e 6c 61 55 54 4e 79 63 33 42 74 64 43 73 31 54 79 39 5a 61 7a 42 61}
    condition:
        any of them
}

rule SHELLDETECT_telnet_1_0_pl
{
    strings:
        $ = {59 57 51 67 5a 47 46 30 59 51 6f 4a 61 57 59 6f 4a 45 56 4f 56 6e 73 6e 51 30 39 4f 56 45 56 4f 56 46 39 55 57 56 42 46 4a 33 30 67 50 58 34 67 4c 32 31 31 62 48 52 70 63 47 46 79 64 46 77 76}
    condition:
        any of them
}

rule SHELLDETECT_foreverpp_0_1_php
{
    strings:
        $ = {50 53 63 77 4e 43 63 37 49 47 4a 79 5a 57 46 72 4f 77 30 4b 43 51 6b 4a 43 57 4e 68 63 32 55 67 4a 7a 55 6e 4f 69 41 67 4a 47 52 68 64 47 55 39 4a 7a 41 31 4a 7a 73 67 59 6e 4a 6c 59 57 73 37}
    condition:
        any of them
}

rule SHELLDETECT_phpbackdoor_1_0_php
{
    strings:
        $ = {61 58 70 6c 49 6c 30 38 4a 46 39 51 54 31 4e 55 57 79 4a 4e 51 56 68 66 52 6b 6c 4d 52 56 39 54 53 56 70 46 49 6c 30 70 43 69 41 67 49 43 42 37 43 69 41 67 49 43 41 67 49 47 6c 6d 4b 47 31 76}
    condition:
        any of them
}

rule SHELLDETECT_antichat_shell_1_0_php
{
    strings:
        $ = {5a 57 78 73 50 43 39 30 61 58 52 73 5a 54 34 38 62 57 56 30 59 53 42 6f 64 48 52 77 4c 57 56 78 64 57 6c 32 50 53 4a 44 62 32 35 30 5a 57 35 30 4c 56 52 35 63 47 55 69 49 47 4e 76 62 6e 52 6c}
    condition:
        any of them
}

rule SHELLDETECT_smartshell_0_0_asp
{
    strings:
        $ = {5a 51 30 4b 43 51 6b 4a 43 56 4a 6c 63 33 42 76 62 6e 4e 6c 4c 6c 64 79 61 58 52 6c 49 43 49 38 5a 6d 39 75 64 43 42 6d 59 57 4e 6c 50 53 49 69 59 58 4a 70 59 57 77 69 49 69 42 7a 61 58 70 6c}
    condition:
        any of them
}

rule SHELLDETECT_webadmin_2_2_php
{
    strings:
        $ = {56 6b 4a 79 41 39 50 69 41 69 52 47 6c 7a 63 32 55 67 5a 6d 6c 73 5a 58 49 67 5a 58 49 67 61 32 39 77 61 57 56 79 5a 58 51 67 64 47 6c 73 49 46 77 69 57 79 55 79 58 56 77 69 4f 6c 78 75 57 79}
    condition:
        any of them
}

rule SHELLDETECT_b374k_17_0_php
{
    strings:
        $ = {4d 47 63 31 63 69 74 71 55 57 52 36 56 47 78 72 4d 6e 64 59 61 56 63 77 64 30 68 31 61 46 42 4e 65 54 4a 42 52 30 4e 70 54 57 73 76 65 6b 35 43 54 44 5a 72 4e 58 46 57 53 30 73 77 53 6d 35 55}
    condition:
        any of them
}

rule SHELLDETECT_cmd_14_0_php
{
    strings:
        $ = {50 44 39 77 61 48 41 4b 4c 79 70 6a 4f 44 59 30 4f 57 45 35 59 54 45 32 4e 54 4e 6d 4f 44 55 79 4f 44 51 7a 5a 6a 51 30 5a 6a 6b 78 4e 6d 4a 6a 59 6a 51 30 5a 43 6f 76 61 57 59 6f 61 58 4e 7a}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_26_0_php
{
    strings:
        $ = {46 55 33 4e 56 51 33 51 6a 4a 79 52 54 49 32 4f 55 64 34 63 48 42 46 64 6a 5a 33 52 47 39 35 59 53 73 78 64 45 35 43 64 56 56 57 55 44 52 48 56 30 46 56 4c 33 5a 76 65 55 31 34 4d 56 67 78 57}
    condition:
        any of them
}

rule SHELLDETECT_ironshell_1_0_php
{
    strings:
        $ = {70 49 48 73 4e 43 69 41 67 49 43 41 67 49 43 41 67 63 48 4a 70 62 6e 51 67 49 6b 5a 70 62 47 55 36 49 69 34 67 49 47 4a 68 63 32 56 75 59 57 31 6c 4b 43 41 6b 58 30 5a 4a 54 45 56 54 57 79 64}
    condition:
        any of them
}

rule SHELLDETECT_bogel_shell_1_0_php
{
    strings:
        $ = {4e 4e 57 57 70 53 4e 30 6c 55 5a 54 51 30 5a 47 74 56 63 32 39 49 62 6e 68 45 57 57 4d 34 5a 48 6c 78 63 6d 4a 32 5a 47 4a 74 61 69 74 71 59 32 38 35 65 57 4e 57 4d 6d 74 72 55 6b 70 48 52 6b}
    condition:
        any of them
}

rule SHELLDETECT_erne_2_0_php
{
    strings:
        $ = {69 4b 53 42 37 44 51 6f 4a 43 51 6b 6b 63 6d 56 7a 64 57 78 30 50 58 4e 6f 5a 57 78 73 58 32 56 34 5a 57 4d 6f 4a 46 39 51 54 31 4e 55 57 79 64 6a 62 32 31 74 59 57 35 6b 4a 31 30 70 4f 77 30}
    condition:
        any of them
}

rule SHELLDETECT_moroccan_spam_0_1_php
{
    strings:
        $ = {49 41 70 4f 59 57 31 6c 4f 6a 77 76 5a 6d 39 75 64 44 34 38 4c 32 52 70 64 6a 34 67 43 6a 77 76 64 47 51 2b 49 41 6f 38 64 47 51 67 64 32 6c 6b 64 47 67 39 49 6a 4d 78 4e 79 49 67 59 6d 39 79}
    condition:
        any of them
}

rule SHELLDETECT_antisecshell_1_0_php
{
    strings:
        $ = {76 5a 6d 39 79 62 54 34 38 4c 33 52 6b 50 6a 77 76 64 48 49 2b 44 51 6f 38 4c 33 52 68 59 6d 78 6c 50 67 30 4b 50 47 4a 79 50 6a 78 6b 61 58 59 67 59 32 78 68 63 33 4d 39 59 6d 46 79 61 47 56}
    condition:
        any of them
}

rule SHELLDETECT_cmos_clr_0_0_php
{
    strings:
        $ = {4f 51 32 6c 42 5a 30 6c 44 51 57 64 4a 51 30 46 6e 53 55 4e 42 5a 30 6c 44 51 57 64 4a 51 30 46 6e 53 55 4e 42 5a 30 6c 44 51 57 64 4a 51 30 46 6e 53 55 4e 42 61 32 4e 48 64 47 31 4f 52 46 5a}
    condition:
        any of them
}

rule SHELLDETECT_s72shell_1_0_php
{
    strings:
        $ = {49 44 77 76 5a 6d 39 75 64 44 34 4e 43 69 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 50 44 39 77 61 48 41 67 44 51 6f 76 4c 79 42 44 61 47 56 6a 61 79 42 6d 62 33 49 67 55 32 46 6d}
    condition:
        any of them
}

rule SHELLDETECT_c100_1_0_php
{
    strings:
        $ = {70 4f 77 6f 67 49 43 41 67 4a 48 56 6b 49 44 30 67 64 58 4a 73 5a 57 35 6a 62 32 52 6c 4b 43 52 6b 61 58 49 70 4f 77 6f 67 49 43 41 67 4a 48 56 32 49 44 30 67 64 58 4a 73 5a 57 35 6a 62 32 52}
    condition:
        any of them
}

rule SHELLDETECT_rhtool_0_0_asp
{
    strings:
        $ = {63 6d 73 67 50 53 42 54 5a 58 4a 32 5a 58 49 75 51 33 4a 6c 59 58 52 6c 54 32 4a 71 5a 57 4e 30 4b 43 4a 58 55 32 4e 79 61 58 42 30 4c 6b 35 6c 64 48 64 76 63 6d 73 69 4b 51 6f 4a 43 56 4e 6c}
    condition:
        any of them
}

rule SHELLDETECT_phpspy_3_0_php
{
    strings:
        $ = {38 4c 33 52 6b 50 69 63 70 4f 77 6f 4a 43 51 6b 4a 43 51 6c 77 4b 43 63 38 64 47 51 2b 4a 79 34 6b 63 6d 39 33 57 79 64 54 5a 58 46 66 61 57 35 66 61 57 35 6b 5a 58 67 6e 58 53 34 6e 50 43 39}
    condition:
        any of them
}

rule SHELLDETECT_brute_force_tool_0_0_php
{
    strings:
        $ = {43 42 6d 62 33 4a 6c 59 57 4e 6f 49 43 67 6b 59 57 78 73 54 47 6c 75 61 33 4d 67 59 58 4d 67 4a 47 74 72 49 44 30 2b 49 43 52 32 64 69 6c 37 49 43 52 68 62 47 78 45 62 57 35 7a 57 31 30 67 50}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_31_0_php
{
    strings:
        $ = {66 4b 43 30 6f 4c 43 68 64 4b 44 6f 72 66 43 67 36 4c 56 38 6f 4c 43 67 36 4b 44 6f 6f 58 53 68 64 4c 43 59 6f 58 79 68 66 4b 47 41 74 58 69 67 73 4b 44 6f 6f 4c 69 68 64 4b 46 30 6f 58 69 67}
    condition:
        any of them
}

rule SHELLDETECT_c99_22_0_php
{
    strings:
        $ = {44 42 6e 61 45 4a 49 52 47 35 61 4b 32 6c 4a 52 45 74 47 65 6b 64 53 65 56 52 6a 5a 45 35 42 57 45 64 31 4d 45 30 35 65 6b 5a 75 55 30 55 33 63 57 4a 46 57 55 5a 6e 65 44 64 6e 52 32 6f 77 4e}
    condition:
        any of them
}

rule SHELLDETECT_wso_4_0_php
{
    strings:
        $ = {68 63 33 4d 70 4b 53 42 37 43 69 41 67 49 43 42 70 5a 69 68 70 63 33 4e 6c 64 43 67 6b 58 31 42 50 55 31 52 62 4a 33 42 68 63 33 4d 6e 58 53 6b 67 4a 69 59 67 4b 47 31 6b 4e 53 67 6b 58 31 42}
    condition:
        any of them
}

rule SHELLDETECT_r57_10_0_php
{
    strings:
        $ = {4c 4d 6d 4a 6f 62 54 45 7a 51 6b 4e 4c 64 6b 4a 46 5a 6e 70 74 4e 55 73 31 54 30 78 32 59 33 70 6a 51 6c 46 72 54 6d 35 69 54 32 70 79 5a 6a 6c 56 63 44 59 35 56 55 4a 33 54 30 39 34 4d 43 39}
    condition:
        any of them
}

rule SHELLDETECT_sec4ever_0_0_php
{
    strings:
        $ = {54 4d 57 38 4b 4e 6a 4e 74 4d 57 34 76 63 32 46 7a 5a 32 35 6b 57 48 70 57 54 44 52 5a 52 55 46 7a 55 46 56 58 5a 54 5a 72 5a 33 56 70 59 56 4d 78 53 47 46 49 5a 46 5a 44 64 41 6f 7a 61 43 73}
    condition:
        any of them
}

rule SHELLDETECT_shell_uploader_6_0_php
{
    strings:
        $ = {30 52 6d 68 7a 62 30 68 73 61 33 4a 73 59 55 59 77 5a 30 56 36 4b 30 64 6b 61 45 4e 46 64 45 4e 68 51 57 6c 5a 61 57 4e 71 55 30 74 5a 56 33 4e 6e 56 30 74 7a 55 48 56 55 54 47 39 4c 54 56 52}
    condition:
        any of them
}

rule SHELLDETECT_wso_6_0_php
{
    strings:
        $ = {56 55 38 76 4e 45 74 4c 61 7a 55 76 4b 33 56 4a 54 31 4e 6b 63 33 68 6c 4f 57 4a 69 63 47 49 35 4d 46 42 50 52 6d 70 43 57 6d 31 6e 59 6e 46 73 64 6d 56 4f 54 6b 39 32 61 32 77 79 56 6d 6c 46}
    condition:
        any of them
}

rule SHELLDETECT_filesman_2_0_php
{
    strings:
        $ = {63 79 42 68 49 47 4e 76 62 6e 4e 6c 63 58 56 6c 62 6d 4e 6c 49 47 39 6d 49 48 56 7a 61 57 35 6e 49 48 42 6c 5a 58 49 74 64 47 38 74 63 47 56 6c 63 69 42 30 63 6d 46 75 63 32 31 70 63 33 4e 70}
    condition:
        any of them
}

rule SHELLDETECT_jackal_3_0_php
{
    strings:
        $ = {30 4b 61 57 59 6f 49 57 56 74 63 48 52 35 4b 43 52 66 55 6b 56 52 56 55 56 54 56 46 73 6e 62 6d 56 33 5a 6d 6c 73 5a 53 64 64 4b 53 6c 37 5a 6d 6c 73 5a 56 39 77 64 58 52 66 59 32 39 75 64 47}
    condition:
        any of them
}

rule SHELLDETECT_r57_7_0_php
{
    strings:
        $ = {4d 6a 34 6d 62 6d 4a 7a 63 44 73 69 4c 69 52 32 59 57 78 31 5a 58 4d 75 49 69 5a 75 59 6e 4e 77 4f 7a 77 76 5a 6d 39 75 64 44 34 38 4c 33 52 6b 50 6a 77 76 64 48 49 2b 49 6a 73 4e 43 69 41 67}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_14_0_php
{
    strings:
        $ = {63 34 59 30 4a 47 4c 33 6b 69 4c 43 4a 6d 55 57 35 46 65 46 5a 43 4f 43 74 45 4e 56 64 45 4e 58 6f 34 55 6d 38 69 4c 43 4a 32 56 6a 63 34 4f 44 6c 6b 5a 6d 64 52 61 6c 46 71 61 57 68 43 4c 7a}
    condition:
        any of them
}

rule SHELLDETECT_webshell_1_0_php
{
    strings:
        $ = {4e 7a 51 30 4c 44 4d 77 4c 44 4d 34 4e 7a 45 73 4d 6a 59 73 4d 7a 49 34 4d 79 77 31 4d 79 77 79 4e 44 67 31 4c 44 55 30 4c 44 6b 31 4e 44 6b 73 4e 54 55 73 4f 44 51 34 4d 79 77 31 4f 53 77 79}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_17_0_php
{
    strings:
        $ = {41 6f 67 59 58 4a 79 59 58 6b 6f 49 6a 78 69 50 6c 74 54 55 55 78 64 50 43 39 69 50 69 49 73 4a 48 4e 31 63 6d 77 75 49 6d 46 6a 64 44 31 7a 63 57 77 6d 5a 44 30 6c 5a 43 49 70 4c 41 6f 67 59}
    condition:
        any of them
}

rule SHELLDETECT_c99_10_0_php
{
    strings:
        $ = {49 43 52 73 61 57 35 6c 4b 51 30 4b 49 43 41 67 65 77 30 4b 49 43 41 67 49 47 6c 6d 49 43 67 68 5a 57 31 77 64 48 6b 6f 4a 47 78 70 62 6d 55 70 4b 51 30 4b 65 77 30 4b 5a 57 4e 6f 62 79 41 69}
    condition:
        any of them
}

rule SHELLDETECT_mrtiger_0_0_php
{
    strings:
        $ = {35 51 32 64 76 5a 32 46 58 57 57 39 4b 52 6a 6c 52 56 44 46 4f 56 56 64 35 5a 47 31 69 4d 30 70 30 57 44 4a 47 61 6d 52 48 62 48 5a 69 61 57 52 6b 53 55 51 77 4f 55 6c 45 52 57 64 4c 55 57 39}
    condition:
        any of them
}

rule SHELLDETECT_empo_0_0_php
{
    strings:
        $ = {55 74 6b 64 6d 70 58 56 44 55 32 52 32 34 72 56 32 4a 4a 56 6b 56 36 55 55 70 73 4a 79 77 6e 62 33 59 35 64 6b 35 69 55 32 5a 35 4d 45 31 35 5a 6e 46 56 56 58 51 32 64 48 42 47 53 79 63 73 4a}
    condition:
        any of them
}

rule SHELLDETECT_cmd_25_0_php
{
    strings:
        $ = {56 68 4f 62 45 35 71 55 6d 5a 61 52 31 5a 71 59 6a 4a 53 62 45 74 44 55 6d 5a 56 52 54 6c 55 56 6b 5a 7a 61 56 6b 79 4f 57 74 61 55 30 70 6b 53 31 4e 72 4e 30 4e 75 4d 44 30 6e 4f 79 41 4b 49}
    condition:
        any of them
}

rule SHELLDETECT_c99_14_0_php
{
    strings:
        $ = {4c 56 57 74 79 53 6a 6c 43 62 58 42 32 63 45 6f 7a 62 57 67 76 4d 6d 35 34 4f 45 5a 73 4d 47 59 31 59 6c 52 47 4f 48 67 76 65 58 63 77 63 45 74 58 55 6c 4a 44 62 79 74 6d 5a 6c 56 52 64 47 56}
    condition:
        any of them
}

rule SHELLDETECT_filesman_26_0_php
{
    strings:
        $ = {70 4f 55 6a 42 6f 4e 44 52 4d 64 44 49 30 54 44 46 76 59 57 77 77 63 57 49 76 5a 44 51 30 63 56 4e 6f 63 57 77 30 4d 30 35 50 56 57 35 75 4d 6e 51 79 55 58 64 45 5a 6b 56 72 5a 48 46 78 55 6a}
    condition:
        any of them
}

rule SHELLDETECT_wso_2_0_php
{
    strings:
        $ = {39 42 52 69 39 45 64 33 5a 5a 61 6a 51 32 51 57 6f 34 62 30 52 4a 53 55 4e 4f 52 56 42 73 54 6d 4e 46 55 57 74 4c 52 30 46 47 5a 55 35 35 57 6c 70 6f 5a 45 59 33 51 6e 70 61 55 6c 68 33 59 6a}
    condition:
        any of them
}

rule SHELLDETECT_configspy_0_0_php
{
    strings:
        $ = {69 49 70 4b 53 42 37 49 41 30 4b 49 43 41 67 49 43 41 67 49 47 6c 6d 49 43 68 70 63 31 39 79 5a 57 46 6b 59 57 4a 73 5a 53 67 6b 5a 47 6c 79 65 69 6b 70 49 48 73 67 44 51 6f 67 49 43 41 67 49}
    condition:
        any of them
}

rule SHELLDETECT_ironshell_3_0_php
{
    strings:
        $ = {32 56 34 5a 57 4e 31 64 47 6c 76 62 6c 39 74 5a 58 52 6f 62 32 51 6f 4b 51 70 37 43 69 41 67 49 43 42 70 5a 69 68 6d 64 57 35 6a 64 47 6c 76 62 6c 39 6c 65 47 6c 7a 64 48 4d 6f 4a 33 42 68 63}
    condition:
        any of them
}

rule SHELLDETECT_joomla_spam_0_1_php
{
    strings:
        $ = {73 65 44 52 4e 56 31 59 32 57 57 78 34 4e 45 31 55 56 6d 4e 6c 52 45 45 78 57 45 68 6e 64 31 6c 57 65 44 52 4e 56 31 4a 6a 5a 55 52 52 64 31 5a 57 65 44 52 4e 56 46 6b 7a 56 56 5a 6f 59 32 56}
    condition:
        any of them
}

rule SHELLDETECT_cmd_11_0_php
{
    strings:
        $ = {50 44 39 77 61 48 41 4b 4c 79 70 6c 59 7a 41 78 4f 54 4a 69 4d 32 46 6c 4e 6a 6b 79 4e 44 45 77 4f 44 6c 6d 4e 47 49 32 59 6d 51 31 5a 44 59 34 4e 44 67 30 4e 43 6f 76 61 57 59 6f 61 58 4e 7a}
    condition:
        any of them
}

rule SHELLDETECT_dxshell_0_0_php
{
    strings:
        $ = {43 63 73 49 43 52 30 61 47 56 7a 5a 54 30 6e 4a 79 6b 67 4c 79 6f 67 52 58 46 31 59 57 77 67 64 47 38 67 52 48 68 56 55 6b 77 6f 4b 53 77 67 59 6e 56 30 49 48 42 79 61 57 35 30 63 79 42 76 64}
    condition:
        any of them
}

rule SHELLDETECT_v0ld3m0r_1_0_php
{
    strings:
        $ = {56 46 55 4d 55 35 56 56 33 6c 6b 64 30 31 70 5a 47 52 4d 51 30 46 72 5a 45 64 57 64 47 4e 44 61 33 42 6c 64 7a 42 4c 51 31 46 72 53 6b 4e 58 56 6d 70 68 52 7a 68 6e 55 55 64 61 63 47 4a 48 56}
    condition:
        any of them
}

rule SHELLDETECT_safemode_5_0_php
{
    strings:
        $ = {5a 57 51 67 58 43 49 6b 5a 6d 6c 73 5a 56 77 69 50 47 4a 79 50 69 49 37 44 51 6f 67 49 43 41 67 49 43 41 67 49 43 42 39 44 51 6f 67 49 43 41 67 49 43 41 67 49 47 56 6a 61 47 38 67 49 6a 78 6d}
    condition:
        any of them
}

rule SHELLDETECT_FaTaLisTiCz_3_0_php
{
    strings:
        $ = {5a 69 68 6d 64 57 35 6a 64 47 6c 76 62 6c 39 6c 65 47 6c 7a 64 48 4d 6f 4a 33 4e 35 63 33 52 6c 62 53 63 70 4b 53 42 37 44 51 6f 67 49 43 41 67 49 43 42 41 62 32 4a 66 63 33 52 68 63 6e 51 6f}
    condition:
        any of them
}

rule SHELLDETECT_noname_0_0_php
{
    strings:
        $ = {53 69 63 73 4a 31 4a 6a 51 57 34 78 53 30 68 69 52 6d 56 7a 4f 47 46 6b 65 58 56 49 4f 53 63 73 4a 30 68 6f 56 69 38 31 59 6b 4a 46 5a 46 5a 48 4e 54 42 7a 56 33 4e 6c 61 79 63 73 4a 7a 4d 31}
    condition:
        any of them
}

rule SHELLDETECT_jspwebshell_1_0_java
{
    strings:
        $ = {46 75 50 53 49 7a 49 6a 34 6d 62 6d 4a 7a 63 44 73 38 4a 54 31 6c 62 6e 59 75 63 58 56 6c 63 6e 6c 49 59 58 4e 6f 64 47 46 69 62 47 55 6f 49 6d 39 7a 4c 6d 35 68 62 57 55 69 4b 53 55 2b 49 44}
    condition:
        any of them
}

rule SHELLDETECT_webadmin_5_2_php
{
    strings:
        $ = {48 30 4e 43 69 35 73 61 58 4e 30 61 57 35 6e 49 48 52 6f 4c 6e 42 6c 63 6d 31 70 63 33 4e 70 62 32 34 67 65 79 42 30 5a 58 68 30 4c 57 46 73 61 57 64 75 4f 69 42 73 5a 57 5a 30 49 48 30 4e 43}
    condition:
        any of them
}

rule SHELLDETECT_wso_8_0_php
{
    strings:
        $ = {71 4f 47 35 54 53 30 68 58 4e 7a 64 71 53 55 56 4f 63 6b 52 53 5a 6d 74 46 4f 55 39 72 5a 57 46 6c 55 54 68 77 56 56 52 4a 64 46 42 33 62 45 56 4f 55 48 46 6f 53 58 42 56 61 6d 77 32 54 31 6c}
    condition:
        any of them
}

rule SHELLDETECT_us3rspl_0_0_pl
{
    strings:
        $ = {31 77 4f 79 42 56 63 32 56 79 63 79 41 38 4c 33 41 2b 44 51 6f 38 63 43 42 6a 62 47 46 7a 63 7a 30 69 63 33 52 35 62 47 55 78 49 6a 35 43 65 58 42 68 63 33 4d 38 4c 33 41 2b 44 51 6f 38 63 43}
    condition:
        any of them
}

rule SHELLDETECT_shell_uploader_0_0_php
{
    strings:
        $ = {2b 49 47 6c 75 5a 47 56 34 4c 6e 42 6f 63 43 63 70 4f 77 30 4b 51 47 56 34 5a 57 4d 6f 4a 32 5a 6c 64 47 4e 6f 49 43 31 76 49 47 6c 75 5a 47 56 34 4c 6e 42 6f 63 43 42 6f 64 48 52 77 4f 69 38 76 61 47 4a 69 59 69 35 6a 62 32 30 75 59 58 55 76 4c 69 34 75 4c 32 6c 75 4c 6e 52 34 64 43 63 70 4f 77 30 4b 51 47 56 34 5a 57 4d 6f 4a 30 64 46 56 43 42 6f 64 48 52 77 4f 69 38 76 61 47 4a 69 59 69 35 6a 62 32 30 75 59 58 55 76 4c 69 34 75 4c 32 6c 75 4c 6e 52}
    condition:
        any of them
}

rule SHELLDETECT_m1n1shell_0_0_php
{
    strings:
        $ = {47 6c 76 62 6a 30 69 50 33 6b 39 50 44 39 77 61 48 41 67 5a 57 4e 6f 62 79 41 6b 63 48 64 6b 4f 79 41 2f 50 69 5a 68 62 58 41 37 65 44 31 31 63 47 78 76 59 57 51 69 49 47 56 75 59 33 52 35 63}
    condition:
        any of them
}

rule SHELLDETECT_shell_uploader_14_0_php
{
    strings:
        $ = {4c 56 55 4a 73 5a 55 64 57 61 6b 74 44 55 6d 70 69 56 31 46 77 54 33 64 76 53 6c 70 58 65 48 70 61 56 32 78 74 53 30 64 61 4d 57 4a 74 54 6a 42 68 56 7a 6c 31 57 44 4a 57 4e 47 46 59 54 6a 42}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_20_0_php
{
    strings:
        $ = {7a 53 47 6c 31 53 31 68 4e 4d 31 6c 69 61 30 55 31 62 33 6c 68 63 47 52 75 64 45 6c 5a 4f 53 74 71 62 6b 56 42 54 6e 5a 48 62 7a 46 70 62 6d 78 44 54 58 70 6b 5a 69 73 32 63 33 42 70 55 55 35}
    condition:
        any of them
}

rule SHELLDETECT_r57_5_0_php
{
    strings:
        $ = {7a 38 2f 50 7a 38 6e 4c 41 6f 6e 63 6e 56 66 64 47 56 34 64 44 59 6e 49 44 30 2b 4a 7a 38 2f 50 7a 38 2f 50 7a 38 2f 50 79 41 2f 50 7a 38 2f 4a 79 77 4b 4a 33 4a 31 58 33 52 6c 65 48 51 33 4a}
    condition:
        any of them
}

rule SHELLDETECT_cpanel_0_0_php
{
    strings:
        $ = {5a 69 42 75 59 57 31 6c 50 53 4a 34 63 43 49 2b 44 51 6f 4e 43 67 30 4b 50 44 39 77 61 48 41 4e 43 67 30 4b 44 51 6f 67 49 43 41 67 49 43 42 70 5a 69 41 6f 4a 46 39 48 52 56 52 62 4a 33 56 7a}
    condition:
        any of them
}

rule SHELLDETECT_cpanel_1_0_php
{
    strings:
        $ = {49 67 64 6d 46 73 64 57 55 39 49 69 63 75 61 48 52 74 62 48 4e 77 5a 57 4e 70 59 57 78 6a 61 47 46 79 63 79 67 6b 5a 6d 6c 73 5a 53 6b 75 4a 79 49 2b 50 47 6c 75 63 48 56 30 49 48 52 35 63 47}
    condition:
        any of them
}

rule SHELLDETECT_jackal_2_0_php
{
    strings:
        $ = {6d 68 73 61 57 35 4c 4b 43 4a 7a 5a 55 4d 39 61 47 56 34 4a 6d 5a 70 62 45 55 39 4a 47 5a 75 4a 6e 64 76 63 6d 74 70 62 6d 64 6b 61 56 49 39 4a 47 4e 33 5a 43 49 70 4c 69 4a 63 49 6a 35 49 5a}
    condition:
        any of them
}

rule SHELLDETECT_filesman_11_0_php
{
    strings:
        $ = {4e 6d 4a 6a 59 57 49 30 4e 54 4d 79 5a 57 49 34 4e 54 52 6c 49 41 30 4b 4a 47 4e 76 62 47 39 79 49 44 30 67 49 69 4d 77 4d 45 5a 47 4e 6a 59 69 4f 77 6b 76 4c 30 4e 76 62 47 39 31 63 67 30 4b}
    condition:
        any of them
}

rule SHELLDETECT_ipays777_0_0_php
{
    strings:
        $ = {36 49 45 5a 42 54 46 4e 46 4f 79 42 39 44 51 70 6d 64 57 35 6a 64 47 6c 76 62 69 42 6e 5a 58 52 6b 61 58 4e 6d 64 57 35 6a 4b 43 6b 67 65 79 41 6b 63 6d 56 36 49 44 30 67 5a 58 68 77 62 47 39}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_24_0_php
{
    strings:
        $ = {48 64 6b 57 6a 52 46 4c 31 6c 76 65 46 55 77 63 6d 39 51 55 46 68 6a 52 30 52 47 63 33 46 45 61 47 4a 69 55 57 70 53 5a 56 46 69 53 57 35 73 4b 30 52 7a 61 6e 4a 47 5a 56 41 79 4d 53 74 71 56}
    condition:
        any of them
}

rule SHELLDETECT_symlink_0_0_php
{
    strings:
        $ = {7a 49 48 64 70 64 47 67 67 64 58 4e 6c 63 6a 6f 67 33 73 66 47 34 2b 55 67 78 2b 48 6a 35 73 66 65 32 69 44 6a 32 69 44 48 30 2b 4d 67 37 65 62 53 30 63 66 4b 35 63 63 38 4c 32 5a 76 62 6e 51}
    condition:
        any of them
}

rule SHELLDETECT_mysql_9_0_php
{
    strings:
        $ = {6c 78 75 49 6a 73 4e 43 67 6b 4a 5a 57 4e 6f 62 79 41 69 50 43 39 30 63 6a 35 63 62 69 49 37 44 51 6f 4a 66 51 30 4b 44 51 6f 4a 5a 57 4e 6f 62 79 41 69 50 43 39 30 59 57 4a 73 5a 54 34 69 4f}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_25_0_php
{
    strings:
        $ = {68 30 57 46 67 79 63 6c 46 75 5a 6c 42 58 63 56 5a 61 4d 47 56 7a 53 47 6c 74 52 48 49 79 5a 47 74 74 4b 7a 56 33 59 6d 70 75 61 6a 4a 71 55 6e 70 76 52 6d 4a 61 55 6e 6c 4d 61 6b 56 73 51 32}
    condition:
        any of them
}

rule SHELLDETECT_wso_18_0_php
{
    strings:
        $ = {54 58 42 50 64 7a 30 39 49 6a 73 67 44 51 70 6c 64 6d 46 73 4b 47 4a 68 63 32 55 32 4e 46 39 6b 5a 57 4e 76 5a 47 55 6f 4a 47 6c 75 61 6d 4a 31 5a 6d 59 70 4b 54 73 4e 43 69 38 71 49 47 4e 35}
    condition:
        any of them
}

rule SHELLDETECT_constance_0_0_php
{
    strings:
        $ = {4e 47 52 6b 5a 47 52 6b 59 69 49 47 39 75 51 32 78 70 59 32 73 39 49 6d 52 76 59 33 56 74 5a 57 35 30 4c 6d 64 6c 64 45 56 73 5a 57 31 6c 62 6e 52 43 65 55 6c 6b 4b 43 64 30 59 32 39 73 62 33}
    condition:
        any of them
}

rule SHELLDETECT_nixshell_0_0_php
{
    strings:
        $ = {37 65 34 36 50 47 4a 79 50 6a 78 30 5a 58 68 30 59 58 4a 6c 59 53 42 79 62 33 64 7a 50 54 67 67 59 32 39 73 63 7a 30 34 4d 44 34 69 4c 6d 4a 68 63 32 55 32 4e 46 39 6c 62 6d 4e 76 5a 47 55 6f}
    condition:
        any of them
}

rule SHELLDETECT_r57_1_0_php
{
    strings:
        $ = {49 47 39 31 64 48 4e 6c 64 44 73 4b 51 6b 39 53 52 45 56 53 4c 55 78 46 52 6c 51 36 49 43 41 67 49 7a 6b 33 51 7a 49 35 4e 69 41 78 63 48 67 67 62 33 56 30 63 32 56 30 4f 77 70 43 54 31 4a 45}
    condition:
        any of them
}

rule SHELLDETECT_efso2_0_0_asp
{
    strings:
        $ = {6a 51 43 5a 2b 4c 46 42 51 4e 6b 64 45 4c 47 73 6e 4f 48 35 50 56 79 77 36 62 54 5a 41 49 30 41 6d 66 6e 34 73 55 48 35 51 4c 48 35 34 62 54 70 75 65 45 73 30 54 47 6b 79 58 6c 64 44 54 6d 4e}
    condition:
        any of them
}

rule SHELLDETECT_phpfilemanager_5_0_php
{
    strings:
        $ = {31 4e 46 55 6c 5a 46 55 6c 73 6e 52 45 39 44 56 55 31 46 54 6c 52 66 55 6b 39 50 56 43 64 64 49 44 30 67 63 33 52 79 58 33 4a 6c 63 47 78 68 59 32 55 6f 49 43 64 63 58 43 63 73 49 43 63 76 4a}
    condition:
        any of them
}

rule SHELLDETECT_al_marhum_1_0_php
{
    strings:
        $ = {56 31 6b 30 5a 6c 52 31 51 6b 39 53 63 32 39 61 62 30 38 79 54 7a 42 59 64 57 55 72 51 56 42 33 54 6b 5a 58 5a 58 52 43 54 55 35 57 54 57 35 44 4b 30 64 73 52 47 6c 68 52 30 46 6b 5a 57 46 4c}
    condition:
        any of them
}

rule SHELLDETECT_filesman_18_0_php
{
    strings:
        $ = {32 61 6c 46 47 64 54 6b 33 61 31 59 30 53 54 52 61 62 6b 31 74 54 57 74 78 51 6a 64 43 65 6d 52 33 56 6d 39 44 62 6c 4e 5a 56 47 64 45 54 54 68 5a 4e 30 4e 6d 56 48 6c 69 55 56 4e 6c 4d 30 64}
    condition:
        any of them
}

rule SHELLDETECT_teamps_0_0_php
{
    strings:
        $ = {58 4a 79 62 33 49 6f 49 6b 35 76 49 47 4e 76 62 6d 5a 70 5a 33 56 79 59 58 52 70 62 32 34 67 5a 6d 6c 73 5a 58 4d 67 5a 6d 39 31 62 6d 51 68 49 69 6b 37 43 69 41 67 49 43 42 39 49 47 56 73 63}
    condition:
        any of them
}

rule SHELLDETECT_remoteview_2_0_php
{
    strings:
        $ = {77 41 2f 41 44 38 41 50 77 41 67 41 44 38 41 50 77 41 2f 41 44 38 41 50 77 41 2f 41 44 38 41 50 77 41 2f 41 44 38 41 50 77 41 67 41 43 63 41 49 77 41 6e 41 43 6b 41 49 67 41 73 41 41 41 4e 43}
    condition:
        any of them
}

rule SHELLDETECT_elmaliseker_1_0_vbs
{
    strings:
        $ = {31 5a 54 30 7a 4d 6a 35 42 63 6d 4e 6f 61 58 5a 6c 49 69 6b 4b 63 6d 56 7a 63 47 39 75 63 32 55 75 64 33 4a 70 64 47 55 6f 49 6a 78 69 63 6a 34 38 61 57 35 77 64 58 51 67 64 48 6c 77 5a 54 31}
    condition:
        any of them
}

rule SHELLDETECT_webshell_2_0_php
{
    strings:
        $ = {32 35 73 62 32 46 6b 58 43 49 2b 50 43 39 6d 62 33 4a 74 50 6a 77 76 5a 47 6c 32 50 69 49 37 43 67 6f 4b 43 6d 56 6a 61 47 38 67 49 6a 78 6b 61 58 59 2b 50 45 5a 50 55 6b 30 67 62 57 56 30 61}
    condition:
        any of them
}

rule SHELLDETECT_simple_shell_0_0_php
{
    strings:
        $ = {63 45 39 35 51 6d 78 5a 4d 6d 68 32 53 55 4e 6a 4f 45 77 7a 55 6d 78 6c 53 46 4a 6f 59 32 31 57 61 46 42 70 59 7a 64 6d 55 54 42 4c 57 6c 64 4f 62 32 4a 35 51 57 35 51 52 31 70 32 59 32 30 77}
    condition:
        any of them
}

rule SHELLDETECT_safemode_0_0_php
{
    strings:
        $ = {6e 70 73 61 57 49 36 4c 79 38 69 4c 69 52 6d 61 57 78 6c 4c 43 41 6b 64 47 56 74 63 43 6b 70 65 77 6f 6b 65 6e 4a 76 5a 47 78 76 49 44 30 67 5a 6d 39 77 5a 57 34 6f 4a 48 52 6c 62 58 41 73 49}
    condition:
        any of them
}

rule SHELLDETECT_sempak_0_0_php
{
    strings:
        $ = {42 6a 62 54 56 4f 54 54 46 42 64 6c 4a 72 53 6c 64 68 53 45 70 52 44 51 70 55 65 6d 78 7a 54 6d 74 73 4d 47 49 7a 62 44 42 4e 53 47 78 76 57 6a 4a 7a 63 6c 64 49 61 33 5a 57 4d 47 52 33 54 6b}
    condition:
        any of them
}

rule SHELLDETECT_shell_uploader_2_0_php
{
    strings:
        $ = {4e 45 61 46 70 42 63 6c 4a 70 53 6a 4d 76 4b 30 39 53 52 57 59 30 4b 32 31 51 61 6a 51 78 57 45 56 69 4e 6b 55 78 54 6a 56 76 54 33 5a 6d 63 46 6f 78 61 6a 46 74 55 32 34 31 62 48 70 32 56 6c}
    condition:
        any of them
}

rule SHELLDETECT_powerdreamshell_0_0_asp
{
    strings:
        $ = {43 69 41 67 49 43 41 6c 50 69 41 38 4c 32 5a 76 62 6e 51 2b 50 43 39 6b 61 58 59 2b 43 69 41 67 49 43 41 67 49 44 77 76 64 47 51 2b 43 69 41 67 49 43 41 38 4c 33 52 79 50 67 6f 67 49 43 41 67}
    condition:
        any of them
}

rule SHELLDETECT_networkfilemanager_0_0_php
{
    strings:
        $ = {49 6c 56 75 59 58 4e 7a 61 57 64 75 5a 57 51 69 4f 77 6f 4b 4a 48 42 76 63 6e 52 62 4e 6a 46 64 49 44 30 67 49 6b 35 4a 49 45 31 42 53 55 77 69 4f 77 6f 4b 4a 48 42 76 63 6e 52 62 4e 6a 4a 64}
    condition:
        any of them
}

rule SHELLDETECT_r57_12_0_php
{
    strings:
        $ = {71 63 55 70 59 52 56 4a 33 56 31 4a 7a 61 54 4a 35 63 33 56 4d 56 30 45 78 64 46 68 78 62 58 64 4e 4d 6d 78 47 61 45 52 56 4f 57 64 72 63 57 6c 68 52 48 4e 75 62 45 6f 33 64 45 78 47 59 6a 4a}
    condition:
        any of them
}

rule SHELLDETECT_cmd_13_0_php
{
    strings:
        $ = {5a 6a 4e 6d 6d 54 4e 6d 7a 44 4e 6d 2f 7a 4f 5a 41 44 4f 5a 4d 7a 4f 5a 5a 6a 4f 5a 6d 54 4f 5a 7a 44 4f 5a 2f 7a 50 4d 41 44 50 4d 4d 7a 50 4d 5a 6a 50 4d 6d 54 50 4d 7a 44 50 4d 2f 7a 50 2f 41 44 50 2f 4d 7a 50 2f 5a 6a 50 2f 6d 54 50 2f 7a 44 50 2f 2f 32 59 41 41 47 59 41 4d 32 59 41 5a 6d 59 41 6d 57 59 41 7a 47 59 41 2f 32 59 7a 41 47 59 7a 4d 32 59 7a 5a 6d 59 7a 6d 57 59 7a 7a 47 59 7a 2f 32 5a 6d 41 47 5a 6d 4d 32 5a 6d 5a 6d 5a 6d 6d 57 5a 6d 7a 47 5a 6d 2f 32 61 5a 41 47 61 5a 4d 32 61 5a 5a 6d 61 5a 6d 57 61 5a 7a 47 61 5a 2f 32 62 4d 41 47 62 4d 4d 32 62 4d 5a 6d}
    condition:
        any of them
}

rule SHELLDETECT_cgitelnet_0_0_pl
{
    strings:
        $ = {75 4a 33 51 67 63 32 56 30 49 48 52 6f 61 58 4d 67 64 47 38 67 59 53 42 32 5a 58 4a 35 49 47 78 68 63 6d 64 6c 49 48 5a 68 62 48 56 6c 4c 69 42 55 61 47 6c 7a 49 47 6c 7a 44 51 30 4b 43 51 6b}
    condition:
        any of them
}

rule SHELLDETECT_filesman_6_0_php
{
    strings:
        $ = {57 78 30 59 69 39 6c 64 6e 5a 75 62 58 46 75 4e 48 51 76 4f 55 52 46 4e 48 41 77 64 6d 52 59 4c 33 5a 30 61 30 31 32 4d 53 39 77 56 69 42 6c 49 43 49 75 49 6e 67 69 4c 69 49 72 49 69 34 69 65}
    condition:
        any of them
}

rule SHELLDETECT_snipershell_2_0_php
{
    strings:
        $ = {51 78 4d 44 63 6e 50 54 34 6e 78 2b 48 6a 35 74 62 6d 32 69 63 73 44 51 6f 6e 5a 57 35 6e 58 32 4a 31 64 48 51 78 4e 53 63 39 50 69 66 46 30 64 50 48 34 53 63 73 44 51 6f 6e 5a 57 35 6e 58 33}
    condition:
        any of them
}

rule SHELLDETECT_gammashell_0_0_pl
{
    strings:
        $ = {6b 59 37 43 69 41 67 59 6d 46 6a 61 32 64 79 62 33 56 75 5a 44 6f 67 49 30 59 77 4d 44 73 4b 66 51 6f 4b 4c 6d 56 75 64 48 4a 70 5a 58 4d 67 65 77 6f 67 49 47 4a 76 63 6d 52 6c 63 6a 6f 67 4d}
    condition:
        any of them
}

rule SHELLDETECT_shell_uploader_7_0_php
{
    strings:
        $ = {48 68 30 4a 79 6b 37 44 51 70 6c 65 47 56 6a 4b 43 64 6a 5a 43 41 76 64 47 31 77 4f 30 64 46 56 43 42 6f 64 48 52 77 4f 69 38 76 62 47 56 30 64 47 39 79 5a 53 35 77 62 43 39 6d 61 57 78 6c 4c}
    condition:
        any of them
}

rule SHELLDETECT_variables_0_0_asp
{
    strings:
        $ = {6c 68 59 6d 78 6c 49 45 35 68 62 57 55 38 4c 30 49 2b 50 43 39 6d 62 32 35 30 50 6a 77 76 63 44 34 4b 49 43 41 67 49 43 41 67 50 43 39 55 52 44 34 4b 49 43 41 67 49 44 78 55 52 43 42 33 61 57}
    condition:
        any of them
}

rule SHELLDETECT_nccshell_0_0_php
{
    strings:
        $ = {47 78 76 59 57 52 6c 5a 46 39 6d 61 57 78 6c 4b 43 52 66 52 6b 6c 4d 52 56 4e 62 4a 33 42 79 62 32 4a 6c 4a 31 31 62 4a 33 52 74 63 46 39 75 59 57 31 6c 4a 31 30 73 49 43 49 75 4c 32 52 70 62}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_6_0_php
{
    strings:
        $ = {6b 74 4d 54 73 4b 49 43 41 67 4a 47 56 34 64 43 41 39 49 43 52 6c 65 48 52 62 4a 47 4e 64 4f 77 6f 67 49 43 41 6b 5a 58 68 30 49 44 30 67 63 33 52 79 64 47 39 73 62 33 64 6c 63 69 67 6b 5a 58}
    condition:
        any of them
}

rule SHELLDETECT_shell_uploader_3_0_php
{
    strings:
        $ = {54 47 68 57 54 32 70 47 49 69 77 69 5a 45 39 6a 5a 6c 46 70 59 32 4e 49 59 30 59 35 4d 54 5a 76 4f 58 4e 49 4f 47 64 4b 62 6e 67 78 54 6d 4e 53 5a 57 4e 78 56 7a 4a 76 63 58 4d 76 55 58 6c 48}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_28_0_php
{
    strings:
        $ = {30 56 53 56 6b 56 53 57 79 64 49 56 46 52 51 58 30 68 50 55 31 51 6e 58 53 34 69 4c 31 77 69 50 6d 68 30 64 48 41 36 4c 79 38 69 4c 6b 41 6b 58 31 4e 46 55 6c 5a 46 55 6c 73 6e 53 46 52 55 55}
    condition:
        any of them
}

rule SHELLDETECT_sincap_0_0_php
{
    strings:
        $ = {59 6d 39 30 64 47 39 74 62 57 46 79 5a 32 6c 75 50 53 49 77 49 69 42 74 59 58 4a 6e 61 57 35 33 61 57 52 30 61 44 30 69 4d 43 49 67 62 57 46 79 5a 32 6c 75 61 47 56 70 5a 32 68 30 50 53 49 77}
    condition:
        any of them
}

rule SHELLDETECT_cgi_python_0_0_py
{
    strings:
        $ = {49 43 41 67 49 43 41 67 64 48 4a 35 4f 67 6f 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 42 6a 61 47 6c 73 5a 46 39 7a 64 47 52 70 62 69 77 67 59 32 68 70 62 47 52 66 63 33 52 6b 62 33 56 30}
    condition:
        any of them
}

rule SHELLDETECT_cmd_6_0_php
{
    strings:
        $ = {48 4f 47 6c 68 55 33 70 30 61 48 4a 58 65 6d 68 55 53 6e 55 34 63 32 6b 31 53 57 6b 33 4f 44 55 72 64 6e 5a 72 53 6c 6c 4d 62 32 56 31 4f 47 4a 79 64 6b 74 6f 5a 7a 46 69 5a 56 46 4e 56 54 4e}
    condition:
        any of them
}

rule SHELLDETECT_configspy_4_0_php
{
    strings:
        $ = {5a 55 55 48 6f 79 51 58 52 4b 56 48 42 6b 54 56 46 54 55 31 4e 6c 52 7a 68 36 51 7a 56 79 61 47 68 51 64 30 39 74 64 33 45 31 61 79 74 6f 56 48 52 70 57 57 46 51 56 45 78 42 53 58 64 58 53 32}
    condition:
        any of them
}

rule SHELLDETECT_cmd_17_0_aspx
{
    strings:
        $ = {5a 79 42 7a 49 44 30 67 63 33 52 74 63 6d 52 79 4c 6c 4a 6c 59 57 52 55 62 30 56 75 5a 43 67 70 4f 77 30 4b 63 33 52 74 63 6d 52 79 4c 6b 4e 73 62 33 4e 6c 4b 43 6b 37 44 51 70 79 5a 58 52 31}
    condition:
        any of them
}

rule SHELLDETECT_wordpress_exploit_0_0_php
{
    strings:
        $ = {32 56 37 49 48 56 75 63 32 56 30 4b 43 52 76 57 48 6c 68 63 57 31 49 62 30 4e 6f 64 6b 68 52 52 6b 4e 32 56 47 78 31 63 57 31 42 51 31 73 6e 61 57 35 6d 62 79 64 64 57 79 64 6d 59 57 6c 73 4a}
    condition:
        any of them
}

rule SHELLDETECT_qReyFuRt_0_0_aspx
{
    strings:
        $ = {4e 7a 59 57 64 6c 4b 54 73 4b 66 51 70 72 63 6b 6c 53 4b 45 46 59 55 32 4a 69 4c 6c 5a 68 62 48 56 6c 4b 54 73 4b 66 51 70 77 64 57 4a 73 61 57 4d 67 64 6d 39 70 5a 43 42 6e 54 45 74 6a 4b 48}
    condition:
        any of them
}

rule SHELLDETECT_simattacker_0_0_php
{
    strings:
        $ = {43 49 38 5a 6d 39 75 64 43 42 7a 61 58 70 6c 50 53 63 78 4a 79 42 6a 62 32 78 76 63 6a 30 6e 49 7a 6b 35 4f 54 6b 35 4f 53 63 2b 52 47 39 75 64 43 42 70 62 69 42 33 61 57 35 6b 62 33 64 7a 49}
    condition:
        any of them
}

rule SHELLDETECT_c99_28_0_php
{
    strings:
        $ = {57 39 74 65 6d 5a 32 53 6d 70 78 56 6c 5a 46 5a 33 52 31 5a 32 31 45 65 55 45 77 59 6d 31 43 57 44 46 77 55 56 4e 42 4f 55 6c 45 61 6e 45 34 62 30 68 74 65 56 70 33 54 54 6c 6e 63 32 4a 6e 56}
    condition:
        any of them
}

rule SHELLDETECT_mysql_8_0_php
{
    strings:
        $ = {59 57 4a 73 5a 58 4d 6f 49 43 52 6b 59 6d 35 68 62 57 55 67 4b 54 73 4e 43 67 30 4b 43 57 6c 6d 4b 43 41 6b 63 46 52 68 59 6d 78 6c 49 44 30 39 49 44 41 67 4b 53 42 37 44 51 6f 4a 43 53 52 74}
    condition:
        any of them
}

rule SHELLDETECT_tryag_0_0_php
{
    strings:
        $ = {4f 56 43 42 44 54 30 78 50 55 6a 31 53 52 55 51 2b 59 32 31 6b 4f 6a 77 76 52 6b 39 4f 56 44 34 6e 4c 69 52 30 59 69 30 2b 62 57 46 72 5a 58 4e 6c 62 47 56 6a 64 43 68 68 63 6e 4a 68 65 53 67}
    condition:
        any of them
}

rule SHELLDETECT_fatalshell_1_0_php
{
    strings:
        $ = {41 36 49 43 52 6b 61 58 4e 6d 64 57 35 6a 50 54 41 70 4f 77 30 4b 4b 48 4e 30 63 6e 52 76 64 58 42 77 5a 58 49 6f 63 33 56 69 63 33 52 79 4b 46 42 49 55 46 39 50 55 79 77 67 4d 43 77 67 4d 79}
    condition:
        any of them
}

rule SHELLDETECT_c99_5_0_php
{
    strings:
        $ = {4e 6c 4c 6e 42 33 5a 43 49 2b 52 6d 6c 75 5a 43 42 7a 5a 58 4a 32 61 57 4e 6c 4c 6e 42 33 5a 43 42 6d 61 57 78 6c 63 79 42 70 62 69 42 6a 64 58 4a 79 5a 57 35 30 49 47 52 70 63 6d 56 6a 64 47}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_13_0_php
{
    strings:
        $ = {6b 74 50 63 6e 68 55 56 53 39 4c 55 57 56 32 55 53 49 73 49 6d 78 47 64 30 4e 6d 56 57 39 6b 63 31 59 32 65 6e 68 77 4d 30 73 30 5a 6a 42 6c 52 6c 67 76 62 48 4e 46 49 69 77 69 55 6a 46 56 59}
    condition:
        any of them
}

rule SHELLDETECT_g00nshell_0_0_php
{
    strings:
        $ = {49 79 4d 6a 49 79 4d 6a 49 79 4d 6a 49 79 4d 6a 49 79 4d 6a 49 79 4d 6a 49 79 4d 6a 49 79 4d 6a 49 77 6f 6a 4d 44 6f 67 54 6d 38 67 63 48 4a 76 64 47 56 6a 64 47 6c 76 62 6a 73 67 59 57 35 35}
    condition:
        any of them
}

rule SHELLDETECT_wacking_1_0_php
{
    strings:
        $ = {54 34 4b 50 48 52 79 50 67 6f 67 49 44 78 30 5a 43 42 33 61 57 52 30 61 44 30 69 4e 54 41 6c 49 69 42 6f 5a 57 6c 6e 61 48 51 39 49 6a 67 7a 49 69 42 32 59 57 78 70 5a 32 34 39 49 6e 52 76 63}
    condition:
        any of them
}

rule SHELLDETECT_mildnet_0_0_php
{
    strings:
        $ = {31 6c 4c 64 79 73 33 56 44 56 51 56 6e 64 4f 65 6b 68 59 55 33 46 50 61 6e 6c 31 54 44 46 6a 52 48 68 4e 65 47 63 7a 64 44 64 59 4d 32 4e 55 51 32 46 54 65 6c 64 30 56 45 46 56 53 43 38 72 5a}
    condition:
        any of them
}

rule SHELLDETECT_gnyshell_1_0_php
{
    strings:
        $ = {48 51 39 4d 53 42 32 59 57 78 70 5a 32 34 39 64 47 39 77 50 6a 78 55 51 55 4a 4d 52 53 42 6f 5a 57 6c 6e 61 48 51 39 4d 53 42 6a 5a 57 78 73 55 33 42 68 59 32 6c 75 5a 7a 30 77 49 47 4e 6c 62}
    condition:
        any of them
}

rule SHELLDETECT_FaTaLisTiCz_6_0_php
{
    strings:
        $ = {63 6d 31 7a 57 79 4a 33 49 6c 31 62 49 6e 49 69 58 54 38 69 49 47 4e 6f 5a 57 4e 72 5a 57 51 69 4f 69 49 69 4b 53 34 69 50 69 42 53 5a 57 46 6b 50 47 4a 79 50 6c 78 75 49 69 34 4e 43 69 41 67}
    condition:
        any of them
}

rule SHELLDETECT_rootshell_1_0_php
{
    strings:
        $ = {69 49 48 4e 30 65 57 78 6c 50 53 4a 6d 62 32 35 30 4c 58 4e 70 65 6d 55 36 4d 54 42 77 64 43 49 2b 50 47 49 2b 55 32 46 6d 5a 53 42 4e 62 32 52 6c 49 45 39 4f 50 43 39 69 50 6a 77 76 5a 6d 39}
    condition:
        any of them
}

rule SHELLDETECT_filesman_5_0_php
{
    strings:
        $ = {62 62 3a 58 48 67 32 4e 56 78 34 4e 7a 5a 63 65 44 59 78 58 48 67 32 51 31 78 34 4d 6a 68 63 65 44 59 33 58 48 67 33 51 56 78 34 4e 6a 6c 63 65 44 5a 46 58 48 67 32 4e 6c 78 34 4e 6b 4e 63 65 44 59 78 58 48 67 33 4e 46 78 34 4e 6a 56 63 65 44 49 34 58 48 67 32 4d 6c 78 34 4e 6a 46 63 65 44 63 7a 58 48 67 32 4e 56 78 34 4d 7a 5a 63 65 44 4d 30 58 48 67 31 52 6c 78 34 4e 6a 52 63 65 44 59 31 58 48 67 32 4d 31 78 34 4e 6b 5a 63 65 44 59 30 58 48 67 32 4e 56 78 34 4d 6a 67 6e 4e 31 67 78 63 6d 55 35 63 7a 4a 36 4c 30 52 75 4f 56 5a 6a 64 32 31 71 5a 6c 70 78 4b 31 42 5a 56 48 52 31 4e 33 4d 79 54 57 35 68 55 54 56 30 4d 6d 70 55 63 47 4e 31 5a 33 41 32 5a 56 42 4b 63 32 31 34 63 6d 74 54 4d 56 42 72 64 55 35 72 56 32 59 33 4e 30 4d 30 51 32 74 53 52 58 46 35 4e 44 4e 54 4e 7a 4d 34 54 6a 46 32 59 6e 56 6d 63 44 64 47 53 55 56 42 55 6b 70 72 51 56 4a 43 51 55 68 55 4e 33 68 53 56 6d 35 4f 53 57 78 31 61 54 52 59 54 7a 5a 6b 4e 30 70 34 4e 7a 4a 55 51 79 39 51 54 6a 4a 6b 62 55 68 36 61 6d 77 34 5a 47 4a 61 5a 6a 64 34 4d 6d 52 74 5a 44 6c 4c 53 6c 68 69 53 45 4e 30 55 46 46 44 59 6c 6c 49 65 6d 70 6e 53 31 64 5a 64 46 70 52 56 30 52 6b 52 6d 38 7a 57 48 5a 71 4c 33 64 49 53 31 42 4e 61 6b 5a 4f 64 6b 64 72 65 6e 64 34 4c 33 5a 55 62 7a 46 6b 4b 32 68 4d 4f 57 4e 78 4d 6b 31 47 4f 58 52 44 4f 57 52 6e 54 44 67 76 52 30 74 4f 5a 54 67 30 54 69 39 71 63 58 68 53 62 44 42 51 52 57 74 30 54 6a 56 32 59 55 78 72 4f 45 46 61 5a 45 56 61 56 31 70 42 4b 30 77 31 63 48 4a 4b 53 33 4e 33 5a 46 52 55 65 53 38 31 65 46 52 4f 64 6a 67 79 65 56 64 74 4d 45 6f 34 63 33 63 78 52 6e 68 4e 5a 6d 39 49 57 47 39 58 52 44 42 75 53 30 59 3d}
    condition:
        any of them
}

rule SHELLDETECT_FaTaLisTiCz_2_0_php
{
    strings:
        $ = {6d 39 31 63 44 77 76 59 6a 34 69 4f 33 30 4e 43 69 41 67 49 43 41 67 49 43 52 79 62 33 64 62 58 53 41 39 49 43 49 38 59 6a 35 51 5a 58 4a 74 63 7a 77 76 59 6a 34 69 4f 77 30 4b 49 43 41 67 49}
    condition:
        any of them
}

rule SHELLDETECT_cybershell_1_0_php
{
    strings:
        $ = {32 50 53 52 66 55 6b 56 52 56 55 56 54 56 46 73 6e 63 33 56 69 62 57 6c 30 64 69 64 64 4f 77 30 4b 4a 47 31 6c 64 47 68 76 5a 44 30 6b 58 31 4a 46 55 56 56 46 55 31 52 62 4a 32 31 6c 64 47 68}
    condition:
        any of them
}

rule SHELLDETECT_b374k_15_0_php
{
    strings:
        $ = {79 63 70 4c 6d 39 75 4b 43 64 6d 62 32 4e 31 63 79 63 73 49 47 5a 31 62 6d 4e 30 61 57 39 75 4b 47 55 70 65 77 6f 4a 43 57 46 79 5a 33 4d 67 50 53 41 6b 4b 43 63 6a 5a 58 5a 68 62 45 46 79 5a}
    condition:
        any of them
}

rule SHELLDETECT_b374k_1_0_php
{
    strings:
        $ = {52 30 64 42 4e 79 39 6f 5a 47 70 34 59 6c 6b 77 5a 57 68 43 57 6e 64 46 54 46 6c 6f 4f 54 59 77 61 55 6c 44 4e 55 74 34 53 46 68 45 51 58 42 4b 56 55 59 76 4d 48 4e 44 53 46 70 35 63 58 4a 69}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_29_0_php
{
    strings:
        $ = {6a 45 70 4c 69 49 72 4a 48 5a 69 4e 47 45 34 4f 44 51 78 4e 31 78 75 49 6a 73 67 66 53 42 39 49 47 5a 31 62 6d 4e 30 61 57 39 75 49 47 35 6c 4e 6a 59 33 5a 47 45 33 4e 69 67 6b 64 6a 6b 31 4e}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_12_0_php
{
    strings:
        $ = {53 6b 68 72 56 31 4e 50 4c 31 56 4d 4e 46 41 32 55 53 74 72 56 31 5a 69 4d 44 52 44 4d 30 52 4e 4c 30 68 33 61 6e 70 6d 4d 6b 4a 4d 54 55 78 79 62 6e 6f 30 5a 45 6c 57 63 30 6c 71 4d 69 63 73}
    condition:
        any of them
}

rule SHELLDETECT_r57_15_0_php
{
    strings:
        $ = {67 49 43 63 73 43 69 64 79 64 56 39 69 64 58 52 30 4d 79 63 67 50 54 34 6e 49 43 41 67 49 43 41 67 49 43 63 73 43 69 64 79 64 56 39 30 5a 58 68 30 4d 54 49 6e 50 54 34 6e 59 6d 46 6a 61 79 31}
    condition:
        any of them
}

rule SHELLDETECT_cbot_0_0_php
{
    strings:
        $ = {75 52 46 56 51 51 32 56 51 53 48 42 77 63 6b 35 79 61 32 67 33 4e 7a 52 4d 52 46 4a 34 52 58 5a 4d 59 6d 68 4e 56 45 59 35 57 45 70 56 64 56 42 47 61 33 70 61 53 6c 68 5a 65 56 5a 43 61 56 68}
    condition:
        any of them
}

rule SHELLDETECT_shell_uploader_19_0_php
{
    strings:
        $ = {4a 54 45 56 54 57 79 64 70 62 57 46 6e 5a 53 64 64 57 79 64 75 59 57 31 6c 4a 31 30 37 49 43 52 31 63 32 56 79 5a 6d 6c 73 5a 56 39 30 62 58 41 67 50 53 41 6b 58 30 5a 4a 54 45 56 54 57 79 64}
    condition:
        any of them
}

rule SHELLDETECT_devil_0_0_php
{
    strings:
        $ = {43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 5a 57 78 7a 5a 51 6f 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 48 73 4b 49 43 41 67 49}
    condition:
        any of them
}

rule SHELLDETECT_sroshell_0_0_php
{
    strings:
        $ = {57 46 72 4f 77 6f 4b 49 43 41 67 49 47 4e 68 63 32 55 67 49 6d 64 36 5a 47 56 6a 62 32 52 6c 49 6a 6f 4b 49 43 41 67 49 43 41 67 61 57 59 67 4b 47 6c 7a 58 32 5a 70 62 47 55 6f 4a 46 42 68 64}
    condition:
        any of them
}

rule SHELLDETECT_shell_commander_0_0_php
{
    strings:
        $ = {6d 51 32 39 79 4d 48 46 78 53 45 52 69 64 44 5a 69 4d 46 56 74 52 56 6c 34 54 6b 56 69 5a 45 4d 72 51 6e 4d 78 4f 48 52 6d 65 45 78 6b 55 31 42 34 52 55 31 53 63 57 4a 6b 51 6d 39 72 54 47 59}
    condition:
        any of them
}

rule SHELLDETECT_b374k_16_0_php
{
    strings:
        $ = {70 71 4f 45 31 46 59 55 39 5a 54 55 38 34 54 55 4a 58 4f 55 51 77 54 44 52 61 64 6b 6f 35 4d 32 31 5a 59 58 4e 6a 57 56 68 51 62 6c 56 49 59 6d 4a 57 4d 31 68 4d 52 30 49 76 65 48 4a 69 65 6b}
    condition:
        any of them
}

rule SHELLDETECT_safemode_6_0_php
{
    strings:
        $ = {70 62 6d 64 6b 61 57 35 6e 63 79 41 7a 49 69 42 7a 61 58 70 6c 50 53 49 31 49 6a 34 38 4c 32 5a 76 62 6e 51 2b 50 47 49 2b 51 6e 6c 77 59 58 4e 7a 49 46 4e 6f 5a 57 78 73 49 45 74 31 62 47 78}
    condition:
        any of them
}

rule SHELLDETECT_ajax_command_shell_0_0_php
{
    strings:
        $ = {6c 61 57 59 6f 63 33 52 79 64 47 39 73 62 33 64 6c 63 69 67 6b 59 32 31 6b 4b 53 41 39 50 53 41 69 59 57 4a 76 64 58 51 69 4b 51 6f 4a 43 58 73 4b 43 51 6b 4a 63 48 4a 70 62 6e 51 67 49 6b 46}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_27_0_php
{
    strings:
        $ = {62 62 3a 58 48 67 79 4d 46 77 31 4d 6c 78 34 4d 6d 5a 63 4e 44 42 63 65 44 59 31 58 44 45 32 4e 6c 78 34 4e 6a 46 63 4d 54 55 30 58 48 67 79 4f 46 77 78 4e 6a 4e 63 65 44 63 30 58 44 45 32 4d 6c 78 34 4e 57 5a 63 4d 54 59 79 58 48 67 32 4e 56 77 78 4e 6a 42 63 65 44 5a 6a 58 44 45 30 4d 56 78 34 4e 6a 4e 63 4d 54 51 31 58 48 67 79 4f 46 77 78 4e 44 4e 63 65 44 59 34 58 44 45 32 4d 6c 78 34 4d 6a 68 63 4e 54 41 3d}
    condition:
        any of them
}

rule SHELLDETECT_shell_uploader_18_0_php
{
    strings:
        $ = {57 62 57 52 73 55 6a 41 31 51 32 4e 72 63 7a 4a 6b 56 55 34 31 55 32 30 77 64 31 6f 79 63 46 5a 58 61 7a 46 7a 57 6b 56 34 54 45 39 47 52 6b 4a 54 4d 30 30 79 57 6d 74 77 57 47 46 48 55 6e 52}
    condition:
        any of them
}

rule SHELLDETECT_cmd_12_0_php
{
    strings:
        $ = {69 62 74 39 4e 4e 51 71 78 77 51 41 44 73 41 50 44 39 77 61 48 41 67 5a 58 5a 68 62 43 68 69 59 58 4e 6c 4e 6a 52 66 5a 47 56 6a 62 32 52 6c 4b 43 64 4a 52 31 5a 71 59 55 63 34 5a 30 6c 75 64}
    condition:
        any of them
}

rule SHELLDETECT_buckethead_0_0_php
{
    strings:
        $ = {6d 4e 74 55 6e 64 6a 62 56 5a 36 59 33 6b 31 4d 47 56 49 55 57 35 4c 56 48 4e 4f 51 32 6c 42 5a 30 6c 44 51 6e 70 6c 56 7a 46 7a 59 56 63 31 63 6b 74 44 59 33 5a 68 52 7a 6c 30 57 6c 4d 34 62}
    condition:
        any of them
}

rule SHELLDETECT_fuckphpshell_0_0_php
{
    strings:
        $ = {37 49 41 6f 67 49 43 41 67 49 43 41 67 49 47 5a 76 62 6e 51 74 5a 6d 46 74 61 57 78 35 4f 69 42 55 5a 58 4a 74 61 57 35 31 63 79 77 67 52 6d 6c 34 5a 57 52 7a 65 58 4d 73 49 45 5a 70 65 47 56}
    condition:
        any of them
}

rule SHELLDETECT_cfexec_0_0_cfm
{
    strings:
        $ = {59 32 5a 7a 59 58 5a 6c 59 32 39 75 64 47 56 75 64 44 34 4e 43 6a 78 77 63 6d 55 2b 44 51 6f 6a 62 58 6c 57 59 58 49 6a 44 51 6f 38 4c 33 42 79 5a 54 34 4e 43 6a 77 76 59 32 5a 70 5a 6a 34 4e}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_9_0_php
{
    strings:
        $ = {31 56 72 52 30 31 43 65 6d 4e 61 54 32 49 76 62 44 5a 45 4d 55 6b 6e 4c 43 64 77 55 31 67 79 4d 55 38 32 4c 33 63 33 61 6a 68 6c 56 7a 42 49 55 6d 64 4a 64 47 64 46 4d 30 4e 49 59 6b 56 4e 59}
    condition:
        any of them
}

rule SHELLDETECT_phpspy_0_0_php
{
    strings:
        $ = {6e 5a 6b 56 7a 55 77 53 30 4e 53 61 32 4a 44 61 33 56 4b 65 55 4a 36 5a 46 64 4f 61 6c 70 59 54 6e 70 4a 51 32 4e 31 53 6b 68 4f 4d 56 6b 79 54 58 56 4b 65 55 4a 74 57 56 64 73 63 30 6c 44 59}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_0_0_php
{
    strings:
        $ = {41 6d 4a 69 41 6f 51 47 6c 7a 58 33 4a 6c 59 57 52 68 59 6d 78 6c 4b 43 49 6b 5a 47 6c 79 4c 79 52 6d 61 57 78 6c 49 69 6b 70 49 43 6b 4b 49 41 6b 4a 43 51 6c 6c 59 32 68 76 49 47 4a 31 61 57}
    condition:
        any of them
}

rule SHELLDETECT_ayyildiz_tim_0_0_php
{
    strings:
        $ = {43 6d 6c 6d 49 43 67 68 5a 57 31 77 64 48 6b 6f 4a 48 64 76 63 6d 74 66 5a 47 6c 79 4b 53 6b 67 65 77 6f 67 49 43 38 71 49 45 45 67 64 32 39 79 61 32 52 70 63 69 42 6f 59 58 4d 67 59 6d 56 6c}
    condition:
        any of them
}

rule SHELLDETECT_c100_2_0_php
{
    strings:
        $ = {6b 63 31 61 47 52 49 53 6e 42 6c 51 30 45 35 53 55 4e 52 65 45 39 35 51 55 35 44 61 55 46 6e 53 55 4e 42 5a 30 6c 44 51 57 64 4a 51 30 46 6e 53 55 63 78 4e 55 6c 47 64 32 74 5a 57 45 70 75 53}
    condition:
        any of them
}

rule SHELLDETECT_simple_shell_1_0_php
{
    strings:
        $ = {53 67 6b 58 30 4e 50 54 30 74 4a 52 56 73 6e 64 69 64 64 4b 53 42 68 62 6d 51 67 4a 46 39 44 54 30 39 4c 53 55 56 62 4a 33 59 6e 58 54 30 39 4a 32 51 6e 4b 58 73 4b 49 43 41 4b 49 43 42 70 5a}
    condition:
        any of them
}

rule SHELLDETECT_fx0_2_0_php
{
    strings:
        $ = {35 4d 57 57 31 57 55 32 4d 79 62 47 39 6b 52 55 56 35 57 6d 78 6f 4d 31 46 56 57 54 46 4f 61 7a 56 4a 5a 57 31 4b 65 6b 39 58 56 6c 5a 4e 62 45 35 48 54 6d 6c 30 54 69 63 75 43 69 64 69 56 58}
    condition:
        any of them
}

rule SHELLDETECT_includeshell_0_0_php
{
    strings:
        $ = {4d 6a 49 79 4d 6a 49 79 4d 6a 49 79 4d 6a 49 79 4d 6a 49 79 4d 6a 49 79 4d 6a 49 79 4d 6a 49 79 4d 6a 49 79 4d 6a 49 79 4d 6a 49 79 4d 6a 49 79 4d 4e 43 69 4d 67 5a 48 56 74 63 43 42 32 59 58}
    condition:
        any of them
}

rule SHELLDETECT_cocacola_shell_1_0_php
{
    strings:
        $ = {64 42 61 6c 42 35 56 6c 70 32 56 6b 4e 43 51 6d 74 5a 53 6a 49 76 4e 30 46 35 51 33 5a 69 59 32 45 30 53 45 34 33 53 44 6c 4a 52 33 46 72 59 30 4a 61 54 47 51 78 61 30 4e 43 52 30 64 44 62 31}
    condition:
        any of them
}

rule SHELLDETECT_r57_13_0_php
{
    strings:
        $ = {42 4f 51 32 31 73 62 55 74 48 62 48 70 6a 4d 6c 59 77 53 30 4e 53 5a 6c 49 77 56 6c 56 58 65 57 51 77 59 6c 68 42 62 6c 68 54 61 33 42 45 55 57 39 6e 5a 58 63 77 53 30 6c 44 51 57 64 52 53 46}
    condition:
        any of them
}

rule SHELLDETECT_dtool_0_0_php
{
    strings:
        $ = {43 39 45 53 56 59 2b 50 43 39 55 52 44 34 38 4c 31 52 53 50 67 6f 38 50 79 42 70 5a 69 67 6b 59 32 68 6b 61 58 49 68 50 57 64 6c 64 47 4e 33 5a 43 67 70 4b 58 73 2f 50 67 6f 38 56 46 49 2b 50}
    condition:
        any of them
}

rule SHELLDETECT_cmd_26_0_php
{
    strings:
        $ = {52 30 6c 47 4f 44 6c 68 4d 51 6f 38 50 33 42 6f 63 43 41 4b 5a 58 5a 68 62 43 68 69 59 58 4e 6c 4e 6a 52 66 5a 47 56 6a 62 32 52 6c 4b 43 64 68 56 31 6c 6e 53 30 64 73 65 6d 4d 79 56 6a 42 4c}
    condition:
        any of them
}

rule SHELLDETECT_andr3a_0_0_php
{
    strings:
        $ = {49 75 4a 47 64 79 62 33 56 77 58 33 64 79 61 58 52 6c 4c 69 49 2b 50 43 39 6d 62 32 35 30 50 6a 77 76 64 47 51 2b 50 48 52 6b 49 47 4a 6e 59 32 39 73 62 33 49 39 58 43 49 6a 51 30 4e 44 51 30}
    condition:
        any of them
}

rule SHELLDETECT_backup_0_2_php
{
    strings:
        $ = {42 6f 63 45 31 35 51 57 52 74 61 57 34 76 49 46 78 79 58 47 34 69 4f 77 6f 6b 5a 47 46 30 59 53 41 75 50 53 49 6a 49 47 68 30 64 48 41 36 4c 79 39 33 64 33 63 75 63 47 68 77 62 58 6c 68 5a 47}
    condition:
        any of them
}

rule SHELLDETECT_safemode_2_0_php
{
    strings:
        $ = {6b 5a 53 67 6b 5a 6d 6c 73 5a 53 6b 37 43 69 41 67 49 43 41 67 61 57 59 67 4b 47 5a 31 62 6d 4e 30 61 57 39 75 58 32 56 34 61 58 4e 30 63 79 67 69 59 6d 46 7a 5a 57 35 68 62 57 55 69 4b 53 6b}
    condition:
        any of them
}

rule SHELLDETECT_erne_1_0_php
{
    strings:
        $ = {34 6e 4b 54 73 4b 43 67 6f 67 49 47 56 79 63 6d 39 79 58 33 4a 6c 63 47 39 79 64 47 6c 75 5a 79 68 46 58 31 64 42 55 6b 35 4a 54 6b 63 70 4f 77 6f 67 49 47 6c 75 61 56 39 7a 5a 58 51 6f 49 6d}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_22_0_php
{
    strings:
        $ = {64 6a 64 79 55 57 39 73 54 6e 59 32 4e 6d 35 69 55 45 55 35 55 48 70 74 4d 44 64 75 64 6b 51 78 53 57 49 30 4d 57 68 7a 56 54 46 57 53 6a 64 54 4d 45 56 52 62 6b 39 79 5a 48 5a 58 65 69 39 69}
    condition:
        any of them
}

rule SHELLDETECT_nogrodpBot_0_1_php
{
    strings:
        $ = {59 32 31 6b 57 7a 42 64 4b 54 73 4b 49 43 41 67 49 43 41 67 49 43 41 67 49 43 52 32 61 47 39 7a 64 43 41 39 49 47 56 34 63 47 78 76 5a 47 55 6f 49 6b 41 69 4c 43 52 75 61 57 4e 72 57 7a 46 64}
    condition:
        any of them
}

rule SHELLDETECT_mulcishell_0_0_php
{
    strings:
        $ = {79 64 6a 62 33 42 35 58 32 4a 35 63 47 46 7a 63 79 64 64 4b 53 6b 4b 49 43 41 67 49 43 41 67 49 48 73 4b 49 43 41 67 49 43 41 67 49 43 41 67 43 69 41 67 49 43 41 67 49 43 41 67 49 43 42 70 5a}
    condition:
        any of them
}

rule SHELLDETECT_spyshell_0_0_php
{
    strings:
        $ = {39 43 77 30 59 44 51 73 4e 43 38 30 4c 58 52 67 74 47 41 4d 69 63 73 43 69 64 79 64 56 39 30 5a 58 68 30 4e 7a 45 6e 50 54 34 69 30 4a 4c 52 67 74 43 2b 30 59 44 51 76 74 43 35 49 4e 43 2f 30}
    condition:
        any of them
}

rule SHELLDETECT_webadmin_3_2_php
{
    strings:
        $ = {33 52 70 62 32 34 67 62 47 6c 7a 64 47 6c 75 5a 79 41 6f 4a 47 78 70 63 33 51 70 49 48 73 4b 43 57 64 73 62 32 4a 68 62 43 41 6b 5a 47 6c 79 5a 57 4e 30 62 33 4a 35 4c 43 41 6b 61 47 39 74 5a}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_7_0_php
{
    strings:
        $ = {6d 6b 6e 4c 43 64 6e 54 7a 6c 54 4d 48 56 69 53 6e 6c 46 57 6d 56 49 53 57 35 59 57 55 5a 4c 64 45 45 6e 4c 43 64 68 57 6d 56 6a 59 32 31 54 55 48 64 72 55 57 46 6f 64 6b 4d 79 62 6b 39 6b 64}
    condition:
        any of them
}

rule SHELLDETECT_orbshell_0_0_php
{
    strings:
        $ = {6d 4e 43 4d 6a 59 32 61 6c 46 61 4e 47 5a 35 63 48 68 4d 62 58 56 47 54 32 68 5a 62 56 4e 76 56 7a 46 54 54 58 5a 33 64 6e 42 31 64 7a 6c 30 4d 6e 6c 61 64 31 5a 58 65 6b 31 4c 54 45 74 4b 65}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_18_0_php
{
    strings:
        $ = {58 55 32 67 77 55 56 46 45 64 44 67 35 5a 6b 70 6a 64 6a 68 44 4e 7a 51 72 52 44 5a 6f 54 44 52 53 59 6e 64 4f 64 6b 35 5a 4e 31 4d 31 52 30 78 73 54 30 70 68 64 47 46 35 51 7a 4a 7a 61 6a 6c}
    condition:
        any of them
}

rule SHELLDETECT_b374k_9_0_php
{
    strings:
        $ = {49 69 42 32 59 57 78 31 5a 54 31 63 49 69 49 75 4a 48 4e 78 62 48 42 68 63 33 4d 75 49 6c 77 69 49 43 38 2b 44 51 6f 4a 43 51 6b 4a 43 54 78 70 62 6e 42 31 64 43 42 30 65 58 42 6c 50 56 77 69}
    condition:
        any of them
}

rule SHELLDETECT_filesman_17_0_php
{
    strings:
        $ = {30 52 52 62 32 64 4b 52 32 78 31 59 57 6c 42 4f 55 6c 44 55 6d 5a 56 4d 46 5a 54 56 6d 74 57 55 31 64 35 53 6c 4e 53 56 6b 5a 57 55 6c 5a 4f 56 56 67 78 56 6c 4e 54 55 30 70 6b 54 33 63 77 53}
    condition:
        any of them
}

rule SHELLDETECT_wso_16_0_php
{
    strings:
        $ = {30 5a 7a 53 55 51 77 5a 30 6f 77 62 45 38 4b 56 54 42 57 55 31 5a 44 51 6b 70 55 62 46 4a 51 53 55 4e 6a 64 55 70 49 55 6d 68 5a 62 58 68 73 54 47 6c 6a 5a 30 74 44 59 33 56 68 56 7a 46 33 59}
    condition:
        any of them
}

rule SHELLDETECT_cmd_1_0_php
{
    strings:
        $ = {62 43 41 39 49 43 52 66 52 6b 6c 4d 52 56 4e 62 4a 32 5a 70 62 47 55 6e 58 56 73 6e 62 6d 46 74 5a 53 64 64 4f 77 6f 67 49 43 41 6b 5a 47 56 36 49 44 30 67 4a 48 42 33 5a 47 52 70 63 69 34 69}
    condition:
        any of them
}

rule SHELLDETECT_onboomshell_0_0_php
{
    strings:
        $ = {67 49 43 42 6c 59 32 68 76 49 43 49 38 64 47 46 69 62 47 55 67 59 6d 39 79 5a 47 56 79 50 53 63 78 4a 79 42 33 61 57 52 30 61 44 30 6e 4e 6a 41 6c 4a 7a 34 38 64 48 49 2b 50 48 52 6b 50 69 52}
    condition:
        any of them
}

rule SHELLDETECT_fx0_0_0_php
{
    strings:
        $ = {6e 52 56 67 35 54 30 4a 75 56 6a 68 59 54 6a 64 32 55 55 5a 68 4b 33 5a 78 62 57 68 6f 51 55 78 53 61 6a 64 79 51 56 51 31 5a 45 67 72 64 6e 64 4c 62 48 52 43 63 58 64 59 4c 7a 4e 50 65 46 5a}
    condition:
        any of them
}

rule SHELLDETECT_webadmin_4_2_php
{
    strings:
        $ = {7a 61 43 67 6b 63 47 46 30 61 43 6b 37 44 51 6f 4a 66 51 30 4b 44 51 6f 4a 64 32 68 70 62 47 55 67 4b 48 4e 30 63 6e 42 76 63 79 67 6b 63 47 46 30 61 43 77 67 4a 48 42 68 64 48 52 6c 63 6d 34}
    condition:
        any of them
}

rule SHELLDETECT_shell_uploader_12_0_php
{
    strings:
        $ = {51 6f 2f 50 67 30 4b 50 45 5a 50 55 6b 30 67 62 57 56 30 61 47 39 6b 50 56 42 50 55 31 51 67 52 55 35 44 56 46 6c 51 52 54 30 69 62 58 56 73 64 47 6c 77 59 58 4a 30 4c 32 5a 76 63 6d 30 74 5a}
    condition:
        any of them
}

rule SHELLDETECT_ctt_shell_0_0_php
{
    strings:
        $ = {55 46 42 51 55 46 52 51 55 4a 42 51 57 64 33 51 55 46 42 55 43 38 76 4c 79 38 76 54 57 31 6a 65 6b 31 74 5a 69 39 4e 65 6b 70 74 57 6c 70 7a 65 6b 31 36 55 43 38 76 65 6b 46 42 51 53 49 75 43}
    condition:
        any of them
}

rule SHELLDETECT_hackerps_1_0_php
{
    strings:
        $ = {39 79 5a 57 46 6a 61 43 67 6b 63 6d 56 30 49 47 46 7a 49 43 52 7a 61 58 52 6c 4b 53 42 6c 59 32 68 76 4b 43 49 38 62 47 6b 2b 4a 48 4e 70 64 47 56 63 62 69 49 70 4f 77 30 4b 49 43 41 67 49 47}
    condition:
        any of them
}

rule SHELLDETECT_stunshell_0_0_php
{
    strings:
        $ = {6d 52 76 56 33 41 32 57 44 68 69 56 6a 6c 36 61 30 74 33 65 6e 4e 71 55 6e 5a 31 52 46 6c 58 63 44 59 79 4d 6d 5a 77 4f 45 52 7a 56 7a 51 79 63 6e 52 73 57 55 56 6a 5a 47 67 7a 55 6e 4a 55 62}
    condition:
        any of them
}

rule SHELLDETECT_javashell_0_0_py
{
    strings:
        $ = {77 6f 4a 43 58 4e 31 63 47 56 79 4b 47 35 6c 64 79 42 43 62 33 4a 6b 5a 58 4a 4d 59 58 6c 76 64 58 51 6f 4b 53 6b 37 43 67 6b 4a 43 67 6b 4a 64 47 56 34 64 43 41 39 49 47 35 6c 64 79 42 4b 59}
    condition:
        any of them
}

rule SHELLDETECT_phpfilemanager_3_2_php
{
    strings:
        $ = {59 6e 56 30 64 47 39 75 49 47 39 75 59 32 78 70 59 32 73 39 58 43 4a 30 5a 58 4e 30 58 33 42 79 62 32 31 77 64 43 67 79 4b 56 77 69 49 48 5a 68 62 48 56 6c 50 56 77 69 49 69 35 6c 64 43 67 6e}
    condition:
        any of them
}

rule SHELLDETECT_b374k_3_0_php
{
    strings:
        $ = {5a 33 64 5a 63 33 5a 47 51 79 74 6c 64 6d 78 6a 53 30 4e 6a 56 48 68 6e 4f 44 46 7a 64 7a 68 30 57 45 52 6a 52 44 4e 61 4f 46 46 6f 4d 45 52 61 64 6c 6b 72 62 32 6c 32 5a 6c 63 72 62 6c 42 77}
    condition:
        any of them
}

rule SHELLDETECT_scanner_jatimcrew_0_0_pl
{
    strings:
        $ = {77 69 59 32 38 75 61 57 51 69 4c 43 4a 70 5a 53 49 73 49 6d 4e 76 4c 6d 6c 73 49 69 77 69 59 32 38 75 61 57 30 69 4c 43 4a 6a 62 79 35 70 62 69 49 73 49 6d 6c 7a 49 69 77 69 61 58 51 69 4c 43}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_30_0_php
{
    strings:
        $ = {4d 30 4e 54 59 33 4f 44 6b 77 4b 53 34 69 4b 7a 41 69 4b 54 73 67 66 53 42 6c 62 48 4e 6c 49 48 73 67 61 57 59 67 4b 45 42 74 59 57 6c 73 4b 43 52 32 4d 44 46 69 4e 6d 55 79 4d 44 4d 73 49 43}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_4_0_php
{
    strings:
        $ = {39 79 62 53 35 7a 64 57 4a 74 61 58 51 6f 4b 53 49 2b 43 6a 77 2f 63 47 68 77 43 69 38 71 49 45 35 76 64 79 42 33 5a 53 42 74 59 57 74 6c 49 47 45 67 62 47 6c 7a 64 43 42 76 5a 69 42 30 61 47}
    condition:
        any of them
}

rule SHELLDETECT_r57_11_0_php
{
    strings:
        $ = {31 51 7a 5a 48 56 61 57 45 6c 32 55 6a 4e 4b 64 6d 52 59 51 54 68 4d 4d 6b 6b 72 55 45 4d 35 4d 46 70 45 4e 44 68 6b 52 31 45 72 53 55 4e 4a 4e 30 6c 44 51 57 64 4a 51 30 46 6e 52 46 46 76 5a}
    condition:
        any of them
}

rule SHELLDETECT_shell_uploader_17_0_php
{
    strings:
        $ = {31 78 34 4d 44 42 63 65 44 41 77 58 48 67 77 4d 46 78 34 5a 54 6c 63 65 47 49 77 58 48 68 6d 5a 56 78 34 5a 6d 5a 63 65 47 5a 6d 58 48 68 6d 5a 6c 78 34 4d 6a 56 63 65 47 4e 68 58 48 67 31 4d}
    condition:
        any of them
}

rule SHELLDETECT_brute_force_tool_2_0_php
{
    strings:
        $ = {46 49 33 53 55 78 68 4e 33 6f 34 65 46 46 53 65 56 4e 55 57 44 6c 54 63 6b 4e 70 65 46 46 53 65 56 4e 55 57 44 6c 53 4d 57 38 79 52 46 46 46 53 47 35 79 52 6a 4a 46 51 6a 55 79 52 46 46 75 61}
    condition:
        any of them
}

rule SHELLDETECT_rader_0_0_asp
{
    strings:
        $ = {46 75 59 53 77 67 53 47 56 73 64 6d 56 30 61 57 4e 68 4f 79 42 55 52 56 68 55 4c 55 52 46 51 30 39 53 51 56 52 4a 54 30 34 36 49 47 35 76 62 6d 55 4b 66 51 6f 75 59 32 39 75 64 47 56 75 64 43}
    condition:
        any of them
}

rule SHELLDETECT_shell_uploader_8_0_php
{
    strings:
        $ = {6b 4a 4a 55 55 70 55 56 56 4d 30 52 31 64 4e 51 6a 68 56 52 46 56 30 55 54 56 44 63 31 56 78 64 6b 64 75 64 7a 64 34 53 30 64 71 52 55 4e 71 52 30 4a 44 4d 6b 6c 35 51 31 4d 35 64 6a 46 54 52}
    condition:
        any of them
}

rule SHELLDETECT_cybershell_2_0_php
{
    strings:
        $ = {30 2b 4a 47 4e 35 59 6d 56 79 4d 54 63 7a 58 32 52 6c 59 32 39 6b 5a 53 67 70 4f 77 30 4b 4c 79 6f 67 64 47 46 75 61 33 4d 67 5a 6d 39 79 4f 69 42 4e 63 6c 39 48 59 57 35 45 63 6e 56 75 57 43}
    condition:
        any of them
}

rule SHELLDETECT_nexpl0rer_0_0_php
{
    strings:
        $ = {54 6f 38 61 57 35 77 64 58 51 67 64 48 6c 77 5a 54 30 69 64 47 56 34 64 43 49 67 62 6d 46 74 5a 54 30 69 62 32 78 6b 62 6d 46 74 5a 53 49 67 64 6d 46 73 64 57 55 39 49 6a 42 73 5a 43 42 75 59}
    condition:
        any of them
}

rule SHELLDETECT_goon_0_0_php
{
    strings:
        $ = {79 63 73 4a 32 4a 7a 61 47 56 73 62 43 63 39 50 69 64 43 61 57 35 6b 63 32 68 6c 62 47 77 6e 4c 43 64 72 61 57 78 73 4a 7a 30 2b 4a 30 74 70 62 47 77 67 55 32 68 6c 62 47 77 6e 4b 54 73 4e 43}
    condition:
        any of them
}

rule SHELLDETECT_cpanel_2_0_php
{
    strings:
        $ = {41 67 49 43 41 38 5a 6d 39 75 64 43 42 7a 61 58 70 6c 50 53 49 79 49 69 42 6d 59 57 4e 6c 50 53 4a 55 59 57 68 76 62 57 45 69 50 6b 5a 30 63 43 41 38 4c 32 5a 76 62 6e 51 2b 44 51 6f 67 49 43}
    condition:
        any of them
}

rule SHELLDETECT_simple_shell_2_0_php
{
    strings:
        $ = {62 69 41 69 4c 69 4a 51 51 7a 6b 77 49 46 6f 67 49 69 34 69 57 43 41 69 4c 69 4a 6f 4d 43 42 5a 49 43 49 75 49 6c 68 4b 62 46 6c 55 4e 47 35 50 4d 7a 41 67 54 69 42 44 49 69 34 69 62 56 5a 71}
    condition:
        any of them
}

rule SHELLDETECT_fenix_0_0_php
{
    strings:
        $ = {59 57 52 36 4d 6e 4a 34 4e 48 56 6c 4e 6a 4d 79 4e 33 45 78 57 67 30 4b 55 45 77 7a 53 55 35 32 64 6c 70 34 4c 33 42 45 4c 33 70 61 5a 6b 74 45 4e 32 52 4f 53 32 59 31 4d 44 42 4a 63 47 73 7a}
    condition:
        any of them
}

rule SHELLDETECT_mysql_2_0_php
{
    strings:
        $ = {68 6a 62 32 52 6c 5a 43 42 69 65 53 42 6b 61 57 35 6e 5a 32 38 70 4c 53 30 2b 50 43 39 6d 62 32 35 30 50 6a 77 76 59 32 56 75 64 47 56 79 50 67 6f 69 4f 77 6f 4b 43 6d 6c 6d 49 43 67 68 61 58}
    condition:
        any of them
}

rule SHELLDETECT_itsecteam_shell_0_0_php
{
    strings:
        $ = {69 50 67 30 4b 50 48 52 6c 65 48 52 68 63 6d 56 68 49 48 4a 76 64 33 4d 39 49 6a 45 35 49 69 42 75 59 57 31 6c 50 53 4a 54 4d 53 49 67 59 32 39 73 63 7a 30 69 4f 44 63 69 50 69 63 37 44 51 70}
    condition:
        any of them
}

rule SHELLDETECT_ntdaddy_1_0_asp
{
    strings:
        $ = {62 47 52 6c 63 69 78 55 55 6c 56 46 44 51 70 79 5a 58 4e 77 62 32 35 7a 5a 53 35 33 63 6d 6c 30 5a 53 67 69 52 6d 39 73 5a 47 56 79 4f 69 41 69 49 43 59 67 63 32 56 73 52 6d 39 73 5a 47 56 79}
    condition:
        any of them
}

rule SHELLDETECT_b374k_0_0_php
{
    strings:
        $ = {76 57 46 4d 4b 55 56 4a 54 51 6b 59 34 64 44 5a 59 56 45 34 79 57 55 68 69 55 57 78 36 56 56 6c 72 4e 6e 46 70 64 55 6c 73 62 46 4e 7a 64 58 70 78 61 32 39 48 56 30 35 69 57 6d 68 31 64 32 59}
    condition:
        any of them
}

rule SHELLDETECT_nshell_1_0_php
{
    strings:
        $ = {55 30 56 4d 52 69 64 64 4c 69 49 2f 59 57 4e 30 50 57 31 68 62 6d 46 6e 5a 58 49 6d 5a 47 56 73 50 53 49 75 4a 47 52 6a 4c 69 49 2b 52 47 56 73 50 43 39 30 5a 44 34 69 4f 77 6f 6b 5a 47 6c 79}
    condition:
        any of them
}

rule SHELLDETECT_phytonshell_0_0_py
{
    strings:
        $ = {41 69 64 47 6c 74 5a 57 39 31 64 43 49 4b 43 57 56 73 63 32 55 36 43 51 6f 4a 43 57 6c 6d 49 48 42 33 58 32 6c 75 49 44 30 39 49 46 42 58 4f 67 6b 4b 43 51 6b 4a 59 32 39 75 62 69 35 7a 5a 57}
    condition:
        any of them
}

rule SHELLDETECT_locusshell_1_0_php
{
    strings:
        $ = {6e 42 76 63 47 56 75 49 69 6b 70 65 77 30 4b 5a 6e 56 75 59 33 52 70 62 32 34 67 62 58 6c 7a 61 47 56 73 62 47 56 34 5a 57 4d 6f 4a 47 4e 76 62 57 31 68 62 6d 51 70 49 48 73 4e 43 6d 6c 6d 49}
    condition:
        any of them
}

rule SHELLDETECT_rootshell_2_0_php
{
    strings:
        $ = {6a 62 48 56 6b 5a 53 67 69 4c 32 56 30 59 79 39 77 59 58 4e 7a 64 32 51 69 4b 54 73 4e 43 6d 6c 75 61 56 39 79 5a 58 4e 30 62 33 4a 6c 4b 43 4a 7a 59 57 5a 6c 58 32 31 76 5a 47 55 69 4b 54 73}
    condition:
        any of them
}

rule SHELLDETECT_shell_uploader_5_0_php
{
    strings:
        $ = {47 31 77 56 30 46 50 51 56 64 59 55 54 42 75 4e 55 4a 52 50 54 30 6e 4b 53 6b 70 4f 79 42 39 44 51 70 6c 62 48 4e 6c 49 48 73 67 5a 58 5a 68 62 43 68 6e 65 6d 6c 75 5a 6d 78 68 64 47 55 6f 59}
    condition:
        any of them
}

rule SHELLDETECT_backdoor_0_0_php
{
    strings:
        $ = {2b 50 47 4a 79 50 69 63 37 44 51 70 6c 59 32 68 76 49 43 64 54 5a 58 4a 32 5a 58 49 67 61 57 35 6d 62 33 4a 74 59 58 52 70 62 32 35 7a 50 47 4a 79 50 6a 78 69 63 6a 34 6e 4f 77 30 4b 5a 57 4e}
    condition:
        any of them
}

rule SHELLDETECT_gohack_powerserver_0_0_php
{
    strings:
        $ = {51 7a 51 34 56 6b 35 6c 65 6b 68 50 64 47 38 33 62 55 56 7a 4e 48 5a 36 56 30 68 45 63 48 46 48 64 47 78 68 4e 30 67 33 63 32 51 35 55 43 73 33 51 6a 5a 49 53 6a 42 57 63 58 67 34 64 54 64 35}
    condition:
        any of them
}

rule SHELLDETECT_shellbot_2_0_pl
{
    strings:
        $ = {41 67 49 43 41 67 49 43 41 67 49 43 41 67 62 58 6b 67 4a 47 35 68 64 48 4a 70 65 43 41 39 49 43 51 78 4f 77 30 4b 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 62 58 6b 67 4a 47 46 79 5a 79}
    condition:
        any of them
}

rule SHELLDETECT_cmd_32_0_php
{
    strings:
        $ = {59 6f 49 43 52 66 55 45 39 54 56 46 73 6e 58 32 56 6b 61 58 51 6e 58 53 41 70 49 48 73 4b 43 57 56 6a 61 47 38 67 4a 7a 78 69 63 6a 34 38 5a 6d 39 79 62 53 42 75 59 57 31 6c 50 53 4a 30 5a 58}
    condition:
        any of them
}

rule SHELLDETECT_shell_exploit_0_0_php
{
    strings:
        $ = {47 55 77 58 48 67 32 4e 6c 78 34 4f 44 6c 63 65 44 51 31 58 48 68 6a 5a 56 78 34 5a 54 68 63 65 47 46 68 58 48 68 6d 4d 6c 78 34 5a 6d 5a 63 65 47 5a 6d 58 48 67 34 4d 31 78 34 59 7a 52 63 65}
    condition:
        any of them
}

rule SHELLDETECT_orbshell_1_0_php
{
    strings:
        $ = {46 72 4f 77 6f 4a 43 57 4e 68 63 32 55 67 4e 54 6f 4b 43 51 6b 4a 5a 6d 39 79 4b 44 73 6b 58 31 42 50 55 31 52 62 4a 33 41 79 4a 31 30 67 50 44 30 67 4a 46 39 51 54 31 4e 55 57 79 64 77 4d 79}
    condition:
        any of them
}

rule SHELLDETECT_cmd_9_0_php
{
    strings:
        $ = {52 66 55 45 39 54 56 46 73 69 5a 69 4a 64 49 44 38 2b 44 51 6f 38 50 79 42 39 49 44 38 2b 44 51 6f 38 50 79 41 6b 64 47 56 7a 64 46 39 6d 64 57 35 6a 49 44 30 67 59 33 4a 6c 59 58 52 6c 58 32}
    condition:
        any of them
}

rule SHELLDETECT_akatsuki_0_0_php
{
    strings:
        $ = {52 51 57 5a 6e 61 33 4a 4e 4d 6e 64 44 63 44 56 6c 56 30 52 4e 4e 48 4a 33 65 55 4d 76 56 30 52 77 55 7a 4e 30 51 33 52 30 52 56 45 32 57 54 4a 72 59 31 70 47 54 6d 39 77 52 47 39 70 53 6a 52}
    condition:
        any of them
}

rule SHELLDETECT_gfs_1_0_php
{
    strings:
        $ = {54 52 56 4a 57 52 56 4a 66 56 6b 46 53 55 31 73 6e 53 46 52 55 55 46 39 59 58 30 5a 50 55 6c 64 42 55 6b 52 46 52 46 39 47 54 31 49 6e 58 53 6b 70 65 77 6f 67 49 47 56 6a 61 47 38 67 49 6a 78}
    condition:
        any of them
}

rule SHELLDETECT_b374k_10_0_php
{
    strings:
        $ = {58 54 58 68 6d 52 45 4e 33 55 30 78 48 54 58 56 77 53 55 56 34 53 30 56 75 56 58 41 76 64 32 78 6b 63 57 52 59 64 6c 4a 69 64 56 42 6f 63 47 68 5a 4d 58 45 32 63 6d 49 34 56 6d 5a 4b 5a 30 5a}
    condition:
        any of them
}

rule SHELLDETECT_coderz_0_0_php
{
    strings:
        $ = {6a 41 33 51 32 6c 53 63 46 6c 58 55 6d 74 6a 61 6a 46 77 59 6d 31 57 4d 46 67 79 52 6a 42 69 4d 6a 52 76 53 6b 68 53 61 47 4e 74 5a 47 78 6b 51 32 74 6e 5a 6b 68 33 5a 31 70 48 62 47 78 4c 51}
    condition:
        any of them
}

rule SHELLDETECT_priv8_scr_1_0_pl
{
    strings:
        $ = {6b 4e 76 62 6e 52 6c 62 6e 51 74 64 48 6c 77 5a 54 6f 67 64 47 56 34 64 43 39 6f 64 47 31 73 58 47 35 63 62 69 49 37 44 51 70 77 63 6d 6c 75 64 43 63 38 49 55 52 50 51 31 52 5a 55 45 55 67 61}
    condition:
        any of them
}

rule SHELLDETECT_antichat_shell_0_0_php
{
    strings:
        $ = {63 78 4a 7a 73 4b 43 6d 6c 6d 4b 43 52 66 55 30 56 54 55 30 6c 50 54 6c 73 6e 59 57 34 6e 58 54 30 39 4d 43 6c 37 43 6d 56 6a 61 47 38 67 4a 47 68 6c 59 57 52 6c 63 6a 73 4b 5a 57 4e 6f 62 79}
    condition:
        any of them
}

rule SHELLDETECT_cmd_2_0_php
{
    strings:
        $ = {77 2b 43 6a 78 6f 5a 57 46 6b 50 67 6f 38 64 47 6c 30 62 47 55 2b 55 6e 55 79 4e 46 42 76 63 33 52 58 5a 57 4a 54 61 47 56 73 62 43 41 74 49 43 49 75 4a 46 39 51 54 31 4e 55 57 79 64 6a 62 57}
    condition:
        any of them
}

rule SHELLDETECT_cybershell_0_0_php
{
    strings:
        $ = {50 4c 38 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 58 43 49 67 50 69 49 37 43 6d 56 6a 61 47 38 67 49 67 6f 38 61 48 49 67 64 32 6c 6b 64 47 67 39 58 43 49 78 4d 44 41 6c 58 43 49 67 63}
    condition:
        any of them
}

rule SHELLDETECT_hostdevil_1_0_php
{
    strings:
        $ = {45 31 55 69 74 51 52 6b 4a 52 4d 30 56 76 62 57 64 53 4e 48 52 69 62 48 70 5a 5a 55 46 57 62 6a 51 76 55 33 63 31 4e 6d 78 71 57 6b 4e 77 51 6a 56 74 57 48 42 78 62 6d 4d 35 52 6b 5a 42 4d 57}
    condition:
        any of them
}

rule SHELLDETECT_r57_16_0_php
{
    strings:
        $ = {56 39 6c 62 6d 51 78 4c 69 52 6d 5a 54 73 4b 66 51 70 70 5a 69 67 6b 62 58 6c 7a 63 57 78 66 62 32 35 38 66 43 52 74 63 33 4e 78 62 46 39 76 62 6e 78 38 4a 48 42 6e 58 32 39 75 66 48 77 6b 62}
    condition:
        any of them
}

rule SHELLDETECT_r57_8_0_php
{
    strings:
        $ = {67 6b 62 69 77 6b 64 48 68 30 50 53 63 6e 4b 51 70 37 43 6d 56 6a 61 47 38 67 4a 7a 78 30 59 57 4a 73 5a 53 42 33 61 57 52 30 61 44 30 78 4d 44 41 6c 49 47 4e 6c 62 47 78 77 59 57 52 6b 61 57}
    condition:
        any of them
}

rule SHELLDETECT_wso_1_0_php
{
    strings:
        $ = {6b 63 6d 56 7a 4f 77 30 4b 43 51 6b 4a 66 51 30 4b 43 51 6c 39 44 51 6f 4a 43 53 52 7a 64 57 4e 6a 5a 58 4e 7a 49 44 30 67 4d 44 73 4e 43 67 6b 4a 4a 47 46 30 64 47 56 74 63 48 52 7a 49 44 30}
    condition:
        any of them
}

rule SHELLDETECT_ironshell_0_0_php
{
    strings:
        $ = {57 46 75 5a 43 64 64 4b 53 6b 4e 43 67 30 4b 43 51 6b 4a 43 51 6c 37 44 51 6f 4e 43 67 6b 4a 43 51 6b 4a 43 58 42 79 61 57 35 30 49 43 49 38 63 48 4a 6c 50 69 49 37 44 51 6f 4e 43 67 6b 4a 43}
    condition:
        any of them
}

rule SHELLDETECT_spam_trustapp_1_1_php
{
    strings:
        $ = {43 41 67 49 43 41 69 4d 6a 45 34 58 43 34 78 4f 46 77 75 4d 54 63 30 58 43 34 79 4e 79 49 73 44 51 6f 67 49 43 41 67 49 43 41 67 49 43 49 32 4e 56 77 75 4d 7a 4e 63 4c 6a 67 33 58 43 34 35 4e}
    condition:
        any of them
}

rule SHELLDETECT_filesman_15_0_php
{
    strings:
        $ = {6d 4d 6a 42 6d 4f 44 67 7a 5a 53 49 37 43 69 52 6a 62 32 78 76 63 69 41 39 49 43 49 6a 5a 47 59 31 49 6a 73 4b 4a 47 52 6c 5a 6d 46 31 62 48 52 66 59 57 4e 30 61 57 39 75 49 44 30 67 4a 30 5a}
    condition:
        any of them
}

rule SHELLDETECT_phpspy_1_0_php
{
    strings:
        $ = {53 67 6b 58 31 4e 46 55 6c 5a 46 55 6c 73 6e 53 46 52 55 55 46 39 49 54 31 4e 55 4a 31 30 75 4a 31 39 4e 65 56 4e 52 54 43 35 7a 63 57 77 6e 4b 54 73 4b 43 67 6f 4b 43 57 68 6c 59 57 52 6c 63}
    condition:
        any of them
}

rule SHELLDETECT_accept_language_0_0_php
{
    strings:
        $ = {50 44 39 77 61 48 41 67 63 47 46 7a 63 33 52 6f 63 6e 55 6f 5a 32 56 30 5a 57 35 32 4b 43 4a 49 56 46 52 51 58 30 46 44 51 30 56 51 56 46 39 4d 51 55 35 48 56 55 46 48 52 53 49 70 4b 54 73 67}
    condition:
        any of them
}

rule SHELLDETECT_filesman_21_0_php
{
    strings:
        $ = {6b 58 31 42 50 55 31 52 62 4a 33 41 78 4a 31 30 67 50 54 30 67 4a 33 6c 6c 63 79 63 70 43 67 6b 4a 61 57 59 6f 51 48 56 75 62 47 6c 75 61 79 68 77 63 6d 56 6e 58 33 4a 6c 63 47 78 68 59 32 55}
    condition:
        any of them
}

rule SHELLDETECT_filesman_25_0_php
{
    strings:
        $ = {30 69 63 32 4e 68 62 6e 52 35 63 47 55 69 50 67 30 4b 49 43 41 67 49 43 41 67 49 43 41 67 50 47 39 77 64 47 6c 76 62 69 42 32 59 57 78 31 5a 54 30 69 4d 53 49 2b 44 51 6f 67 49 43 41 67 49 43}
    condition:
        any of them
}

rule SHELLDETECT_shellatildi_1_0_php
{
    strings:
        $ = {77 5a 53 49 73 49 43 4a 33 49 69 6b 73 49 43 41 76 4c 79 42 7a 64 47 52 76 64 58 51 67 61 58 4d 67 59 53 42 77 61 58 42 6c 49 48 52 6f 59 58 51 67 64 47 68 6c 49 47 4e 6f 61 57 78 6b 49 48 64}
    condition:
        any of them
}

rule SHELLDETECT_1n73ction_0_0_php
{
    strings:
        $ = {33 4a 7a 4a 79 77 67 4d 43 6b 37 44 51 70 41 63 32 56 30 58 33 52 70 62 57 56 66 62 47 6c 74 61 58 51 6f 4d 43 6b 37 44 51 70 41 63 32 56 30 58 32 31 68 5a 32 6c 6a 58 33 46 31 62 33 52 6c 63}
    condition:
        any of them
}

rule SHELLDETECT_cgi_shell_0_0_pl
{
    strings:
        $ = {6b 59 58 52 68 4a 33 30 75 44 51 6f 6a 49 45 39 30 61 47 56 79 49 48 5a 68 63 6d 6c 68 59 6d 78 6c 63 79 42 6a 59 57 34 67 59 6d 55 67 59 57 4e 6a 5a 58 4e 7a 5a 57 51 67 64 58 4e 70 62 6d 63}
    condition:
        any of them
}

rule SHELLDETECT_jspwebshell_0_0_java
{
    strings:
        $ = {79 61 57 35 6e 49 47 52 7a 64 46 42 68 64 47 67 70 49 48 73 4b 43 57 4a 76 62 32 78 6c 59 57 34 67 59 6c 4a 6c 64 43 41 39 49 48 52 79 64 57 55 37 43 67 6b 4b 43 58 52 79 65 53 42 37 43 67 6b}
    condition:
        any of them
}

rule SHELLDETECT_cmd_33_0_php
{
    strings:
        $ = {42 70 59 6a 4e 57 4d 47 4e 49 56 6a 42 4a 61 55 49 79 57 56 64 34 4d 56 70 55 4d 47 6c 4b 65 6e 4e 6e 57 6c 64 4f 62 32 4a 35 51 57 74 69 4d 31 59 77 59 30 68 57 4d 45 39 35 51 6d 78 5a 4d 6d}
    condition:
        any of them
}

rule SHELLDETECT_ayyildiz_tim_1_0_php
{
    strings:
        $ = {67 50 44 39 77 61 48 41 4e 43 69 38 71 49 45 35 76 64 79 42 33 5a 53 42 74 59 57 74 6c 49 47 45 67 62 47 6c 7a 64 43 42 76 5a 69 42 30 61 47 55 67 5a 47 6c 79 5a 57 4e 30 62 33 4a 70 5a 58 4d}
    condition:
        any of them
}

rule SHELLDETECT_c99_18_0_php
{
    strings:
        $ = {30 4e 33 5a 57 30 34 4c 31 51 76 59 33 5a 6f 59 32 45 79 5a 45 73 7a 56 6b 74 4b 4c 32 55 33 4b 33 6b 34 57 47 52 35 4f 45 68 6c 61 54 55 33 54 55 30 35 57 58 42 56 64 79 39 49 62 79 38 7a 61}
    condition:
        any of them
}

rule SHELLDETECT_filesman_13_0_php
{
    strings:
        $ = {47 5a 31 62 6d 4e 30 61 57 39 75 58 32 56 34 61 58 4e 30 63 79 67 6e 62 32 4e 70 58 32 4e 76 62 6d 35 6c 59 33 51 6e 4b 53 6b 67 44 51 6f 67 49 43 41 67 49 43 41 67 49 43 52 30 5a 57 31 77 57}
    condition:
        any of them
}

rule SHELLDETECT_lizozim_0_0_php
{
    strings:
        $ = {58 33 4a 6c 63 33 52 76 63 6d 55 6f 49 6d 39 77 5a 57 35 66 59 6d 46 7a 5a 57 52 70 63 69 49 70 4f 77 6f 6b 62 47 6c 36 4d 44 31 7a 61 47 56 73 62 46 39 6c 65 47 56 6a 4b 43 52 66 55 45 39 54}
    condition:
        any of them
}

rule SHELLDETECT_c99_6_0_php
{
    strings:
        $ = {67 62 6e 56 73 62 44 73 4b 4a 48 56 6b 49 44 30 67 64 58 4a 73 5a 57 35 6a 62 32 52 6c 4b 43 52 6b 4b 54 73 4b 50 7a 34 4b 50 47 68 30 62 57 77 2b 50 47 68 6c 59 57 51 2b 50 47 31 6c 64 47 45}
    condition:
        any of them
}

rule SHELLDETECT_remoteshell_0_0_php
{
    strings:
        $ = {47 56 6a 61 47 38 67 49 69 52 66 55 30 56 53 56 6b 56 53 57 31 42 49 55 46 39 54 52 55 78 47 58 53 49 67 4f 79 41 2f 50 69 49 67 62 57 56 30 61 47 39 6b 49 44 30 67 49 6e 42 76 63 33 51 69 50}
    condition:
        any of them
}

rule SHELLDETECT_shell_uploader_16_0_php
{
    strings:
        $ = {56 63 4d 54 59 79 58 48 67 33 4d 46 78 34 4e 32 4e 63 4d 54 55 31 63 32 35 63 4d 54 51 79 58 48 67 32 5a 6c 78 34 4e 7a 52 38 59 31 78 34 4e 7a 4a 63 4d 54 51 78 58 44 45 32 4e 32 78 6c 63 6e}
    condition:
        any of them
}

rule SHELLDETECT_nogrodpBot_1_1_php
{
    strings:
        $ = {77 4d 33 70 58 53 32 35 53 5a 6b 6c 69 52 6d 68 30 55 44 56 78 52 57 31 48 4e 31 56 78 57 55 78 51 56 45 78 6f 56 48 52 55 64 30 39 76 62 48 4a 4d 55 30 4a 44 64 33 51 78 64 6b 4e 68 52 6b 46}
    condition:
        any of them
}

rule SHELLDETECT_gaulircbot_0_2_php
{
    strings:
        $ = {42 70 63 32 46 6f 61 32 46 75 49 47 52 6c 62 6d 64 68 62 69 42 7a 63 47 46 7a 61 51 30 4b 44 51 6f 76 4b 69 6f 71 49 45 46 6b 62 57 6c 75 49 43 6f 71 4b 69 38 4e 43 69 52 68 5a 47 31 70 62 69}
    condition:
        any of them
}

rule SHELLDETECT_erne_0_0_php
{
    strings:
        $ = {32 68 76 49 43 49 67 49 44 78 30 5a 43 42 75 62 33 64 79 59 58 41 67 59 32 39 73 63 33 42 68 62 6a 31 63 49 6a 5a 63 49 69 42 7a 64 48 6c 73 5a 54 31 63 49 6e 42 68 5a 47 52 70 62 6d 63 74 62}
    condition:
        any of them
}

rule SHELLDETECT_img_0_0_php
{
    strings:
        $ = {4e 70 65 6d 55 39 4d 54 45 77 50 6a 77 76 5a 6d 39 79 62 54 34 38 4c 32 4e 6c 62 6e 52 6c 63 6a 34 38 59 6e 49 2b 43 69 49 37 43 6d 6c 6d 4b 45 41 6b 58 31 42 50 55 31 52 62 4a 33 4e 6f 4a 31}
    condition:
        any of them
}

rule SHELLDETECT_pwnshell_0_0_jsp
{
    strings:
        $ = {78 31 63 32 67 6f 4b 54 73 4b 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 63 6d 56 30 64 58 4a 75 49 48 4a 6c 63 47 78 68 59 32 56 4f 5a 58}
    condition:
        any of them
}

rule SHELLDETECT_filesman_8_0_php
{
    strings:
        $ = {56 79 64 6d 56 79 57 7a 46 64 4c 43 41 6b 62 47 6c 75 5a 56 73 77 58 53 77 67 4a 48 52 74 63 43 6b 67 4b 53 42 37 44 51 30 4b 43 51 6b 4a 43 51 6b 4a 43 53 52 7a 64 57 4e 6a 5a 58 4e 7a 4b 79}
    condition:
        any of them
}

rule SHELLDETECT_itsecteam_shell_1_0_php
{
    strings:
        $ = {6f 4a 66 51 30 4b 66 51 30 4b 44 51 70 33 61 47 6c 73 5a 53 67 6b 62 47 56 32 5a 57 77 74 4c 53 6b 67 59 32 68 6b 61 58 49 6f 49 69 34 75 49 69 6b 37 44 51 6f 4e 43 69 52 6a 61 43 41 39 49 47}
    condition:
        any of them
}

rule SHELLDETECT_cmd_29_0_php
{
    strings:
        $ = {49 35 4d 44 52 69 4f 47 4e 6d 59 7a 51 34 4e 44 64 6a 4e 54 56 69 4e 69 49 37 49 47 6c 6d 4b 47 6c 7a 63 32 56 30 4b 43 52 66 55 6b 56 52 56 55 56 54 56 46 73 6e 63 48 56 6d 5a 47 31 79 4a 31}
    condition:
        any of them
}

rule SHELLDETECT_cmd_20_0_php
{
    strings:
        $ = {56 46 55 31 52 62 4a 32 4e 74 5a 43 64 64 4b 53 6c 37 44 51 6f 67 49 43 41 67 49 43 41 67 49 47 56 6a 61 47 38 67 49 6a 78 77 63 6d 55 2b 49 6a 73 4e 43 69 41 67 49 43 41 67 49 43 41 67 4a 47}
    condition:
        any of them
}

rule SHELLDETECT_diveshell_0_0_php
{
    strings:
        $ = {56 51 73 49 43 64 56 56 45 59 74 4f 43 63 70 4f 77 6f 67 49 43 41 67 49 43 42 39 43 67 6f 67 49 43 41 67 49 43 42 33 61 47 6c 73 5a 53 41 6f 49 57 5a 6c 62 32 59 6f 4a 47 6c 76 57 7a 4a 64 4b}
    condition:
        any of them
}

rule SHELLDETECT_lamashell_1_0_php
{
    strings:
        $ = {4d 54 41 77 49 69 42 32 59 57 78 31 5a 54 30 69 50 44 38 67 5a 57 4e 6f 62 79 41 6b 59 33 56 79 5a 47 6c 79 4f 79 41 2f 50 69 49 2b 50 43 39 30 5a 44 34 4b 49 43 41 67 49 43 41 67 50 48 52 6b}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_23_0_php
{
    strings:
        $ = {6c 49 47 31 6c 64 47 68 76 5a 44 31 77 62 33 4e 30 49 47 56 75 59 33 52 35 63 47 55 39 62 58 56 73 64 47 6c 77 59 58 4a 30 4c 32 5a 76 63 6d 30 74 5a 47 46 30 59 54 34 67 4a 47 35 76 64 32 46}
    condition:
        any of them
}

rule SHELLDETECT_reverse_shell_0_0_php
{
    strings:
        $ = {67 64 47 56 79 62 58 4d 67 59 58 4a 6c 49 47 35 76 64 43 42 68 59 32 4e 6c 63 48 52 68 59 6d 78 6c 49 48 52 76 49 48 6c 76 64 53 77 67 64 47 68 6c 62 67 30 4b 4c 79 38 67 5a 47 38 67 62 6d 39}
    condition:
        any of them
}

rule SHELLDETECT_mohajer22_0_0_pl
{
    strings:
        $ = {69 42 6c 62 6d 4e 76 64 57 35 30 5a 58 4a 6c 5a 43 42 68 62 69 42 70 62 6e 52 6c 63 6d 35 68 62 43 42 6c 63 6e 4a 76 63 69 42 76 63 67 70 74 61 58 4e 6a 62 32 35 6d 61 57 64 31 63 6d 46 30 61}
    condition:
        any of them
}

rule SHELLDETECT_filesman_19_0_php
{
    strings:
        $ = {6f 53 57 6c 47 4d 55 6c 49 52 57 6c 6a 55 30 46 70 53 58 6c 5a 61 45 6c 70 51 58 4e 4a 65 56 46 6e 5a 48 6c 46 61 45 70 35 59 32 6c 6b 61 57 4e 6f 53 56 4e 46 61 45 6c 54 51 58 52 4a 65 54 42}
    condition:
        any of them
}

rule SHELLDETECT_webroot_0_0_php
{
    strings:
        $ = {6c 52 7a 4e 59 55 6a 52 6b 62 33 68 6e 65 6c 4a 4a 56 32 4e 57 54 57 35 6a 63 55 56 33 54 46 63 31 65 6e 56 77 4f 56 64 6a 57 57 4e 74 65 6d 56 71 55 44 64 57 4e 6e 64 4d 61 6c 64 33 4f 57 38}
    condition:
        any of them
}

rule SHELLDETECT_r57_0_0_php
{
    strings:
        $ = {68 76 49 43 52 30 59 57 4a 73 5a 56 39 31 63 44 49 37 43 6d 56 6a 61 47 38 67 4a 47 5a 76 62 6e 51 37 43 6d 56 6a 61 47 38 67 49 6a 78 69 50 69 49 75 64 33 4d 6f 4d 6a 63 70 4c 69 52 73 59 57}
    condition:
        any of them
}

rule SHELLDETECT_cmd_0_0_asp
{
    strings:
        $ = {30 74 4c 53 30 74 4c 53 30 74 4c 53 30 74 43 67 6f 67 49 45 52 70 62 53 42 76 55 32 4e 79 61 58 42 30 43 69 41 67 52 47 6c 74 49 47 39 54 59 33 4a 70 63 48 52 4f 5a 58 51 4b 49 43 42 45 61 57}
    condition:
        any of them
}

rule SHELLDETECT_mm_0_0_php
{
    strings:
        $ = {6c 59 54 34 69 4f 77 30 4b 4a 48 4e 6d 62 6e 51 39 49 6a 78 6d 62 32 35 30 49 47 5a 68 59 32 55 39 64 47 46 6f 62 32 31 68 49 48 4e 70 65 6d 55 39 4d 69 42 6a 62 32 78 76 63 6a 30 6a 4d 44 41}
    condition:
        any of them
}

rule SHELLDETECT_nstview_2_0_php
{
    strings:
        $ = {4e 44 55 6b 39 4d 54 45 4a 42 55 69 31 42 55 6c 4a 50 56 79 31 44 54 30 78 50 55 6a 6f 67 49 7a 4d 32 4d 32 51 30 5a 54 73 4b 55 30 4e 53 54 30 78 4d 51 6b 46 53 4c 56 52 53 51 55 4e 4c 4c 55}
    condition:
        any of them
}

rule SHELLDETECT_phpmyadmin_exploit_0_0_php
{
    strings:
        $ = {54 49 75 4e 69 34 30 4c 58 42 73 4d 69 38 6e 4c 41 6f 6e 4c 33 42 6f 63 45 31 35 51 57 52 74 61 57 34 74 4d 69 34 32 4c 6a 51 74 63 47 77 7a 4c 79 63 73 43 69 63 76 63 47 68 77 54 58 6c 42 5a}
    condition:
        any of them
}

rule SHELLDETECT_b374k_2_0_php
{
    strings:
        $ = {4d 6c 46 6d 59 6e 70 4b 54 58 70 33 61 43 74 43 53 55 73 4b 59 6b 46 50 53 54 52 6a 53 47 38 32 56 32 4d 30 5a 79 74 59 54 47 68 46 54 32 39 70 65 47 56 30 65 44 6c 45 62 6a 4e 4f 61 6d 64 50}
    condition:
        any of them
}

rule SHELLDETECT_shell_uploader_13_0_php
{
    strings:
        $ = {70 4f 4f 56 4a 61 4d 45 59 32 62 32 31 56 4e 44 59 30 59 30 6c 50 4d 45 46 6a 4d 55 64 79 57 55 78 6b 65 57 68 4d 52 44 64 55 55 48 4e 45 4c 33 42 30 54 53 74 35 59 57 31 73 52 44 6c 36 64 44}
    condition:
        any of them
}

rule SHELLDETECT_cmd_35_0_php
{
    strings:
        $ = {65 47 74 79 62 33 4a 70 49 44 30 67 49 6d 45 34 59 54 51 33 59 7a 42 68 4d 54 59 33 4e 32 59 77 4e 32 4e 68 5a 57 55 77 4f 47 46 6b 5a 6d 56 69 4e 54 6b 7a 5a 57 51 77 49 6a 73 67 61 57 59 6f}
    condition:
        any of them
}

rule SHELLDETECT_empixcrew_0_0_pl
{
    strings:
        $ = {76 59 32 74 6c 64 43 6b 37 44 51 70 39 44 51 70 7a 5a 57 35 6b 63 6d 46 33 4b 43 52 4a 55 6b 4e 66 59 33 56 79 58 33 4e 76 59 32 74 6c 64 43 77 67 49 6c 42 53 53 56 5a 4e 55 30 63 67 4a 48 42}
    condition:
        any of them
}

rule SHELLDETECT_worse_1_0_php
{
    strings:
        $ = {77 76 64 48 49 2b 49 6a 73 4e 43 67 30 4b 63 48 4a 70 62 6e 51 67 49 6a 78 30 63 6a 34 38 64 47 51 2b 50 47 49 2b 51 32 68 68 62 6d 64 6c 49 47 52 70 63 6d 56 6a 64 47 39 79 65 54 6f 38 4c 32}
    condition:
        any of them
}

rule SHELLDETECT_winx_0_0_php
{
    strings:
        $ = {56 56 4a 46 4a 31 30 75 49 6a 77 76 5a 6d 39 75 64 44 34 38 4c 33 52 6b 50 69 49 37 43 6e 42 79 61 57 35 30 49 43 41 67 49 43 49 38 4c 33 52 79 50 69 49 37 43 6e 42 79 61 57 35 30 49 43 41 67}
    condition:
        any of them
}

rule SHELLDETECT_wso_11_0_php
{
    strings:
        $ = {5a 54 4e 5a 59 7a 4a 61 57 44 64 73 64 57 4e 32 4e 6c 6c 47 65 6a 5a 42 5a 30 52 6c 4e 58 46 61 53 47 55 78 4e 53 74 6e 64 6b 78 76 55 30 31 6d 4e 48 6c 48 51 6d 78 32 4e 48 5a 70 4d 48 68 56}
    condition:
        any of them
}

rule SHELLDETECT_b374k_14_0_php
{
    strings:
        $ = {50 58 74 39 4b 54 74 32 59 58 49 67 5a 7a 31 6a 4c 6d 49 75 59 32 78 70 59 32 73 37 5a 33 78 38 4b 47 63 39 59 79 35 69 4c 6d 4e 73 61 57 4e 72 50 58 74 39 4c 47 4d 75 62 32 35 6a 62 47 6c 6a}
    condition:
        any of them
}

rule SHELLDETECT_c99_15_0_php
{
    strings:
        $ = {6c 78 34 5a 6a 56 63 65 47 51 32 58 48 68 6a 59 31 78 34 4e 6d 56 63 65 47 4a 68 58 48 67 77 5a 6c 78 34 4d 6a 52 63 65 47 4d 32 58 48 67 35 59 31 78 34 4e 47 56 63 65 47 4d 30 58 48 68 6c 4e}
    condition:
        any of them
}

rule SHELLDETECT_coderz_1_0_php
{
    strings:
        $ = {79 38 76 4f 56 52 5a 4e 44 41 31 56 32 5a 78 54 32 31 32 61 6b 6b 72 59 6b 68 76 59 57 39 52 63 30 31 52 65 46 49 72 64 58 56 69 62 6a 64 69 64 53 73 77 5a 69 38 76 4c 33 6c 49 4e 55 4a 42 52}
    condition:
        any of them
}

rule SHELLDETECT_wso_9_0_php
{
    strings:
        $ = {52 6c 49 44 30 67 51 47 6c 75 61 56 39 6e 5a 58 51 6f 4a 33 4e 68 5a 6d 56 66 62 57 39 6b 5a 53 63 70 4f 77 30 4b 61 57 59 6f 49 53 52 7a 59 57 5a 6c 58 32 31 76 5a 47 55 70 44 51 6f 67 49 43}
    condition:
        any of them
}

rule SHELLDETECT_mysql_3_0_php
{
    strings:
        $ = {50 6a 78 68 49 47 68 79 5a 57 59 39 4a 79 52 51 53 46 42 66 55 30 56 4d 52 6a 39 68 59 33 52 70 62 32 34 39 64 58 52 70 62 48 4d 6d 59 32 39 74 62 57 46 75 5a 44 31 7a 61 47 39 33 58 33 42 79}
    condition:
        any of them
}

rule SHELLDETECT_snipershell_1_0_php
{
    strings:
        $ = {53 64 75 4a 7a 34 38 5a 6d 39 75 64 43 42 6d 59 57 4e 6c 50 58 52 68 61 47 39 74 59 53 42 7a 61 58 70 6c 50 53 30 79 50 6a 78 69 50 6d 38 74 4c 53 31 62 49 46 4e 75 53 58 42 46 63 6c 39 54 51}
    condition:
        any of them
}

rule SHELLDETECT_filesman_22_0_php
{
    strings:
        $ = {46 6c 62 58 45 33 54 6e 46 33 4f 48 4e 59 51 6c 6b 77 4d 6c 59 30 64 33 51 77 52 7a 6c 71 64 48 64 58 54 48 4a 48 65 45 68 68 62 56 46 6d 54 47 30 34 51 58 4a 53 5a 44 4e 6d 4c 33 70 6d 51 7a}
    condition:
        any of them
}

rule SHELLDETECT_wso_3_0_php
{
    strings:
        $ = {68 63 6e 4a 68 65 53 6b 37 43 69 41 67 49 43 41 67 49 43 41 67 66 51 6f 67 49 43 41 67 49 43 41 67 49 43 52 66 55 45 39 54 56 43 41 39 49 48 4e 30 63 6d 6c 77 63 32 78 68 63 32 68 6c 63 31 39}
    condition:
        any of them
}

rule SHELLDETECT_wso_10_0_php
{
    strings:
        $ = {74 6d 5a 6d 68 56 57 6d 6f 7a 53 48 68 4d 52 55 52 74 63 6a 46 4a 5a 30 6c 6e 63 56 56 35 59 32 68 4c 53 33 55 34 63 6a 6b 32 62 55 4a 45 53 47 74 51 53 45 67 30 61 6e 59 34 62 53 39 4b 55 30}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_5_0_php
{
    strings:
        $ = {66 59 6e 56 6d 5a 6c 39 77 63 6d 56 77 59 58 4a 6c 4b 43 6b 37 49 41 30 4b 61 57 59 67 4b 43 46 6d 64 57 35 6a 64 47 6c 76 62 6c 39 6c 65 47 6c 7a 64 48 4d 6f 49 6d 4d 35 4f 56 39 7a 5a 58 4e}
    condition:
        any of them
}

rule SHELLDETECT_arab_black_hat_1_0_pl
{
    strings:
        $ = {59 6a 49 31 4d 45 6c 48 54 6e 5a 69 52 7a 6c 35 55 46 4e 4a 61 6b 31 45 51 6b 64 53 61 6b 46 33 53 57 6f 31 4d 32 51 7a 59 33 56 52 57 45 70 6f 57 57 6b 78 51 32 4a 48 52 6d 70 68 4d 6d 68 6f}
    condition:
        any of them
}

rule SHELLDETECT_webadmin_0_2_php
{
    strings:
        $ = {67 4a 47 6c 7a 62 47 46 7a 64 43 41 39 49 47 46 79 63 6d 46 35 4b 44 41 67 50 54 34 67 56 46 4a 56 52 53 6b 37 43 67 6c 6c 59 32 68 76 4b 43 49 4a 50 48 52 79 50 6c 78 75 49 69 6b 37 43 67 6c}
    condition:
        any of them
}

rule SHELLDETECT_pzadv_1_1_php
{
    strings:
        $ = {32 46 69 63 32 39 73 64 58 52 6c 4a 7a 73 4b 58 33 45 75 63 33 52 35 62 47 55 75 64 32 6c 6b 64 47 67 67 50 53 41 6e 4d 54 5a 77 65 43 63 37 43 6c 39 78 57 31 39 75 58 53 67 6e 5a 6e 4a 68 62}
    condition:
        any of them
}

rule SHELLDETECT_entrika_0_0_php
{
    strings:
        $ = {50 44 39 77 61 48 41 4b 4a 47 56 75 64 48 4a 35 58 32 78 70 62 6d 55 39 49 6b 68 42 51 30 74 6c 5a 43 42 69 65 53 42 46 62 6e 52 79 61 55 74 68 49 6a 73 4b 4a 47 5a 77 49 44 30 67 5a 6d 39 77}
    condition:
        any of them
}

rule SHELLDETECT_r57_3_0_php
{
    strings:
        $ = {6c 65 48 51 31 4e 43 63 39 50 69 66 44 6a 38 4f 75 77 36 6a 44 73 63 4f 71 49 4d 4f 79 77 36 58 44 71 73 4f 78 77 37 4c 44 6f 43 44 44 6f 69 44 44 74 4d 4f 67 77 36 6e 44 71 38 4f 67 77 37 55}
    condition:
        any of them
}

rule SHELLDETECT_b64shell_0_0_php
{
    strings:
        $ = {6e 57 54 4a 47 65 6c 70 54 51 57 6c 6a 52 31 4a 74 53 57 70 76 5a 30 70 48 54 6a 42 6c 57 45 4a 73 55 46 4e 4b 61 47 4e 49 51 6e 4e 68 56 30 35 6f 5a 45 64 73 64 6d 4a 70 4f 58 64 61 52 31 6c}
    condition:
        any of them
}

rule SHELLDETECT_stunshell_3_0_php
{
    strings:
        $ = {4f 53 55 77 34 55 55 31 79 57 46 56 6a 59 30 70 47 59 6b 78 36 62 6b 4a 30 4d 30 4e 78 59 57 49 35 64 6c 46 34 56 32 68 4c 55 47 46 32 4b 32 39 68 4d 6b 46 79 55 57 5a 33 53 6a 59 34 4c 30 4a}
    condition:
        any of them
}

rule SHELLDETECT_backdoorconnect_0_0_pl
{
    strings:
        $ = {6d 35 6c 59 33 52 43 59 57 4e 72 49 45 4a 68 59 32 74 6b 62 32 39 79 49 48 5a 7a 49 44 45 75 4d 43 42 69 65 53 42 4d 62 33 4a 45 49 47 39 6d 49 45 6c 53 51 55 34 67 53 45 46 44 53 30 56 53 55}
    condition:
        any of them
}

rule SHELLDETECT_nstview_1_0_php
{
    strings:
        $ = {69 62 6d 39 6f 64 58 41 67 4c 33 52 74 63 43 39 75 63 33 52 66 59 6d 51 67 4a 69 49 70 4f 77 70 31 62 6d 78 70 62 6d 73 6f 49 69 39 30 62 58 41 76 62 6e 4e 30 58 32 4e 66 59 6d 51 75 59 79 49}
    condition:
        any of them
}

rule SHELLDETECT_n3fa5t1ca_0_0_php
{
    strings:
        $ = {6c 4f 77 30 4b 44 51 6f 67 49 43 42 39 44 51 6f 4e 43 67 30 4b 44 51 70 6d 64 57 35 6a 64 47 6c 76 62 69 42 6e 5a 58 52 66 63 47 56 79 62 58 4d 6f 4a 47 5a 75 4b 51 30 4b 44 51 70 37 44 51 6f}
    condition:
        any of them
}

rule SHELLDETECT_iframe_0_0_php
{
    strings:
        $ = {57 43 63 75 4a 7a 4a 4f 64 6d 4a 75 4a 79 34 6e 55 6d 78 6c 53 46 49 6e 4c 69 64 6d 57 54 4e 4b 62 46 6c 59 55 69 63 75 4a 32 77 6e 4b 53 78 69 59 58 4e 6c 4e 6a 52 66 5a 47 56 6a 62 32 52 6c}
    condition:
        any of them
}

rule SHELLDETECT_cmd_36_0_php
{
    strings:
        $ = {4d 54 77 6c 51 43 42 51 59 57 64 6c 49 45 78 68 62 6d 64 31 59 57 64 6c 50 53 4a 4b 63 32 4e 79 61 58 42 30 49 69 55 2b 50 43 56 6c 64 6d 46 73 4b 46 4a 6c 63 58 56 6c 63 33 51 75 53 58 52 6c}
    condition:
        any of them
}

rule SHELLDETECT_cmd_27_0_php
{
    strings:
        $ = {62 62 3a 4a 46 39 62 58 54 30 72 4b 79 52 66 58 7a 73 67 4a 46 39 62 58 54 30 6b 58 31 73 74 4c 53 52 66 58 31 31 62 4a 46 39 66 50 6a 34 6b 58 31 39 64 4f 79 52 66 57 79 52 66 58 31 30 75 50 53 67 6f 4a 46 39 66 4b 79 52 66 58 79 6b 72 49 43 52 66 57 79 52 66 58 79 30 6b 58 31 39 64 4b 53 34 6f 4a 46 39 66 4b 79 52 66 58 79 73 6b 58 31 38 70 4b 79 52 66 57 79 52 66 58 79 30 6b 58 31 39 64 4f 77 3d 3d}
    condition:
        any of them
}

rule SHELLDETECT_120667kk_0_0_php
{
    strings:
        $ = {64 47 5a 76 63 6d 30 6e 58 53 6b 70 44 51 6f 67 49 43 41 67 65 77 30 4b 49 43 41 67 49 43 41 6b 5a 69 41 39 49 43 52 66 52 30 56 55 57 79 64 6d 61 57 78 6c 4a 31 30 37 44 51 6f 67 49 43 41 67}
    condition:
        any of them
}

rule SHELLDETECT_stunshell_4_0_php
{
    strings:
        $ = {4e 4c 33 64 42 64 54 4a 31 62 6c 4a 68 65 6c 4a 71 56 55 6c 79 59 58 4e 51 63 32 70 58 55 57 56 34 4b 30 39 46 63 45 70 44 57 6e 70 54 52 7a 52 6b 51 7a 46 59 53 6a 5a 7a 53 30 4e 55 57 6b 4e}
    condition:
        any of them
}

rule SHELLDETECT_cmd_28_0_php
{
    strings:
        $ = {6a 34 38 61 57 35 77 64 58 51 67 62 6d 46 74 5a 54 30 69 59 32 31 6b 49 69 42 30 65 58 42 6c 50 53 4a 30 5a 58 68 30 49 69 42 7a 61 58 70 6c 50 53 49 78 4d 7a 67 69 49 48 5a 68 62 48 56 6c 50}
    condition:
        any of them
}

rule SHELLDETECT_xinfo_0_0_php
{
    strings:
        $ = {38 4c 33 52 68 59 6d 78 6c 50 69 49 37 43 67 6f 67 4a 48 42 6c 63 6d 52 70 63 69 41 39 49 45 42 77 5a 58 4a 74 61 58 4e 7a 61 57 39 75 63 79 68 6d 61 57 78 6c 63 47 56 79 62 58 4d 6f 4a 48 52}
    condition:
        any of them
}

rule SHELLDETECT_c99_11_0_php
{
    strings:
        $ = {4e 66 59 58 4a 79 49 44 30 67 4a 47 35 76 64 47 78 7a 49 44 30 67 62 6e 56 73 62 44 73 4b 4a 48 56 6b 49 44 30 67 64 58 4a 73 5a 57 35 6a 62 32 52 6c 4b 43 52 6b 4b 54 73 4b 50 7a 34 38 61 48}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_21_0_php
{
    strings:
        $ = {72 51 6d 70 48 54 56 6b 32 4e 31 42 43 54 58 4a 31 64 7a 68 6a 4e 58 52 6c 54 6a 49 31 64 6b 52 46 56 32 34 35 62 6b 6c 6a 61 6a 6c 7a 51 6d 39 70 62 57 4e 32 5a 55 56 75 53 47 45 34 51 57 55}
    condition:
        any of them
}

rule SHELLDETECT_shellatildi_0_0_php
{
    strings:
        $ = {69 41 67 49 43 41 67 49 47 4a 79 5a 57 46 72 4f 77 30 4b 49 43 41 67 66 51 30 4b 44 51 6f 67 49 43 41 76 4c 79 42 58 59 57 6c 30 49 48 56 75 64 47 6c 73 49 47 45 67 59 32 39 74 62 57 46 75 5a}
    condition:
        any of them
}

rule SHELLDETECT_filesman_4_0_php
{
    strings:
        $ = {52 30 61 55 6f 32 4d 48 6b 7a 4d 58 42 42 54 33 42 45 52 6e 6c 4b 5a 55 64 6f 62 30 35 55 62 58 42 4f 63 54 68 43 56 33 4d 77 65 57 46 36 4f 45 6c 7a 54 47 78 43 62 55 31 6d 51 6b 39 6c 64 32}
    condition:
        any of them
}

rule SHELLDETECT_nstview_3_0_php
{
    strings:
        $ = {49 43 68 75 63 33 51 70 49 48 64 6f 61 57 4e 6f 49 47 78 35 62 6e 67 4e 43 6b 6c 7a 49 47 78 70 62 6d 74 7a 49 47 6c 75 63 33 52 68 62 47 78 6c 5a 44 38 67 4b 47 35 7a 64 43 6b 67 64 32}
    condition:
        any of them
}

rule SHELLDETECT_blood3rpriv8_0_0_php
{
    strings:
        $ = {62 57 46 70 62 43 68 7a 4b 53 45 69 4b 54 73 4e 43 67 30 4b 66 51 30 4b 5a 57 4e 6f 62 79 41 69 55 33 56 6a 59 32 56 7a 63 32 5a 31 62 47 78 35 49 48 4e 6c 62 6e 51 67 62 57 46 70 62 43 68 7a}
    condition:
        any of them
}

rule SHELLDETECT_stakershell_0_0_php
{
    strings:
        $ = {5a 54 30 69 64 47 56 34 64 43 49 67 62 6d 46 74 5a 54 30 69 62 6e 4a 6c 62 6d 46 74 5a 53 49 2b 44 51 6f 38 61 57 35 77 64 58 51 67 64 48 6c 77 5a 54 30 69 63 33 56 69 62 57 6c 30 49 69 42 32}
    condition:
        any of them
}

rule SHELLDETECT_mysql_5_0_php
{
    strings:
        $ = {67 50 53 41 69 5a 6e 56 75 59 33 52 70 62 32 35 7a 49 69 6b 67 65 77 6f 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 42 70 5a 69 41 6f 4a 48 4e 30 59 58 52 6c 50 54 30 78 4b 53 42 37 43 69 41}
    condition:
        any of them
}

rule SHELLDETECT_devilzshell_1_0_php
{
    strings:
        $ = {41 39 49 43 4a 6b 5a 58 5a 70 62 48 70 54 61 47 56 73 62 43 49 37 44 51 6f 6b 63 32 68 6c 62 47 78 66 5a 6d 46 72 5a 56 39 75 59 57 31 6c 49 44 30 67 49 6c 4e 6c 63 6e 5a 6c 63 69 42 4d 62 32}
    condition:
        any of them
}

rule SHELLDETECT_c99_7_0_php
{
    strings:
        $ = {79 59 6a 4d 54 59 77 4e 54 73 6d 49 7a 45 32 4d 44 67 37 4a 69 4d 78 4e 6a 41 79 4f 79 59 6a 4d 54 55 35 4d 7a 73 38 4c 32 5a 76 62 6e 51 2b 50 43 39 7a 63 47 46 75 50 6a 78 6d 62 32 35 30 49}
    condition:
        any of them
}

rule SHELLDETECT_rootshell_0_0_php
{
    strings:
        $ = {68 62 57 55 70 4f 77 30 4b 66 51 30 4b 5a 57 78 7a 5a 57 6c 6d 4b 43 52 66 55 45 39 54 56 46 73 6e 64 48 6c 77 5a 53 64 64 50 54 30 33 4b 51 30 4b 65 77 30 4b 5a 57 4e 6f 62 79 42 68 62 47 6c}
    condition:
        any of them
}

rule SHELLDETECT_c99_3_0_php
{
    strings:
        $ = {52 7a 68 4f 65 47 73 77 62 31 42 6b 52 31 6c 47 59 32 4e 42 57 45 56 54 54 54 52 74 61 31 64 4b 54 44 4d 31 4c 32 5a 71 55 54 51 30 54 44 68 7a 56 54 52 46 4d 32 6f 78 54 31 5a 70 62 46 42 6e}
    condition:
        any of them
}

rule SHELLDETECT_spam_1_0_php
{
    strings:
        $ = {48 4d 6f 4a 48 59 32 4e 6d 49 78 4f 44 67 32 4e 69 77 67 4e 44 41 35 4e 69 6b 70 49 48 73 67 4a 48 59 34 5a 44 63 33 4e 32 59 7a 4f 43 41 75 50 53 41 6b 64 6a 4d 30 4d 57 4a 6c 4f 54 64 6b 4f}
    condition:
        any of them
}

rule SHELLDETECT_backup_1_2_php
{
    strings:
        $ = {49 47 52 6c 62 47 56 30 5a 53 42 30 61 47 55 67 5a 33 70 70 63 43 42 6d 61 57 78 6c 49 47 46 73 63 32 38 75 49 45 6b 67 63 6d 56 6a 62 32 31 74 5a 57 35 6b 49 47 78 6c 59 58 5a 70 62 6d 63 67}
    condition:
        any of them
}

rule SHELLDETECT_pbot_0_0_php
{
    strings:
        $ = {70 5a 69 68 70 63 33 4e 6c 64 43 67 6b 59 32 31 6b 57 7a 46 64 4b 53 41 6d 4a 69 41 6b 59 32 31 6b 57 7a 46 64 49 44 30 39 49 6a 41 77 4d 53 49 70 44 51 6f 67 49 43 41 67 49 43 41 67 65 77 30}
    condition:
        any of them
}

rule SHELLDETECT_webshell_0_0_php
{
    strings:
        $ = {62 6b 78 75 4d 31 46 69 56 46 4a 6a 62 30 68 55 61 47 74 44 51 6c 4a 55 53 58 70 6e 55 6b 31 5a 51 55 5a 53 62 56 6c 76 4e 58 42 49 63 55 46 48 61 6e 70 57 63 57 68 44 59 33 46 6e 52 33 42 6a}
    condition:
        any of them
}

rule SHELLDETECT_b374k_8_0_php
{
    strings:
        $ = {69 49 69 34 6b 63 48 64 6b 4c 69 4a 63 49 69 41 76 50 67 6f 4a 43 54 77 76 5a 6d 39 79 62 54 34 4b 43 51 6b 38 4c 32 52 70 64 6a 34 69 4f 77 6f 4a 43 53 52 7a 58 33 4a 6c 63 33 56 73 64 43 41}
    condition:
        any of them
}

rule SHELLDETECT_c99_0_0_php
{
    strings:
        $ = {31 5a 32 55 44 4d 33 54 45 56 42 56 47 46 76 55 58 42 45 55 47 30 30 54 31 4e 7a 59 6e 70 54 65 55 31 30 59 69 39 32 65 6a 42 4a 4e 57 39 6d 52 47 70 31 4e 7a 59 30 62 30 6f 79 4e 56 52 69 57}
    condition:
        any of them
}

rule SHELLDETECT_FaTaLisTiCz_1_0_php
{
    strings:
        $ = {49 43 41 67 4a 48 42 79 59 33 4d 67 50 53 42 68 63 6e 4a 68 65 53 67 70 4f 77 30 4b 49 43 41 67 49 43 41 67 64 57 35 7a 5a 58 51 6f 4a 48 4e 30 59 57 4e 72 57 7a 42 64 4b 54 73 4e 43 69 41 67}
    condition:
        any of them
}

rule SHELLDETECT_klasvayv_0_0_asp
{
    strings:
        $ = {78 76 63 6a 30 69 55 6d 56 6b 49 6a 34 67 43 69 41 67 49 43 41 67 49 43 41 67 49 43 41 38 64 47 56 34 64 47 46 79 5a 57 45 67 62 6d 46 74 5a 54 30 69 5a 48 56 36 5a 57 35 34 49 69 41 4b 49 43}
    condition:
        any of them
}

rule SHELLDETECT_wso_14_0_php
{
    strings:
        $ = {53 57 56 48 5a 45 52 44 5a 57 52 4c 56 6b 70 66 54 6b 46 50 4e 6e 6b 71 64 48 6c 6e 63 6b 68 71 63 43 70 4d 4e 45 70 61 4f 58 70 42 65 6b 35 7a 5a 6b 6c 58 54 45 31 43 4e 46 70 48 4d 6e 52 79}
    condition:
        any of them
}

rule SHELLDETECT_shellbot_1_0_pl
{
    strings:
        $ = {69 41 6b 63 47 39 79 64 47 45 73 49 46 42 79 62 33 52 76 49 44 30 2b 49 43 64 30 59 33 41 6e 4c 43 42 55 61 57 31 6c 62 33 56 30 49 44 30 2b 49 44 51 70 4f 77 6f 67 49 43 41 67 49 43 41 67 49}
    condition:
        any of them
}

rule SHELLDETECT_phvayv_0_0_php
{
    strings:
        $ = {54 41 77 4a 53 49 67 61 57 51 39 49 6b 46 31 64 47 39 4f 64 57 31 69 5a 58 49 30 49 69 42 6f 5a 57 6c 6e 61 48 51 39 49 6a 45 35 49 6a 34 4b 49 43 41 67 49 43 41 67 49 43 41 67 49 44 78 30 63}
    condition:
        any of them
}

rule SHELLDETECT_zorro_1_0_pl
{
    strings:
        $ = {6c 6c 62 6e 52 6c 4c 54 35 79 5a 57 31 76 64 6d 55 6f 4a 47 5a 6f 4b 54 73 4b 49 43 41 67 49 43 41 67 4a 47 5a 6f 4c 54 35 6a 62 47 39 7a 5a 54 73 4b 49 43 41 67 49 43 41 67 5a 47 56 73 5a 58}
    condition:
        any of them
}

rule SHELLDETECT_i47_0_0_php
{
    strings:
        $ = {73 62 6d 74 68 53 48 4e 35 56 54 59 34 53 48 70 78 53 6b 74 79 4e 69 39 6d 4e 33 6c 5a 54 56 68 79 59 57 4e 57 59 6e 64 6d 54 31 5a 71 54 48 68 6d 54 6d 4d 33 64 56 68 30 4b 33 5a 30 63 44 6c}
    condition:
        any of them
}

rule SHELLDETECT_lostdc_0_0_php
{
    strings:
        $ = {7a 35 63 62 69 49 37 43 69 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 63 48 4a 70 62 6e 51 67 49 6c 4e 6a 63 6d 6c 77 64 44 6f 67 50 47 4a 79 49 43 38 2b 50}
    condition:
        any of them
}

rule SHELLDETECT_c99_12_0_php
{
    strings:
        $ = {43 38 76 5a 53 35 6e 49 43 4a 6a 4f 69 49 73 49 43 49 76 49 69 77 69 4c 32 68 76 62 57 55 69 43 69 52 30 61 57 31 6c 62 47 6c 74 61 58 51 67 50 53 41 32 4d 44 73 67 4c 79 39 73 61 57 31 70 64}
    condition:
        any of them
}

rule SHELLDETECT_removexplorer_0_0_vb
{
    strings:
        $ = {33 56 73 64 41 6f 67 62 48 5a 42 64 48 52 79 61 57 4a 31 64 47 56 7a 49 44 30 67 55 33 42 73 61 58 51 6f 51 32 39 75 64 6d 56 79 64 45 4a 70 62 6d 46 79 65 53 68 42 64 48 52 79 61 57 4a 31 64}
    condition:
        any of them
}

rule SHELLDETECT_ekin0x_0_0_php
{
    strings:
        $ = {6f 49 57 5a 31 62 6d 4e 30 61 57 39 75 58 32 56 34 61 58 4e 30 63 79 68 7a 61 47 56 73 62 46 39 6c 65 47 56 6a 4b 53 6c 37 4a 47 39 77 62 33 41 39 63 47 39 77 5a 57 34 6f 4a 47 39 6a 62 57 51}
    condition:
        any of them
}

rule SHELLDETECT_1n73ction_1_0_php
{
    strings:
        $ = {43 41 67 49 43 41 67 63 48 4a 70 62 6e 52 4d 62 32 64 70 62 69 67 70 4f 77 30 4b 43 55 42 70 62 6d 6c 66 63 32 56 30 4b 43 64 76 64 58 52 77 64 58 52 66 59 6e 56 6d 5a 6d 56 79 61 57 35 6e 4a}
    condition:
        any of them
}

rule SHELLDETECT_zehir4_0_0_asp
{
    strings:
        $ = {49 44 77 76 64 47 51 2b 50 48 52 6b 50 6a 78 6d 62 32 35 30 49 47 4e 76 62 47 39 79 50 58 6c 6c 62 47 78 76 64 7a 35 35 59 58 70 74 59 53 42 35 5a 58 52 72 61 58 4e 70 49 48 5a 68 63 69 45 38}
    condition:
        any of them
}

rule SHELLDETECT_wso_20_0_php
{
    strings:
        $ = {32 59 58 49 67 63 79 78 68 4c 47 6b 73 61 69 78 79 4c 47 4d 73 62 43 78 69 50 57 52 76 59 33 56 74 5a 57 35 30 4c 6d 64 6c 64 45 56 73 5a 57 31 6c 62 6e 52 7a 51 6e 6c 55 59 57 64 4f 59 57 31}
    condition:
        any of them
}

rule SHELLDETECT_egyspider_1_0_php
{
    strings:
        $ = {6b 37 44 51 6f 67 49 43 42 39 44 51 6f 67 49 43 42 70 5a 69 41 6f 58 43 52 6a 59 58 4e 6c 49 44 31 2b 49 43 39 65 62 58 4e 6e 58 48 4d 72 4b 46 78 54 4b 79 6b 67 4b 43 34 71 4b 53 38 70 49 48}
    condition:
        any of them
}

rule SHELLDETECT_gfs_2_0_php
{
    strings:
        $ = {54 64 79 49 37 44 51 6f 6b 63 47 39 79 64 46 73 79 4d 54 41 32 58 53 41 39 49 43 4a 4e 57 6b 46 51 49 6a 73 4e 43 69 52 77 62 33 4a 30 57 7a 49 78 4e 44 42 64 49 44 30 67 49 6b 52 6c 5a 58 42}
    condition:
        any of them
}

rule SHELLDETECT_shell_uploader_9_0_php
{
    strings:
        $ = {32 57 6c 55 7a 61 32 68 45 54 45 74 44 62 47 78 79 62 32 73 30 52 30 35 58 53 46 64 6e 63 31 4e 55 65 56 68 70 4d 31 64 76 64 56 6c 4c 57 44 56 6d 55 30 78 79 57 47 78 79 53 46 6c 57 53 6b 64}
    condition:
        any of them
}

rule SHELLDETECT_shellbot_0_0_pl
{
    strings:
        $ = {44 65 79 52 6b 59 32 4e 7a 62 32 4e 72 66 58 74 6a 64 58 4a 69 65 58 52 6c 66 53 41 39 49 44 41 37 44 51 6f 67 49 43 52 45 51 30 4e 37 4a 47 52 6a 59 33 4e 76 59 32 74 39 65 32 46 79 63 58 56}
    condition:
        any of them
}

rule SHELLDETECT_obet_0_0_php
{
    strings:
        $ = {33 67 73 4a 47 56 30 4c 43 52 6d 62 32 39 30 5a 58 49 73 4a 47 68 6a 64 32 51 37 44 51 70 6c 59 32 68 76 49 43 63 38 61 57 31 6e 49 48 4e 79 59 7a 30 69 61 48 52 30 63 44 6f 76 4c 33 63 77 62}
    condition:
        any of them
}

rule SHELLDETECT_mysql_1_0_php
{
    strings:
        $ = {32 39 79 59 58 52 70 62 32 34 36 62 6d 39 75 5a 51 70 39 43 69 38 76 4c 53 30 2b 43 6a 77 76 63 33 52 35 62 47 55 2b 43 6a 77 76 61 47 56 68 5a 44 34 4b 50 47 4a 76 5a 48 6b 2b 43 6a 77 2f 43}
    condition:
        any of them
}

rule SHELLDETECT_cmd_22_0_php
{
    strings:
        $ = {6b 70 4b 53 6c 37 44 51 70 6c 59 32 68 76 4b 43 4a 54 59 57 5a 6c 49 45 31 76 5a 47 55 67 62 32 59 67 64 47 68 70 63 79 42 54 5a 58 4a 32 5a 58 49 67 61 58 4d 67 4f 69 41 69 4b 54 73 4e 43 6d}
    condition:
        any of them
}

rule SHELLDETECT_h4ntu_0_0_php
{
    strings:
        $ = {46 49 2b 43 6a 77 2f 63 47 68 77 43 69 41 67 66 51 6f 2f 50 67 6f 67 49 44 78 55 55 6a 34 4b 43 69 41 67 50 46 52 45 50 6a 78 45 53 56 59 67 55 31 52 5a 54 45 55 39 49 6d 5a 76 62 6e 51 74 5a}
    condition:
        any of them
}

rule SHELLDETECT_symlink_1_0_php
{
    strings:
        $ = {64 66 59 6d 78 68 62 6d 73 6e 49 47 68 79 5a 57 59 39 4a 79 52 6a 62 32 35 6d 61 57 63 6e 50 6d 4e 76 62 6d 5a 70 5a 7a 77 76 59 54 34 38 4c 33 52 6b 50 6a 78 30 5a 44 34 69 4c 69 52 79 4c 69}
    condition:
        any of them
}

rule SHELLDETECT_r57_4_0_php
{
    strings:
        $ = {4e 51 4d 32 4e 70 4e 45 31 54 63 6d 6c 58 64 6b 56 54 4e 54 46 56 62 32 4e 46 54 45 55 76 55 48 6c 5a 61 47 4e 5a 61 6b 64 72 62 6a 5a 52 62 57 49 7a 52 30 77 30 4f 46 41 77 57 46 70 6b 62 6b}
    condition:
        any of them
}

rule SHELLDETECT_locusshell_0_0_php
{
    strings:
        $ = {59 6d 73 77 64 6b 35 58 4e 48 5a 52 56 58 42 31 54 44 41 77 4d 57 4a 70 4f 57 46 6a 52 7a 52 32 59 6c 5a 77 64 55 77 7a 63 45 74 69 61 54 68 32 54 30 68 6b 51 6c 46 56 4d 54 4e 52 55 30 6c 31}
    condition:
        any of them
}

rule SHELLDETECT_filesman_3_0_php
{
    strings:
        $ = {4d 7a 57 6a 5a 6b 62 30 46 61 65 57 64 73 62 57 46 46 5a 46 6c 6d 64 69 39 4a 62 6d 31 75 61 56 56 49 64 47 56 6d 52 45 46 4a 61 58 4e 73 51 6d 64 43 54 32 45 32 61 6b 4a 61 4b 7a 42 61 65 55}
    condition:
        any of them
}

rule SHELLDETECT_wacking_0_0_php
{
    strings:
        $ = {30 51 6c 52 6d 65 55 52 6d 5a 6e 64 42 52 44 51 32 63 55 46 42 51 55 46 70 4d 7a 4d 34 61 54 41 77 54 58 64 6d 4f 45 56 55 4e 44 46 4e 54 57 5a 35 52 43 39 36 4f 54 4a 42 4d 6d 38 76 57 44 52}
    condition:
        any of them
}

rule SHELLDETECT_wso_17_0_php
{
    strings:
        $ = {52 63 65 44 59 35 62 32 35 68 62 47 78 35 4c 43 42 63 65 44 59 78 49 46 78 34 4d 7a 51 77 4e 43 42 4f 58 48 67 32 5a 6e 52 63 65 44 49 77 58 48 67 30 4e 6c 78 34 4e 6d 5a 63 65 44 63 31 62 6d}
    condition:
        any of them
}

rule SHELLDETECT_stunshell_1_0_php
{
    strings:
        $ = {6b 31 76 51 55 30 77 4e 30 68 4c 56 55 39 33 53 32 4a 31 52 48 64 36 63 33 64 79 64 57 4a 4f 61 6e 4a 6c 56 55 52 47 56 32 64 45 51 6b 46 33 59 57 70 43 4d 30 46 70 59 55 68 48 64 6d 5a 31 65}
    condition:
        any of them
}

rule SHELLDETECT_spam_0_0_php
{
    strings:
        $ = {43 52 32 4d 32 51 79 4e 6d 49 77 59 6a 45 70 49 48 73 67 5a 32 78 76 59 6d 46 73 49 43 52 32 4e 6a 45 35 5a 44 63 31 5a 6a 67 37 49 47 6c 6d 49 43 67 68 61 57 35 66 59 58 4a 79 59 58 6b 6f 4a}
    condition:
        any of them
}

rule SHELLDETECT_1n73ction_2_0_php
{
    strings:
        $ = {46 6f 4d 47 51 35 55 30 52 53 56 7a 4a 74 54 32 4a 59 55 6a 6c 34 64 46 70 35 63 55 56 61 56 6e 70 75 65 6e 5a 32 51 55 68 61 4d 44 64 7a 65 6d 52 46 4e 7a 42 4d 54 6d 74 55 55 55 35 6b 61 33}
    condition:
        any of them
}

rule SHELLDETECT_safemode_4_0_php
{
    strings:
        $ = {43 41 67 49 43 41 67 4c 79 38 4e 43 69 38 76 4c 79 38 76 4c 79 38 76 4c 79 38 76 4c 79 38 76 4c 79 38 76 4c 79 38 76 4c 79 38 76 4c 79 38 76 4c 79 38 76 4c 79 38 4e 43 67 30 4b 44 51 70 70 5a}
    condition:
        any of them
}

rule SHELLDETECT_lurm_0_0_cgi
{
    strings:
        $ = {6a 49 79 4d 6a 49 79 4d 6a 49 79 4d 6a 49 79 4d 6a 49 79 4d 6a 49 79 4d 6a 49 77 6f 4b 49 31 59 67 59 32 56 73 61 6d 46 6f 49 47 35 6c 63 32 46 75 61 32 4e 70 62 32 35 70 63 6d 39 32 59 57 35}
    condition:
        any of them
}

rule SHELLDETECT_filesman_7_0_php
{
    strings:
        $ = {6b 37 49 47 56 34 61 58 51 37 49 48 30 67 50 7a 34 38 50 33 42 6f 63 43 42 70 5a 69 68 70 63 33 4e 6c 64 43 67 6b 58 30 64 46 56 46 73 69 64 44 63 32 4d 6a 52 75 49 6c 30 70 4b 58 73 67 49 43}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_16_0_php
{
    strings:
        $ = {76 64 48 49 2b 58 47 34 69 4f 77 6f 4b 49 43 41 4a 5a 57 4e 6f 62 79 41 69 50 43 39 30 59 57 4a 73 5a 54 34 38 4c 33 52 6b 50 69 49 37 43 67 6f 67 43 57 56 6a 61 47 38 67 49 6a 77 76 64 47 46}
    condition:
        any of them
}

rule SHELLDETECT_kadotshell_1_0_php
{
    strings:
        $ = {47 56 75 5a 43 49 37 44 51 70 69 63 6d 56 68 61 7a 73 4e 43 67 30 4b 44 51 6f 76 4c 31 42 49 55 43 42 46 64 6d 46 73 49 45 4e 76 5a 47 55 67 5a 58 68 6c 59 33 56 30 61 57 39 75 44 51 70 6a 59}
    condition:
        any of them
}

rule SHELLDETECT_irc_bot_1_0_pl
{
    strings:
        $ = {6d 5a 76 63 6d 73 37 44 51 6f 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 48 4e 35 63 33 52 6c 62 53 41 6f 59 43 52 72 61 57 78 73 5a 47 41 70 4f 77 30 4b 49 43 41 67 49 43 41 67 49}
    condition:
        any of them
}

rule SHELLDETECT_r57_2_0_php
{
    strings:
        $ = {6d 49 7a 45 77 4e 7a 63 37 4a 69 4d 78 4d 44 67 31 4f 79 63 73 43 69 64 79 64 56 39 30 5a 58 68 30 4e 6a 51 6e 50 54 34 6e 4a 69 4d 78 4d 44 51 30 4f 79 59 6a 4d 54 41 34 4d 44 73 6d 49 7a 45}
    condition:
        any of them
}

rule SHELLDETECT_asmodeus_0_0_pl
{
    strings:
        $ = {32 52 6c 64 58 4d 67 55 47 56 79 62 43 42 53 5a 57 31 76 64 47 55 67 55 32 68 6c 62 47 78 63 62 69 49 37 43 67 70 7a 65 58 4e 30 5a 57 30 6f 5a 47 46 30 5a 53 6b 37 43 67 70 7a 65 58 4e 30 5a}
    condition:
        any of them
}

rule SHELLDETECT_cmd_10_0_php
{
    strings:
        $ = {50 44 39 77 61 48 41 4e 43 6d 6c 6d 4b 43 52 66 55 45 39 54 56 46 73 69 61 32 56 35 49 6c 30 67 50 54 30 67 49 6d 59 77 5a 47 56 6b 4e 44 64 6b 5a 6d 45 34 59 54 4d 34 5a 47 51 30 4e 6d 55 35}
    condition:
        any of them
}

rule SHELLDETECT_remoteview_0_0_php
{
    strings:
        $ = {35 68 62 57 55 39 4d 53 4e 6a 62 32 35 32 5a 58 4a 30 50 6d 31 6b 4e 54 77 76 59 54 34 70 50 43 39 6f 4d 6a 34 38 55 44 34 69 4f 77 6f 4b 49 43 41 67 61 57 59 67 4b 43 46 70 63 33 4e 6c 64 43}
    condition:
        any of them
}

rule SHELLDETECT_r57_9_0_php
{
    strings:
        $ = {64 59 4b 33 56 6d 4d 46 67 72 56 55 52 75 59 30 6c 45 4d 54 46 34 52 57 6b 79 55 6b 56 51 61 44 42 6b 54 6a 46 6b 62 6e 46 6f 52 56 46 36 62 44 68 6e 64 6c 42 76 54 6c 6c 6d 53 44 46 53 63 58}
    condition:
        any of them
}

rule SHELLDETECT_shellarchive_0_0_php
{
    strings:
        $ = {49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 52 6b 61 58 4a 66 62 47 6c 7a 64 43 41 39 49 47 6c 74 59 58 42 66 62 47 6c 7a 64 43 67 6b 63 33 52 79}
    condition:
        any of them
}

rule SHELLDETECT_priv8_scr_0_0_pl
{
    strings:
        $ = {67 6e 4c 32 68 76 62 57 55 76 4a 79 34 6b 64 58 4e 6c 63 69 34 6e 4c 33 42 31 59 6d 78 70 59 31 39 6f 64 47 31 73 4c 32 46 6a 59 32 56 7a 58 33 64 6c 59 69 39 6a 62 32 35 6d 61 57 63 75 63 47}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_11_0_php
{
    strings:
        $ = {79 4f 58 46 6d 63 48 5a 45 57 6a 49 77 65 56 5a 56 57 45 46 51 49 69 77 69 4d 6b 39 35 4e 57 68 57 55 58 68 55 59 6b 39 72 51 6c 4d 72 61 54 52 61 55 45 56 45 5a 6e 4e 6d 53 6a 45 7a 52 6b 56}
    condition:
        any of them
}

rule SHELLDETECT_b374k_7_0_php
{
    strings:
        $ = {6c 58 55 6b 46 78 4f 58 42 51 55 30 4a 53 63 30 35 31 59 6e 68 6b 4f 53 74 59 59 57 68 32 64 30 35 6c 53 58 46 45 64 46 4a 59 52 48 45 76 65 46 46 4c 57 45 4e 6c 56 44 6c 78 4b 33 51 4e 43 6b}
    condition:
        any of them
}

rule SHELLDETECT_mysql_adminer_0_2_php
{
    strings:
        $ = {51 75 59 58 42 77 5a 57 35 6b 51 32 68 70 62 47 51 6f 5a 57 52 70 64 43 6b 37 5a 6d 6c 6c 62 47 51 75 63 33 52 35 62 47 55 75 5a 47 6c 7a 63 47 78 68 65 54 30 6e 62 6d 39 75 5a 53 63 37 5a 57}
    condition:
        any of them
}

rule SHELLDETECT_loadshell_0_0_php
{
    strings:
        $ = {63 6d 52 6c 63 6a 6f 67 4d 58 42 34 49 48 4e 76 62 47 6c 6b 49 43 4e 44 51 6b 46 43 4e 7a 67 37 49 48 30 4b 49 32 4e 76 62 6e 52 6c 62 6e 51 67 65 79 42 77 59 57 52 6b 61 57 35 6e 4f 69 41 78}
    condition:
        any of them
}

rule SHELLDETECT_filesman_16_0_php
{
    strings:
        $ = {42 56 56 33 49 30 63 33 41 30 55 45 55 76 64 58 4e 42 51 33 70 35 53 45 35 6a 51 7a 51 35 5a 31 45 34 54 45 5a 6f 5a 6e 52 78 4f 44 42 42 4f 48 56 49 51 33 68 55 4b 30 63 72 61 57 35 43 56 6d}
    condition:
        any of them
}

rule SHELLDETECT_r57_6_0_php
{
    strings:
        $ = {58 32 56 34 61 58 4e 30 63 79 67 69 62 57 46 70 62 43 49 70 4b 58 73 4e 43 6d 56 6a 61 47 38 67 4a 48 52 68 59 6d 78 6c 58 33 56 77 4d 53 34 6b 62 47 46 75 5a 31 73 6b 62 47 46 75 5a 33 56 68}
    condition:
        any of them
}

rule SHELLDETECT_tdshell_0_0_php
{
    strings:
        $ = {55 31 52 46 78 62 58 53 39 6e 4c 43 41 69 57 31 30 69 4b 54 73 4b 43 51 6b 4a 43 56 52 45 63 32 68 6c 62 47 78 66 64 47 46 69 63 31 39 74 62 32 52 70 5a 6e 6c 66 64 47 46 69 4b 47 4e 31 63 6e}
    condition:
        any of them
}

rule SHELLDETECT_r57_19_0_php
{
    strings:
        $ = {4d 43 6b 37 43 51 6f 67 61 57 59 6f 49 53 52 6a 62 32 35 75 5a 57 4e 30 61 57 39 75 4b 53 42 37 49 47 5a 6c 4b 43 52 73 59 57 35 6e 64 57 46 6e 5a 53 77 77 4b 54 73 67 66 51 6f 67 5a 57 78 7a}
    condition:
        any of them
}

rule SHELLDETECT_c99_4_0_php
{
    strings:
        $ = {49 69 52 79 5a 57 46 73 4c 33 4e 77 62 47 39 70 64 48 6f 75 65 6d 6c 77 49 6a 73 67 50 7a 34 69 50 6a 78 69 63 6a 34 38 59 6e 49 2b 49 41 6f 38 61 57 35 77 64 58 51 67 64 48 6c 77 5a 54 31 7a}
    condition:
        any of them
}

rule SHELLDETECT_remoteview_1_0_php
{
    strings:
        $ = {51 37 50 43 39 6d 62 32 35 30 50 69 49 70 4f 77 6f 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 38 63 32 4e 79 61 58 42 30 49 48 52 35 63 47 55 39 49 6e 52 6c 65 48 51 76 61 6d}
    condition:
        any of them
}

rule SHELLDETECT_perlwebshell_0_0_pl
{
    strings:
        $ = {4a 45 5a 50 55 6b 31 37 52 45 5a 4a 54 45 56 39 4b 53 6c 62 4e 31 30 37 43 69 41 67 49 43 67 6b 5a 6d 6c 73 5a 57 35 68 62 57 55 67 50 53 41 6b 52 6b 39 53 54 58 74 45 52 6b 6c 4d 52 58 30 70}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_10_0_php
{
    strings:
        $ = {64 54 55 79 63 73 4a 33 64 6c 65 6a 64 51 56 7a 41 35 52 6b 5a 57 63 44 64 53 5a 45 70 73 4a 79 77 6e 62 6b 6c 48 63 69 74 58 62 44 5a 43 54 33 59 34 63 6c 52 35 64 56 63 6e 4c 43 64 56 57 57}
    condition:
        any of them
}

rule SHELLDETECT_dxshell_2_0_php
{
    strings:
        $ = {58 33 49 6f 4a 45 64 4d 54 30 4a 42 54 46 4d 70 4f 79 63 73 44 51 6f 4a 4a 33 42 6f 63 46 39 70 62 6d 6b 6e 43 54 30 2b 43 53 63 6b 53 55 35 4a 50 57 6c 75 61 56 39 6e 5a 58 52 66 59 57 78 73}
    condition:
        any of them
}

rule SHELLDETECT_phpspy_4_0_php
{
    strings:
        $ = {47 51 67 62 6d 39 33 63 6d 46 77 50 69 30 74 50 43 39 30 5a 44 34 6e 4b 54 73 4b 43 51 6b 4a 63 43 67 6e 50 48 52 6b 49 47 35 76 64 33 4a 68 63 44 34 6e 4b 54 73 4b 43 51 6b 4a 63 43 67 6e 50}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_19_0_php
{
    strings:
        $ = {6c 75 5a 33 4d 6e 58 56 73 6e 5a 6d 6c 73 5a 53 31 31 63 47 78 76 59 57 51 6e 58 53 6b 67 65 79 41 2f 50 67 6f 38 59 6e 49 2b 50 47 4a 79 50 67 6f 38 5a 6d 6c 6c 62 47 52 7a 5a 58 51 2b 43 69}
    condition:
        any of them
}

rule SHELLDETECT_jackal_4_0_php
{
    strings:
        $ = {2b 53 47 56 34 50 43 39 30 5a 44 34 38 64 47 51 67 64 32 6c 6b 64 47 67 39 4a 7a 49 31 4a 53 63 67 59 6d 64 6a 62 32 78 76 63 6a 30 6e 49 7a 49 34 4d 6a 67 79 4f 43 63 2b 50 43 39 30 5a 44 34}
    condition:
        any of them
}

rule SHELLDETECT_mysql_0_0_php
{
    strings:
        $ = {67 58 47 34 69 4f 77 70 6c 59 32 68 76 49 43 49 38 59 53 42 6f 63 6d 56 6d 50 53 63 6b 55 45 68 51 58 31 4e 46 54 45 59 2f 59 57 4e 30 61 57 39 75 50 58 5a 70 5a 58 64 45 59 58 52 68 4a 6d 52}
    condition:
        any of them
}

rule SHELLDETECT_wso_13_0_php
{
    strings:
        $ = {59 33 6c 6d 51 57 46 59 61 56 6c 42 57 45 49 7a 51 56 4e 42 53 45 67 30 51 33 6c 42 59 55 46 59 4e 57 31 77 64 6d 46 58 4e 47 39 4b 65 47 5a 33 54 32 6c 6a 63 30 4a 44 52 58 42 47 51 6b 49 35}
    condition:
        any of them
}

rule SHELLDETECT_extplorer_0_2_php
{
    strings:
        $ = {73 49 47 5a 68 62 48 4e 6c 49 43 6b 37 44 51 70 6f 5a 57 46 6b 5a 58 49 6f 49 43 64 51 63 6d 46 6e 62 57 45 36 49 47 35 76 4c 57 4e 68 59 32 68 6c 4a 79 41 70 4f 77 30 4b 44 51 70 6c 59 32 68}
    condition:
        any of them
}

rule SHELLDETECT_rhtool_1_0_asp
{
    strings:
        $ = {56 54 65 58 4e 30 5a 57 31 50 59 6d 70 6c 59 33 51 69 4b 51 6f 4a 43 56 4e 6c 64 43 42 6d 49 44 30 67 5a 6e 4e 76 4c 6b 64 6c 64 45 5a 70 62 47 55 6f 63 33 52 79 52 6d 6c 73 5a 57 35 68 62 57}
    condition:
        any of them
}

rule SHELLDETECT_fatalshell_0_0_php
{
    strings:
        $ = {6e 51 75 50 53 52 73 59 57 35 6e 57 79 64 31 63 47 78 76 59 57 52 76 61 79 64 64 4f 77 70 39 43 67 70 70 5a 69 68 70 63 33 4e 6c 64 43 67 6b 58 31 42 50 55 31 52 62 4a 33 56 77 62 47 39 68 5a}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_34_0_php
{
    strings:
        $ = {46 5a 4b 54 7a 4a 6a 57 47 39 6f 63 46 5a 6d 4e 44 6b 72 54 32 5a 32 4e 30 6f 34 57 45 59 34 64 30 52 46 4d 30 74 52 4b 32 5a 52 64 6c 70 6e 54 30 4a 45 51 6c 68 52 5a 48 46 4a 59 6a 68 6f 54}
    condition:
        any of them
}

rule SHELLDETECT_cmd_19_0_php
{
    strings:
        $ = {48 55 77 4d 44 59 7a 58 48 55 77 4d 44 59 31 58 48 55 77 4d 44 59 30 58 48 55 77 4d 44 59 35 58 48 55 77 4d 44 5a 44 58 48 55 77 4d 44 4e 43 58 48 55 77 4d 44 49 32 58 48 55 77 4d 44 49 7a 58}
    condition:
        any of them
}

rule SHELLDETECT_zehir4_1_0_php
{
    strings:
        $ = {79 49 69 6b 75 56 6d 46 73 64 57 55 4b 43 57 31 68 65 44 31 76 59 6d 70 56 63 47 78 76 59 57 51 75 52 6d 6c 6c 62 47 52 7a 4b 43 4a 74 59 58 67 69 4b 53 35 57 59 57 78 31 5a 51 6f 4b 43 57 5a}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_36_0_php
{
    strings:
        $ = {76 57 55 39 72 4f 48 4e 78 4f 47 56 6a 55 6d 70 49 62 6a 46 6d 56 30 4a 34 4b 7a 4d 79 61 6e 64 6d 56 58 4a 43 65 6e 41 33 57 55 64 4a 5a 48 6c 6c 4d 6c 70 43 62 47 6c 4b 57 6e 4a 69 5a 58 51}
    condition:
        any of them
}

rule SHELLDETECT_c99_24_0_php
{
    strings:
        $ = {63 32 68 7a 61 47 56 34 61 58 51 6f 4b 54 74 39 43 6d 6c 6d 49 43 67 6b 59 57 4e 30 49 44 30 39 49 43 4a 7a 5a 57 4e 31 63 6d 6c 30 65 53 49 70 43 6e 73 4b 49 47 56 6a 61 47 38 67 49 6a 78 6a}
    condition:
        any of them
}

rule SHELLDETECT_simattacker_1_0_php
{
    strings:
        $ = {64 47 67 69 4c 43 4a 33 4b 79 49 70 4f 77 6f 4a 5a 6e 64 79 61 58 52 6c 49 43 67 6b 5a 6e 41 73 49 69 49 70 49 44 73 4b 43 57 5a 33 63 6d 6c 30 5a 53 41 6f 4a 47 5a 77 4c 43 52 7a 59 58 5a 6c}
    condition:
        any of them
}

rule SHELLDETECT_wso_15_0_php
{
    strings:
        $ = {63 6c 64 35 64 47 5a 56 4d 33 4e 52 51 32 55 35 59 55 5a 59 62 56 4e 4e 5a 45 4e 53 53 45 5a 30 52 44 42 6d 4d 44 5a 55 54 44 64 4c 65 57 39 6e 4f 55 4a 5a 64 6c 70 51 52 45 56 54 4e 47 78 44}
    condition:
        any of them
}

rule SHELLDETECT_casus15_0_0_php
{
    strings:
        $ = {49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 6b 5a 47 39 7a 50 53 41 69 51 76 5a 35 62 47 55 67 51 6d 6c 79 49 45 52 76 63 33 6c 68 49 46 5a 68 63 6d 52 35}
    condition:
        any of them
}

rule SHELLDETECT_telnet_0_0_pl
{
    strings:
        $ = {31 6c 50 53 51 78 58 47 35 63 62 69 49 37 43 69 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 42 77 63 6d 6c 75 64 43 42 33 61 47 6c 73 5a 53 67 38 55 30 56 4f 52 45 5a 4a 54 45}
    condition:
        any of them
}

rule SHELLDETECT_cristercorp_infocollector_0_0_php
{
    strings:
        $ = {79 4b 45 42 70 62 6d 6c 66 5a 32 56 30 4b 43 4a 7a 59 57 5a 6c 58 32 31 76 5a 47 55 69 4b 53 6b 67 50 54 30 67 49 6d 39 75 49 69 6b 67 65 79 41 67 4a 48 4e 68 5a 6d 56 74 62 32 52 6c 49 44 30}
    condition:
        any of them
}

rule SHELLDETECT_filesman_24_0_php
{
    strings:
        $ = {5a 70 5a 79 35 77 61 48 41 69 4c 41 30 4b 43 51 6b 69 62 47 39 6a 59 58 52 6c 49 47 4e 76 62 6d 5a 70 5a 79 35 70 62 6d 4d 69 49 44 30 2b 49 43 4a 73 62 32 4e 68 64 47 55 67 59 32 39 75 5a 6d}
    condition:
        any of them
}

rule SHELLDETECT_tbdsecurity_0_0_php
{
    strings:
        $ = {6a 56 46 42 4b 54 7a 68 72 61 45 64 77 5a 32 30 31 64 31 68 61 53 6c 70 30 63 6e 46 54 62 55 35 32 4b 32 74 49 53 56 46 49 4f 55 39 72 56 55 39 69 61 43 74 43 52 56 68 44 63 57 35 53 65 54 6c}
    condition:
        any of them
}

rule SHELLDETECT_wso_12_0_php
{
    strings:
        $ = {46 55 53 47 68 53 55 32 35 4b 52 56 4e 48 64 33 6c 4f 4d 57 52 68 54 54 41 31 59 57 4e 59 56 54 42 4f 56 46 6b 78 56 44 46 57 61 46 70 57 51 6d 35 50 56 7a 6b 32 57 58 6b 35 53 46 51 79 56 54}
    condition:
        any of them
}

rule SHELLDETECT_backdoor_3_0_php
{
    strings:
        $ = {44 56 45 31 34 61 6b 52 55 54 31 5a 55 5a 56 6c 30 53 47 46 73 63 30 64 31 62 6d 4e 49 56 47 78 32 59 33 4a 47 65 45 59 77 57 46 70 56 62 57 35 4b 54 7a 4e 70 57 45 4e 4e 4d 57 70 6d 62 45 78}
    condition:
        any of them
}

rule SHELLDETECT_shell_uploader_4_0_php
{
    strings:
        $ = {7a 4d 76 62 30 70 4f 57 6d 31 4e 4e 30 35 51 51 6e 49 31 59 33 68 79 61 7a 42 7a 4e 55 51 72 55 33 46 71 4d 6b 68 61 59 6b 35 6e 63 47 70 4c 4b 32 68 45 4d 30 63 69 4c 43 4a 49 65 6b 35 50 56}
    condition:
        any of them
}

rule SHELLDETECT_postman_0_1_php
{
    strings:
        $ = {56 78 34 4e 44 68 63 65 44 59 32 58 48 67 7a 4d 31 78 34 4e 44 6c 63 65 44 55 30 58 48 67 31 5a 56 78 34 4e 6d 4a 63 65 44 4d 31 58 48 67 30 4d 46 78 34 4d 32 4e 63 65 44 59 35 58 48 67 7a 4e}
    condition:
        any of them
}

rule SHELLDETECT_coderz_2_0_php
{
    strings:
        $ = {4e 6c 59 6d 56 69 5a 57 49 6e 50 67 30 4b 50 47 4e 6c 62 6e 52 6c 63 6a 34 4e 43 6a 78 69 50 6a 78 6d 62 32 35 30 49 48 4e 70 65 6d 55 39 4a 7a 59 6e 49 47 5a 68 59 32 55 39 4a 31 64 6c 59 6d}
    condition:
        any of them
}

rule SHELLDETECT_locusshell_2_0_php
{
    strings:
        $ = {48 4f 57 74 51 56 6b 4a 51 56 54 46 52 4b 31 42 48 62 48 56 6a 53 46 59 77 53 55 68 53 4e 57 4e 48 56 54 6c 68 52 32 78 72 57 6b 64 57 64 55 6c 48 4e 57 68 69 56 31 55 35 57 56 64 4f 4d 45 6c}
    condition:
        any of them
}

rule SHELLDETECT_nixshell_1_0_php
{
    strings:
        $ = {4e 70 64 47 55 73 49 44 67 77 4c 43 41 6b 5a 58 4a 79 62 6d 38 73 49 43 52 6c 63 6e 4a 7a 64 48 49 73 49 44 4d 77 4b 54 73 67 44 51 70 70 5a 69 41 6f 49 53 52 6d 63 43 6b 67 65 79 41 4e 43 69}
    condition:
        any of them
}

rule SHELLDETECT_webadmin_1_2_php
{
    strings:
        $ = {56 2f 6a 5a 41 78 55 49 42 4f 30 63 38 7a 4b 63 53 6d 74 31 72 67 4e 68 4e 30 79 38 67 6d 4f 78 70 77 6c 78 64 47 34 44 5a 4c 4a 41 56 35 74 71 64 70 71 6d 4b 77 75 70 35 45 79 43 36 4a 54 32}
    condition:
        any of them
}

rule SHELLDETECT_telnetd_2_0_pl
{
    strings:
        $ = {39 6e 4f 77 6f 4b 49 43 42 70 5a 69 41 6f 4a 48 4a 6c 63 58 56 70 63 6d 55 70 49 48 73 4b 49 43 41 67 49 43 4d 67 59 57 78 73 49 47 5a 76 64 57 35 6b 49 47 64 76 62 6d 35 68 49 47 4a 6c 49 47}
    condition:
        any of them
}

rule SHELLDETECT_phpshell_3_0_php
{
    strings:
        $ = {68 79 5a 57 59 39 49 69 56 7a 50 33 64 76 63 6d 74 66 5a 47 6c 79 50 53 56 7a 49 6a 34 6c 63 7a 77 76 59 54 34 76 74 43 77 4b 4a 46 42 49 55 46 39 54 52 55 78 47 4c 43 42 31 63 6d 78 6c 62 6d}
    condition:
        any of them
}

rule SHELLDETECT_safemode_3_0_php
{
    strings:
        $ = {30 5a 58 49 2b 50 48 52 68 59 6d 78 6c 50 6a 78 30 63 6a 34 38 64 47 51 2b 50 47 5a 76 63 6d 30 67 59 57 4e 30 61 57 39 75 50 56 77 69 4a 46 4e 47 61 57 78 6c 54 6d 46 74 5a 54 38 6b 64 58 4a}
    condition:
        any of them
}

rule SHELLDETECT_devilz0de_0_0_php
{
    strings:
        $ = {63 6d 46 75 5a 32 55 6f 49 6b 45 69 4c 43 4a 61 49 69 6b 67 59 58 4d 67 4a 47 78 6c 64 48 52 6c 63 69 6b 67 44 51 6f 4a 65 79 41 4e 43 67 6b 6b 59 6d 39 76 62 43 41 39 49 45 42 70 63 31 39 6b}
    condition:
        any of them
}

rule SHELLDETECT_lostdc_1_0_php
{
    strings:
        $ = {30 5a 44 35 63 62 69 49 37 44 51 70 77 63 6d 6c 75 64 43 41 69 50 48 52 6b 50 6c 73 67 50 47 45 67 59 32 78 68 63 33 4d 67 50 53 42 63 49 6d 68 6c 59 57 52 63 49 69 42 6f 63 6d 56 6d 49 44 30}
    condition:
        any of them
}

rule SHELLDETECT_v0ld3m0rt_0_0_php
{
    strings:
        $ = {53 57 35 4d 62 57 67 77 59 6c 64 34 65 6d 4e 48 56 6d 70 68 56 30 5a 7a 57 54 4a 6f 61 47 4e 75 54 57 39 4b 52 6a 6c 52 56 44 46 4f 56 56 64 35 5a 47 68 4b 4d 54 42 77 54 47 6c 6a 61 56 42 70}
    condition:
        any of them
}

rule SHELLDETECT_pbot_2_0_php
{
    strings:
        $ = {63 4d 6d 4a 76 64 46 77 79 58 54 6f 67 63 47 68 77 59 6d 39 30 49 44 49 75 4d 43 42 69 65 54 73 67 49 32 4e 79 5a 58 64 41 59 32 39 79 63 43 34 69 4b 54 73 4e 43 69 41 67 49 43 41 67 49 43 41}
    condition:
        any of them
}

rule SHELLDETECT_kral_0_0_php
{
    strings:
        $ = {51 74 59 32 39 73 62 33 49 36 49 43 4d 77 4d 44 41 77 4d 44 41 37 43 6e 30 4b 4c 6e 4e 30 65 57 78 6c 4e 43 42 37 5a 6d 39 75 64 43 31 33 5a 57 6c 6e 61 48 51 36 49 47 4a 76 62 47 52 39 43 6d}
    condition:
        any of them
}

rule SHELLDETECT_hshell_0_0_php
{
    strings:
        $ = {5a 47 31 47 63 32 52 58 56 54 6c 4a 62 45 70 73 59 6d 31 47 64 46 70 55 4f 47 6c 4a 51 7a 67 72 52 46 46 76 4f 46 41 7a 51 6d 39 6a 51 30 49 35 53 55 64 57 63 32 4d 79 56 6e 42 61 61 57 64 72}
    condition:
        any of them
}

rule SHELLDETECT_hostdevil_0_0_php
{
    strings:
        $ = {4e 32 4a 43 62 6c 46 32 64 57 52 34 57 44 4a 75 5a 56 5a 74 4b 7a 52 6f 4d 7a 42 34 4e 31 41 78 55 45 68 32 57 6e 56 48 59 69 74 59 5a 6e 6f 78 56 6d 5a 68 63 6b 6c 68 61 6a 5a 69 63 57 68 5a}
    condition:
        any of them
}

rule SHELLDETECT_aspx_shell_0_0_aspx
{
    strings:
        $ = {39 49 45 4e 76 62 57 31 68 62 6d 52 55 65 58 42 6c 4c 6c 52 6c 65 48 51 37 44 51 6f 67 49 43 41 67 49 43 41 67 49 43 41 67 49 43 42 6a 62 32 31 74 4c 6b 4e 76 62 57 31 68 62 6d 52 55 5a 58 68}
    condition:
        any of them
}

rule SHELLDETECT_itsecteam_shell_2_0_php
{
    strings:
        $ = {43 49 76 49 69 77 67 4a 47 35 68 62 57 55 70 4f 77 6f 6b 5a 6e 49 67 50 53 41 69 58 48 67 31 4d 46 78 34 4e 47 4a 63 65 44 41 7a 58 48 67 77 4e 43 49 37 43 69 52 6d 63 69 41 75 50 53 41 69 58}
    condition:
        any of them
}

rule SHELLDETECT_FaTaLisTiCz_4_0_php
{
    strings:
        $ = {49 48 73 67 61 57 59 67 4b 43 46 70 63 31 39 75 64 57 31 6c 63 6d 6c 6a 4b 43 52 6d 63 57 4a 66 62 47 56 75 5a 32 68 30 4b 53 6b 67 65 79 52 6d 63 57 4a 66 62 47 56 75 5a 32 68 30 49 44 30 67}
    condition:
        any of them
}

rule SHELLDETECT_brute_force_tool_1_0_php
{
    strings:
        $ = {6d 64 70 62 69 31 73 5a 57 5a 30 4f 69 41 31 63 48 67 37 44 51 70 39 44 51 70 70 62 6e 42 31 64 43 41 73 49 48 52 6c 65 48 52 68 63 6d 56 68 49 43 77 67 59 6e 56 30 64 47 39 75 49 43 77 67 59}
    condition:
        any of them
}

rule SHELLDETECT_crystal_0_0_php
{
    strings:
        $ = {67 49 44 68 77 64 43 41 67 49 43 41 67 49 43 41 68 61 57 31 77 62 33 4a 30 59 57 35 30 4f 77 70 69 59 57 4e 72 5a 33 4a 76 64 57 35 6b 4c 57 4e 76 62 47 39 79 4f 69 41 67 49 43 4d 78 4d 54 45}
    condition:
        any of them
}

rule SHELLDETECT_update_0_0_php
{
    strings:
        $ = {63 47 55 39 58 43 4a 30 5a 58 68 30 58 43 49 2b 50 47 4a 79 50 67 70 31 63 32 56 79 62 6d 46 74 5a 53 41 36 49 44 78 4a 54 6c 42 56 56 43 42 7a 61 58 70 6c 50 56 77 69 4d 54 56 63 49 69 42 32}
    condition:
        any of them
}

rule SHELLDETECT_FaTaLisTiCz_5_0_php
{
    strings:
        $ = {58 45 33 55 31 49 76 55 48 4e 61 52 44 5a 77 57 6c 41 35 4d 57 4e 4e 56 43 39 4d 4f 46 64 58 52 58 70 4c 64 6d 4a 6d 56 45 78 4a 4f 46 68 6a 4e 6b 46 71 56 6e 70 72 64 6e 5a 32 4e 32 70 70 4e}
    condition:
        any of them
}

rule SHELLDETECT_jackal_5_0_php
{
    strings:
        $ = {35 6a 64 47 6c 76 62 6e 4d 73 4a 33 4e 6f 5a 57 78 73 58 32 56 34 5a 57 4d 6e 4b 53 6c 37 4a 47 56 34 5a 57 4d 39 49 48 4e 6f 5a 57 78 73 58 32 56 34 5a 57 4d 6f 4a 47 4e 76 62 57 31 68 62 6d}
    condition:
        any of them
}

rule SHELLDETECT_cmd_5_0_php
{
    strings:
        $ = {6a 62 6c 56 75 53 31 4e 72 5a 32 55 7a 51 6d 68 6a 4d 30 34 77 59 55 68 4b 4d 55 74 44 55 6d 5a 56 61 31 5a 53 56 6c 56 57 56 46 5a 47 63 32 35 68 52 7a 6b 78 57 6b 64 73 64 57 46 54 5a 47 52}
    condition:
        any of them
}

rule SHELLDETECT_c99_23_0_php
{
    strings:
        $ = {31 52 6e 4e 6d 39 30 4b 33 68 45 56 6c 6c 4d 54 33 4e 44 64 69 39 61 65 6d 68 31 52 7a 46 5a 56 56 59 35 64 47 39 68 57 6d 64 58 54 55 68 6d 5a 56 46 48 54 6c 6b 33 64 55 78 33 4d 6b 4e 6b 57}
    condition:
        any of them
}

rule SHELLDETECT_configspy_2_0_php
{
    strings:
        $ = {31 63 48 67 67 4f 48 42 34 49 43 46 70 62 58 42 76 63 6e 52 68 62 6e 51 37 59 6d 39 79 5a 47 56 79 4f 69 42 75 62 32 35 6c 49 43 46 70 62 58 42 76 63 6e 52 68 62 6e 51 37 59 6d 39 79 5a 47 56}
    condition:
        any of them
}

rule SHELLDETECT_bogel_shell_0_0_php
{
    strings:
        $ = {30 5a 6d 59 76 59 6c 56 5a 52 56 68 6b 62 47 38 77 63 31 5a 47 65 6b 55 34 51 32 45 35 51 56 52 44 4e 6c 46 77 5a 57 74 69 5a 6b 46 51 55 6c 49 32 52 56 70 71 4e 46 42 6a 64 48 63 79 65 6a 56}
    condition:
        any of them
}

rule SHELLDETECT_snipershell_0_0_php
{
    strings:
        $ = {4a 46 39 51 54 31 4e 55 57 79 64 7a 62 6d 34 6e 58 54 73 4b 66 51 70 39 49 47 56 73 63 32 55 67 65 77 6f 6b 64 54 46 77 50 53 52 66 52 30 56 55 57 79 64 7a 62 6d 34 6e 58 54 73 4b 66 51 70 39}
    condition:
        any of them
}

rule SHELLDETECT_explore_0_0_asp
{
    strings:
        $ = {32 4e 79 61 57 4a 70 62 6d 63 67 64 47 68 6c 49 47 52 79 61 58 5a 6c 49 48 52 35 63 47 55 67 62 32 59 67 59 53 42 6e 61 58 5a 6c 62 69 42 45 63 6d 6c 32 5a 53 42 76 59 6d 70 6c 59 33 51 75 44}
    condition:
        any of them
}

rule SHELLDETECT_mysql_4_0_php
{
    strings:
        $ = {67 6f 67 49 43 41 67 49 43 41 67 49 43 41 67 50 48 52 6b 49 47 46 73 61 57 64 75 50 53 4a 6a 5a 57 35 30 5a 58 49 69 49 47 4e 73 59 58 4e 7a 50 53 4a 30 61 58 52 73 5a 53 49 2b 52 47 46 30 59}
    condition:
        any of them
}

