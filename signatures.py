XOBF_CALL_INTO = "E8"

XOBF_FIRST_ENTRY_SIGNATURE = "8F 05 ? ? ? ? 50 B8 ? ? ? ? 8D 80 ? ? ? ? 87 05 ? ? ? ? 58 F3 90"

XOBF_ENTRY_SIGNATURE_A = "8F 05 ? ? ? ? 50 90 B8 ? ? ? ? 8D 80 ? ? ? ? 87 05 ? ? ? ? 58 F3 90"
XOBF_ENTRY_SIGNATURE_B = "8F 05 ? ? ? ? 50 8B 05 ? ? ? ? 8D 80 ? ? ? ? 87 05 ? ? ? ? 58 F3 90"

XOBF_ENTRY__OBFUSCATED_RET_ADDRESS_MEM = "8F 05 ? ? ? ?"  # pop     dword ptr ds:loc_40302D
XOBF_ENTRY__DECODE_KEY_OPERAND = "B8 ? ? ? ?"  # mov     eax, 4DDB40F9h
XOBF_ENTRY__DECODE_KEY_MEM = "8B 05 ? ? ? ?"  # mov     eax, dword ptr ds:loc_40302D
XOBF_ENTRY__OBTAIN_INSTRUCTION_BYTES = "8D 80 ? ? ? ?"  # lea     eax, [eax-0DCB4091h]
XOBF_ENTRY__RESOLVE_INSTRUCTIONS_TO_MEM = "87 05 ? ? ? ?"  # xchg    eax, ds:dword_40301B

XOBF_EXIT_SIGNATURE_A = "50 66 B8 ? ? 66 87 05 ? ? ? ? B8 ? ? ? ? 87 04 24 C3"
XOBF_EXIT_SIGNATURE_B = "50 66 B8 ? ? 66 87 05 ? ? ? ? B8 ? ? ? ? 8D 40 ? 87 04 24 C3"
