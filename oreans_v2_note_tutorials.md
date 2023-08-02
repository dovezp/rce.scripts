# Oreans v2 Note Tutorials
Here are some tutorials to get started. More details and tutorials will be provided when I have the time and am not busy.


###  Easy Solutions:
#### Common Obfuscations:
```
=====================================================================================================
sample a (al byte nop copy):
mov al, 90
stosb
// or
stos byte ptr ds:[edi] 
// restore
pop eax 
// copy swap
stos byte ptr ds:[edi] 
// for larger where mov reg accord == right size and uses stosb, stosw, and stosd

=====================================================================================================
sample b (call or jmp ch switcher-roo):
// modifies 1st byte @ edx register transforming into call or jump depending on (cross)
// where value of mod r/m byte of al (cross) ch = E8 and cl (cross) ch = E9
// pop stack address to edx
pop dword ptr ds:[edx]     
// modify 1st byte in edx to direct call / jmp
mov byte ptr ds:[edx], ch
pop dword ptr ds:[edx]
pop dword ptr ds:[eax]

=====================================================================================================
sample c (simplify math):
mov eax, 0xc3b074e1
add eax, ecx
add eax, 0x3f5fb370
where:
eax = 0xc3b074e1
eax = eax + ecx
eax = eax + 0x3f5fb370

let eax = x, ecx = y:
⭣x = 0xc3b074e1          (no longer needed)
⭣x = 0xc3b074e1 + y      (lowest base ref x)
⭣x = x + 0x3f5fb370      (sub lowest base ref x into x)

substitute:
x = 0xc3b074e1 + y + 0x3f5fb370

final:
add eax, 0x103102851
add eax, ecx

=====================================================================================================
sample d (more simplify math):
0350FFE0: pop ecx
035100A0: sub ecx, 0x519
03510164: sub ecx, 0x310fa2f
03510204: mov ebp, 0x2f2540b
035102CD: add ebp, ecx
03510384: push ecx

0350FFE0: pop ecx
035100A0: sub ecx, 0x310FF48 (ecx = ecx - 0x519; ecx = ecx - 0x310fa2f; ecx = ecx - 0x310fa2f + 0x519)
03510204: mov ebp, 0x2f2540b
035102CD: add ebp, ecx
03510384: push ecx

to continue...
```
#### IAT redirection fixing:
```
=====================================================================================================
(iat solution method a)
upon stepping through for older versions "cmp eax, 10000h" (3D 00 00 01 00) (1.8.X+ -> 2.1.X+)
upon stepping through find "cmp eax, 1000h" (3D 00 10 00 00) (2.1.X+ -> 2.1.X+)
there are some cases where "cmp eax, 1000" is not found in later versions mostly (2.2.X -> 2.4.X+)
later versions use "cmp eax, 7D00h" (3D 00 7D 00 00)

sample, found typically in front area of .encode section:
72 EA                   jb      short 3B8D195
3D 00 7D 00 00          cmp     eax, 7D00h
73 1A                   jnb     short 3B8D1CC
3D 00 05 00 00          cmp     eax, 500h
72 0E                   jb      short 3B8D1C7

accessing encode section after pe header completed
search and follow all 4 magic jumps, can nop
break on each; 
the eax register will contain the address to the original api upon stopping on the magic jump eip

0F 84 ?? ?? ?? ?? 
0F 84 ?? ?? ?? ?? 
0F 84 ?? ?? ?? ?? 
0F 84 ?? ?? ?? ?? 


in below where XXXX is, it is a constant location obfuscated ebp "table" 
themida stores internal api accessors and checks like "IsDebuggerPresent" in the dword ptr for ebp
i will cover that in [Bypass "hide-from", "monitor-blockers", and "anti-*" checks]
since solving the issue in this tutorial is unrelated to the IAT redirection of the original process

find "cmp dword ptr[ebp+XXXX], eax" 
     "je YYYY" (39 85 ?? ?? ?? ?? 0F 84)
     
edit je to jmp to avoid jumping to ZwTerminateProcess after magic jumps are nop'd. 

=====================================================================================================
to continue...
```


#### VM OEP original OEP finding:
```
=====================================================================================================
(oep find method a)
break on return @ ZwFreeVirtualMemory 
break on access for code section (example: .text)

=====================================================================================================
(oep find method b)
break on return @ GetProcessHeap

=====================================================================================================
to continue...
```


#### Detect vm section hops and remove junk buffers:
```
=====================================================================================================
(junk code fix method a)
obtain mapped memory sections.
find the normal code section (ex: .text, @ 00401000).
find size of normal code section (ex: .text, @ 1000).

obtain clue to where vm section is (ex: .asdnfowi, @ 03101000).
obtain clue to what vm size is (ex: .asdnfowi, @ 1000).

where vm_list = array of pairs for easy reference later on
where area_start = normal code section base
where area_end = area_start + normal code section base + size

start iteration of re-assembling memory in .text with library of choice (ex: capstone).

for (; area_start < area_end; area_start++)

  where vm_start = none
  where vm_end = none

  if (E9 ?? ?? ?? ?? (memory) @ area_start == true)
      where XXXXX = address ->jmp XXXXX
      if ((vm section) >= XXXXX) ||  XXXXX < (vm section + vm size))
         vm_start = XXXXX
         
         (start iterating)
         for (search_end = vm_start; search_end < area_end; search_end++)
            where YYYY = search_end
            if (89 ?? 89 ?? 89 ?? 89 ?? @ YYYY == true)
               vm_end == YYYY
               (store to array for later)
               vm_list.push(pair(vm_start, vm_end))
               where nop_start = vm_start + 4 (following bytes to jump address) + 1 ((address) next)
               while (nop_start <= vm_end):
                  (memory) @ nop_start = 0x90
                  nop_start++
               (exit from current internal loop)
               break; 
          (continue to next area_start (address))
          
=====================================================================================================
to continue...
```


#### Defeat ENCODE / ENCRYPT:
```
=====================================================================================================
(emulation method a)
note: byte size of "encoded" before landing strip move same, same is same length as "decoded" 
the same goes with mutation, and virtualization. 
highly not to nop region unless you know for sure. 
note: having extra bytes between junk buffer and mov same, same strip means you messed something up!

fairly straight forward trick:
0) find tail end (89 ?? 89 ?? 89 ?? 89 ?? E8)
1) breakpoint on move same, same landing strip 
2) nop first call
3) nop second call 
4) it is decoded

call themida_extract_point: <- decode encoded region below
encoded data
(89 ?? 89 ?? 89 ?? 89 ??) <- landing pad
call themida_extract_point: <- encode decoded region above

=====================================================================================================
to continue...
```

#### Entry Info:
```
=====================================================================================================
(obtain entry and check decoded-encode section)
snippet of a pre-arranged json config for a tool I made in 2014:
"themida": {
        "description":"additional themida info to display in ida.",
        "decode": {
          "description":"finds themida entry point and decoded pe header reading region in ida.",
          "entry":"56 50 53 E8 ?? ?? ?? ?? ?? 58 89 C3 40 2D ?? ?? ?? ?? 2D ?? ?? ?? ?? 05 ?? ?? ?? ?? 80 3B CC 75 19 C6 03 00 BB ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 50 E8 ?? ?? ?? ?? 83 C0 ?? 89 44 24 08 5B 58 C3",
          "decode":"55 89 E5 50 53 51 56 8B 75 08 8B 4D 0C C1 E9 02 8B 45 10 8B 5D 14 85 C9 74 0A 31 06 01 1E 83 C6 04 49 EB F2 5E 59 5B 58 C9 C2 10 00",
          "unique_header_signature":[
            {"scan_last":"?? 58 89 C3 40 2D ?? ?? ?? ?? 2D ?? ?? ?? ?? 05 ?? ?? ?? ??"},
            {"mov_result":"mov eax, RESULT"},
            {"scan_last":"40 2D ?? ?? ?? ?? 2D ?? ?? ?? ?? 05 ?? ?? ?? ??"},
            {"scan_last":"83 C0 ??"},
            {"solve":"eax"}
          ]
        },
=====================================================================================================
to continue...
```

#### Bypass "hide-from", "monitor-blockers", and "anti-*" checks:
```
=====================================================================================================
(anti-debug (advanced & ultra) bypass method a)

anti-debugger window string detection bypass:
-----------------------------------------------------------------------------------------------------
reads and writes memory internally in vm section can be easy to spot internal stacks
the ecx register is used to hold string memory - goal is to null it out
accessors use: mov [ecx+04], add [ecx+04], add [ecx]


find "add [ecx], 1499CFCB" (81 01 CB CF 99 14)

find following instances. some are junk code to trick reversing via redundancy
in order to make it easier modifying all saves time via searching, like so:
AOBSCAN(OLLYDBG_2, OLLYDBG_1, END_OF_FILE_MEMORY, 81 01 CB CF 99 14)
AOBSCAN(OLLYDBG_3, OLLYDBG_2, END_OF_FILE_MEMORY, 81 01 CB CF 99 14)

write (81 01 00 00 00 00) or any other preferred method to zero ecx pointer values

repeat the following for the other constants:

find "mov [ecx+04], CE78753C" (C7 41 04 3C 75 78 CE)

write (C7 41 04 00 00 00 00) or any other preferred method to zero ecx pointer values 

find "mov [ecx+04], CE5F5969" (C7 41 04 69 59 5F CE)

write (C7 41 04 00 00 00 00) or any other preferred method to zero ecx pointer values 

find "add [ecx+04], 31D6D710" (81 41 04 10 D7 D6 31)

write (81 01 00 00 00 00) or any other preferred method to zero ecx pointer values

find "mov [ecx+04], CE706B34" (C7 41 04 34 6B 70 CE)

write (C7 41 04 00 00 00 00) or any other preferred method to zero ecx pointer values 


anti-debugger hardware debugger breakpoint bypass:
-----------------------------------------------------------------------------------------------------
   (sub method aa)
    find Address of Kernel32.IsDebuggerPresent 
    reverse address (ex: 30 58 17 74)
    search in vm section and break on access
    
    where XXXXX = address found
    where YYYYYYY = obfuscated api table @ ebp holding all checks and api calls
    
    search from XXXXX find "cmp dword ptr [ebp+YYYYYYY], 00" (83 BD ?? ?? ?? ?? 00)
    (ex: [ebp+14C33618] is Kernel32.IsDebuggerPresent compare check and call)
     
    find "call dword ptr [ebp+YYYYYYY]" (FF 95 ?? ?? ?? ??)
    write "mov eax, 0" (B8 00 00 00 00 90) (force always false) @ found location
   
   (sub method ab*)
    hook 74175830 (Kernel32.IsDebuggerPresent)
    set eax register 00000001 -> 00000000
    jump to return 
    
    *note: 
    doesn't work against "cmp dword ptr [ebp+YYYYYYY], 00" check since eax is already set to 1 before call, 
    which means [ebp+YYYYYYY] has already been set as well
    can however fixed and prevent detection by setting "mov [ebp+YYYYYYY], 00"
    
=====================================================================================================
(anti-debug (advanced & ultra) bypass method b)
this alt-method is much easier and doesn't require much effort to do 
terminates all other protections in the same category
very easy hook since they all wrap into one thread
there are several other ways to do this but this is by far the most simple and basic way 
can be applied to bypass other anti's

thread killer:
-----------------------------------------------------------------------------------------------------
// if not found do a for each for every string constant combo listed in method a
AOBSCAN(first_found_address, 81 01 CB CF 99 14)

// memory size is fitted to ~amount of opcode size needed
alloc(terminate_current_thread_hook, 48)
[ENABLE]
label(returnhere)
label(exit)

terminate_current_thread_hook:
push 0
call GetCurrentThread
push eax                    
push 0                    

push 8000                   
push 0                      
push eax          
push TerminateThread 
jmp VirtualFree
// frees thread
// kills without returning back to original code

exit:
jmp returnhere

first_found_address:
jmp terminate_current_thread_hook
nop
returnhere:

[DISABLE]
// no reason to return to original code. placed anyways
dealloc(terminate_current_thread_hook)
first_found_address:
add [ecx], 1499CFCB

=====================================================================================================
(anti-file-monitor & anti-reg-monitor bypass method a)

anti-file-monitor & anti-registry-monitor window string detection bypass:
-----------------------------------------------------------------------------------------------------
reads and writes memory internally in vm section can be easy to spot internal stacks
file monitors are much easier to spot and are hex'd reversed strings (ex: mgeR = Regm) which are then 
normalized
apply the same logic for anti-debug bypass for this
accessors use: mov es:[esi], mov [esi], mov [esi+04], [esi+08], [esi+0C], [esi+10]

mov [esi],    6D676552        "mgeR"    (C7 06 52 65 67 6D)
mov [esi],    656C6946        "eliF"    (C7 06 46 69 6C 65)
mov [esi],    36343831        "6481"    (C7 06 31 38 34 36)
mov [esi],    434F5250        "CORP"    (C7 06 50 52 4F 43)
mov [esi+04], 4C505845        "LPXE"    (C7 46 04 45 58 50 4C)
mov [esi+04], 6C636E6F        "lcno"    (C7 46 04 6F 6E 63 6C)
mov [esi+04], 31342D37        "14-7"    (C7 46 04 37 2D 34 31)
mov [esi+04], 636E6F6D        "monc"    (C7 46 04 6D 6F 6E 63)
mov [esi+04], 5F4E4F4D        "_NOM"    (C7 46 04 4D 4F 4E 5F)
mov [esi+08], 7373616C        "ssal"    (C7 46 08 6C 61 73 73)
mov [esi+08], 444E4957        "DNIW"    (C7 46 08 57 49 4E 44)
mov [esi+0C], 435F574F        "OW_C"    (C7 46 0C 4F 57 5F 43)
mov [esi+10], 5353414C        "SSAL"    (C7 46 10 4C 41 53 53)
=====================================================================================================
(anti-debug (advanced & ultra) & (anti-file-monitor & anti-reg-monitor) & (anti-vm) bypass list)
snippet of a pre-arranged json config for a tool I made in 2014:
looks for 2.3.0.0 -> 2.3.2.0 for common anti's
"anti": {
          "description":"finds themida anti-* protections in ida.",
          "signatures": [
            {"anti_debug_a":"C7 01 A5 95 CA 54"},
            {"anti_debug_b":"81 01 CB CF 99 14"},
            {"anti_debug_c":"C7 41 04 3C 75 78 CE"},
            {"anti_debug_d":"C7 41 04 69 59 5F CE"},
            {"anti_debug_e":"81 41 04 10 D7 D6 31"},
            {"anti_debug_f":"C7 41 04 34 6B 70 CE"},
            {"anti_debug_g":"81 02 51 FD 67 0C"},
            {"anti_monitor_a":"C7 06 52 65 67 6D"},
            {"anti_monitor_b":"C7 06 46 69 6C 65"},
            {"anti_monitor_c":"C7 06 31 38 34 36"},
            {"anti_monitor_d":"C7 06 50 52 4F 43"},
            {"anti_monitor_e":"C7 46 08 61 73 73 00"},
            {"anti_monitor_f":"C7 46 04 45 58 50 4C"},
            {"anti_monitor_g":"C7 46 04 6F 6E 63 6C"},
            {"anti_monitor_h":"C7 46 04 37 2D 34 31"},
            {"anti_monitor_i":"C7 46 04 6D 6F 6E 63"},
            {"anti_monitor_j":"C7 46 04 4D 4F 4E 5F"},
            {"anti_monitor_k":"C7 46 08 6C 61 73 73"},
            {"anti_monitor_l":"C7 46 08 57 49 4E 44"},
            {"anti_monitor_m":"C7 46 0C 4F 57 5F 43"},
            {"anti_monitor_n":"C7 46 10 4C 41 53 53"},
            {"anti_virtual_machine_a":"50 0F 01 44 24 FE 58 C1 E8 18 3D FF 00 00 00"},
            {"anti_virtual_machine_b":"50 0F 01 4C 24 FE"},
            {"anti_virtual_machine_c":"B9 0A 00 00 00 B8 04 D7 55 48 05 64 81 F7 0D ?? 65 D4 85 86 BA 40 B6 34 00 81 EA E8 5F 34 00 ED 81 ?? 68 58 4D 56"},
            {"anti_virtual_machine_d":"0F 00 04 24 66 8B 04 24"},
            {"anti_virtual_machine_e":"B8 68 58 4D 56 B9 14 00 00 00 66 BA 58 56 ED 64 8F 05 00 00 00 00"},
            {"anti_virtual_machine_f":" 89 04 24 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 31 DB 31 C0 40 0F 3F 07 0B"}
          ]
}
=====================================================================================================
(integ check bypass patten)
snippet of a pre-arranged json config for a tool I made in 2014:
outer patterns need to be updated ~ alternatively break on access above inner to find outer
looks for 2.3.0.0 -> 2.3.2.0 for integ check patterns
        "integrity": {
          "description":"finds themida code integrity check 'crc' protections in ida.",
          "combinations":[{"inner":"ebx", "outer":"eax"},{"inner":"ebx", "outer":"ecx"},{"inner":"ecx", "outer":"edx"}],
          "inner": {
            "description":"crc where REG32_A determines what the resulting outer crc register will be.",
            "signature": "83 ?? 00 0F 85 ?? 00 00 00 83 ?? 04 00 0F 84 ?? ?? 00 00",
            "location": 2,
            "struture": ["add REG8, [REG32_A]", "pop REG32_A"]
          },
          "outer": {
            "description":"crc where inner REG32_A match to outer determines what the resulting outer crc signature will be.",
            "location":-2,
            "structure_a":["mov REG32_A, [REG32_A]", "mov REG32_A, [REG32_A]"],
            "structure_a_signature":"8B ? 8B ? 81 ? ? ? ? ? 01 ? 81",
            "structure_b":["mov REG32_A, [REG32_A]", "add REG32_B, REG32_B", "mov REG32_A, [REG32_A]"],
            "structure_b_signature":"8B ? ? ? 8B ? 81 ? ? ? ? ? 01 ? 81",
            "structure_c":["mov REG32_A, [REG32_A]", "unknown", "unknown", "unknown", "unknown", "mov REG32_A, [REG32_A]", "unknown", "unknown", "unknown", "and REG32, CONST"],
            "structure_c_signature":"8B ? ? ? 81 ? ? ? ? ? ? ? 81 ? ? ? ? ? 8B ? ? ? ? ? ? ? ? ? ? 81"
          },
          
          
checksum register jump cycle iterations:
found in front chunk of (.extract) after .ntdll check and internal heap segment

81 ?? ?? 00 00 00 FF E0
81 ?? ?? 00 00 00 FF E1
81 ?? ?? 00 00 00 FF E2
81 ?? ?? 00 00 00 FF E3
81 ?? ?? 00 00 00 FF E6
81 ?? ?? 00 00 00 FF E7

exit of entry jump routine:
follow front and deobfuscate entry to easily spot spinlock and next crc cycle
01 ?? 05 ?? ?? ?? ?? FF 20 

=====================================================================================================
to continue...
```


#### Detect "advanced-api" usages and restore api:
```
to continue...
```


#### VM "ice-fishing" spin-lock monitoring:
```
=====================================================================================================
snippet of a pre-arranged json config for a tool I made in 2014:
looks for 2.3.0.0 -> 2.3.2.0 for common patterns regarding vm types where tiger, fish, puma, shark all had a entry same style
note: since 2.3.5+ or so they changed the entry structures and 2.3.9+ removing cisc and risc for later versions
"cisc": {
              "entry_signatures":[
                {"start": [
                  "push 32BIT",
                  "jmp ADDRESS"
                ]},
                {"start": [
                  "push 28BIT",
                  "jmp ADDRESS"
                ]}
              ],
              "core_signature": "68 ?? ?? 00 00 89 ?? 24",
              "unique_signatures": [
                {"scan_first": "0B C9 0F 85 ?? FE FF FF FF 74 24 24 FF 34 24"},
                {"scan_first": "FC 68 ?? ?? 00 00 89 ?? 24 ?? ?? 24"}
              ],
              "spinlock": "31 C0 F0 0F B1 ?? ?? ?? 00 00 0F ?? ?? FF FF FF"
            },
            "fish": {
              "start": [
                "push 24BIT",
                "push 8BIT",
                "jmp ADDRESS",
                "jmp ADDRESS"
              ],
              "core_signature": "9C 60 E8 00 00 00 00 59 83 E9 ?? 81 E9 ?? ?? ?? ?? BD ?? ?? 00 00 01 CD 51 B9 01 00 00 00 BB ?? 00 00 00 31 C0 F0 0F B1 4C 1D 00 74 04 F3 90 EB F2",
              "unique_signatures": [{"removed":"removed"},{"removed":"removed"}],
              "spinlock": "31 C0 F0 0F B1 4C 1D 00 74 04 F3 90 EB F2"
            },
            "puma": {
              "start": [
                "push 24BIT",
                "push 8BIT",
                "jmp ADDRESS",
                "jmp ADDRESS"
              ],
              "core_signature": "9C 60 E8 00 00 00 00 59 83 E9 ?? 81 E9 ?? ?? ?? ?? BD ?? ?? 00 00 01 CD 51 B9 01 00 00 00 BB ?? 00 00 00 31 C0 F0 0F B1 4C 1D 00 74 04 F3 90 EB F2",
              "unique_signatures": [{"removed":"removed"},{"removed":"removed"}],
              "spinlock": "31 C0 F0 0F B1 4C 1D 00 74 04 F3 90 EB F2"
            },
            ...
=====================================================================================================
to continue...
```
