# Themida v3 
## Sample SecureEngine Control Flow
```asm
007271B8 | E8 4B010000              | call tea32_tiger_white_mutate_protected.727308          |
007271BD | 53                       | push ebx                                                |
007271BE | 89E3                     | mov ebx,esp                                             |
007271C0 | 53                       | push ebx                                                |

tea32_tiger_white_mutate_protected.727308 ->

00727308 | 58                       | pop eax                                                 |
00727309 | 53                       | push ebx                                                |
0072730A | 51                       | push ecx                                                | ecx:EntryPoint
0072730B | 52                       | push edx                                                | edx:EntryPoint
0072730C | 56                       | push esi                                                | esi:EntryPoint
0072730D | 57                       | push edi                                                | edi:EntryPoint
0072730E | 55                       | push ebp                                                |
0072730F | 89C3                     | mov ebx,eax                                             |
00727311 | 83EB 05                  | sub ebx,5                                               |
00727314 | B9 B8013200              | mov ecx,3201B8                                          | ecx:EntryPoint
00727319 | 29CB                     | sub ebx,ecx                                             | ecx:EntryPoint
0072731B | 50                       | push eax                                                |
0072731C | B8 65210600              | mov eax,62165                                           |
00727321 | 01D8                     | add eax,ebx                                             |
00727323 | 8338 00                  | cmp dword ptr ds:[eax],0                                |
00727326 | 74 03                    | je tea32_tiger_white_mutate_protected.72732B            |
00727328 | 58                       | pop eax                                                 |
00727329 | EB 15                    | jmp tea32_tiger_white_mutate_protected.727340           |

-----------------------------------------------------------------------------------------------

007EF210 | E8 4B010000              | call tea32_tiger_white_mutate_protected.7EF360          |
007EF215 | 53                       | push ebx                                                |
007EF216 | 89E3                     | mov ebx,esp                                             |
007EF218 | 53                       | push ebx                                                |

tea32_tiger_white_mutate_protected.7EF360 ->

007EF360 | 58                       | pop eax                                                 |
007EF361 | 53                       | push ebx                                                |
007EF362 | 51                       | push ecx                                                | ecx:EntryPoint
007EF363 | 52                       | push edx                                                | edx:EntryPoint
007EF364 | 56                       | push esi                                                | esi:EntryPoint
007EF365 | 57                       | push edi                                                | edi:EntryPoint
007EF366 | 55                       | push ebp                                                |
007EF367 | 89C3                     | mov ebx,eax                                             |
007EF369 | 83EB 05                  | sub ebx,5                                               |
007EF36C | B9 10823E00              | mov ecx,3E8210                                          | ecx:EntryPoint
007EF371 | 29CB                     | sub ebx,ecx                                             | ecx:EntryPoint
007EF373 | 50                       | push eax                                                |
007EF374 | B8 57C91300              | mov eax,13C957                                          |
007EF379 | 01D8                     | add eax,ebx                                             |
007EF37B | 8338 00                  | cmp dword ptr ds:[eax],0                                |
007EF37E | 74 03                    | je tea32_tiger_white_mutate_protected.7EF383            |
007EF380 | 58                       | pop eax                                                 |
007EF381 | EB 15                    | jmp tea32_tiger_white_mutate_protected.7EF398           |
007EF383 | 58                       | pop eax                                                 |
```

### Sample Patterns
```py
THEMIDA_ENTRY_START_SIGNATURE = "55 E9 ?? ?? ?? ?? 5D E9 ?? ?? ?? ??"
THEMIDA_ENTRY_PRE_JUMP_SIGNATURE = "E8 ?? ?? ?? FF E9 ?? ?? ?? FF"
THEMIDA_ENTRY_POST_JUMP_SIGNATURE = "81 ED ?? ?? ?? 00 E9 ?? ?? ?? ??"
```
