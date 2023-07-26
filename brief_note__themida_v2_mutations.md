# Some Themida v2 Mutations

## chain expand a
```asm
fyofwrns:00406F08 add     ebx, 240E380Ah
fyofwrns:00406F0E sub     ebx, esi
fyofwrns:00406F10 sub     ebx, 240E380Ah
```
```asm
EBX = ((EBX + 240E380Ah) - ESI) - 240E380Ah
```
## pop edx
```asm
fyofwrns:00406ED4 mov     edx, esp
fyofwrns:00406ED6 add     edx, 4
```
## chain expand b
```asm
fyofwrns:00406EBE add     ebx, eax
fyofwrns:00406EC0 add     ebx, 7C20155Fh
```
```asm
EBX = (EBX + EAX) + 7C20155Fh
```
## stack duplication 
```asm
fyofwrns:00406EC6 push    dword ptr [esp]
fyofwrns:00406EC9 push    dword ptr [esp]
```
```asm
[ESP+0] = [ESP]
[ESP+4] = [ESP]
```
## move reg_a, reg_a (nop)
```asm
fyofwrns:00406ED3 push    edx
fyofwrns:00406ED4 mov     edx, esp
fyofwrns:00406ED6 add     edx, 4
```
## xchg reg, reg
```asm
fyofwrns:00406F1C xchg    edx, [esp]
// mov dest, source
```
```asm
mov t, [esp]
mov [esp], edx
mov edx, t
```
## pop stack inc cancel
```asm
fyofwrns:00406F1F pop     esp
fyofwrns:00406F20 sub     esp, 4
```
```asm
mov reg, [esp]
add esp, 0x04
sub esp, 0x04
```

## Virtual PC Detection
```asm
themida_:004384C3 0F 3F 07 0B                 vpcext  7, 0Bh                          ; Virtual PC - ISA extension
themida_:004384C7 64 8F 05 00 00 00 00        pop     large dword ptr fs:0
themida_:004384CE 83 C4 04                    add     esp, 4                          ; Add
themida_:004384D1 6A 00                       push    0
themida_:004384D3 53                          push    ebx
themida_:004384D4 E8 03 00 00 00              call    sub_4384DC                      ; Call Procedure
themida_:004384D9 20 5B C3                    and     [ebx-3Dh], bl   
```
