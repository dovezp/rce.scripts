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

## increase reg_a by 1
```asm
inc reg_a
```
```asm
add reg_a, 1
```
## decrease reg_a by 1
```asm
dec reg_a
```
```asm
sub reg_a, 1
```
## neg reg_a
```asm
neg reg_a
```
```asm
not reg_a
inc reg_a
```
```asm
dec reg_a
not reg_a
```
```asm
push reg_b
mov reg_b, 0
sub reg_b, reg_a
xchg reg_a, reg_b
pop reg_b
```

## movement reg_b -> reg_a
```asm
MOV reg_a, reg_b
```
```asm
push reg_b
pop reg_a
```

## absorb self reg_a
```asm
mov reg_a, random_const_2
mov reg_a, random_const_1
mov reg_a, reg_a
```
```asm
push reg_a
pop reg_a
```
```asm
inc reg_a  
not reg_a
neg reg_a  
```
```asm
test reg_a, 1
jz __even
or reg_a, 1
jmp __out
__even:
or reg_a, 1
sub reg_a, 1
__out:
```
```asm
push reg_a
or reg_a, random_const
and reg_a, [ESP]
add ESP, 4
```
```asm
push reg_a
and reg_a, random_const
or reg_a, [ESP]
add ESP, 4
```
```asm
push random_const
xor [ESP], random_const  ; xor [ESP], [ESP]
add reg_a, [ESP]
add ESP, 4
```
```asm
push edx
push eax
mov eax, random_const
mul 0
add reg_a, edx
pop eax
pop edx
```
```asm
push edx
push eax
mov eax, reg_a
mul 1
mov reg_a, edx
pop eax
pop edx
```
```asm
add reg_a, 0
```
```asm
xor reg_a, 0
```
```asm
or reg_a, 0
```
```asm
and reg_a, 0xffffffff ; -1
```
```asm
and reg_a, reg_a
```
```asm
or reg_a, reg_a
```
```asm
push reg_a
or reg_a, random_const
and reg_a, [ESP]
add ESP, 4
```
```asm
push reg_a
and reg_a, random_const
or reg_a, [ESP]
add ESP, 4
```
```asm
push edx
push eax
mov eax, reg_a
mul 0xffffffff ; -1
mul 0xffffffff ; -1
mov reg_a, edx
pop eax
pop edx
```

## zero
```asm
sub reg_a, reg_a
```
```asm
xor reg_a, reg_a
```
```asm
mov reg_a, 0
```
```asm
shl reg_a, 0
```
```asm
mov MEM1, reg_a
mov reg_a, MEM1 
```
```asm
push edx
push eax
mov eax, reg_a
mul 0
mov reg_a, edx
pop eax
pop edx
```
```asm
push reg_a
not reg_a
and reg_a, [ESP]
add ESP, 4
```
## and reg_a, 0
```asm
push reg_a
push reg_a
push reg_a
or [ESP], random_const_1
add [ESP+4], random_const_1
and [ESP+8], random_const_1
sub [ESP], [ESP+4]
add [ESP], [ESP+8]
mov reg_a, [ESP]
add ESP, 0xC
```
```asm
push reg_a
push reg_a
xor [ESP], random_const_1
xor [ESP+4], random_const_1
sub [ESP], [ESP+4]
mov reg_a, [ESP]
add ESP, 8
```
## xor

```asm
push reg_b
xor [ESP], reg_a
mov reg_a, [ESP]
add ESP, 4
```

```asm
PUSH REG1
XOR [esp], REG2
POP REG1
```

```asm
push edx
push eax
push reg_a
push reg_a
add [ESP], reg_b
and [ESP+4], reg_b
mov eax, [ESP+4]
mul 2
mov [ESP+4], edx
sub [ESP], [ESP+4]
mov reg_a, [ESP]
add ESP, 8
pop eax
pop edx
```

```asm
push edx    
push eax   
push reg_a  
push reg_a  
and [ESP], reg_b
or [ESP+4], reg_b
sub [ESP], [ESP+4]
mov eax, [ESP]
mul 0xffffffff ; -1
mov reg_a, edx 
add ESP, 8 
pop eax
pop edx
```
