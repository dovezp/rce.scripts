# Some Operations

## Addition
### x + y to assembly
```asm
0x0000000000400a0c <+0>:     mov    eax,DWORD PTR [rbp-0x4]
0x0000000000400a0f <+3>:     mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400a12 <+6>:     add    eax,edx
0x0000000000400a14 <+8>:     mov    DWORD PTR [rbp-0xc],eax
0x0000000000400a17 <+11>:    mov    eax,0x0
0x0000000000400a1c <+16>:    leave
0x0000000000400a1d <+17>:    ret
```

### x + y → 2(x ∨ y) − (x ⊕ y) to assembly
```asm
0x0000000000400a0c <+0>:     mov    eax,DWORD PTR [rbp-0x4]
0x0000000000400a0f <+3>:     mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400a12 <+6>:     or     eax,edx
0x0000000000400a14 <+8>:     shl    eax,0x1
0x0000000000400a17 <+11>:    mov    edx,DWORD PTR [rbp-0x4]
0x0000000000400a1a <+14>:    mov    ecx,DWORD PTR [rbp-0x8]
0x0000000000400a1d <+17>:    xor    edx,ecx   
0x0000000000400a1f <+19>:    sub    eax,edx
0x0000000000400a21 <+21>:    mov    DWORD PTR [rbp-0xc],eax
0x0000000000400a24 <+24>:    mov    eax,DWORD PTR [rbp-0xc]
0x0000000000400a27 <+27>:    leave
0x0000000000400a28 <+28>:    ret
```

### x + y → (x ⊕ ¬y) + 2(x ∨ y) + 1 to assembly
```asm
0x0000000000400a29 <+0>:     mov    eax,DWORD PTR [rbp-0x4]
0x0000000000400a2c <+3>:     mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400a2f <+6>:     not    edx
0x0000000000400a31 <+8>:     xor    eax,edx
0x0000000000400a33 <+10>:    mov    edx,DWORD PTR [rbp-0x4]
0x0000000000400a36 <+13>:    mov    ecx,DWORD PTR [rbp-0x8]
0x0000000000400a39 <+16>:    or     eax,edx
0x0000000000400a3b <+18>:    or     eax,ecx
0x0000000000400a3d <+20>:    shl    eax,0x1
0x0000000000400a40 <+23>:    add    eax,0x1
0x0000000000400a43 <+26>:    mov    DWORD PTR [rbp-0xc],eax
0x0000000000400a46 <+29>:    mov    eax,DWORD PTR [rbp-0xc]
0x0000000000400a49 <+32>:    leave
0x0000000000400a4a <+33>:    ret
```

### x + y → (x ⊕ y) + 2y − 2(¬x ∧ y) to assembly
```asm
0x0000000000400a4b <+0>:     mov    eax,DWORD PTR [rbp-0x4]
0x0000000000400a4e <+3>:     mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400a51 <+6>:     xor    eax,edx
0x0000000000400a53 <+8>:     mov    ecx,DWORD PTR [rbp-0x8]
0x0000000000400a56 <+11>:    shl    ecx,0x1
0x0000000000400a59 <+14>:    mov    edx,DWORD PTR [rbp-0x4]
0x0000000000400a5c <+17>:    not    edx
0x0000000000400a5e <+19>:    and    edx,DWORD PTR [rbp-0x8]
0x0000000000400a61 <+22>:    not    edx
0x0000000000400a63 <+24>:    shl    edx,0x1
0x0000000000400a66 <+27>:    sub    ecx,edx
0x0000000000400a68 <+29>:    add    eax,ecx
0x0000000000400a6a <+31>:    mov    DWORD PTR [rbp-0xc],eax
0x0000000000400a6d <+34>:    mov    eax,DWORD PTR [rbp-0xc]
0x0000000000400a70 <+37>:    leave
0x0000000000400a71 <+38>:    ret
```

## Subtraction
### x - y to assembly
```asm
0x0000000000400a72 <+0>:     mov    eax,DWORD PTR [rbp-0x4]
0x0000000000400a75 <+3>:     mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400a78 <+6>:     sub    eax,edx
0x0000000000400a7a <+8>:     mov    DWORD PTR [rbp-0xc],eax
0x0000000000400a7d <+11>:    mov    eax,DWORD PTR [rbp-0xc]
0x0000000000400a80 <+14>:    leave
0x0000000000400a81 <+15>:    ret
```

### x - y → x + (−y) to assembly
```asm
0x0000000000400a72 <+0>:     mov    eax,DWORD PTR [rbp-0x4]
0x0000000000400a75 <+3>:     mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400a78 <+6>:     neg    edx
0x0000000000400a7a <+8>:     add    eax,edx
0x0000000000400a7c <+10>:    mov    DWORD PTR [rbp-0xc],eax
0x0000000000400a7f <+13>:    mov    eax,DWORD PTR [rbp-0xc]
0x0000000000400a82 <+16>:    leave
0x0000000000400a83 <+17>:    ret
```

### x − y → 2(x ∧ ¬y) − (x ⊕ y) to assembly
```asm
0x0000000000400a84 <+0>:     mov    eax,DWORD PTR [rbp-0x4]
0x0000000000400a87 <+3>:     mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400a8a <+6>:     not    edx
0x0000000000400a8c <+8>:     and    eax,edx
0x0000000000400a8e <+10>:    shl    eax,0x1
0x0000000000400a91 <+13>:    mov    edx,DWORD PTR [rbp-0x4]
0x0000000000400a94 <+16>:    mov    ecx,DWORD PTR [rbp-0x8]
0x0000000000400a97 <+19>:    xor    edx,ecx
0x0000000000400a99 <+21>:    sub    eax,edx
0x0000000000400a9b <+23>:    mov    DWORD PTR [rbp-0xc],eax
0x0000000000400a9e <+26>:    mov    eax,DWORD PTR [rbp-0xc]
0x0000000000400aa1 <+29>:    leave
0x0000000000400aa2 <+30>:    ret
```

### x − y → x ∧ ¬y − ¬x ∧ y to assembly
```asm
0x0000000000400aa3 <+0>:     mov    eax,DWORD PTR [rbp-0x4]
0x0000000000400aa6 <+3>:     mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400aa9 <+6>:     not    edx
0x0000000000400aab <+8>:     and    eax,edx
0x0000000000400aad <+10>:    mov    edx,DWORD PTR [rbp-0x4]
0x0000000000400ab0 <+13>:    not    edx
0x0000000000400ab2 <+15>:    mov    ecx,DWORD PTR [rbp-0x8]
0x0000000000400ab5 <+18>:    and    edx,ecx
0x0000000000400ab7 <+20>:    not    edx
0x0000000000400ab9 <+22>:    sub    eax,edx
0x0000000000400abb <+24>:    mov    DWORD PTR [rbp-0xc],eax
0x0000000000400abe <+27>:    mov    eax,DWORD PTR [rbp-0xc]
0x0000000000400ac1 <+30>:    leave
0x0000000000400ac2 <+31>:    ret
```

### x − y → ¬(¬x + y) ∧ ¬(¬x + y) to assembly
```asm
0x0000000000400ac3 <+0>:     mov    eax,DWORD PTR [rbp-0x4]
0x0000000000400ac6 <+3>:     mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400ac9 <+6>:     not    edx
0x0000000000400acb <+8>:     add    eax,edx
0x0000000000400acd <+10>:    not    eax
0x0000000000400acf <+12>:    mov    edx,DWORD PTR [rbp-0x4]
0x0000000000400ad2 <+15>:    mov    ecx,DWORD PTR [rbp-0x8]
0x0000000000400ad5 <+18>:    not    ecx
0x0000000000400ad7 <+20>:    add    edx,ecx
0x0000000000400ad9 <+22>:    not    edx
0x0000000000400adb <+24>:    and    eax,edx
0x0000000000400add <+26>:    mov    DWORD PTR [rbp-0xc],eax
0x0000000000400ae0 <+29>:    mov    eax,DWORD PTR [rbp-0xc]
0x0000000000400ae3 <+32>:    leave
0x0000000000400ae4 <+33>:    ret
```

## XOR
### x ⊕ y to assembly
```asm
0x0000000000400ae5 <+0>:     mov    eax,DWORD PTR [rbp-0x4]
0x0000000000400ae8 <+3>:     mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400aeb <+6>:     xor    eax,edx
0x0000000000400aed <+8>:     mov    DWORD PTR [rbp-0xc],eax
0x0000000000400af0 <+11>:    mov    eax,DWORD PTR [rbp-0xc]
0x0000000000400af3 <+14>:    leave
0x0000000000400af4 <+15>:    ret
```

### x ⊕ y → (x ∨ y) − (x ∧ y) to assembly
```asm
0x0000000000400ae5 <+0>:     mov    eax,DWORD PTR [rbp-0x4]
0x0000000000400ae8 <+3>:     mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400aeb <+6>:     or     eax,edx
0x0000000000400aed <+8>:     mov    edx,DWORD PTR [rbp-0x4]
0x0000000000400af0 <+11>:    mov    ecx,DWORD PTR [rbp-0x8]
0x0000000000400af3 <+14>:    and    edx,ecx
0x0000000000400af5 <+16>:    sub    eax,edx
0x0000000000400af7 <+18>:    mov    DWORD PTR [rbp-0xc],eax
0x0000000000400afa <+21>:    mov    eax,DWORD PTR [rbp-0xc]
0x0000000000400afd <+24>:    leave
0x0000000000400afe <+25>:    ret
```

### x ⊕ y → (x ∨ y) − y + (¬x ∧ y) to assembly
```asm
0x0000000000400aff <+0>:     mov    eax,DWORD PTR [rbp-0x4]
0x0000000000400b02 <+3>:     mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400b05 <+6>:     or     eax,edx
0x0000000000400b07 <+8>:     mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400b0a <+11>:    sub    eax,edx
0x0000000000400b0c <+13>:    mov    edx,DWORD PTR [rbp-0x4]
0x0000000000400b0f <+16>:    not    edx
0x0000000000400b11 <+18>:    mov    ecx,DWORD PTR [rbp-0x8]
0x0000000000400b14 <+21>:    and    edx,ecx
0x0000000000400b16 <+23>:    add    eax,edx
0x0000000000400b18 <+25>:    mov    DWORD PTR [rbp-0xc],eax
0x0000000000400b1b <+28>:    mov    eax,DWORD PTR [rbp-0xc]
0x0000000000400b1e <+31>:    leave
0x0000000000400b1f <+32>:    ret
```

### x ⊕ y → (x ∨ y) − (¬x ∨ y) + (¬x) to assembly
```asm
0x0000000000400b20 <+0>:     mov    eax,DWORD PTR [rbp-0x4]
0x0000000000400b23 <+3>:     mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400b26 <+6>:     or     eax,edx
0x0000000000400b28 <+8>:     mov    edx,DWORD PTR [rbp-0x4]
0x0000000000400b2b <+11>:    not    edx
0x0000000000400b2d <+13>:    or     edx,DWORD PTR [rbp-0x8]
0x0000000000400b30 <+16>:    not    edx
0x0000000000400b32 <+18>:    sub    eax,edx
0x0000000000400b34 <+20>:    mov    edx,DWORD PTR [rbp-0x4]
0x0000000000400b37 <+23>:    not    edx
0x0000000000400b39 <+25>:    add    eax,edx
0x0000000000400b3b <+27>:    mov    DWORD PTR [rbp-0xc],eax
0x0000000000400b3e <+30>:    mov    eax,DWORD PTR [rbp-0xc]
0x0000000000400b41 <+33>:    leave
0x0000000000400b42 <+34>:    ret
```

## AND
### x ∧ y to assembly
```asm
0x0000000000400b43 <+0>:     mov    eax,DWORD PTR [rbp-0x4]
0x0000000000400b46 <+3>:     mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400b49 <+6>:     and    eax,edx
0x0000000000400b4b <+8>:     mov    DWORD PTR [rbp-0xc],eax
0x0000000000400b4e <+11>:    mov    eax,DWORD PTR [rbp-0xc]
0x0000000000400b51 <+14>:    leave
0x0000000000400b52 <+15>:    ret
```

### x ∧ y → ¬(¬x ∨ ¬y) to assembly
```asm
0x0000000000400b43 <+0>:     mov    eax,DWORD PTR [rbp-0x4]
0x0000000000400b46 <+3>:     not    eax
0x0000000000400b48 <+5>:     mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400b4b <+8>:     not    edx
0x0000000000400b4d <+10>:    or     eax,edx
0x0000000000400b4f <+12>:    not    eax
0x0000000000400b51 <+14>:    mov    DWORD PTR [rbp-0xc],eax
0x0000000000400b54 <+17>:    mov    eax,DWORD PTR [rbp-0xc]
0x0000000000400b57 <+20>:    leave
0x0000000000400b58 <+21>:    ret
```

### x ∧ y → (x ∨ y) − (¬x ∧ y) − (x ∧ ¬y) to assembly
```asm
0x0000000000400b59 <+0>:     mov    eax,DWORD PTR [rbp-0x4]
0x0000000000400b5c <+3>:     mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400b5f <+6>:     or     eax,edx
0x0000000000400b61 <+8>:     mov    edx,DWORD PTR [rbp-0x4]
0x0000000000400b64 <+11>:    not    edx
0x0000000000400b66 <+13>:    mov    ecx,DWORD PTR [rbp-0x8]
0x0000000000400b69 <+16>:    and    edx,ecx
0x0000000000400b6b <+18>:    sub    eax,edx
0x0000000000400b6d <+20>:    mov    edx,DWORD PTR [rbp-0x4]
0x0000000000400b70 <+23>:    mov    ecx,DWORD PTR [rbp-0x8]
0x0000000000400b73 <+26>:    not    ecx
0x0000000000400b75 <+28>:    and    edx,ecx
0x0000000000400b77 <+30>:    sub    eax,edx
0x0000000000400b79 <+32>:    mov    DWORD PTR [rbp-0xc],eax
0x0000000000400b7c <+35>:    mov    eax,DWORD PTR [rbp-0xc]
0x0000000000400b7f <+38>:    leave
0x0000000000400b80 <+39>:    ret
```

### x ∧ y → −(x ⊕ y) + y + (x ∧ ¬y) to assembly
```asm
0x0000000000400b81 <+0>:     mov    eax,DWORD PTR [rbp-0x4]
0x0000000000400b84 <+3>:     mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400b87 <+6>:     xor    eax,edx
0x0000000000400b89 <+8>:     not    eax
0x0000000000400b8b <+10>:    mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400b8e <+13>:    add    eax,edx
0x0000000000400b90 <+15>:    mov    edx,DWORD PTR [rbp-0x4]
0x0000000000400b93 <+18>:    mov    ecx,DWORD PTR [rbp-0x8]
0x0000000000400b96 <+21>:    not    ecx
0x0000000000400b98 <+23>:    and    edx,ecx
0x0000000000400b9a <+25>:    add    eax,edx
0x0000000000400b9c <+27>:    mov    DWORD PTR [rbp-0xc],eax
0x0000000000400b9f <+30>:    mov    eax,DWORD PTR [rbp-0xc]
0x0000000000400ba2 <+33>:    leave
0x0000000000400ba3 <+34>:    ret
```

## OR
### x ∨ y to assembly
```asm
0x0000000000400ba4 <+0>:     mov    eax,DWORD PTR [rbp-0x4]
0x0000000000400ba7 <+3>:     mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400baa <+6>:     or     eax,edx
0x0000000000400bac <+8>:     mov    DWORD PTR [rbp-0xc],eax
0x0000000000400baf <+11>:    mov    eax,DWORD PTR [rbp-0xc]
0x0000000000400bb2 <+14>:    leave
0x0000000000400bb3 <+15>:    ret
```

### x ∨ y → (x ∧ ¬y) + y to assembly
```asm
0x0000000000400ba4 <+0>:     mov    eax,DWORD PTR [rbp-0x4]
0x0000000000400ba7 <+3>:     mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400baa <+6>:     not    edx
0x0000000000400bac <+8>:     and    eax,edx
0x0000000000400bae <+10>:    mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400bb1 <+13>:    add    eax,edx
0x0000000000400bb3 <+15>:    mov    DWORD PTR [rbp-0xc],eax
0x0000000000400bb6 <+18>:    mov    eax,DWORD PTR [rbp-0xc]
0x0000000000400bb9 <+21>:    leave
0x0000000000400bba <+22>:    ret
```

### x ∨ y → (x ⊕ y) + y − (¬x ∧ y) to assembly
```asm
0x0000000000400bbb <+0>:     mov    eax,DWORD PTR [rbp-0x4]
0x0000000000400bbe <+3>:     mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400bc1 <+6>:     xor    eax,edx
0x0000000000400bc3 <+8>:     mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400bc6 <+11>:    add    eax,edx
0x0000000000400bc8 <+13>:    mov    edx,DWORD PTR [rbp-0x4]
0x0000000000400bcb <+16>:    not    edx
0x0000000000400bcd <+18>:    mov    ecx,DWORD PTR [rbp-0x8]
0x0000000000400bd0 <+21>:    and    edx,ecx
0x0000000000400bd2 <+23>:    sub    eax,edx
0x0000000000400bd4 <+25>:    mov    DWORD PTR [rbp-0xc],eax
0x0000000000400bd7 <+28>:    mov    eax,DWORD PTR [rbp-0xc]
0x0000000000400bda <+31>:    leave
0x0000000000400bdb <+32>:    ret
```

###  x ∨ y → (x ⊕ y) + (¬x ∨ y) − (¬x) to assembly
```asm
0x0000000000400bdc <+0>:     mov    eax,DWORD PTR [rbp-0x4]
0x0000000000400bdf <+3>:     mov    edx,DWORD PTR [rbp-0x8]
0x0000000000400be2 <+6>:     xor    eax,edx
0x0000000000400be4 <+8>:     mov    edx,DWORD PTR [rbp-0x4]
0x0000000000400be7 <+11>:    not    edx
0x0000000000400be9 <+13>:    or     eax,edx
0x0000000000400beb <+15>:    mov    edx,DWORD PTR [rbp-0x4]
0x0000000000400bee <+18>:    not    edx
0x0000000000400bf0 <+20>:    sub    eax,edx
0x0000000000400bf2 <+22>:    mov    DWORD PTR [rbp-0xc],eax
0x0000000000400bf5 <+25>:    mov    eax,DWORD PTR [rbp-0xc]
0x0000000000400bf8 <+28>:    leave
0x0000000000400bf9 <+29>:    ret
```
