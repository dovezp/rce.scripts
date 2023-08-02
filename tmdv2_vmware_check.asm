; init vmware check
02FF8782: mov eax,0x564d5868
02FF8787: mov ecx,0x14
02FF878C: mov dx,0x5658
02FF8790: in eax,dx
02FF8791: pop dword fs:[0x0]
02FF8798: add esp,4
02FF8839: cmp eax,0
02FF883E: jbe  0x2ffe2ca
02FF8844: cmp dword ss:[ebp+0x17570201],1
02FF884F: jnz  0x2ffe2ca
02FF8855: mov dword ss:[ebp+0x17572ac6],1
02FF8860: cmp dword ss:[ebp+0x17572ac6],0
02FF886B: jnz  0x2ff90dd
02FF8871: cmp dword ss:[ebp+0x17570201],1
02FF887C: jnz  0x2ff90dd
02FF8882: push ax
02FF8929: sldt word ds:[esp]
02FF892E: pop ax
02FF89C8: or ax,ax
02FF89CB: jz  0x2ff9109
02FF89D1: mov dword ss:[ebp+0x17572ac6],1
02FF8A81: cmp dword ss:[ebp+0x17572a52],0
02FF8A8C: jnz  0x2ffafa1
02FF8A92: cmp dword ss:[ebp+0x17572a12],0
02FF8A9D: jz  0x2ffafb6
02FF8AA3: push eax
02FF8AA6: mov dword ss:[ebp+0x175731ca],0x43d
02FF8AB2: call dword ss:[ebp+0x17571e48]
02FF8AB9: pop eax
02FF8B54: lea eax,ss:[ebp+0x1778b55f]
02FF8B5B: push eax
02FF8BF8: call dword ss:[ebp+0x17571ca5]
02FF8BFF: mov ebx,eax
02FF8CCC: lea eax,ss:[ebp+0x1778b553]
02FF8CD3: push eax
02FF8D7B: push ebx
02FF8E38: call dword ss:[ebp+0x17572ba2]
02FF8E3F: mov dword ss:[ebp+0x17571802],eax
02FF8E46: lea eax,ss:[ebp+0x1778d8c0]
02FF8E4D: mov dword ss:[ebp+0x17571cf8],eax
02FF8E54: call dword ss:[ebp+0x17571802]
02FF8E5B: mov ebx,eax
02FF8EF7: xor esi,esi
02FF8EF9: cmp esi,0xa
02FF8EFF: jz  0x2ffc208
02FF8F05: push ecx
02FF8F95: call dword ss:[ebp+0x17571802]
02FF8F9C: pop ecx
02FF9038: cmp ebx,eax
02FF903A: jz  0x2ffba01
02FF9040: mov ebx,eax
02FF90EA: inc esi
02FF9178: nop
02FF9179: jmp  0x2ffb3ca
02FF917E: mov dword ds:[esp],ecx
02FF9182: pop eax
02FF918C: pop ecx
02FF9196: pop edx
02FF91F4: cmp dword ss:[ebp+0x17572a52],0
02FF91FF: jnz  0x2ffa282
02FF9205: cmp dword ss:[ebp+0x17572a12],0
02FF9210: jz  0x2ffa297
02FF9216: push eax
02FF9219: mov dword ss:[ebp+0x17571f40],0x7d9
02FF9225: call dword ss:[ebp+0x17571c43]
02FF922C: pop eax
02FF92B3: push eax
02FF935A: mov ebx,eax
02FF93E7: push ebx
02FF93E8: lea ebx,ss:[ebp+0x17571089]
02FF93EF: mov eax,dword ds:[ebx]
02FF93F2: mov dword ds:[ebx],eax
02FF93F5: mov eax,dword ds:[ebx+0x50]
02FF93F9: mov dword ds:[ebx+0x50],eax
02FF93FD: lea ebx,ss:[ebp+0x1778aff1]
02FF9404: mov eax,dword ds:[ebx]
02FF9407: mov dword ds:[ebx],eax
02FF940A: pop ebx
02FF940B: push 0
02FF9410: lea eax,ss:[ebp+0x1778aff1]
02FF9417: push eax
02FF94B9: push 0x60
02FF94BE: lea eax,ss:[ebp+0x17571089]
02FF94C5: push eax
02FF9559: push 0
02FF955E: push 0
02FF9563: push 0x7fad1eff
02FF9580: xchg dword ds:[esp],ecx
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
02FFB255: cmp dword ss:[ebp+0x1778b569],0 
; jmp check for vmware
02FFB260: jz  0x2ff8782					 
; pop zero
02FFB266: pop dword fs:[0x0]			 
02FFB26D: add esp,4
02FFB273: cmp dword ss:[ebp+0x17572ac6],0
02FFB27E: jnz  0x2ff90dd
02FFB284: cmp dword ss:[ebp+0x17570201],1
02FFB28F: jnz  0x2ff90dd
02FFB295: push ax
02FFB33C: sldt word ds:[esp]
02FFB341: pop ax
02FFB3DB: or ax,ax
02FFB3DE: jz  0x2ff9109
02FFB3E4: mov dword ss:[ebp+0x17572ac6],1
02FFB494: cmp dword ss:[ebp+0x17572a52],0
02FFB49F: jnz  0x2ffafa1
02FFB4A5: cmp dword ss:[ebp+0x17572a12],0
02FFB4B0: jz  0x2ffafb6
02FFB4B6: push eax
02FFB4B9: mov dword ss:[ebp+0x175731ca],0x43d
02FFB4C5: call dword ss:[ebp+0x17571e48]
02FFB4CC: pop eax
02FFB567: lea eax,ss:[ebp+0x1778b55f]
02FFB56E: push eax
02FFB60B: call dword ss:[ebp+0x17571ca5]
02FFB612: mov ebx,eax
02FFB6DF: lea eax,ss:[ebp+0x1778b553]
02FFB6E6: push eax
02FFB78E: push ebx
02FFB84B: call dword ss:[ebp+0x17572ba2]
02FFB852: mov dword ss:[ebp+0x17571802],eax
02FFB859: lea eax,ss:[ebp+0x1778d8c0]
02FFB860: mov dword ss:[ebp+0x17571cf8],eax
02FFB867: call dword ss:[ebp+0x17571802]
02FFB86E: mov ebx,eax
02FFB90A: xor esi,esi
02FFB90C: cmp esi,0xa
02FFB912: jz  0x2ffc208
02FFB918: push ecx
02FFB9A8: call dword ss:[ebp+0x17571802]
02FFB9AF: pop ecx
02FFBA4B: cmp ebx,eax
02FFBA4D: jz  0x2ffba01
02FFBA4F: mov ebx,eax
02FFBAF9: inc esi
02FFBB87: nop
02FFBB88: jmp  0x2ffb3ca
02FFBB8D: mov dword ds:[esp],ecx
02FFBB91: pop eax
02FFBB9B: pop ecx
02FFBBA5: pop edx
02FFBC03: cmp dword ss:[ebp+0x17572a52],0
02FFBC0E: jnz  0x2ffa282
02FFBC14: cmp dword ss:[ebp+0x17572a12],0
02FFBC1F: jz  0x2ffa297
02FFBC25: push eax
02FFBC28: mov dword ss:[ebp+0x17571f40],0x7d9
02FFBC34: call dword ss:[ebp+0x17571c43]
02FFBC3B: pop eax
02FFBCC2: push eax
02FFBD69: mov ebx,eax
02FFBDF6: push ebx
02FFBDF7: lea ebx,ss:[ebp+0x17571089]
02FFBDFE: mov eax,dword ds:[ebx]
02FFBE01: mov dword ds:[ebx],eax
02FFBE04: mov eax,dword ds:[ebx+0x50]
02FFBE08: mov dword ds:[ebx+0x50],eax
02FFBE0C: lea ebx,ss:[ebp+0x1778aff1]
02FFBE13: mov eax,dword ds:[ebx]
02FFBE16: mov dword ds:[ebx],eax
02FFBE19: pop ebx
02FFBE1A: push 0
02FFBE1F: lea eax,ss:[ebp+0x1778aff1]
02FFBE26: push eax
02FFBEC8: push 0x60
02FFBECD: lea eax,ss:[ebp+0x17571089]
02FFBED4: push eax
02FFBF68: push 0
02FFBF6D: push 0
02FFBF72: push 0x7fad1eff
02FFBF8F: xchg dword ds:[esp],ecx
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
02FFE2CA: lea eax,ss:[ebp+0x1778cc40]
02FFE2D1: push eax
02FFE3BB: push dword fs:[0x0]
02FFE3C2: mov dword fs:[0x0],esp
02FFE3C9: xor ebx,ebx
02FFE3CB: xor eax,eax
02FFE3CD: inc eax
02FFE3CE: pop es
02FFE3CF: or esp,dword ds:[edi+ecx*4+0x5]
02FFE3D4: add byte ds:[eax],al
02FFE3D7: add byte ds:[eax],al
02FFE3DA: add esp,4
02FFE3E0: cmp ebx,0xff
02FFE3E6: jz  0x2ffc190
02FFE3EC: mov dword ss:[ebp+0x17572ac6],1
02FFE3F7: cmp dword ss:[ebp+0x17572ac6],0
02FFE402: jnz  0x2ff90dd
02FFE408: cmp dword ss:[ebp+0x17570201],1
02FFE413: jnz  0x2ff90dd
02FFE419: push ax
02FFE4C0: sldt word ds:[esp]
02FFE4C5: pop ax
02FFE55F: or ax,ax
02FFE562: jz  0x2ff9109
02FFE568: mov dword ss:[ebp+0x17572ac6],1
02FFE618: cmp dword ss:[ebp+0x17572a52],0
02FFE623: jnz  0x2ffafa1
02FFE629: cmp dword ss:[ebp+0x17572a12],0
02FFE634: jz  0x2ffafb6
02FFE63A: push eax
02FFE63D: mov dword ss:[ebp+0x175731ca],0x43d
02FFE649: call dword ss:[ebp+0x17571e48]
02FFE650: pop eax
02FFE6EB: lea eax,ss:[ebp+0x1778b55f]
02FFE6F2: push eax
02FFE78F: call dword ss:[ebp+0x17571ca5]
02FFE796: mov ebx,eax
02FFE863: lea eax,ss:[ebp+0x1778b553]
02FFE86A: push eax
02FFE912: push ebx
02FFE9CF: call dword ss:[ebp+0x17572ba2]
02FFE9D6: mov dword ss:[ebp+0x17571802],eax
02FFE9DD: lea eax,ss:[ebp+0x1778d8c0]
02FFE9E4: mov dword ss:[ebp+0x17571cf8],eax
02FFE9EB: call dword ss:[ebp+0x17571802]
02FFE9F2: mov ebx,eax
02FFEA8E: xor esi,esi
02FFEA90: cmp esi,0xa
02FFEA96: jz  0x2ffc208
02FFEA9C: push ecx
02FFEB2C: call dword ss:[ebp+0x17571802]
02FFEB33: pop ecx
02FFEBCF: cmp ebx,eax
02FFEBD1: jz  0x2ffba01
02FFEBD7: mov ebx,eax
02FFEC81: inc esi
02FFED0F: nop
02FFED10: jmp  0x2ffb3ca
02FFED15: mov dword ds:[esp],ecx
02FFED19: pop eax
02FFED23: pop ecx
02FFED2D: pop edx
02FFED8B: cmp dword ss:[ebp+0x17572a52],0
02FFED96: jnz  0x2ffa282
02FFED9C: cmp dword ss:[ebp+0x17572a12],0
02FFEDA7: jz  0x2ffa297
02FFEDAD: push eax
02FFEDB0: mov dword ss:[ebp+0x17571f40],0x7d9
02FFEDBC: call dword ss:[ebp+0x17571c43]
02FFEDC3: pop eax
02FFEE4A: push eax
02FFEEF1: mov ebx,eax
02FFEF7E: push ebx
02FFEF7F: lea ebx,ss:[ebp+0x17571089]
02FFEF86: mov eax,dword ds:[ebx]
02FFEF89: mov dword ds:[ebx],eax
02FFEF8C: mov eax,dword ds:[ebx+0x50]
02FFEF90: mov dword ds:[ebx+0x50],eax
02FFEF94: lea ebx,ss:[ebp+0x1778aff1]
02FFEF9B: mov eax,dword ds:[ebx]
02FFEF9E: mov dword ds:[ebx],eax
02FFEFA1: pop ebx
02FFEFA2: push 0
02FFEFA7: lea eax,ss:[ebp+0x1778aff1]
02FFEFAE: push eax
02FFF050: push 0x60
02FFF055: lea eax,ss:[ebp+0x17571089]
02FFF05C: push eax
02FFF0F0: push 0
02FFF0F5: push 0
02FFF0FA: push 0x7fad1eff
02FFF117: xchg dword ds:[esp],ecx
