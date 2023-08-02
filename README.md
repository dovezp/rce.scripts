# IDA Metadata

An idea which created an IDA script that allows you to build "chains" of methods from strings.

## Idea

idea: string xref -> code block

source:
```
.text:0199A710 334 89 84 24 0C 02 00 00        mov     [esp+330h+rcAffected.bottom], eax
.text:0199A717 334 8B 84 24 80 00 00 00        mov     eax, [esp+330h+tCur]
.text:0199A71E 334 8D 48 01                    lea     this, [eax+1]               ; Load Effective Address
.text:0199A721 334 48                          dec     eax                         ; Decrement by 1
.text:0199A722 334 8D 94 24 04 02 00 00        lea     edx, [esp+330h+rcAffected.top] ; Load Effective Address
.text:0199A729 334 52                          push    edx                         ; rc
.text:0199A72A 338 89 84 24 0C 02 00 00        mov     [esp+334h+rcAffected.right], eax
.text:0199A731 338 8D 84 24 C0 01 00 00        lea     eax, [esp+334h+ptHit_MinX.y] ; Load Effective Address
.text:0199A738 338 68 28 AC 53 02              push    offset str_RemoteShoot      ; "RemoteShoot"
.text:0199A73D 33C 50                          push    eax                         ; result
.text:0199A73E 340 89 8C 24 1C 02 00 00        mov     [esp+33Ch+var_120], this
.text:0199A745 340 E8 86 1D 68 FF              call    ?LogParam@@YA?AV?$ZXString@D@@PADABUtagRECT@@@Z ; #STR: "rc%s=%d,%d,%d,%d|"
.text:0199A745
```

target:
```
.text:026128AD 3C0 8B 8D E8 FE FF FF           mov     ecx, [ebp-118h]
.text:026128B3 3C0 8B 95 58 FE FF FF           mov     edx, [ebp-1A8h]
.text:026128B9 3C0 3B CA                       cmp     ecx, edx                    ; Compare Two Operands
.text:026128BB 3C0 8B C2                       mov     eax, edx
.text:026128BD 3C0 0F 4C C1                    cmovl   eax, ecx                    ; Move if Less (SF!=OF)
.text:026128C0 3C0 3B D1                       cmp     edx, ecx                    ; Compare Two Operands
.text:026128C2 3C0 89 45 CC                    mov     [ebp-34h], eax
.text:026128C5 3C0 8B C2                       mov     eax, edx
.text:026128C7 3C0 0F 4C C1                    cmovl   eax, ecx                    ; Move if Less (SF!=OF)
.text:026128CA 3C0 8B 8D 4C FE FF FF           mov     ecx, [ebp-1B4h]
.text:026128D0 3C0 89 45 D4                    mov     [ebp-2Ch], eax
.text:026128D3 3C0 8D 41 01                    lea     eax, [ecx+1]                ; Load Effective Address
.text:026128D6 3C0 89 45 D8                    mov     [ebp-28h], eax
.text:026128D9 3C0 8D 41 FF                    lea     eax, [ecx-1]                ; Load Effective Address
.text:026128DC 3C0 89 45 D0                    mov     [ebp-30h], eax
.text:026128DF 3C0 8D 45 CC                    lea     eax, [ebp-34h]              ; Load Effective Address
.text:026128E2 3C0 50                          push    eax
.text:026128E3 3C4 8D 85 48 FD FF FF           lea     eax, [ebp-2B8h]             ; Load Effective Address
.text:026128E9 3C4 68 EC 86 FF 02              push    offset str_RemoteShoot      ; "RemoteShoot"
.text:026128EE 3C8 50                          push    eax
.text:026128EF 3CC E8 3C B5 60 FE              call    sub_C1DE30                  ; Call Procedure ; #STR: "rc%s=%d,%d,%d,%d|"
.text:026128EF
```

```
prove that source == target
from string address -> target text address
iterate till instruction is either call or jump (uncon / con)
sub-target = get branch item address
sub-target-size = get branch item size
for s in strings:
    for each ref in s:
        if eref.ea >= sub-target and eref.ea <= sub-target + sub-target-size:
            found = contains a string
            if found == source-string:
                rename sub-target with source branch call
                break

push count usually stays the same between call blocks
use that as well?
```
The script takes strings as input and attempts to find cross-references (xrefs) to these strings within the code. It then builds method chains by following the xrefs to create a sequence of function calls based on the matched strings.

### String Identifier and Preprocessing

* [Reference script, is_ascii_or_uni.py](https://github.com/dovezp/rce.scripts/blob/ida-metadata/is_ascii_or_uni.py)
* [Reference script, string-fixer.py](https://github.com/dovezp/rce.scripts/blob/ida-metadata/string-fixer.py)

### String Chaining
* [Reference script, idea-build-string-chains.py](https://github.com/dovezp/rce.scripts/blob/ida-metadata/idea-build-string-chains.py)
* [Reference script, string_v1.py](https://github.com/dovezp/rce.scripts/blob/ida-metadata/strings_v1.py)
* [Reference script, string_v2.py](https://github.com/dovezp/rce.scripts/blob/ida-metadata/string_v2.py)
* [Reference script, strings_chainer.py](https://github.com/dovezp/rce.scripts/blob/ida-metadata/strings_chainer.py)

## Feedback

I welcome your constructive input - both negative and positive. I will continue to try to provide updates when able. At some point you may find errors, inconsistencies, or methods that could be improved, or are missing altogether. Your feedback is critical to help improve future revisions.

The best way to reach out is by opening a new issue in this repository:

https://github.com/dovezp/rce.scripts/issues

Please be sure to refer to what your situation is when giving feedback and if possible link the topic in question.

Many thanks.

<hr/>

<p align="center">
  <p align="center">
    <a href="https://hits.seeyoufarm.com/api/count/graph/dailyhits.svg?url=https://github.com/dovezp/rce.scripts">
      <img src="https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2Fdovezp%2Frce.scripts&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=hits&edge_flat=true" alt="repository hits">
    </a>
    <a href="https://github.com/dovezp/rce.scripts/releases">
      <img src="https://img.shields.io/github/downloads/dovezp/rce.scripts/total?style=flat-square" alt="downloads"/>
    </a>
    <a href="https://github.com/dovezp/rce.scripts/graphs/contributors">
      <img src="https://img.shields.io/github/contributors/dovezp/rce.scripts?style=flat-square" alt="contributors"/>
    </a>
    <a href="https://github.com/dovezp/rce.scripts/watchers">
      <img src="https://img.shields.io/github/watchers/dovezp/rce.scripts?style=flat-square" alt="watchers"/>
    </a>
    <a href="https://github.com/dovezp/rce.scripts/stargazers">
      <img src="https://img.shields.io/github/stars/dovezp/rce.scripts?style=flat-square" alt="stars"/>
    </a>
    <a href="https://github.com/dovezp/rce.scripts/network/members">
      <img src="https://img.shields.io/github/forks/dovezp/rce.scripts?style=flat-square" alt="forks"/>
    </a>
  </p>
</p>

<p align="center">
  <a href="https://github.com/dovezp">
    <img width="64" heigth="64" src="https://avatars.githubusercontent.com/u/89095890" alt="dovezp"/>
  </a>
</p>
