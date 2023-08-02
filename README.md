# Oreans

The following is related to handling Oreans unvirtualization, unpacking, debugging, and deobfuscation within IDA 7.0, 7.5, and x64dbg.

## Oreans v1.8 UnVirtualization Concept

* [Reference script, themida_1.8_unvirt_draft.py](https://github.com/dovezp/rce.scripts/blob/oreans/themida_1.8_unvirt_draft.py)

  This script contains functions and logic for defining and working with the "VMContext" structure, finding VMs, handlers, and their offsets, and creating/setting the VMContext within the IDA database.

  The overall flow of the Themida 1.8 unvirtualization script is as follows:
  
  * Define and create the "VMContext" structure within IDA using define_vmcontext(handler_len).
  * Find VMs and their corresponding handlers within the binary using `find_vms()` and `find_lodsb(ea)`.
  * Backtrace and prune potential handlers to identify valid handlers for the VM using `backtrace_crefs(ea)`.
  * Identify and set the handler array within the VMContext structure.
  * Create and set the VMContext at a specific base address using `set_vmcontext(ea)`.
  * Obtain information about the VM using the Context class, which takes in the VMContext's base address and related information.
 
* [Reference dataset, oreans_handlers.csv](https://github.com/dovezp/rce.scripts/blob/oreans/oreans_handlers.csv)

## Oreans v2 Entry Unpacking Decryption Concept

* [Reference script, themida_entry.py](https://github.com/dovezp/rce.scripts/blob/oreans/themida_entry.py)

  The example script decodes the entry buffer of data located at 0x3233008 with a length of 0x400 bytes using two encryption keys 0x2E188729 and 0x40B2470.

## Oreans v2 Macro Identifiers

* [Reference script, oreans_macro_entry_identifier_biased.py](https://github.com/dovezp/rce.scripts/blob/oreans/oreans_macro_entry_identifier_biased.py)

  This script is a Python script designed to identify and analyze macro entry points in programs protected by Oreans using a biased search starting from the beginning of the text segment and iteratively finds potential macro entry points. It then verifies the accuracy of these potential entries and logs the results.
  
* [Reference script, oreans_macro_entry_identifier_reversal.py](https://github.com/dovezp/rce.scripts/blob/oreans/oreans_macro_entry_identifier_reversal.py)

  This script is a Python script designed to identify and analyze macro entry points in programs protected by Oreans using a more accurate reversal approach, starting from the end of the text segment and iteratively finding potential macro entry points by searching for landing strips.

## Oreans v2 Antis

* [Reference script, oreans_anti_debug_blacklist_identifier.py](https://github.com/dovezp/rce.scripts/blob/oreans/oreans_anti_debug_blacklist_identifier.py)

  This script is a Python script designed to identify anti-debugging blacklist signatures in programs protected by Oreans Version 2.

* [Reference code, tmdv2_vmware_check.asm](https://github.com/dovezp/rce.scripts/blob/oreans/tmdv2_vmware_check.asm)
  
  This example code performs various checks related to VMware virtualization. 
  
  * It checks whether the value stored in the "eax" register is equal to 0. If not, it jumps to the address at 0x2FFE2CA.
  
  * At the address 0x2FFE2CA, the code performs some checks related to VMware virtualization:
  
  * It checks the value stored at the memory location "[ebp+0x1778b569]" and jumps to 0x2FF8782 if the value is zero.
  * Otherwise, it continues executing the next instructions.
  
  * The code then performs additional checks, and if the conditions are met, it sets a flag by storing 1 in the memory location "[ebp+0x17572ac6]."
  
  * At multiple places in the code, it checks for the value stored in "[ebp+0x17572ac6]" and jumps to 0x2FF90DD if it is non-zero.
  
  * The code also checks for the value stored in "[ebp+0x17570201]" and jumps to 0x2FF90DD if it is not equal to 1.
  
  * There are multiple calls to functions whose addresses are stored in various memory locations.
  
  * The code contains a loop that iterates 10 times, and in each iteration, it calls a function, compares the result with a stored value, and jumps to 0x2FFBA01 if the condition is met.

* [Reference write-up, Analysis: Oreans Themida 2.3.5.10 (x86) → Anti-Debugger Detections](https://dovezp.github.io/portfolio/2020/08/27/WRITEUP_Analysis__Oreans_Themida__2.3.5.10_x32_-_Anti-Debugger-Detections.html)

  This write-up presents an analysis of an executable protected with Oreans Themida 2.3.5.10 (x86) and provides recommendations for handling its anti-debugging measures. The conclusions are as follows:
  
  Themida's anti-debugging measures should not be trusted, and no Themida thread should be considered friendly unless hijacked for your advantage.
  
  It is essential to kill off the blacklists anti-debug thread. This can be achieved by searching for the provided signatures, hooking, terminating the current thread, and restoring the original hooked memory to prevent any future integrity check issues.
  
  The best way to kill off Themida threads is by setting a breakpoint on KERNEL32.Sleep, determining the call's origin by reading the topmost ESP, and checking if the caller is within the Themida segment.
  
  An alternative method involves hooking NtQueryInformationThread and NtSetInformationThread, which can achieve similar results and also check for the ThreadHideFromDebugger within the thread context.
  
  Killing off Themida-generated threads can significantly improve a process's speed and remove annoyances during debugging. This approach works against various anti-protection features developed by Oreans.

## Oreans v2 Junk

* [Reference script, ida_vm_junk_buffer.py](https://github.com/dovezp/rce.scripts/blob/oreans/ida_vm_junk_buffer.py)

  This script analyzes a binary protected with Themida. It identifies and extracts virtual machines (VMs) generated by Themida and provides options to patch and hide the junk code inserted by Themida's virtualization process. The script also creates a JSON file with information about the VMs found in the binary.

## Oreans Chains 

* [Reference script, simplify_jmp_chain.py](https://github.com/dovezp/rce.scripts/blob/oreans/simplify_jmp_chain.py)

  This script performs simplification on the disassembly of a binary. The goal is to remove unnecessary "jmp" instructions and simplify the code flow for better analysis. The script iteratively follows the flow of "jmp" and "call" instructions, omitting conditional jumps, and creates a new simplified output for further examination.

* [Reference script, is_jmp_chain.py](https://github.com/dovezp/rce.scripts/blob/oreans/is_jmp_chain.py)

  This script determines if an address leads to a jump chain. A jump chain is declared if there is more than one unconditional jump instruction (jmp) encountered in sequence. The script uses IDA functions to obtain the mnemonic and operand values from an address and then iterates through the instructions to identify the jump chain.

* [Reference script, final_jmp_chain_address.py](https://github.com/dovezp/rce.scripts/blob/oreans/final_jmp_chain_address.py)
  
  This script analyzes a binary to identify the end point of a jump chain. The script follows a chain of consecutive unconditional jump (jmp) instructions and determines the final destination address in the chain. It prints the number of jumps taken and the ending address of the jump chain.

## Oreans Notes

* [Reference note, brief_note__themida_v2_mutations.md](https://github.com/dovezp/rce.scripts/blob/oreans/brief_note__themida_v2_mutations.md)

  This contains a list of Themida v2 mutations along with corresponding assembly code snippets. Each mutation is described by its effect on registers or memory, and some have multiple possible implementations in assembly code. The mutations involve various operations, such as addition, subtraction, bitwise operations, multiplication, and zeroing out a register.
    
* [Reference note, oreans_v2_note_tutorials.md](https://github.com/dovezp/rce.scripts/blob/oreans/oreans_v2_note_tutorials.md)

  These notes provide tutorials and information related to various topics, including easy solutions, IAT redirection fixing, VM OEP (Original Entry Point) finding, detecting VM section hops and removing junk buffers, defeating ENCODE/ENCRYPT protections, entry info, bypassing anti-debug, anti-file-monitor, anti-reg-monitor, anti-VM protections, detecting "advanced-api" usages, restoring API, and monitoring VM "ice-fishing" spin-locks.
    
* [Reference note, themida_v3_secureengine_notes.md](https://github.com/dovezp/rce.scripts/blob/oreans/themida_v3_secureengine_notes.md)
* [Reference note, oreans_demo_vm_hooking.md](https://github.com/dovezp/rce.scripts/blob/oreans/oreans_demo_vm_hooking.md)

## Oreans OEP Finder

* [Reference script, oreans_oep_finder.py](https://github.com/dovezp/rce.scripts/blob/oreans/oreans_oep_finder.py)

  This script is an (Original Entry Point) finder designed to work with software protected by Oreans. The OEP is the entry point of the program after all anti-debugging and protection mechanisms have been bypassed or resolved.

### Oreans v2 Unpacking OEP Demo
https://github.com/dovezp/rce.scripts/assets/89095890/6e225737-0867-4a1e-94d1-10106c8c7841

### Oreans v3 Unpacking OEP Demo
https://github.com/dovezp/rce.scripts/assets/89095890/ff25b2d6-57d4-499a-87e7-4a8444d57c46

## Oreans v3 API Unwrapping

* [Reference script, oreans_api_unwrapper_x.py](https://github.com/dovezp/rce.scripts/blob/oreans/oreans_api_unwrapper_x.py)

  This example script is an API unwrapper designed to work with software protected by Themida 3.0.0.0 to 3.0.8.0's API wrapping technique.

* [Reference script, oreans_oep_finder_with_api_unwrapper.py](https://github.com/dovezp/rce.scripts/blob/oreans/oreans_oep_finder_with_api_unwrapper.py)

  This example script is an OEP (Original Entry Point) finder and unpacker designed to work with software protected by Themida 3.0.8.0.
  1. Locate the Import Address Table (IAT): The script searches for the IAT entries and stores their addresses and values.
  
  2. Monitor program execution: The script sets breakpoints on specific API calls ("VirtualProtect") and monitors the program's execution.
  
  3. Detect possible imports: While the program executes, the script detects possible API calls within the IAT entries.
  
  4. Identify OEP: The script finds the original entry point of the program based on the monitored execution and information gathered from the IAT.
  
  5. Display results: The script informs the user about the detected OEP, whether it is the actual OEP or a possible one.

* [Reference write-up, Analysis: Oreans Themida 3.0.8.0 (x32) → Advanced API-Wrapping](https://dovezp.github.io/portfolio/2020/05/23/WRITEUP_Analysis__Oreans_Themida__3.0.8.0_x32_-_Advanced_API-Wrapping.html)

  This document provides an analysis of an executable protected with Oreans Themida 3.0.8.0 (x86) and focuses on the advanced API-wrapping mechanism used by the protection software. The conclusion of the analysis is that each obfuscated Import Address Table (IAT) entry is decrypted using two hard-coded keys. 

### Unpacking Imports Oreans v3 Demo 
https://github.com/dovezp/rce.scripts/assets/89095890/83c2a278-93b3-475e-a177-fd99bb72c0d9

### Unpacking Advanced API Wrapping Oreans v3 Demo 
https://github.com/dovezp/rce.scripts/assets/89095890/92e6eb6e-6f8d-4e09-9759-efa3503d9370


## License

This project is licensed under the [BSD 3-Clause License (Revised)](https://tldrlegal.com/license/bsd-3-clause-license-(revised)).

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
