# Oreans Scripts

The scripts related to handling Oreans unvirtualization, unpacking, debugging, and deobfuscation within IDA 7.0, 7.5, and x64dbg.

## Oreans Themida v1.8 UnVirtualization Draft

* [Reference script, themida_1.8_unvirt_draft.py](https://github.com/dovezp/rce.scripts/blob/oreans/themida_1.8_unvirt_draft.py)
* [Reference dataset, oreans_handlers.csv](https://github.com/dovezp/rce.scripts/blob/oreans/oreans_handlers.csv)

This script contains functions and logic for defining and working with the "VMContext" structure, finding VMs, handlers, and their offsets, and creating/setting the VMContext within the IDA database.

The overall flow of the Themida 1.8 unvirtualization script is as follows:

* Define and create the "VMContext" structure within IDA using define_vmcontext(handler_len).
* Find VMs and their corresponding handlers within the binary using `find_vms()` and `find_lodsb(ea)`.
* Backtrace and prune potential handlers to identify valid handlers for the VM using `backtrace_crefs(ea)`.
* Identify and set the handler array within the VMContext structure.
* Create and set the VMContext at a specific base address using `set_vmcontext(ea)`.
* Obtain information about the VM using the Context class, which takes in the VMContext's base address and related information.

## Oreans v2 Entry Unpacking Decryption

* [Reference script, themida_entry.py](https://github.com/dovezp/rce.scripts/blob/oreans/themida_entry.py)

## Oreans v2 Macro Identifiers

* [Reference script, oreans_macro_entry_identifier_biased.py](https://github.com/dovezp/rce.scripts/blob/oreans/oreans_macro_entry_identifier_biased.py)
* [Reference script, oreans_macro_entry_identifier_reversal.py](https://github.com/dovezp/rce.scripts/blob/oreans/oreans_macro_entry_identifier_reversal.py)

## Oreans v2 Antis

* [Reference script, oreans_anti_debug_blacklist_identifier.py](https://github.com/dovezp/rce.scripts/blob/oreans/oreans_anti_debug_blacklist_identifier.py)
* [Reference code, tmdv2_vmware_check.asm](https://github.com/dovezp/rce.scripts/blob/oreans/tmdv2_vmware_check.asm)

## Oreans v2 Junk

* [Reference script, ida_vm_junk_buffer.py](https://github.com/dovezp/rce.scripts/blob/oreans/ida_vm_junk_buffer.py)

## Oreans Chains 

* [Reference script, simplify_jmp_chain.py](https://github.com/dovezp/rce.scripts/blob/oreans/simplify_jmp_chain.py)
* [Reference script, is_jmp_chain.py](https://github.com/dovezp/rce.scripts/blob/oreans/is_jmp_chain.py)
* [Reference script, final_jmp_chain_address.py](https://github.com/dovezp/rce.scripts/blob/oreans/final_jmp_chain_address.py)

## Oreans Notes

* [Reference note, brief_note__themida_v2_mutations.md](https://github.com/dovezp/rce.scripts/blob/oreans/brief_note__themida_v2_mutations.md)
* [Reference note, oreans_v2_note_tutorials.md](https://github.com/dovezp/rce.scripts/blob/oreans/oreans_v2_note_tutorials.md)
* [Reference note, themida_v3_secureengine_notes.md](https://github.com/dovezp/rce.scripts/blob/oreans/themida_v3_secureengine_notes.md)
* [Reference note, oreans_demo_vm_hooking.md](https://github.com/dovezp/rce.scripts/blob/oreans/oreans_demo_vm_hooking.md)

## Oreans OEP Finder

* [Reference script, oreans_oep_finder.py](https://github.com/dovezp/rce.scripts/blob/oreans/oreans_oep_finder.py)

### Oreans v2 Unpacking OEP Demo
https://github.com/dovezp/rce.scripts/assets/89095890/6e225737-0867-4a1e-94d1-10106c8c7841

### Oreans v3 Unpacking OEP Demo
https://github.com/dovezp/rce.scripts/assets/89095890/ff25b2d6-57d4-499a-87e7-4a8444d57c46

## Oreans v3 API Unwrapping

* [Reference script, oreans_api_unwrapper_x.py](https://github.com/dovezp/rce.scripts/blob/oreans/oreans_api_unwrapper_x.py)
* [Reference script, oreans_oep_finder_with_api_unwrapper.py](https://github.com/dovezp/rce.scripts/blob/oreans/oreans_oep_finder_with_api_unwrapper.py)
* [Reference write-up, Analysis: Oreans Themida 3.0.8.0 (x32) → Advanced API-Wrapping](https://dovezp.github.io/portfolio/2020/05/23/WRITEUP_Analysis__Oreans_Themida__3.0.8.0_x32_-_Advanced_API-Wrapping.html)

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
