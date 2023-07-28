# IDA Scripts
## Personal Shenanigans

The scripts related for handling "Themida unvirtualization" within IDA 7.0, 7.5 and x64dbg

This script contains functions and logic for defining and working with the "VMContext" structure, finding VMs, handlers, and their offsets, and creating/setting the VMContext within the IDA database.

The overall flow of the Themida 1.8 unvirtualization script is as follows:

* Define and create the "VMContext" structure within IDA using define_vmcontext(handler_len).
* Find VMs and their corresponding handlers within the binary using `find_vms()` and `find_lodsb(ea)`.
* Backtrace and prune potential handlers to identify valid handlers for the VM using `backtrace_crefs(ea)`.
* Identify and set the handler array within the VMContext structure.
* Create and set the VMContext at a specific base address using `set_vmcontext(ea)`.
* Obtain information about the VM using the Context class, which takes in the VMContext's base address and related information.

https://github.com/dovezp/ida.scripts/assets/89095890/ff25b2d6-57d4-499a-87e7-4a8444d57c46

https://github.com/dovezp/ida.scripts/assets/89095890/83c2a278-93b3-475e-a177-fd99bb72c0d9

https://github.com/dovezp/ida.scripts/assets/89095890/6e225737-0867-4a1e-94d1-10106c8c7841

https://github.com/dovezp/ida.scripts/assets/89095890/92e6eb6e-6f8d-4e09-9759-efa3503d9370

## License

This project is licensed under the [BSD 3-Clause License (Revised)](https://tldrlegal.com/license/bsd-3-clause-license-(revised)).

## Feedback

I welcome your constructive input - both negative and positive. I will continue to try to provide updates when able. At some point you may find errors, inconsistencies, or methods that could be improved, or are missing altogether. Your feedback is critical to help improve future revisions.

The best way to reach out is by opening a new issue in this repository:

https://github.com/dovezp/ida.scripts/issues

Please be sure to refer to what your situation is when giving feedback and if possible link the topic in question.

Many thanks.

<hr/>

<p align="center">
  <p align="center">
    <a href="https://hits.seeyoufarm.com/api/count/graph/dailyhits.svg?url=https://github.com/dovezp/ida.scripts">
      <img src="https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2Fdovezp%2Fida.scripts&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=hits&edge_flat=true" alt="repository hits">
    </a>
    <a href="https://github.com/dovezp/ida.scripts/releases">
      <img src="https://img.shields.io/github/downloads/dovezp/ida.scripts/total?style=flat-square" alt="downloads"/>
    </a>
    <a href="https://github.com/dovezp/ida.scripts/graphs/contributors">
      <img src="https://img.shields.io/github/contributors/dovezp/ida.scripts?style=flat-square" alt="contributors"/>
    </a>
    <a href="https://github.com/dovezp/ida.scripts/watchers">
      <img src="https://img.shields.io/github/watchers/dovezp/ida.scripts?style=flat-square" alt="watchers"/>
    </a>
    <a href="https://github.com/dovezp/ida.scripts/stargazers">
      <img src="https://img.shields.io/github/stars/dovezp/ida.scripts?style=flat-square" alt="stars"/>
    </a>
    <a href="https://github.com/dovezp/ida.scripts/network/members">
      <img src="https://img.shields.io/github/forks/dovezp/ida.scripts?style=flat-square" alt="forks"/>
    </a>
  </p>
</p>

<p align="center">
  <a href="https://github.com/dovezp">
    <img width="64" heigth="64" src="https://avatars.githubusercontent.com/u/89095890" alt="dovezp"/>
  </a>
</p>
