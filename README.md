<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/user-attachments/assets/135f23ff-6ed6-4967-a1bb-58787ddb9781">
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/user-attachments/assets/d6120c35-8ffd-4b51-a29f-341439fbfa39">
    <img alt="MODEM73" src="https://i.ibb.co/wZKznzrF/MODEM73-blk.png">
  </picture>
</p>

This repository builds [MODEM73](https://github.com/RFnexus/modem73) with basic build hardening, a seccomp-BPF filter and memory-deny-write-execute enforcement. A Landlock sandbox is applied to restrict network and filesystem access. 
The hardening overlay introduces bounds-checked sliding windows and finite-sample sanitization helpers for the demodulation kernels.

Use with [hardened_malloc](https://github.com/GrapheneOS/hardened_malloc) is recommended.




