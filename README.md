# RTCore64

RTCore64 - kernel mode driver, which is included in popular GPU monitoring and overclocking software such as MSI Afterburner, RivaTuner Statistics Server (RTSS), and EVGA Precision X.

My opensource driver is does not use the original source codes and is a reverse-engineered driver using [Ghidra](https://en.wikipedia.org/wiki/Ghidra) and [Radare2](https://en.wikipedia.org/wiki/Radare2). The rights have not been violated, and the new driver cannot be signed due to the EV certificate. I hope that the vulnerabilities can be closed using my security patches.

The main goal of the project is to recreate a secure driver with fixed vulnerabilities and errors made by past developers.

### Functions

Driver RTCore64.sys allows the specified software to interact with the hardware (GPU, temperature sensors, voltage) directly at a low level.

- Control of the rotation speed GPU fans
- Changing the core and memory frequencies (overclocking)
- Voltage change (voltmode)
- Displays metrics (FPS, temperature) on top of fullscreen games

Fixed vulnerabilities in opensource driver RTCore64.sys:

- [x] (CVE-2019-16098)[https://www.sophos.com/en-us/blog/blackbyte-ransomware-returns]
- [x] (CVE-2024-1443)[https://fluidattacks.com/advisories/coltrane]
- [x] (CVE-2024-1460)[https://fluidattacks.com/advisories/mingus]
- [x] (CVE-2024-3745)[https://fluidattacks.com/advisories/gershwin]

Fixed no publish vulnerabilities and bugs which OpenRTCore64 contributors to this project found:

- Local Privilege Escalation using w/r to MSR regs ([view code](https://github.com/GermanAizek/RTCore64/blob/2ed2fbe3fb10de3ed7eca7565f6b759d7ce4bcf1/main.c#L40-L61))
- Unfiltered read/write in any IO port ([view code](https://github.com/GermanAizek/RTCore64/blob/2ed2fbe3fb10de3ed7eca7565f6b759d7ce4bcf1/pci.c#L8-L53))
- IoDevice leak ([view code](https://github.com/GermanAizek/RTCore64/blob/d1cce3220d5ff89d40495dd2ae03ae8361e4a8b8/main.c#L352-L353))

Authors:

- 2026 - Herman Semenoff <<GermanAizek@yandex.ru>> ([germanaizek.github.io](https://germanaizek.github.io))
- (Sep 30 2016 - Aug 27 2017) - Micro-Star International (MSI), RivaTuner Team <<security@msi.com>>
