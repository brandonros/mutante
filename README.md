# mutante
Windows kernel-mode hardware identifier (HWID) spoofer. It does not use any hooking, so it can be completelly unloaded after use.

## Features
- Disk serials (works on both SATA and NVMe drives)
- Disable S.M.A.R.T functionality
- SMBIOS (tables 0-3) modification (not zeroing)

## Credits
- Me (@SamuelTulach) - Putting it all together
- n0Lin (@Alex3434) - [Static disk spoofing without hooks](https://github.com/Alex3434/wmi-static-spoofer)
- IChooseYou - [Disable S.M.A.R.T functionality](https://www.unknowncheats.me/forum/2441916-post67.html) and [finding SMBIOS physical address](https://www.unknowncheats.me/forum/2436698-post9.html)
- btdt (@btdt) - [Finding SMBIOS physical address (again)](https://github.com/btbd/hwid/blob/master/Kernel/main.c#L558) and [signanture scanning functions](https://github.com/btbd/hwid/blob/master/Kernel/util.c#L112)

## Building / known working versions

```
System Information -> System Summary -> Microsoft Windows 10 Pro 10.0.19045 (22H2 as per https://learn.microsoft.com/en-us/windows/release-health/release-information, which would use `WDK for Windows 10, version 2004` as per https://learn.microsoft.com/en-us/windows-hardware/drivers/other-wdk-downloads)

Microsoft Visual Studio Community 2019 - 16.11.25
  Workloads:
    Desktop development with C++ workload
  Individual components:
    MSVC v142 - VS 2019 C++ x64/x86 build tools (Latest)
    MSVC v142 - VS 2019 C++ x64/x86 Spectre-mitigated libs (Latest)
    Windows 10 Driver Kit (from https://go.microsoft.com/fwlink/?linkid=2128854)
```
