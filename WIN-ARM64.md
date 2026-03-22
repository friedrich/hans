# Building Hans -- Windows ARM64 (MSVC)

This document describes how to build Hans natively on **Windows ARM64** using Visual Studio and CMake. This replaces the legacy CYGWIN/Makefile build for x86.

---

## Requirements

| Tool | Version | Notes |
|---|---|---|
| Visual Studio | 2026 Community (or 2022) | With **Desktop development with C++** workload |
| CMake | Bundled with Visual Studio | Must be added to PATH |
| TAP-Windows driver | Any | Included with [OpenVPN](https://openvpn.net/community-downloads/) |

---

## 1. Add CMake to PATH

CMake ships with Visual Studio but is not added to PATH automatically.

Open PowerShell as **Administrator** and run:

```powershell
$cmakePath = "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";$cmakePath", "Machine")
```

> For Visual Studio 2022, replace `\18\` with `\17\` or `\2022\` in the path above.

Close and reopen PowerShell, then verify:

```powershell
cmake --version
```

---

## 2. Configure the Build

Open PowerShell, navigate to the project folder and run:

```powershell
cd C:\path\to\hans
cmake -B build -A ARM64
```

You should see output ending with:
```
-- Build files have been written to: ...\hans\build
```

---

## 3. Compile

```powershell
cmake --build build --config Release
```

The executable will be at:
```
build\Release\hans.exe
```

---

## 4. Clean Build (if needed)

If you are recompiling after source changes:

```powershell
Remove-Item -Recurse -Force build
cmake -B build -A ARM64
cmake --build build --config Release
```

---

## 5. Verify No Debug Info (optional)

To confirm the Release binary has no embedded debug information:

```powershell
& "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.50.35717\bin\Hostarm64\arm64\dumpbin.exe" /headers build\Release\hans.exe | Select-String "debug"
```

Expected output:
```
0 [       0] RVA [size] of Debug Directory
```

---

## Runtime Requirements

The **TAP-Windows** driver must be installed before running `hans.exe`. It is bundled with [OpenVPN](https://openvpn.net/community-downloads/) -- installing OpenVPN is sufficient.

---

## Windows-specific Files

These files were added for the Windows/MSVC port and have no effect on Linux builds:

| File | Purpose |
|---|---|
| `src/win32_compat.h` / `.cpp` | POSIX compatibility layer (sockets, threads) |
| `src/tun_dev_win32.c` | TAP-Windows adapter driver with Overlapped I/O |
| `CMakeLists.txt` | CMake build system replacing the original Makefile |

> `src/hans_time.h` / `hans_time.cpp` were renamed from `time.h` / `time.cpp` to avoid a naming conflict with the MSVC system header `<time.h>`.
