#!/usr/bin/env python3
"""
kick_recovery.py — Zero-Data-Loss Recovery Mode Exit Tool (Windows)
-------------------------------------------------------------------
Uses Apple's locally installed MobileDevice.dll + CoreFoundation.dll
(from Microsoft Store 'Apple Devices' or classic 'iTunes') to set
NVRAM `auto-boot=true` and reboot an iPhone stuck in Recovery Mode (PID 0x1281)
without wiping user data or buying commercial wrapper tools.

Note: If an OTA update retry counter is still active in NVRAM, the first run
will allow iBoot to exhaust its remaining OTA boot attempts (~3 cycles) and
return to Recovery Mode. Running this script a second time will then boot the
intact pre-update iOS installation cleanly.
"""

import ctypes
import glob
import os
import shutil
import subprocess
import sys
import tempfile

REQUIRED_DLLS = [
    "MobileDevice.dll",
    "CoreFoundation.dll",
    "objc.dll",
    "libdispatch.dll",
    "pthreadVC2.dll",
    "ASL.dll",
    "icudt62.dll",
    "icuuc.dll",
    "libicuin.dll",
    "libicuuc.dll",
    "libxml2.dll",
    "zlib1.dll",
    "crypto-44.dll",
    "ssl-46.dll",
    "crypto-57.dll",
    "ssl-60.dll",
    "CFNetwork.dll",
    "SQLite3.dll",
    "AppleVersions.dll",
]


def find_apple_dll_source() -> str:
    """Locate MobileDevice.dll from Apple Devices (MSIX) or classic Apple Mobile Device Support."""
    # 1. Check running AMPDevicesAgent process path via PowerShell if WindowsApps listing is restricted
    try:
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            "(Get-AppxPackage -Name 'AppleInc.AppleDevices' | Select-Object -First 1).InstallLocation",
        ]
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()
        if out and os.path.exists(os.path.join(out, "MobileDevice.dll")):
            return out
    except Exception:
        pass

    # 2. Fallback glob in WindowsApps or Common Files
    candidates = glob.glob(r"C:\Program Files\WindowsApps\AppleInc.AppleDevices_*") + [
        r"C:\Program Files\Common Files\Apple\Mobile Device Support",
        r"C:\Program Files (x86)\Common Files\Apple\Mobile Device Support",
    ]
    for path in candidates:
        if os.path.exists(os.path.join(path, "MobileDevice.dll")):
            return path

    raise FileNotFoundError(
        "No se encontró MobileDevice.dll. Instala 'Dispositivos Apple' (Apple Devices) desde Microsoft Store."
    )


def stage_sdk_dlls(src_dir: str) -> str:
    """Copy DLLs out of WindowsApps if needed so Python LoadLibrary isn't blocked by MSIX ACLs."""
    if "WindowsApps" not in src_dir:
        return src_dir

    stage_dir = os.path.join(tempfile.gettempdir(), "iboot_apple_sdk_cache")
    os.makedirs(stage_dir, exist_ok=True)
    for dll in REQUIRED_DLLS:
        s = os.path.join(src_dir, dll)
        t = os.path.join(stage_dir, dll)
        if os.path.exists(s) and not os.path.exists(t):
            shutil.copy2(s, t)
    return stage_dir


def stop_competing_agents() -> None:
    """Release exclusive USB pipe held by AppleDevices / AMPDevicesAgent / iTunes."""
    subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "Stop-Process -Name AppleDevices,AMPDevicesAgent,iTunes -Force -ErrorAction SilentlyContinue",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    print("[*] Liberando pipe USB (cerrando AppleDevices / iTunes si están abiertos)...")
    stop_competing_agents()

    src_dir = find_apple_dll_source()
    sdk_dir = stage_sdk_dlls(src_dir)
    os.add_dll_directory(sdk_dir)
    os.environ["PATH"] = sdk_dir + ";" + os.environ.get("PATH", "")

    cf = ctypes.CDLL(os.path.join(sdk_dir, "CoreFoundation.dll"))
    md = ctypes.CDLL(os.path.join(sdk_dir, "MobileDevice.dll"))

    cf.CFRunLoopRunInMode.argtypes = [ctypes.c_void_p, ctypes.c_double, ctypes.c_bool]
    cf.CFRunLoopRunInMode.restype = ctypes.c_int32

    md.AMRecoveryModeDeviceGetChipID.argtypes = [ctypes.c_void_p]
    md.AMRecoveryModeDeviceGetChipID.restype = ctypes.c_uint32
    md.AMRecoveryModeDeviceGetBoardID.argtypes = [ctypes.c_void_p]
    md.AMRecoveryModeDeviceGetBoardID.restype = ctypes.c_uint32
    md.AMRecoveryModeDeviceSetAutoBoot.argtypes = [ctypes.c_void_p, ctypes.c_uint8]
    md.AMRecoveryModeDeviceSetAutoBoot.restype = ctypes.c_uint32
    md.AMRecoveryModeDeviceReboot.argtypes = [ctypes.c_void_p]
    md.AMRecoveryModeDeviceReboot.restype = ctypes.c_uint32

    cb_type = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
    fired = []

    def on_recovery_connect(dev: int) -> None:
        fired.append(dev)
        chip = md.AMRecoveryModeDeviceGetChipID(dev)
        board = md.AMRecoveryModeDeviceGetBoardID(dev)
        print(f"[+] Dispositivo en Recovery detectado (ChipID=0x{chip:X}, BoardID=0x{board:X})")
        r1 = md.AMRecoveryModeDeviceSetAutoBoot(dev, 1)
        print(f"[>] AMRecoveryModeDeviceSetAutoBoot(dev, 1) -> status=0x{r1:X}")
        r2 = md.AMRecoveryModeDeviceReboot(dev)
        print(f"[>] AMRecoveryModeDeviceReboot(dev)         -> status=0x{r2:X}")
        print("[!] Listo: desconecta el cable USB para permitir el arranque autónomo.")

    cb_noop = cb_type(lambda d: None)
    cb_rec = cb_type(on_recovery_connect)

    md.AMRestoreRegisterForDeviceNotifications.argtypes = [
        cb_type,
        cb_type,
        cb_type,
        cb_type,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    md.AMRestoreRegisterForDeviceNotifications.restype = ctypes.c_uint32
    md.AMRestoreRegisterForDeviceNotifications(cb_noop, cb_rec, cb_noop, cb_noop, 0, None)

    run_loop_mode = ctypes.c_void_p.in_dll(cf, "kCFRunLoopDefaultMode")
    for _ in range(25):
        cf.CFRunLoopRunInMode(run_loop_mode, 0.2, True)
        if fired:
            return 0

    print("[-] No se detectó ningún iPhone en modo Recovery (USB PID 0x1281).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
