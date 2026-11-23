#!/usr/bin/env python3
"""
iboot_preflight.py — iBoot Pre-Flight Radar for iPhone 12 (iPhone13,2 / d53g)
------------------------------------------------------------------------------
Detects without touching the iPhone (and without downloading the full ~11 GB IPSW,
fetching only ~1 MB via HTTP Range) whether an iOS release contains the
'Rosaline I2C Timeout Panic' bug (0x0d6d8d5372d7850a:245 in mBoot-20457.42.5)
that traps devices with replacement displays (repairStatus=1) in Recovery Mode
with Error 4013.

Usage:
  uv run python iboot_preflight.py                     # Live check of currently signed Apple IPSWs
  uv run python iboot_preflight.py --url <ipsw_url>    # Check a specific Apple CDN IPSW URL (~1 MB)
  uv run python iboot_preflight.py --ipsw <file.ipsw>  # Offline check on a local IPSW file
"""

import argparse
import json
import struct
import sys
import urllib.request
import zipfile

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from pyimg4 import IM4P
from remotezip import RemoteZip

DEVICE_IDENTIFIER = "iPhone13,2"
IBOOT_ZIP_PATH = "Firmware/all_flash/iBoot.d53g.RELEASE.im4p"
KNOWN_BAD_MBOOT = "mBoot-20457.42.5"

# Exact ARM64 little-endian encoding of the 64-bit source file hash 0x0d6d8d5372d7850a:
#   mov  x0, #0x850a             (0xD290A140)
#   movk x0, #0x72d7, lsl #16    (0xF2AE5AE0)
#   movk x0, #0x8d53, lsl #32    (0xF2D1AA60)
#   movk x0, #0xd6d,  lsl #48    (0xF2E1ADA0)
SIG_I2C_PANIC_HASH = struct.pack(
    "<IIII",
    0xD290A140,
    0xF2AE5AE0,
    0xF2D1AA60,
    0xF2E1ADA0,
)

# ARM64 encoding of `mov w8, #0x1804` used in the Restore/OTA Rosaline I2C probe
SIG_ROSALINE_CMD_0X1804 = struct.pack("<I", 0x52830088)


def fetch_latest_signed_firmwares(device: str = DEVICE_IDENTIFIER) -> list[dict]:
    url = f"https://api.ipsw.me/v4/device/{device}?type=ipsw"
    req = urllib.request.Request(url, headers={"User-Agent": "iBoot-PreFlight/1.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return [fw for fw in data.get("firmwares", []) if fw.get("signed")]


def load_im4p_from_local(ipsw_path: str) -> bytes:
    print(f"[*] Leyendo {IBOOT_ZIP_PATH} desde archivo local: {ipsw_path}")
    with zipfile.ZipFile(ipsw_path, "r") as zf:
        return zf.read(IBOOT_ZIP_PATH)


def load_im4p_from_url(ipsw_url: str) -> bytes:
    print(f"[*] Descargando SOLO {IBOOT_ZIP_PATH} (~1 MB via HTTP Range) desde CDN de Apple...")
    with RemoteZip(ipsw_url, support_suffix_range=False) as rz:
        return rz.read(IBOOT_ZIP_PATH)


def analyze_raw_iboot_binary(raw_bin: bytes, mboot_tag: str = "unknown") -> dict:
    base_addr = 0x1FC04C000
    if len(raw_bin) >= 0x388:
        cand = struct.unpack_from("<Q", raw_bin, 0x380)[0]
        if 0x1F0000000 <= cand <= 0x1FF000000:
            base_addr = cand

    has_rosaline_str = b"rosaline-serial-num" in raw_bin
    hash_offset = raw_bin.find(SIG_I2C_PANIC_HASH)
    rosaline_cmd_count = raw_bin.count(SIG_ROSALINE_CMD_0X1804)

    panic_line = None
    snippet = []
    if hash_offset != -1:
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        start = max(0, hash_offset - 0x1C)
        va_start = base_addr + start
        chunk = raw_bin[start : hash_offset + 0x20]
        for insn in md.disasm(chunk, va_start):
            snippet.append(f"0x{insn.address:x}: {insn.mnemonic:6s} {insn.op_str}")
            if insn.mnemonic == "mov" and insn.op_str.startswith("w1, #"):
                val_str = insn.op_str.split("#")[1]
                panic_line = int(val_str, 16) if val_str.startswith("0x") else int(val_str)

    return {
        "mboot_version": mboot_tag,
        "decompressed_bytes": len(raw_bin),
        "base_address": hex(base_addr),
        "has_rosaline_probe": has_rosaline_str,
        "rosaline_0x1804_occurrences": rosaline_cmd_count,
        "has_i2c_timeout_panic_hash": hash_offset != -1,
        "panic_va": hex(base_addr + hash_offset) if hash_offset != -1 else None,
        "panic_line": panic_line,
        "disasm_snippet": snippet,
    }


def analyze_iboot_im4p(raw_im4p: bytes) -> dict:
    im4p = IM4P(raw_im4p)
    mboot_tag = im4p.description or "unknown"
    im4p.payload.decompress()
    return analyze_raw_iboot_binary(im4p.payload.data, mboot_tag=mboot_tag)


def evaluate_verdict_code(res: dict) -> int:
    """Return 2 = RED (known broken), 1 = YELLOW (high risk), 0 = GREEN (patched/safe)."""
    if res["mboot_version"] == KNOWN_BAD_MBOOT:
        return 2
    if res["has_i2c_timeout_panic_hash"] and res["has_rosaline_probe"] and res["rosaline_0x1804_occurrences"] >= 2:
        return 1
    return 0


def print_verdict(label: str, res: dict) -> int:
    code = evaluate_verdict_code(res)
    panic_status = (
        f"DETECTADO en {res['panic_va']} (línea {res['panic_line']})"
        if res["has_i2c_timeout_panic_hash"]
        else "NO DETECTADO"
    )

    print("\n" + "=" * 68)
    print(f" REPORTE PRE-FLIGHT: {label}")
    print("=" * 68)
    print(f"  Bootloader (iBoot/iBEC) : {res['mboot_version']}")
    print(f"  Tamaño descomprimido    : {res['decompressed_bytes']:,} bytes (Base {res['base_address']})")
    print(f"  Probe 'rosaline-serial' : {'SÍ' if res['has_rosaline_probe'] else 'NO'} (cmd 0x1804 x{res['rosaline_0x1804_occurrences']})")
    print(f"  Panic I2C d6d8d5372d7850a: {panic_status}")

    if res["disasm_snippet"]:
        print("\n  [Desensamblado ARM64 del punto de ruptura]")
        for line in res["disasm_snippet"]:
            print(f"    {line}")

    print("-" * 68)
    if code == 2:
        print("  🚨 VEREDICTO: SEMÁFORO ROJO (BLOQUEADO)")
        print(f"     Contiene exactamente el bootloader roto ({KNOWN_BAD_MBOOT}).")
        print("     NO ACTUALIZAR: causará Error 4013 / iBoot Panic en iPhone 12 con pantalla reemplazada.")
    elif code == 1:
        print("  ⚠️  VEREDICTO: SEMÁFORO AMARILLO / RIESGO ALTO")
        print(f"     El bootloader cambió ({res['mboot_version']}), pero sigue teniendo")
        print("     el probe Rosaline 0x1804 y el mismo panic duro en timeout de I2C.")
    else:
        print("  🟢 VEREDICTO: SEMÁFORO VERDE")
        print(f"     Nuevo bootloader ({res['mboot_version']}) y la firma del bug cambió/desapareció.")
        print("     Haz respaldo en iCloud primero y procede con seguridad.")
    print("=" * 68)
    return code


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="Radar Pre-Flight iBoot para iPhone 12 (d53g)")
    parser.add_argument("--ipsw", help="Ruta a un .ipsw local para analizar offline")
    parser.add_argument("--url", help="URL directa de un .ipsw en updates.cdn-apple.com")
    args = parser.parse_args()

    if args.ipsw:
        raw = load_im4p_from_local(args.ipsw)
        return print_verdict(args.ipsw, analyze_iboot_im4p(raw))

    if args.url:
        raw = load_im4p_from_url(args.url)
        return print_verdict(args.url, analyze_iboot_im4p(raw))

    print(f"[*] Consultando firmwares firmados actualmente por Apple para {DEVICE_IDENTIFIER}...")
    signed = fetch_latest_signed_firmwares(DEVICE_IDENTIFIER)
    if not signed:
        print("[-] No se encontraron firmwares firmados.")
        return 1

    exit_code = 0
    for fw in signed:
        label = f"iOS {fw['version']} (Build {fw['buildid']})"
        raw = load_im4p_from_url(fw["url"])
        code = print_verdict(label, analyze_iboot_im4p(raw))
        exit_code = max(exit_code, code)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
