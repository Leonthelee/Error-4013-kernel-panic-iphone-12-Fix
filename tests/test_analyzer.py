import pathlib
import struct

from iboot_preflight import (
    KNOWN_BAD_MBOOT,
    SIG_I2C_PANIC_HASH,
    SIG_ROSALINE_CMD_0X1804,
    analyze_raw_iboot_binary,
    evaluate_verdict_code,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_detects_buggy_mboot_signature():
    # Build a synthetic buffer mimicking mBoot header at 0x380 + Rosaline probe + I2C panic hash
    buf = bytearray(0x1000)
    struct.pack_into("<Q", buf, 0x380, 0x1FC04C000)
    buf[0x500 : 0x500 + 19] = b"rosaline-serial-num"
    buf[0x600 : 0x604] = SIG_ROSALINE_CMD_0X1804
    buf[0x620 : 0x624] = SIG_ROSALINE_CMD_0X1804

    # Place panic hash + `mov w1, #0xf5` (0x52801EA1)
    off = 0x800
    buf[off : off + 16] = SIG_I2C_PANIC_HASH
    struct.pack_into("<I", buf, off + 16, 0x52801EA1)

    res = analyze_raw_iboot_binary(bytes(buf), mboot_tag=KNOWN_BAD_MBOOT)
    assert res["base_address"] == "0x1fc04c000"
    assert res["has_rosaline_probe"] is True
    assert res["rosaline_0x1804_occurrences"] == 2
    assert res["has_i2c_timeout_panic_hash"] is True
    assert res["panic_line"] == 245
    assert evaluate_verdict_code(res) == 2


def test_green_verdict_when_patched():
    buf = bytearray(0x1000)
    struct.pack_into("<Q", buf, 0x380, 0x1FC04C000)
    res = analyze_raw_iboot_binary(bytes(buf), mboot_tag="mBoot-20500.1.1")
    assert res["has_i2c_timeout_panic_hash"] is False
    assert evaluate_verdict_code(res) == 0


def test_no_pii_or_device_identifiers_in_repo():
    # Ensure zero personal serials, ECIDs, or local workstation usernames are tracked
    forbidden_substrings = [
        "DNPH" + "34GS0F0X",
        "4660" + "A83001E",
        "4836" + "309532702",
        "DGA-" + "MOPSOPORTE",
        "aa676f20" + "d7f984b4",
        "A584EC36" + "-7DA7",
    ]
    for path in REPO_ROOT.rglob("*"):
        if any(part in {".git", ".venv", "__pycache__", ".pytest_cache"} for part in path.parts):
            continue
        if path.is_file():
            content = path.read_text(encoding="utf-8", errors="ignore")
            for needle in forbidden_substrings:
                assert needle not in content, f"Forbidden identifier found in {path.relative_to(REPO_ROOT)}"
