# Apple Feedback Assistant Report Template

Submit at [https://feedbackassistant.apple.com](https://feedbackassistant.apple.com) (**iOS & iPadOS** → **Software Update / Restore**).

## Title
`[Regression] iBoot/iBEC mBoot-20457.42.5 (iOS 27.2.1 / 24B156) hard-panics in I2C driver (d6d8d5372d7850a:245) when probing rosaline-serial-num (cmd 0x1804) during Restore/OTA on iPhone13,2 with repairStatus=1 (Error 4013)`

## Description

### Summary
Updating or restoring an **iPhone 12 (`iPhone13,2` / `d53gap`, `CPID: 0x8101`, `socRevision: 0x11`)** with `repairStatus: "1"` (replacement display / aftermarket Rosaline ambient light sensor) to **iOS 27.2.1 (`24B156`)** deterministically triggers an **iBoot Panic** inside **`mBoot-20457.42.5`** before XNU (`RestoreKernelCache`) starts.

This reproduces identically across:
1. **OTA updates** (`24B119` → `24B156`, resulting in `MobileSoftwareUpdateErrorDomain error 78` bootloop).
2. **USB Update** via Apple Devices on Windows (`Customer Upgrade Install`, resulting in **Error 4013** after 6.2s).
3. **USB Erase Restore** via Apple Devices on Windows (`Customer Erase Install`, resulting in **Error 4013** after 6.2s).

Normal OS boot succeeds 100% once `auto-boot=true` is restored in NVRAM after OTA retry exhaustion, because normal boot skips the `0x1804` I2C command.

### Root Cause Analysis (Disassembly of `mBoot-20457.42.5`, Base `0x1fc04c000`)
From the `panic-base+socd` SOCD container:
- **Panic String:** `iBoot Panic: : d6d8d5372d7850a:245`
- **Breadcrumbs:** `3000f(72647472)` (`rdtr`), `3000f(7264736b)` (`rdsk`), `3000f(726b726e)` (`rkrn`)

Call chain in `iBoot.d53g.RELEASE.im4p` (`mBoot-20457.42.5`):
1. **`0x1fc0ca5c8`** (`UpdateDeviceTree` for Restore/OTA boot): Calls `0x1fc0c9868` to populate `"rosaline-serial-num"` in the DeviceTree right before `"arm-io/spi1/multi-touch"`.
2. **`0x1fc0c98ac` → `0x1fc0c9538`:** Calls `0x1fc15d118` (`0x1fc0c958c`). On normal boot (`w0 == 0`), `cbz w0, #0x1fc0c95c0` skips the `0x1804` transaction. During Restore/OTA (`w0 != 0`), `0x1fc0c9598` executes `mov w8, #0x1804` and calls the I2C transfer routine `0x1fc1018e0` at **`0x1fc0c95b8`**.
3. **`0x1fc1018e0` → `0x1fc101a04` (I2C polling loop):** Polls MMIO `[x8, #0x14]` bit 27 (`tbnz w9, #0x1b, #0x1fc101a08`). When an aftermarket/repaired display's Rosaline IC does not complete the `0x1804` transaction within the timeout (`x21`), instead of returning `-1` so `UpdateDeviceTree` can omit `"rosaline-serial-num"`, the I2C driver calls **`panic(0x0d6d8d5372d7850a, 245)`** at `0x1fc101a04`.

### Expected Behavior
A non-responsive or third-party sensor on the `rosaline` I2C bus during `UpdateDeviceTree` (`rdtr` population) must not hard-panic `iBoot`/`iBEC` and brick user devices into Recovery Mode (`Error 4013`). Timeout on `0x1804` should gracefully abort the transfer, reset the I2C bus, and return an error code so OS restore/update can proceed.
