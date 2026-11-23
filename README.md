# Error 4013 / iBoot Panic on iPhone 12 — Fix & Pre-Flight Radar

**Zero-data-loss Recovery Mode rescue (`kick_recovery.py`) + ARM64 reverse-engineering root cause + Pre-Flight IPSW scanner (`iboot_preflight.py`) for iPhone 12 (`iPhone13,2` / `d53g`) stuck in Recovery Mode with Error `4013`.**

---

## Resumen Ejecutivo (Español)

Si tu **iPhone 12 (`iPhone13,2`) con pantalla reemplazada (`repairStatus = 1`)** quedó atrapado en **Modo Recuperación (Error `4013` a los 6.2 segundos)** al intentar actualizar a **iOS 27.2.1 (`24B156`)** por OTA o por PC (*Dispositivos Apple* / *iTunes*), **tu placa madre, tu memoria NAND y tus datos NO están dañados**.

### 1. ¿Cuál es la causa real? (Ingeniería Inversa de `mBoot-20457.42.5`)

Al desensamblar el bootloader `iBoot` / `iBEC` (`mBoot-20457.42.5`, base `0x1fc04c000`) y cruzarlo con el volcado `SOCD` (`iBoot Panic: d6d8d5372d7850a:245`) y los logs `iPhoneUpdater`:

1. Cuando el iPhone intenta instalar una actualización o restaurarse (cargando `rdtr` *RestoreDeviceTree*, `rdsk` *RestoreRamDisk* y `rkrn` *RestoreKernelCache*), la rutina `UpdateDeviceTree` (`0x1fc0ca5c8`) llama a `0x1fc0c9868` para consultar **`"rosaline-serial-num"`** (*Rosaline* es el nombre interno de Apple para el chip del sensor de luz ambiental / TrueTone en la pantalla).
2. En `0x1fc0c958c`, `iBoot` verifica el modo de arranque:
   * **En arranque normal (`w0 == 0`):** ejecuta `cbz w0, #0x1fc0c95c0` y **OMITE** el comando I2C `0x1804`. Por eso el sistema operativo normal arranca y funciona sin fallas.
   * **En actualización / restauración (`w0 != 0`):** ejecuta `mov w8, #0x1804` y llama a la transferencia I2C (`0x1fc1018e0`) desde `0x1fc0c95b8`.
3. Cuando el sensor alternativo de una pantalla reemplazada no responde al comando `0x1804`, el bucle de polling MMIO (`[x8, #0x14]` bit 27 en `0x1fc1019d4`) agota el timeout y, **en vez de devolver un código de error (`-1`)**, el driver I2C llama directamente a **`panic(0x0d6d8d5372d7850a, 245)`** en `0x1fc101a04`:

```armasm
0x1fc1019d4: ldr    x8, [x19, #0x20]        ; Base MMIO controlador I2C
0x1fc1019d8: ldr    w9, [x8, #0x14]         ; Registro de estado I2C
0x1fc1019dc: tbnz   w9, #0x1b, #0x1fc101a08 ; ¿Transferencia completada?
0x1fc1019e0: bl     #0x1fc04c57c            ; get_ticks()
0x1fc1019e4: sub    x8, x0, x20             ; elapsed = now - start
0x1fc1019e8: cmp    x8, x21                 ; ¿elapsed < timeout?
0x1fc1019ec: b.lo   #0x1fc1019d4
0x1fc1019f0: mov    x0, #0x850a             ; Hash 0x0d6d8d5372d7850a
0x1fc1019f4: movk   x0, #0x72d7, lsl #16
0x1fc1019f8: movk   x0, #0x8d53, lsl #32
0x1fc1019fc: movk   x0, #0xd6d,  lsl #48
0x1fc101a00: mov    w1, #0xf5               ; Línea 245 (0xf5)
0x1fc101a04: bl     #0x1fc0786c0            ; panic("%llx:%d", hash, 245) -> Error 4013!
```

4. Como el crash ocurre en `iBoot` **antes** de que arranque `RestoreOS` (`restored_external`), **ningún intento fallido de actualización o restauración llega a tocar ni borrar la partición de datos en la NAND**.

---

### 2. Cómo rescatar el iPhone SIN perder datos (`kick_recovery.py`)

No necesitas pagar herramientas comerciales (*Fixppo*, *ReiBoot*, etc.), que solo envuelven `MobileDevice.dll` de Apple.

#### Requisitos en Windows
* Tener instalado **Dispositivos Apple** (*Apple Devices* desde Microsoft Store) o *iTunes*.
* Python 3.11+.

#### Pasos de rescate
1. Conecta el iPhone en Modo Recuperación al PC y ejecuta:
   ```powershell
   python kick_recovery.py
   ```
2. El script engancha `MobileDevice.dll` por C-ABI y envía:
   * `AMRecoveryModeDeviceSetAutoBoot(dev, 1)` (`auto-boot=true` en NVRAM)
   * `AMRecoveryModeDeviceReboot(dev)`
3. **Importante si venías de una actualización OTA fallida:**
   * En la primera ejecución, si aún quedan reintentos pendientes de `ota-retry` en NVRAM, el iPhone dará ~3 reinicios en la manzana agotando el contador del instalador y volverá a mostrar el ícono de Recovery.
   * **Vuelve a correr `python kick_recovery.py` una segunda vez** y desconecta el cable USB de inmediato: ya limpio el flag de OTA, `iBoot` tomará la rama `w0 == 0` y levantará tu iOS anterior con **todos tus datos intactos**.
4. **Apenas encienda el iPhone:**
   * Haz un respaldo inmediato en iCloud.
   * Ve a **Configuración → General → Almacenamiento del iPhone** y **elimina la actualización descargada**.
   * Ve a **Configuración → General → Actualización de software → Actualizaciones automáticas** y apaga **Descargar** e **Instalar**.
   * **NO intentes actualizar a `24B156` desde el PC** (dispara exactamente el mismo `iBoot Panic` en `iBEC`).

---

### 3. Radar Pre-Flight para futuras versiones de iOS (`iboot_preflight.py`)

Antes de instalar una futura actualización (`27.2.2`, `27.3`, etc.), este escáner descarga **únicamente ~1 MB (`iBoot.d53g.RELEASE.im4p`) mediante `HTTP Range`** directo desde el CDN de Apple (sin bajar los 11 GB del `.ipsw`), lo descomprime en memoria, desensambla ARM64 con `Capstone` y verifica si Apple ya parchó el `panic()` del bus I2C:

```powershell
uv sync
uv run python iboot_preflight.py
```

* 🚨 **SEMÁFORO ROJO (Exit 2):** Sigue trayendo `mBoot-20457.42.5`. **No actualizar** (causará Error 4013).
* ⚠️ **SEMÁFORO AMARILLO (Exit 1):** Cambió la versión de `mBoot`, pero persisten tanto el comando `0x1804` de `rosaline-serial-num` como el `panic(0x0d6d8d5372d7850a, 245)`.
* 🟢 **SEMÁFORO VERDE (Exit 0):** Nuevo `mBoot` y desapareció la firma del `panic` en timeout I2C.

---

## English Summary

Updating or restoring an **iPhone 12 (`iPhone13,2` / `d53gap`)** with a replacement screen (`repairStatus = 1`) to **iOS 27.2.1 (`24B156`)** triggers a deterministic **`iBoot Panic` (`d6d8d5372d7850a:245`)** inside **`mBoot-20457.42.5`** while populating `"rosaline-serial-num"` (`cmd 0x1804` over I2C) for `RestoreDeviceTree` (`rdtr`). Because `RestoreOS` never boots, user data on NAND remains untouched.

* Use **`kick_recovery.py`** on Windows to invoke Apple's local `MobileDevice.dll` (`AMRecoveryModeDeviceSetAutoBoot(dev, 1)` + `AMRecoveryModeDeviceReboot`) and boot back into your existing iOS with zero data loss.
* Use **`iboot_preflight.py`** to inspect future Apple IPSWs in ~3 seconds (~1 MB HTTP Range fetch) before updating.
* See [`docs/APPLE_BUG_REPORT.md`](docs/APPLE_BUG_REPORT.md) and [`docs/sanitized_socd_panic.json`](docs/sanitized_socd_panic.json) for full disassembly details and a ready-to-submit Apple Feedback Assistant report.
