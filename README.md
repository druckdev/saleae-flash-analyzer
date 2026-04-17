# SPI NOR Flash (W25/JEDEC)

A Saleae Logic 2 High Level Analyzer that decodes SPI NOR flash commands
compatible with the JEDEC/W25 instruction set.

## Compatibility

The core instruction set originated with Winbond's W25 series and has become a
de-facto industry standard, implemented identically (or near-identically) across
virtually every SPI NOR flash vendor:

| Vendor | Families |
|---|---|
| Winbond | W25Q16–W25Q128, W25R128JV, W25R256JW |
| GigaDevice | GD25Q, GD25R |
| ISSI | IS25LP, IS25WP |
| Macronix | MX25L, MX25R |
| Micron | MT25Q, N25Q |
| Spansion / Cypress / Infineon | S25FL |
| XMC, Boya, and others | Most W25Q-pin-compatible parts |

The following commands decode correctly regardless of vendor:

- All core read, write, and erase operations
- Status registers (SR-1/2/3), write enable/disable
- JEDEC ID, manufacturer/device ID, unique ID, SFDP
- Quad/Dual SPI read commands
- Block/sector lock, suspend/resume, reset
- 4-byte address mode control and dedicated 4-byte opcodes (≥256 Mbit parts)

**RPMC** (`9Bh`/`96h`) is specific to Winbond W25R parts and defined by JESD260.
Some Micron parts implement a different monotonic counter scheme under different
opcodes — those would appear as unknown.

**Vendor-specific divergences** that may show unexpected results:

- `C8h`/`C5h` Extended Address Register — Winbond convention; Micron uses `C3h`
  for a similar purpose, Macronix uses a different scheme.
- `77h` Set Burst with Wrap — Winbond-specific, not universal.
- Security/OTP register address layout (`42h`/`44h`/`48h`) varies by vendor
  though the opcodes are the same.
- Block lock granularity (`36h`/`39h`/`3Dh`) differs in behaviour across vendors.

The JEDEC SFDP register (`5Ah`) is mandated by JESD216 and present on all
modern parts; the decoded data bytes will contain the device's self-describing
parameter table.

## Setup

1. Add an **SPI** analyzer to your capture (configure clock polarity, phase, and
   chip-select as needed for your hardware).
2. Add this extension as a High Level Analyzer on top of the SPI analyzer.
3. Adjust **Max Displayed Bytes** (default 16) to control how many data bytes
   appear in each annotation bubble.

## What is decoded

| Category | Commands |
|---|---|
| **Read** | Read Data (03h / 13h), Fast Read (0Bh / 0Ch), Read SFDP (5Ah), Read Security Register (48h), Read Unique ID (4Bh), Read JEDEC ID (9Fh), Read Manufacturer/Device ID (90h / ABh), Read SR-1/2/3, Read Block Lock (3Dh), Read Extended Address Register (C8h) |
| **Write/Program** | Page Program (02h), Program Security Register (42h), Write SR-1/2/3, Write Extended Address Register (C5h) |
| **Erase** | Sector (20h), 32KB Block (52h), 64KB Block (D8h), Chip (C7h / 60h), Erase Security Register (44h) |
| **Control** | Write Enable/Disable (06h / 04h / 50h), Power-down (B9h), Enable Reset + Reset (66h / 99h), Block Lock/Unlock (36h / 39h / 7Eh / 98h), Suspend/Resume (75h / 7Ah), Enter/Exit 4-Byte Address Mode (B7h / E9h) |
| **Quad/Dual SPI** | Fast Read Quad I/O (EBh / ECh), Fast Read Quad Output (6Bh / 6Ch), Fast Read Dual I/O (BBh / BCh), Fast Read Dual Output (3Bh / 3Ch), Quad Page Program (32h), Set Burst with Wrap (77h), Read Mfr/Dev ID Dual/Quad (92h / 94h) |
| **RPMC** | OP1 – Write Root Key, Update HMAC Key, Increment Counter, Request Counter (9Bh + subtype); Read RPMC Status/Data (96h) |

Unknown opcodes are shown in grey with their raw bytes.

## Notes on Quad/Dual commands

The SPI analyzer captures only a single data line. For Quad/Dual commands the
address and payload travel on multiple lines simultaneously, so only the command
byte itself is meaningful in a single-line capture. The annotation shows the
command name and the number of bytes captured, but no address or data.

## Notes on 4-byte addressing

Parts larger than 128 Mbit (e.g. W25R256JW) support a 4-byte address mode.
The dedicated 4-byte opcodes (`13h`, `0Ch`, `3Ch`, `6Ch`, `BCh`, `ECh`) are
always decoded with a 4-byte address regardless of the current address mode
setting. The shared 3-byte opcodes (`03h`, `0Bh`, `20h`, etc.) are always
decoded with a 3-byte address; if the device is currently in 4-byte mode those
annotations will show a wrong address.
