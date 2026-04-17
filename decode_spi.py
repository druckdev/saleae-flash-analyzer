#!/usr/bin/env python3
"""
SPI NOR Flash (W25/JEDEC) Command Decoder
Parses Saleae Logic SPI CSV exports and decodes them against the JEDEC/W25-compatible
SPI NOR flash instruction set: Winbond W25Q/W25R, GigaDevice GD25, ISSI IS25,
Macronix MX25, Micron MT25Q/N25Q, Spansion/Infineon S25FL, and others.

Transaction boundary detection:
  - Packet ID change (if the CSV has proper CS-based grouping), OR
  - Timing gap > max(gap_factor * recent_byte_period, abs_gap_s)

Quad/Dual SPI commands: only the command byte is on the single MOSI line;
address and data are captured on multi-wire lines and appear as garbage in a
single-SPI capture.  These commands are reported by name only; everything
after the opcode is discarded.
"""

import csv
import sys
import argparse
from dataclasses import dataclass, field
from typing import List, Optional, Iterator

# ── Formatting helpers ────────────────────────────────────────────────────────

def fmt_bytes(data: List[int], max_n: int = 32) -> str:
    if not data:
        return "(none)"
    shown = data[:max_n]
    s = " ".join(f"{b:02X}" for b in shown)
    if len(data) > max_n:
        s += f" … [{len(data)} bytes total]"
    return s


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class Row:
    time: float
    packet_id: int
    mosi: int
    miso: int


@dataclass
class Transaction:
    start_time: float
    rows: List[Row] = field(default_factory=list)

    @property
    def mosi_bytes(self) -> List[int]:
        return [r.mosi for r in self.rows]

    @property
    def miso_bytes(self) -> List[int]:
        return [r.miso for r in self.rows]


# ── Instruction table ─────────────────────────────────────────────────────────
#
# addr  : number of 3-byte address fields sent on single MOSI
# dummy : number of dummy bytes sent on single MOSI
# dir   : "read"  → data comes back on MISO
#         "write" → data sent on MOSI
#         None    → no data phase (address/erase-only commands)
# multi : True → after the command byte the bus switches to dual/quad lines;
#                discard everything after the opcode.

COMMANDS: dict = {
    # ── Write control ─────────────────────────────────────────────────────────
    0x06: {"name": "Write Enable",                         "addr": 0, "dummy": 0, "dir": None,    "multi": False},
    0x50: {"name": "Volatile SR Write Enable",              "addr": 0, "dummy": 0, "dir": None,    "multi": False},
    0x04: {"name": "Write Disable",                         "addr": 0, "dummy": 0, "dir": None,    "multi": False},

    # ── Device identification ─────────────────────────────────────────────────
    0xAB: {"name": "Release Power-down / Device ID",        "addr": 3, "dummy": 0, "dir": "read",  "multi": False},
    0x90: {"name": "Read Manufacturer/Device ID",           "addr": 3, "dummy": 0, "dir": "read",  "multi": False},
    0x9F: {"name": "Read JEDEC ID",                         "addr": 0, "dummy": 0, "dir": "read",  "multi": False},
    0x4B: {"name": "Read Unique ID",                        "addr": 0, "dummy": 4, "dir": "read",  "multi": False},

    # ── Read ──────────────────────────────────────────────────────────────────
    0x03: {"name": "Read Data",                             "addr": 3, "dummy": 0, "dir": "read",  "multi": False},
    0x0B: {"name": "Fast Read",                             "addr": 3, "dummy": 1, "dir": "read",  "multi": False},
    0x3B: {"name": "Fast Read Dual Output",                 "addr": 3, "dummy": 1, "dir": "read",  "multi": True},   # data on 2 lines
    0x6B: {"name": "Fast Read Quad Output",                 "addr": 3, "dummy": 1, "dir": "read",  "multi": True},   # data on 4 lines
    0xBB: {"name": "Fast Read Dual I/O",                    "addr": 3, "dummy": 1, "dir": "read",  "multi": True},   # addr+data on 2 lines
    0xEB: {"name": "Fast Read Quad I/O",                    "addr": 3, "dummy": 3, "dir": "read",  "multi": True},   # addr+data on 4 lines

    # ── Write ─────────────────────────────────────────────────────────────────
    0x77: {"name": "Set Burst with Wrap",                   "addr": 0, "dummy": 3, "dir": "write", "multi": True},
    0x02: {"name": "Page Program",                          "addr": 3, "dummy": 0, "dir": "write", "multi": False},
    0x32: {"name": "Quad Input Page Program",               "addr": 3, "dummy": 0, "dir": "write", "multi": True},   # data on 4 lines

    # ── Erase ─────────────────────────────────────────────────────────────────
    0x20: {"name": "Sector Erase (4KB)",                    "addr": 3, "dummy": 0, "dir": None,    "multi": False},
    0x52: {"name": "32KB Block Erase",                      "addr": 3, "dummy": 0, "dir": None,    "multi": False},
    0xD8: {"name": "64KB Block Erase",                      "addr": 3, "dummy": 0, "dir": None,    "multi": False},
    0xC7: {"name": "Chip Erase",                            "addr": 0, "dummy": 0, "dir": None,    "multi": False},
    0x60: {"name": "Chip Erase (alt)",                      "addr": 0, "dummy": 0, "dir": None,    "multi": False},

    # ── Status / Configuration registers ─────────────────────────────────────
    0x05: {"name": "Read Status Register-1",                "addr": 0, "dummy": 0, "dir": "read",  "multi": False},
    0x01: {"name": "Write Status Register-1",               "addr": 0, "dummy": 0, "dir": "write", "multi": False},
    0x35: {"name": "Read Status Register-2",                "addr": 0, "dummy": 0, "dir": "read",  "multi": False},
    0x31: {"name": "Write Status Register-2",               "addr": 0, "dummy": 0, "dir": "write", "multi": False},
    0x15: {"name": "Read Status Register-3",                "addr": 0, "dummy": 0, "dir": "read",  "multi": False},
    0x11: {"name": "Write Status Register-3",               "addr": 0, "dummy": 0, "dir": "write", "multi": False},

    # ── SFDP / Security registers ─────────────────────────────────────────────
    0x5A: {"name": "Read SFDP Register",                    "addr": 3, "dummy": 1, "dir": "read",  "multi": False},
    0x44: {"name": "Erase Security Register",               "addr": 3, "dummy": 0, "dir": None,    "multi": False},
    0x42: {"name": "Program Security Register",             "addr": 3, "dummy": 0, "dir": "write", "multi": False},
    0x48: {"name": "Read Security Register",                "addr": 3, "dummy": 1, "dir": "read",  "multi": False},

    # ── Block / Sector lock ───────────────────────────────────────────────────
    0x7E: {"name": "Global Block Lock",                     "addr": 0, "dummy": 0, "dir": None,    "multi": False},
    0x98: {"name": "Global Block Unlock",                   "addr": 0, "dummy": 0, "dir": None,    "multi": False},
    0x3D: {"name": "Read Block/Sector Lock",                "addr": 3, "dummy": 0, "dir": "read",  "multi": False},
    0x36: {"name": "Individual Block Lock",                 "addr": 3, "dummy": 0, "dir": None,    "multi": False},
    0x39: {"name": "Individual Block Unlock",               "addr": 3, "dummy": 0, "dir": None,    "multi": False},

    # ── Suspend / Resume / Power ──────────────────────────────────────────────
    0x75: {"name": "Erase/Program Suspend",                 "addr": 0, "dummy": 0, "dir": None,    "multi": False},
    0x7A: {"name": "Erase/Program Resume",                  "addr": 0, "dummy": 0, "dir": None,    "multi": False},
    0xB9: {"name": "Power-down",                            "addr": 0, "dummy": 0, "dir": None,    "multi": False},

    # ── Reset ─────────────────────────────────────────────────────────────────
    0x66: {"name": "Enable Reset",                          "addr": 0, "dummy": 0, "dir": None,    "multi": False},
    0x99: {"name": "Reset Device",                          "addr": 0, "dummy": 0, "dir": None,    "multi": False},

    # ── 4-byte address mode (W25R256JW and larger) ────────────────────────────
    # Note: when in 4-byte mode the 3-byte opcodes (03h, 0Bh, …) silently take
    # a 4th address byte; the decoder cannot detect this without state tracking.
    # The dedicated opcodes below are unambiguously 4-byte regardless of mode.
    0xB7: {"name": "Enter 4-Byte Address Mode",             "addr": 0, "dummy": 0, "dir": None,    "multi": False},
    0xE9: {"name": "Exit 4-Byte Address Mode",              "addr": 0, "dummy": 0, "dir": None,    "multi": False},
    0xC8: {"name": "Read Extended Address Register",        "addr": 0, "dummy": 0, "dir": "read",  "multi": False},
    0xC5: {"name": "Write Extended Address Register",       "addr": 0, "dummy": 0, "dir": "write", "multi": False},
    0x13: {"name": "Read Data (4-byte addr)",               "addr": 4, "dummy": 0, "dir": "read",  "multi": False},
    0x0C: {"name": "Fast Read (4-byte addr)",               "addr": 4, "dummy": 1, "dir": "read",  "multi": False},
    0x3C: {"name": "Fast Read Dual Output (4-byte addr)",   "addr": 4, "dummy": 1, "dir": "read",  "multi": True},
    0x6C: {"name": "Fast Read Quad Output (4-byte addr)",   "addr": 4, "dummy": 1, "dir": "read",  "multi": True},
    0xBC: {"name": "Fast Read Dual I/O (4-byte addr)",      "addr": 4, "dummy": 1, "dir": "read",  "multi": True},
    0xEC: {"name": "Fast Read Quad I/O (4-byte addr)",      "addr": 4, "dummy": 3, "dir": "read",  "multi": True},

    # ── RPMC ──────────────────────────────────────────────────────────────────
    # 0x9B is dispatched further based on the CmdType byte (byte 2)
    0x9B: {"name": "RPMC OP1",                              "addr": 0, "dummy": 0, "dir": "write", "multi": False, "rpmc_op1": True},
    0x96: {"name": "Read RPMC Status/Data",                 "addr": 0, "dummy": 1, "dir": "read",  "multi": False},

    # ── Dual/Quad device-ID reads (address/data on multi lines) ──────────────
    0x92: {"name": "Read Manufacturer/Device ID Dual I/O",  "addr": 3, "dummy": 0, "dir": "read",  "multi": True},
    0x94: {"name": "Read Manufacturer/Device ID Quad I/O",  "addr": 3, "dummy": 0, "dir": "read",  "multi": True},
}

RPMC_OP1_SUBTYPES = {
    0x00: "Write Root Key Register",
    0x01: "Update HMAC Key Register",
    0x02: "Increment Monotonic Counter",
    0x03: "Request Monotonic Counter",
}


# ── Transaction grouping ──────────────────────────────────────────────────────

def parse_and_group(
    path: str,
    gap_factor: float = 1.5,
    abs_gap_s: float = 1.0e-6,
    max_rows: Optional[int] = None,
) -> Iterator[Transaction]:
    """
    Stream rows from *path* and yield completed Transaction objects.

    Boundary rules (first match wins):
      1. Packet ID changes between consecutive rows.
      2. Time delta > max(gap_factor × median-of-recent-byte-periods, abs_gap_s).
    """
    current_rows: List[Row] = []
    prev_time: Optional[float] = None
    prev_pid: Optional[int] = None
    recent_deltas: List[float] = []   # sliding window of intra-transaction deltas
    rows_read = 0

    with open(path, newline="") as fh:
        reader = csv.reader(fh)
        next(reader)  # skip header

        for raw in reader:
            if max_rows and rows_read >= max_rows:
                break
            rows_read += 1

            try:
                time = float(raw[0])
                pid  = int(raw[1])
                mosi = int(raw[2], 16)
                miso = int(raw[3], 16)
            except (ValueError, IndexError):
                continue

            r = Row(time, pid, mosi, miso)

            if prev_time is None:
                current_rows.append(r)
                prev_time, prev_pid = time, pid
                continue

            delta = time - prev_time
            prev_time = time

            # Determine whether this row starts a new transaction
            pid_break = (pid != prev_pid)
            prev_pid = pid

            if recent_deltas:
                # Use median of recent within-transaction byte intervals
                sorted_d = sorted(recent_deltas)
                median_d = sorted_d[len(sorted_d) // 2]
                threshold = max(median_d * gap_factor, abs_gap_s)
            else:
                threshold = abs_gap_s

            time_break = delta > threshold

            if pid_break or time_break:
                if current_rows:
                    yield Transaction(current_rows[0].time, current_rows)
                current_rows = [r]
                recent_deltas = []
            else:
                current_rows.append(r)
                recent_deltas.append(delta)
                if len(recent_deltas) > 8:
                    recent_deltas.pop(0)

    if current_rows:
        yield Transaction(current_rows[0].time, current_rows)


# ── Decoder ───────────────────────────────────────────────────────────────────

def decode_transaction(tx: Transaction, max_data: int = 32) -> str:
    mosi = tx.mosi_bytes
    miso = tx.miso_bytes

    if not mosi:
        return "(empty)"

    opcode = mosi[0]

    if opcode not in COMMANDS:
        raw = " ".join(f"{b:02X}" for b in mosi)
        return f"UNKNOWN [0x{opcode:02X}]  ({len(mosi)} byte(s): {raw})"

    cmd  = COMMANDS[opcode]
    name = cmd["name"]

    # Multi-line command: discard everything after the opcode
    if cmd["multi"]:
        return (f"{name} [0x{opcode:02X}]"
                f"  (quad/dual — addr/data on multi-wire lines; "
                f"{len(mosi)} bytes captured)")

    # RPMC OP1: dispatch on CmdType (byte 2)
    if cmd.get("rpmc_op1"):
        if len(mosi) >= 2:
            sub    = mosi[1]
            sub_name = RPMC_OP1_SUBTYPES.get(sub, f"Reserved subtype 0x{sub:02X}")
            caddr  = f"counter_addr=0x{mosi[2]:02X}" if len(mosi) > 2 else "counter_addr=?"
            return f"RPMC OP1 – {sub_name} [0x9B / 0x{sub:02X}]  {caddr}"
        return f"RPMC OP1 [0x9B]  (incomplete — only {len(mosi)} byte(s))"

    n_addr  = cmd["addr"]
    n_dummy = cmd["dummy"]
    data_start = 1 + n_addr + n_dummy

    # Address
    addr_str = ""
    if n_addr > 0:
        addr_bytes = mosi[1 : 1 + n_addr]
        if len(addr_bytes) == n_addr:
            addr = int.from_bytes(addr_bytes, "big")
            addr_str = f"  addr=0x{addr:0{n_addr * 2}X}"
        else:
            addr_str = "  addr=INCOMPLETE"

    # Data
    data_str = ""
    if cmd["dir"] == "read" and len(miso) > data_start:
        data = miso[data_start:]
        data_str = f"  → {fmt_bytes(data, max_data)}"
    elif cmd["dir"] == "write" and len(mosi) > data_start:
        data = mosi[data_start:]
        data_str = f"  ← {fmt_bytes(data, max_data)}"

    return f"{name} [0x{opcode:02X}]{addr_str}{data_str}"


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Decode W25R128JV SPI commands from a Saleae Logic CSV export.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("csv", help="Saleae Logic SPI CSV file")
    ap.add_argument("--gap-factor", type=float, default=1.5,
                    help="Threshold multiplier over recent byte period to detect CS boundary")
    ap.add_argument("--abs-gap", type=float, default=1e-6,
                    help="Absolute minimum gap (seconds) that always signals a new transaction")
    ap.add_argument("--max-data", type=int, default=32,
                    help="Max data bytes shown per transaction")
    ap.add_argument("--max-rows", type=int, default=None,
                    help="Stop after reading this many CSV rows (for quick tests)")
    ap.add_argument("--max-transactions", type=int, default=None,
                    help="Stop after decoding this many transactions")
    ap.add_argument("--no-timestamps", action="store_true",
                    help="Omit timestamps from output")
    args = ap.parse_args()

    n_tx       = 0
    n_known    = 0
    n_unknown  = 0
    unknown_opcodes: set = set()
    cmd_counts: dict = {}

    print(f"# SPI NOR Flash (W25/JEDEC) Decoder  |  {args.csv}")
    print(f"# gap_factor={args.gap_factor}  abs_gap={args.abs_gap*1e6:.2f}µs"
          f"  max_data={args.max_data} bytes")
    print()

    gen = parse_and_group(args.csv, args.gap_factor, args.abs_gap, args.max_rows)

    for tx in gen:
        n_tx += 1
        decoded = decode_transaction(tx, args.max_data)

        if not args.no_timestamps:
            ts = f"[{tx.start_time:.9f}] "
        else:
            ts = ""

        print(f"{ts}{decoded}")

        opcode = tx.mosi_bytes[0]
        if opcode not in COMMANDS:
            n_unknown += 1
            unknown_opcodes.add(opcode)
        else:
            key = COMMANDS[opcode]["name"]
            cmd_counts[key] = cmd_counts.get(key, 0) + 1
            n_known += 1

        if args.max_transactions and n_tx >= args.max_transactions:
            print(f"\n# (stopped after {n_tx} transactions)")
            break

    # ── Sanity-check summary ──────────────────────────────────────────────────
    all_known_names = {v["name"] for v in COMMANDS.values()}
    seen_names      = set(cmd_counts.keys())
    never_seen      = all_known_names - seen_names

    print()
    print("# ── Summary " + "─" * 60)
    print(f"#  Total transactions : {n_tx}")
    print(f"#  Known commands     : {n_known}")
    print(f"#  Unknown opcodes    : {n_unknown}"
          + (f"  ({', '.join(f'0x{o:02X}' for o in sorted(unknown_opcodes))})"
             if unknown_opcodes else ""))
    print()
    print("#  Command breakdown (known):")
    for name, count in sorted(cmd_counts.items(), key=lambda kv: -kv[1]):
        print(f"#    {count:8d}×  {name}")
    if never_seen:
        print()
        print("#  Commands defined in table but NOT seen in capture:")
        for name in sorted(never_seen):
            print(f"#    {name}")


if __name__ == "__main__":
    main()
