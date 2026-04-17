# High Level Analyzer – SPI NOR Flash (W25/JEDEC) Command Decoder
# Covers the Standard/Dual/Quad SPI and RPMC instruction set shared by the
# W25Q/W25R family and compatible parts from GigaDevice (GD25), ISSI (IS25),
# Macronix (MX25), Micron (MT25Q/N25Q), Spansion/Infineon (S25FL), and others.
# Includes dedicated 4-byte-address opcodes for ≥256 Mbit parts.
#
# Quad/Dual SPI commands: only the command byte travels on the single MOSI
# line; address and data are on multiple lines and appear as garbage in a
# standard SPI capture.  Those bytes are discarded; only the opcode is shown.

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, NumberSetting


# ── Display helpers ───────────────────────────────────────────────────────────

def _fmt(data: bytes, max_n: int) -> str:
    """Return a compact hex string, ellipsis-truncated to max_n bytes."""
    if not data:
        return ''
    shown = data[:max_n]
    s = ' '.join(f'{b:02X}' for b in shown)
    if len(data) > max_n:
        s += f' …[{len(data)}B]'
    return s


# ── Instruction table ─────────────────────────────────────────────────────────
#
# addr  – number of address bytes sent on single MOSI
# dummy – number of dummy bytes sent on single MOSI
# dir   – 'read'  → payload on MISO
#         'write' → payload on MOSI
#         None    → no data phase
# multi – True: after the opcode the bus switches to dual/quad lines;
#               discard everything past the first byte
# rtype – result_types key used for coloring in Logic 2

COMMANDS = {
    # ── Write control ────────────────────────────────────────────────────────
    0x06: {'name': 'Write Enable',                         'addr': 0, 'dummy': 0, 'dir': None,    'multi': False, 'rtype': 'ctrl'},
    0x50: {'name': 'Volatile SR Write Enable',              'addr': 0, 'dummy': 0, 'dir': None,    'multi': False, 'rtype': 'ctrl'},
    0x04: {'name': 'Write Disable',                         'addr': 0, 'dummy': 0, 'dir': None,    'multi': False, 'rtype': 'ctrl'},

    # ── Device identification ────────────────────────────────────────────────
    0xAB: {'name': 'Release Power-down / Device ID',        'addr': 3, 'dummy': 0, 'dir': 'read',  'multi': False, 'rtype': 'read'},
    0x90: {'name': 'Read Manufacturer/Device ID',           'addr': 3, 'dummy': 0, 'dir': 'read',  'multi': False, 'rtype': 'read'},
    0x9F: {'name': 'Read JEDEC ID',                         'addr': 0, 'dummy': 0, 'dir': 'read',  'multi': False, 'rtype': 'read'},
    0x4B: {'name': 'Read Unique ID',                        'addr': 0, 'dummy': 4, 'dir': 'read',  'multi': False, 'rtype': 'read'},

    # ── Standard SPI reads ───────────────────────────────────────────────────
    0x03: {'name': 'Read Data',                             'addr': 3, 'dummy': 0, 'dir': 'read',  'multi': False, 'rtype': 'read'},
    0x0B: {'name': 'Fast Read',                             'addr': 3, 'dummy': 1, 'dir': 'read',  'multi': False, 'rtype': 'read'},

    # ── Dual / Quad reads (addr+data on multiple lines) ──────────────────────
    0x3B: {'name': 'Fast Read Dual Output',                 'addr': 3, 'dummy': 1, 'dir': 'read',  'multi': True,  'rtype': 'multi'},
    0x6B: {'name': 'Fast Read Quad Output',                 'addr': 3, 'dummy': 1, 'dir': 'read',  'multi': True,  'rtype': 'multi'},
    0xBB: {'name': 'Fast Read Dual I/O',                    'addr': 3, 'dummy': 1, 'dir': 'read',  'multi': True,  'rtype': 'multi'},
    0xEB: {'name': 'Fast Read Quad I/O',                    'addr': 3, 'dummy': 3, 'dir': 'read',  'multi': True,  'rtype': 'multi'},

    # ── Write / Program ──────────────────────────────────────────────────────
    0x02: {'name': 'Page Program',                          'addr': 3, 'dummy': 0, 'dir': 'write', 'multi': False, 'rtype': 'write'},
    0x32: {'name': 'Quad Input Page Program',               'addr': 3, 'dummy': 0, 'dir': 'write', 'multi': True,  'rtype': 'multi'},
    0x77: {'name': 'Set Burst with Wrap',                   'addr': 0, 'dummy': 3, 'dir': 'write', 'multi': True,  'rtype': 'multi'},

    # ── Erase ────────────────────────────────────────────────────────────────
    0x20: {'name': 'Sector Erase (4KB)',                    'addr': 3, 'dummy': 0, 'dir': None,    'multi': False, 'rtype': 'erase'},
    0x52: {'name': '32KB Block Erase',                      'addr': 3, 'dummy': 0, 'dir': None,    'multi': False, 'rtype': 'erase'},
    0xD8: {'name': '64KB Block Erase',                      'addr': 3, 'dummy': 0, 'dir': None,    'multi': False, 'rtype': 'erase'},
    0xC7: {'name': 'Chip Erase',                            'addr': 0, 'dummy': 0, 'dir': None,    'multi': False, 'rtype': 'erase'},
    0x60: {'name': 'Chip Erase (alt)',                      'addr': 0, 'dummy': 0, 'dir': None,    'multi': False, 'rtype': 'erase'},

    # ── Status / Configuration registers ────────────────────────────────────
    0x05: {'name': 'Read SR-1',                             'addr': 0, 'dummy': 0, 'dir': 'read',  'multi': False, 'rtype': 'status'},
    0x01: {'name': 'Write SR-1',                            'addr': 0, 'dummy': 0, 'dir': 'write', 'multi': False, 'rtype': 'status'},
    0x35: {'name': 'Read SR-2',                             'addr': 0, 'dummy': 0, 'dir': 'read',  'multi': False, 'rtype': 'status'},
    0x31: {'name': 'Write SR-2',                            'addr': 0, 'dummy': 0, 'dir': 'write', 'multi': False, 'rtype': 'status'},
    0x15: {'name': 'Read SR-3',                             'addr': 0, 'dummy': 0, 'dir': 'read',  'multi': False, 'rtype': 'status'},
    0x11: {'name': 'Write SR-3',                            'addr': 0, 'dummy': 0, 'dir': 'write', 'multi': False, 'rtype': 'status'},

    # ── SFDP / Security registers ────────────────────────────────────────────
    0x5A: {'name': 'Read SFDP',                             'addr': 3, 'dummy': 1, 'dir': 'read',  'multi': False, 'rtype': 'read'},
    0x44: {'name': 'Erase Security Register',               'addr': 3, 'dummy': 0, 'dir': None,    'multi': False, 'rtype': 'erase'},
    0x42: {'name': 'Program Security Register',             'addr': 3, 'dummy': 0, 'dir': 'write', 'multi': False, 'rtype': 'write'},
    0x48: {'name': 'Read Security Register',                'addr': 3, 'dummy': 1, 'dir': 'read',  'multi': False, 'rtype': 'read'},

    # ── Block / Sector lock ──────────────────────────────────────────────────
    0x7E: {'name': 'Global Block Lock',                     'addr': 0, 'dummy': 0, 'dir': None,    'multi': False, 'rtype': 'ctrl'},
    0x98: {'name': 'Global Block Unlock',                   'addr': 0, 'dummy': 0, 'dir': None,    'multi': False, 'rtype': 'ctrl'},
    0x3D: {'name': 'Read Block/Sector Lock',                'addr': 3, 'dummy': 0, 'dir': 'read',  'multi': False, 'rtype': 'status'},
    0x36: {'name': 'Individual Block Lock',                 'addr': 3, 'dummy': 0, 'dir': None,    'multi': False, 'rtype': 'ctrl'},
    0x39: {'name': 'Individual Block Unlock',               'addr': 3, 'dummy': 0, 'dir': None,    'multi': False, 'rtype': 'ctrl'},

    # ── Suspend / Resume / Power / Reset ────────────────────────────────────
    0x75: {'name': 'Erase/Program Suspend',                 'addr': 0, 'dummy': 0, 'dir': None,    'multi': False, 'rtype': 'ctrl'},
    0x7A: {'name': 'Erase/Program Resume',                  'addr': 0, 'dummy': 0, 'dir': None,    'multi': False, 'rtype': 'ctrl'},
    0xB9: {'name': 'Power-down',                            'addr': 0, 'dummy': 0, 'dir': None,    'multi': False, 'rtype': 'ctrl'},
    0x66: {'name': 'Enable Reset',                          'addr': 0, 'dummy': 0, 'dir': None,    'multi': False, 'rtype': 'ctrl'},
    0x99: {'name': 'Reset Device',                          'addr': 0, 'dummy': 0, 'dir': None,    'multi': False, 'rtype': 'ctrl'},

    # ── 4-byte address mode (W25R256JW and larger) ────────────────────────────
    # Note: when in 4-byte mode the 3-byte opcodes (03h, 0Bh, …) silently take
    # a 4th address byte; the decoder cannot detect this without state tracking.
    # The dedicated opcodes below are unambiguously 4-byte regardless of mode.
    0xB7: {'name': 'Enter 4-Byte Address Mode',             'addr': 0, 'dummy': 0, 'dir': None,    'multi': False, 'rtype': 'ctrl'},
    0xE9: {'name': 'Exit 4-Byte Address Mode',              'addr': 0, 'dummy': 0, 'dir': None,    'multi': False, 'rtype': 'ctrl'},
    0xC8: {'name': 'Read Extended Address Register',        'addr': 0, 'dummy': 0, 'dir': 'read',  'multi': False, 'rtype': 'status'},
    0xC5: {'name': 'Write Extended Address Register',       'addr': 0, 'dummy': 0, 'dir': 'write', 'multi': False, 'rtype': 'status'},
    0x13: {'name': 'Read Data (4-byte addr)',               'addr': 4, 'dummy': 0, 'dir': 'read',  'multi': False, 'rtype': 'read'},
    0x0C: {'name': 'Fast Read (4-byte addr)',               'addr': 4, 'dummy': 1, 'dir': 'read',  'multi': False, 'rtype': 'read'},
    0x3C: {'name': 'Fast Read Dual Output (4-byte addr)',   'addr': 4, 'dummy': 1, 'dir': 'read',  'multi': True,  'rtype': 'multi'},
    0x6C: {'name': 'Fast Read Quad Output (4-byte addr)',   'addr': 4, 'dummy': 1, 'dir': 'read',  'multi': True,  'rtype': 'multi'},
    0xBC: {'name': 'Fast Read Dual I/O (4-byte addr)',      'addr': 4, 'dummy': 1, 'dir': 'read',  'multi': True,  'rtype': 'multi'},
    0xEC: {'name': 'Fast Read Quad I/O (4-byte addr)',      'addr': 4, 'dummy': 3, 'dir': 'read',  'multi': True,  'rtype': 'multi'},

    # ── RPMC ─────────────────────────────────────────────────────────────────
    # 0x9B is further dispatched by _analyze_rpmc() based on CmdType (byte 2)
    0x9B: {'name': 'RPMC OP1',                              'addr': 0, 'dummy': 0, 'dir': 'write', 'multi': False, 'rtype': 'rpmc', 'rpmc_op1': True},
    0x96: {'name': 'Read RPMC Status/Data',                 'addr': 0, 'dummy': 1, 'dir': 'read',  'multi': False, 'rtype': 'rpmc'},

    # ── Dual/Quad device-ID reads ────────────────────────────────────────────
    0x92: {'name': 'Read Mfr/Dev ID Dual I/O',              'addr': 3, 'dummy': 0, 'dir': 'read',  'multi': True,  'rtype': 'multi'},
    0x94: {'name': 'Read Mfr/Dev ID Quad I/O',              'addr': 3, 'dummy': 0, 'dir': 'read',  'multi': True,  'rtype': 'multi'},
}

_RPMC_SUBTYPES = {
    0x00: 'Write Root Key',
    0x01: 'Update HMAC Key',
    0x02: 'Increment Counter',
    0x03: 'Request Counter',
}

# Maximum bytes captured per transaction (avoids huge allocations for long reads)
_CAP_BYTES = 300


# ── HLA class ─────────────────────────────────────────────────────────────────

class Hla(HighLevelAnalyzer):
    # Number of data bytes shown in the annotation (address bytes not counted)
    max_displayed_bytes = NumberSetting(min_value=1, max_value=64)

    result_types = {
        'read':    {'format': '{{data.str}}'},
        'write':   {'format': '{{data.str}}'},
        'erase':   {'format': '{{data.str}}'},
        'status':  {'format': '{{data.str}}'},
        'ctrl':    {'format': '{{data.str}}'},
        'multi':   {'format': '{{data.str}}'},
        'rpmc':    {'format': '{{data.str}}'},
        'unknown': {'format': '{{data.str}}'},
    }

    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.mosi = b''
        self.miso = b''
        self.captured = 0

    # ── Frame accumulation ────────────────────────────────────────────────────

    def decode(self, frame: AnalyzerFrame):
        if frame.type == 'enable':
            self.start_time = frame.start_time
            self.mosi = b''
            self.miso = b''
            self.captured = 0

        elif frame.type == 'result':
            if self.start_time is None:          # capture started mid-transaction
                self.start_time = frame.start_time
            if self.captured < _CAP_BYTES:
                self.mosi += frame.data['mosi']
                self.miso += frame.data['miso']
            self.captured += 1

        elif frame.type == 'disable':
            self.end_time = frame.end_time
            result = self._analyze()
            # Reset for next transaction
            self.start_time = None
            self.mosi = b''
            self.miso = b''
            self.captured = 0
            return result

        elif frame.type == 'error':
            self.start_time = None
            self.mosi = b''
            self.miso = b''
            self.captured = 0

        return None

    # ── Decode logic ──────────────────────────────────────────────────────────

    def _analyze(self) -> AnalyzerFrame:
        if not self.mosi:
            return None

        opcode = self.mosi[0]
        max_n = int(self.max_displayed_bytes)

        if opcode not in COMMANDS:
            raw = ' '.join(f'{b:02X}' for b in self.mosi[:8])
            return AnalyzerFrame('unknown', self.start_time, self.end_time, {
                'str': f'UNKNOWN [0x{opcode:02X}]  {raw}'
            })

        cmd = COMMANDS[opcode]

        # ── Quad/Dual: discard everything after the opcode ─────────────────
        if cmd['multi']:
            extra = f' ({self.captured}B captured)'
            return AnalyzerFrame(cmd['rtype'], self.start_time, self.end_time, {
                'str': f"{cmd['name']} [0x{opcode:02X}]{extra}"
            })

        # ── RPMC OP1: dispatch on CmdType byte ─────────────────────────────
        if cmd.get('rpmc_op1'):
            return self._analyze_rpmc()

        # ── Standard decode: address + data ───────────────────────────────
        n_addr     = cmd['addr']
        n_dummy    = cmd['dummy']
        data_start = 1 + n_addr + n_dummy

        addr_str = ''
        if n_addr > 0 and len(self.mosi) >= 1 + n_addr:
            addr = int.from_bytes(self.mosi[1:1 + n_addr], 'big')
            addr_str = f' @0x{addr:0{n_addr * 2}X}'

        data_str = ''
        if cmd['dir'] == 'read' and len(self.miso) > data_start:
            data_str = '  →  ' + _fmt(self.miso[data_start:], max_n)
        elif cmd['dir'] == 'write' and len(self.mosi) > data_start:
            data_str = '  ←  ' + _fmt(self.mosi[data_start:], max_n)

        return AnalyzerFrame(cmd['rtype'], self.start_time, self.end_time, {
            'str': f"{cmd['name']} [0x{opcode:02X}]{addr_str}{data_str}"
        })

    def _analyze_rpmc(self) -> AnalyzerFrame:
        """Decode RPMC OP1 (0x9B) commands, dispatching on the CmdType byte."""
        if len(self.mosi) < 2:
            return AnalyzerFrame('rpmc', self.start_time, self.end_time, {
                'str': 'RPMC OP1 [0x9B]  (incomplete)'
            })

        sub      = self.mosi[1]
        sub_name = _RPMC_SUBTYPES.get(sub, f'Reserved SubType 0x{sub:02X}')
        caddr    = self.mosi[2] if len(self.mosi) > 2 else None
        caddr_s  = f' counter={caddr}' if caddr is not None else ''

        if sub == 0x00:   # Write Root Key
            key = self.mosi[4:36].hex() if len(self.mosi) >= 36 else '(short)'
            detail = f'  key=0x{key}'
        elif sub == 0x01: # Update HMAC Key
            kd = self.mosi[4:8].hex() if len(self.mosi) >= 8 else '(short)'
            detail = f'  key_data=0x{kd}'
        elif sub == 0x02: # Increment Counter
            prev = int.from_bytes(self.mosi[4:8], 'big') if len(self.mosi) >= 8 else '?'
            detail = f'  prev_val={prev}'
        elif sub == 0x03: # Request Counter
            tag = self.mosi[4:16].hex() if len(self.mosi) >= 16 else '(short)'
            detail = f'  tag=0x{tag}'
        else:
            detail = ''

        return AnalyzerFrame('rpmc', self.start_time, self.end_time, {
            'str': f'RPMC: {sub_name} [0x9B/0x{sub:02X}]{caddr_s}{detail}'
        })
