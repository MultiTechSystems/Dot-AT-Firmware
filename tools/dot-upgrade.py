#!/usr/bin/env python3
"""
Dot Firmware Upgrade Tool

Cross-platform tool for updating MultiTech Dot devices (mDot, xDot, xDot-ES,
xDot-AD) over serial. Replaces the TeraTerm TTL script dependency.

Lives in the Dot-AT-Firmware repository alongside the firmware binaries it
operates on. Scans the repo to find available firmware, handles CRC and
bootloader stripping automatically, and transfers via YMODEM.

Usage:
    python dot-upgrade.py --gui                          # Launch GUI
    python dot-upgrade.py upgrade XDOTAD US915 /dev/ttyUSB0  # CLI upgrade
    python dot-upgrade.py list                            # List firmware
    python dot-upgrade.py versions                        # List git versions
    python dot-upgrade.py ports                           # List serial ports

Requirements:
    pip install -r requirements.txt
"""

import os
import sys
import re
import enum
import struct
import binascii
import argparse
import time
import tempfile
import subprocess
import threading
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Callable

# ---------------------------------------------------------------------------
# Optional dependency imports
# ---------------------------------------------------------------------------

HAS_SERIAL = False
HAS_XMODEM = False
HAS_TK = False

try:
    import serial
    import serial.tools.list_ports
    HAS_SERIAL = True
except ImportError:
    pass

try:
    import xmodem
    HAS_XMODEM = True
except ImportError:
    pass

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    HAS_TK = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_DIR = SCRIPT_DIR.parent  # Dot-AT-Firmware root

BL_PROMPT = b'bootloader :>'
NEWLINE = b'\r\n'


# ===========================================================================
# Section 1: Device Types
# ===========================================================================

class DeviceType(enum.Enum):
    """Supported Dot device types."""
    MDOT = "mdot"
    XDOT = "xdot"
    XDOTES = "xdotes"
    XDOTAD = "xdotad"


@dataclass
class DeviceProperties:
    """Hardware-specific properties that control upgrade behavior."""
    device_type: DeviceType
    name: str
    app_offset: int
    needs_crc: bool
    upgrade_command: str
    upgrade_timeout: float
    transfer_setup_time: float
    dir_name: str  # Directory name in the repo (MDOT, XDOT, etc.)
    bootloader_key: str  # Preferred key to stay in bootloader ('mts' or 'xdt')

    @property
    def is_xdot_family(self) -> bool:
        return self.device_type in (
            DeviceType.XDOT, DeviceType.XDOTES, DeviceType.XDOTAD
        )


DEVICE_PROPS = {
    DeviceType.MDOT: DeviceProperties(
        device_type=DeviceType.MDOT,
        name="mDot",
        app_offset=0x10000,
        needs_crc=True,
        upgrade_command="upgrade ymodem",
        upgrade_timeout=30,
        transfer_setup_time=15,
        dir_name="MDOT",
        bootloader_key="mts",
    ),
    DeviceType.XDOT: DeviceProperties(
        device_type=DeviceType.XDOT,
        name="xDot",
        app_offset=0xD000,
        needs_crc=False,
        upgrade_command="upgrade",
        upgrade_timeout=0,
        transfer_setup_time=30,
        dir_name="XDOT",
        bootloader_key="xdt",
    ),
    DeviceType.XDOTES: DeviceProperties(
        device_type=DeviceType.XDOTES,
        name="xDot-ES",
        app_offset=0x10000,
        needs_crc=False,
        upgrade_command="upgrade",
        upgrade_timeout=0,
        transfer_setup_time=30,
        dir_name="XDOTES",
        bootloader_key="xdt",
    ),
    DeviceType.XDOTAD: DeviceProperties(
        device_type=DeviceType.XDOTAD,
        name="xDot-AD",
        app_offset=0x10000,
        needs_crc=True,
        upgrade_command="upgrade",
        upgrade_timeout=90,
        transfer_setup_time=30,
        dir_name="XDOTAD",
        bootloader_key="xdt",
    ),
}


def get_device_type(name: str) -> Optional[DeviceType]:
    """Resolve a device type from a user-provided string."""
    name = name.upper().replace("-", "").replace("_", "")
    aliases = {
        "MDOT": DeviceType.MDOT,
        "MTDOT": DeviceType.MDOT,
        "XDOT": DeviceType.XDOT,
        "XDOTES": DeviceType.XDOTES,
        "XDOTAD": DeviceType.XDOTAD,
    }
    return aliases.get(name)


# ===========================================================================
# Section 2: Firmware Repository Scanner
# ===========================================================================

@dataclass
class FirmwareInfo:
    """Parsed firmware binary metadata."""
    device_type: DeviceType
    version: str
    freq_plan: str
    build_type: str  # 'application', 'application-debug', 'debug', 'full'
    path: Path

    @property
    def display_name(self) -> str:
        suffix = ""
        if self.build_type == "application-debug":
            suffix = " (app-debug)"
        elif self.build_type == "debug":
            suffix = " (debug)"
        elif self.build_type == "full":
            suffix = " (full+bootloader)"
        return f"{self.version}  {self.freq_plan}{suffix}"

    @property
    def is_application(self) -> bool:
        return self.build_type in ("application", "application-debug")

    @property
    def is_debug_only(self) -> bool:
        """True for standalone debug builds (DEBUG/ dir) that lack a
        bootloader and must be flashed via drag-and-drop or JTAG/SWD."""
        return self.build_type in ("debug", "swapped-debug")


# Regex to parse firmware filenames.
# Handles both mbed-os and xdot-max32670 platform suffixes.
# Examples:
#   mdot-firmware-4.1.38-US915-mbed-os-6.8.0-application.bin
#   xdotad-firmware-4.3.2-AS923_JAPAN-xdot-max32670-application.bin
#   mdot-firmware-4.1.38-ALL-PLANS-mbed-os-6.8.0-debug.bin
_FW_PATTERN = re.compile(
    r'(?P<device>mdot|xdot|xdotes|xdotad)-firmware-'
    r'(?P<version>\d+\.\d+\.\d+(?:-[\w.]+)?)-'
    r'(?P<freq>.+?)-'
    r'(?:mbed-os-[\d.]+|xdot-max32670)'
    r'(?:-(?P<suffix>application-debug|swapped-debug|application|debug))?'
    r'\.bin$'
)

_DEVICE_DIRS = {
    'MDOT': DeviceType.MDOT,
    'XDOT': DeviceType.XDOT,
    'XDOTES': DeviceType.XDOTES,
    'XDOTAD': DeviceType.XDOTAD,
}


class FirmwareRepo:
    """Scans the Dot-AT-Firmware repository for available firmware."""

    def __init__(self, repo_path: Optional[Path] = None):
        self.repo_path = Path(repo_path) if repo_path else REPO_DIR

    # ---- Firmware scanning ------------------------------------------------

    def scan(self, device_type: Optional[DeviceType] = None,
             apps_only: bool = True) -> List[FirmwareInfo]:
        """
        Scan repo for firmware files.

        Args:
            device_type: Filter to a single device type, or None for all.
            apps_only: If True, only return application-only images (safe for
                       bootloader upgrade). If False, return all build types.
        """
        firmwares = []
        dirs = _DEVICE_DIRS.items()
        if device_type is not None:
            dirs = [(DEVICE_PROPS[device_type].dir_name, device_type)]

        for dir_name, dt in dirs:
            dir_path = self.repo_path / dir_name
            if not dir_path.exists():
                continue

            if apps_only:
                search_dirs = [dir_path / 'APPS']
            else:
                search_dirs = [dir_path, dir_path / 'APPS', dir_path / 'DEBUG']

            for search_dir in search_dirs:
                if not search_dir.exists():
                    continue
                for bin_file in sorted(search_dir.glob('*.bin')):
                    fw = self._parse_filename(bin_file, dt)
                    if fw:
                        firmwares.append(fw)

        return sorted(firmwares, key=lambda f: (
            f.device_type.value, f.freq_plan, f.build_type
        ))

    def get_freq_plans(self, device_type: DeviceType) -> List[str]:
        """Get available frequency plans for a device type."""
        firmwares = self.scan(device_type=device_type, apps_only=True)
        plans = sorted(set(fw.freq_plan for fw in firmwares))
        return plans

    def find_firmware(self, device_type: DeviceType, freq_plan: str,
                      debug: bool = False) -> Optional[FirmwareInfo]:
        """Find a specific application firmware file."""
        firmwares = self.scan(device_type=device_type, apps_only=True)
        target_build = "application-debug" if debug else "application"
        for fw in firmwares:
            if fw.freq_plan == freq_plan and fw.build_type == target_build:
                return fw
        return None

    def _parse_filename(self, path: Path,
                        device_type: DeviceType) -> Optional[FirmwareInfo]:
        m = _FW_PATTERN.match(path.name)
        if not m:
            return None
        suffix = m.group('suffix') or 'full'
        return FirmwareInfo(
            device_type=device_type,
            version=m.group('version'),
            freq_plan=m.group('freq'),
            build_type=suffix,
            path=path,
        )

    # ---- Git version support ----------------------------------------------

    def _git(self, *args) -> Optional[str]:
        """Run a git command in the repo directory."""
        try:
            result = subprocess.run(
                ['git'] + list(args),
                capture_output=True, text=True,
                cwd=self.repo_path, timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return None
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    def get_versions(self) -> List[str]:
        """Get available firmware versions from git tags."""
        output = self._git('tag', '-l')
        if not output:
            return []
        tags = [t.strip().lstrip('v') for t in output.split('\n') if t.strip()]
        version_re = re.compile(r'^\d+\.\d+\.\d+')
        versions = [t for t in tags if version_re.match(t)]
        # Sort by numeric version components
        def sort_key(v):
            parts = re.findall(r'\d+', v)
            return [int(p) for p in parts[:3]]
        return sorted(set(versions), key=sort_key)

    def get_current_version(self) -> Optional[str]:
        """Get the current firmware version from the latest git tag."""
        tag = self._git('describe', '--tags', '--abbrev=0')
        if tag:
            return tag.lstrip('v')
        return None

    def checkout_version(self, version: str) -> bool:
        """Checkout a specific firmware version by git tag."""
        # Try the version as-is, then with 'v' prefix
        for tag in (version, f'v{version}'):
            if self._git('checkout', tag) is not None:
                return True
        return False


# ===========================================================================
# Section 3: Image Processing
# ===========================================================================

def calculate_crc32(data: bytes) -> bytes:
    """Calculate CRC32 of data, returned as 4 little-endian bytes."""
    crc = binascii.crc32(data) & 0xFFFFFFFF
    return crc.to_bytes(4, byteorder='little')


def is_application_filename(path: Path) -> bool:
    """Check if a firmware filename indicates it is application-only."""
    return '-application' in path.stem


def is_debug_only_image(path: Path) -> bool:
    """
    Detect if a firmware file is a standalone debug build.

    Debug builds live in the DEBUG/ directory and have filenames ending
    in '-debug.bin' (or '-swapped-debug.bin') WITHOUT '-application' in
    the name.  They may lack a bootloader entirely (e.g. xDot-ES) and
    must be flashed via drag-and-drop or JTAG/SWD -- never via the
    serial bootloader.
    """
    name = path.name
    parent = path.parent.name

    # Files with -application-debug are fine (AT firmware with debug info)
    if '-application' in name:
        return False

    # Files in the DEBUG/ directory ending with -debug.bin
    if parent == 'DEBUG' and name.endswith('-debug.bin'):
        return True

    return False


def detect_full_image(path: Path, device_type: DeviceType) -> bool:
    """
    Heuristic to detect if a binary is a full image (bootloader + app)
    rather than application-only.

    Checks:
    1. Filename does NOT contain '-application'
    2. File lives in the device root dir or DEBUG, not APPS
    3. File is NOT a debug-only image
    """
    name = path.name
    parent = path.parent.name

    if '-application' in name:
        return False

    # Files in APPS/ are always application-only
    if parent == 'APPS':
        return False

    # Debug-only images are a separate category -- not "full images"
    if is_debug_only_image(path):
        return False

    # Files in device root without -application are full images
    return True


def prepare_upgrade_image(image_data: bytes, device_type: DeviceType,
                          source_path: Path) -> Tuple[bytes, str]:
    """
    Prepare a firmware image for serial bootloader upgrade.

    - If the image is a full image (has bootloader), strip it
    - If the device requires CRC, append it

    Returns:
        Tuple of (processed image bytes, description of what was done)
    """
    props = DEVICE_PROPS[device_type]
    actions = []

    is_full = detect_full_image(source_path, device_type)

    if is_full:
        original_size = len(image_data)
        image_data = image_data[props.app_offset:]
        actions.append(
            f"Stripped bootloader (0x{props.app_offset:X} bytes, "
            f"{original_size} -> {len(image_data)} bytes)"
        )

    if props.needs_crc:
        crc = calculate_crc32(image_data)
        image_data = image_data + crc
        actions.append(f"Appended CRC32 ({crc.hex()})")

    if not actions:
        actions.append("No processing needed")

    return image_data, "; ".join(actions)


# ===========================================================================
# Section 4: YMODEM Protocol
# ===========================================================================

def _require_serial():
    if not HAS_SERIAL:
        print("ERROR: pyserial is required for serial operations.")
        print("  Install with: pip install pyserial")
        sys.exit(1)


def _require_xmodem():
    if not HAS_XMODEM:
        print("ERROR: xmodem package is required for firmware transfer.")
        print("  Install with: pip install xmodem")
        sys.exit(1)


class YModem:
    """YMODEM serial file transfer protocol."""

    CRC_TIMEOUT = 5.0
    NAK_TIMEOUT = 10.0
    MAX_ERRORS = 10

    def __init__(self, getc, putc):
        self._getc = getc
        self._putc = putc
        self._xmodem = xmodem.XMODEM(getc, putc, mode='xmodem1k')

    def send(self, file_path: str, setup_timeout: float = 10.0,
             callback: Optional[Callable] = None) -> bool:
        """
        Send a file using YMODEM protocol.

        Args:
            file_path: Path to the file to send.
            setup_timeout: Seconds to wait for device to ACK the header.
            callback: Progress callback(total_packets, success, errors).
                      Called with total_packets=-1 after sending header.
        """
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path).encode('utf-8')

        with open(file_path, 'rb') as fd:
            # --- Send YMODEM header frame (filename + size) ---
            errors = 0
            while errors < self.MAX_ERRORS:
                c = self._getc(1, self.CRC_TIMEOUT)
                if c == xmodem.CRC:
                    frame = struct.pack(
                        f'{len(file_name)}sB{len(str(file_size))}sc',
                        file_name, 0x00,
                        str(file_size).encode('utf-8'), b' '
                    )
                    frame = frame.ljust(128, b'\x00')
                    crc = binascii.crc_hqx(frame, 0)
                    packet = struct.pack(
                        '!cBB128sH', xmodem.SOH,
                        0, 0xFF, frame, crc
                    )
                    self._putc(packet)

                    if callable(callback):
                        callback(-1, 0, 0)

                    c = self._getc(1, setup_timeout)
                    if c == xmodem.ACK:
                        errors = 0
                        break
                    else:
                        errors += 1

            if errors > 0:
                return False

            # --- Send file data using XMODEM-1K ---
            if not self._xmodem.send(fd, callback=callback):
                return False

            # --- Send EOT and closing frame ---
            self._putc(xmodem.EOT)
            c = self._getc(1, self.NAK_TIMEOUT)
            if c == xmodem.ACK:
                c = self._getc(1, self.NAK_TIMEOUT)

            if c == xmodem.CRC:
                frame = b'\x00' * 128
                crc = binascii.crc_hqx(frame, 0)
                packet = struct.pack(
                    '!cBB128sH', xmodem.SOH,
                    0, 0xFF, frame, crc
                )
                self._putc(packet)
                self._getc(1, self.NAK_TIMEOUT)

            return True


# ===========================================================================
# Section 5: Serial Upgrade Engine
# ===========================================================================

class UpgradeError(Exception):
    """Raised when an upgrade operation fails."""
    pass


# Serial interface type
INTERFACE_AT = 'at'         # AT command port (echoes, supports ATZ reset)
INTERFACE_DEBUG = 'debug'   # Debug/log port (no echo, requires manual reset)
INTERFACE_AUTO = 'auto'     # Auto-detect by probing for AT response


class SerialUpgrade:
    """
    Handles the complete serial firmware upgrade workflow:
    1. Open serial port
    2. Enter device bootloader
    3. Send upgrade via YMODEM
    4. Wait for upgrade to complete
    """

    def __init__(self, port: str, device_type: DeviceType,
                 baudrate: int = 115200,
                 interface: str = INTERFACE_AUTO,
                 log_cb: Optional[Callable[[str], None]] = None,
                 progress_cb: Optional[Callable[[int, int], None]] = None):
        self.port = port
        self.device_type = device_type
        self.props = DEVICE_PROPS[device_type]
        self.baudrate = baudrate
        self.interface = interface
        self._echo = True  # AT port echoes; debug port does not
        self._log_cb = log_cb
        self._progress_cb = progress_cb
        self._ser = None
        self._xfer_size = 0
        self._xferd = 0
        self._cancelled = False

    # ---- Port management --------------------------------------------------

    @staticmethod
    def list_ports() -> List[Tuple[str, str]]:
        """List available serial ports as (device, description) tuples."""
        _require_serial()
        ports = serial.tools.list_ports.comports()
        return [(p.device, p.description) for p in sorted(ports)]

    def open(self):
        """Open the serial port."""
        _require_serial()
        self._ser = serial.Serial(
            self.port, baudrate=self.baudrate,
            bytesize=8, parity='N', stopbits=1,
            timeout=0.25, xonxoff=0, rtscts=1,
        )
        self._log(f"Opened {self.port} at {self.baudrate} baud")

    def close(self):
        """Close the serial port."""
        if self._ser:
            self._ser.close()
            self._ser = None

    def cancel(self):
        """Signal cancellation of an in-progress upgrade."""
        self._cancelled = True

    # ---- Logging / progress -----------------------------------------------

    def _log(self, msg: str):
        if self._log_cb:
            self._log_cb(msg)
        else:
            print(msg)

    def _progress(self, transferred: int, total: int):
        if self._progress_cb:
            self._progress_cb(transferred, total)

    # ---- Low-level serial -------------------------------------------------

    def _read(self, n: int, timeout: Optional[float] = None) -> bytes:
        if timeout is not None:
            end_time = time.time() + timeout
            data = b''
            while len(data) < n and time.time() < end_time:
                data += self._ser.read(n - len(data))
            return data
        return self._ser.read(n)

    def _read_until_prompt(self, timeout: float) -> bool:
        """Read serial data until the bootloader prompt is found."""
        end_time = time.time() + timeout
        buf = b''
        while time.time() < end_time:
            b = self._ser.read(1)
            if b == b'':
                continue
            buf += b
            if buf.endswith(BL_PROMPT[4:]):  # match 'loader :>'
                return True
        return False

    def _flush_input(self):
        """Drain any pending data from serial input."""
        while len(self._ser.read(256)) > 0:
            pass

    # ---- AT commands ------------------------------------------------------

    def send_at_command(self, cmd: str, timeout: float = 2.0) -> Optional[str]:
        """
        Send an AT command and return the response text.

        Only works when the device is in AT command mode (not bootloader).
        Returns None if no valid response is received.
        """
        self._flush_input()
        self._ser.write(cmd.encode() + NEWLINE)
        time.sleep(0.1)

        # Read response until OK or ERROR, or timeout
        end_time = time.time() + timeout
        buf = b''
        while time.time() < end_time:
            chunk = self._ser.read(256)
            if chunk:
                buf += chunk
                # Check for response terminators
                if b'OK' in buf or b'ERROR' in buf:
                    break
            else:
                if buf:
                    break

        if not buf:
            return None

        # Decode and clean up: strip echo of the command, trailing OK/ERROR
        text = buf.decode('utf-8', errors='replace')
        lines = [l.strip() for l in text.splitlines()]

        # Remove the echoed command and OK/ERROR lines
        result_lines = []
        for line in lines:
            if line == cmd or line == 'OK' or line == 'ERROR' or not line:
                continue
            result_lines.append(line)

        return '\n'.join(result_lines) if result_lines else None

    def query_device_info(self) -> Optional[str]:
        """
        Query device identification using ATI command.

        Returns the ATI response string, or None if not available.
        """
        return self.send_at_command('ATI')

    def wait_for_application(self, timeout: float = 10.0) -> bool:
        """
        After an upgrade, wait for the device to boot back into AT command
        mode by probing with 'AT' until we get 'OK'.
        """
        self._log("Waiting for device to boot into application...")
        end_time = time.time() + timeout
        while time.time() < end_time:
            self._flush_input()
            self._ser.write(b'AT' + NEWLINE)
            time.sleep(1.0)
            resp = self._ser.read(128)
            if b'OK' in resp:
                return True
        return False

    # ---- Bootloader entry -------------------------------------------------

    def _detect_interface(self) -> str:
        """Probe serial port to determine if it is an AT or debug interface."""
        self._flush_input()
        self._ser.write(b'AT' + NEWLINE)
        time.sleep(0.5)
        resp = self._ser.read(128)

        if b'OK' in resp:
            return INTERFACE_AT

        # Check if we're already at a bootloader prompt
        if BL_PROMPT[4:] in resp:
            return INTERFACE_AT  # Doesn't matter, we're already in BL

        return INTERFACE_DEBUG

    def _already_in_bootloader(self) -> bool:
        """Check if the device is already sitting at a bootloader prompt."""
        self._flush_input()
        self._ser.write(NEWLINE)
        time.sleep(0.3)
        resp = self._ser.read(128)
        return BL_PROMPT[4:] in resp

    def enter_bootloader(self, timeout: float = 30,
                         interface_override: Optional[str] = None):
        """
        Enter device bootloader.

        Behavior depends on the interface type:
        - AT command interface: sends ATZ to reset, then 'mts' to stay in
          bootloader.  The AT port echoes characters.
        - Debug interface: requires the user to manually reset the device.
          The tool continuously sends data to catch the boot window.
          The debug port does NOT echo characters.

        Args:
            timeout: Maximum time to wait for bootloader entry.
            interface_override: If set, skip detection and use this interface
                type directly.  Useful when the caller has already probed.
        """
        # Check if already in bootloader
        if self._already_in_bootloader():
            self._echo = True  # bootloader always echoes
            self._flush_input()
            self._log("Device already in bootloader")
            return

        # Determine interface type
        if interface_override:
            detected = interface_override
            self._log(f"Using interface: {detected}")
        elif self.interface == INTERFACE_AUTO:
            detected = self._detect_interface()
            self._log(f"Detected interface: {detected}")
        else:
            detected = self.interface
            self._log(f"Using interface: {detected}")

        if detected == INTERFACE_AT:
            self._enter_bootloader_at(timeout)
        else:
            self._enter_bootloader_debug(timeout)

    def _enter_bootloader_at(self, timeout: float):
        """
        Enter bootloader via AT command interface.

        The AT port echoes characters.  After ATZ resets the device, the
        bootloader starts and echoes input.  We try each bootloader key
        ('mts', 'xdt') -- send the first character repeatedly and wait
        for it to be echoed back (confirms bootloader is running), then
        complete the sequence to stay in bootloader.
        """
        self._echo = True

        self._log("Sending ATZ to reset device...")
        self._ser.write(b'ATZ' + NEWLINE)

        end_time = time.time() + timeout
        found = False

        # Try each key.  The echo-detection approach works because the
        # bootloader echoes every character -- if we send 'm' and get
        # 'm' back, the bootloader is alive and expects 'mts'.
        for bl_key in self.BL_KEYS:
            key_str = bl_key.decode()
            first_char = bl_key[0:1]
            rest_chars = bl_key[1:]

            self._log(f"Waiting for bootloader (sending '{key_str}')...")
            key_deadline = min(end_time, time.time() + timeout / len(self.BL_KEYS))

            while time.time() < key_deadline:
                self._ser.write(first_char)
                resp = self._read(1, timeout=0.5)
                if resp == first_char:
                    # Bootloader is alive and echoing -- complete the key
                    self._ser.write(rest_chars + NEWLINE)
                    resp = self._read(1, timeout=0.5)
                    if resp == rest_chars[0:1]:
                        # Wait for the full prompt
                        if self._read_until_prompt(
                            min(5, key_deadline - time.time())
                        ):
                            found = True
                            break

            if found:
                break

        if not found:
            raise UpgradeError(
                "Failed to enter bootloader via AT interface. "
                "Ensure the device is connected and responding to AT commands."
            )

        self._flush_input()
        self._log("Entered bootloader successfully")

    def _enter_bootloader_debug(self, timeout: float):
        """
        Enter bootloader via debug/log interface.

        The debug port does NOT echo characters and does NOT support AT
        commands.  To enter the bootloader the device must be reset, then
        the bootloader must receive input within ~250ms of boot.

        Strategy: try serial break with several timing patterns (matching
        what works in TeraTerm), then fall back to manual reset.
        """
        self._echo = False

        # --- Attempt 1: serial break with multiple timing strategies ---
        self._log("Attempting serial break reset...")

        found = self._break_and_enter()

        if not found:
            # --- Attempt 2: ask for manual reset ---
            self._log("")
            self._log("Serial break did not enter bootloader.")
            self._log(">>> Reset the device now (power cycle or press reset button) <<<")
            self._log(f"Waiting up to {int(timeout)} seconds...")
            self._log("")

            # Watch for banner on manual reset so we can pick the right key
            found, banner = self._wait_for_banner(timeout=timeout)
            if found:
                pass  # Already at prompt
            elif banner:
                keys = self._pick_debug_keys(banner)
                for key in keys:
                    key_display = key.decode('ascii', errors='replace').replace('\r', '\\r').replace('\n', '\\n') or '(newline)'
                    self._log(f"  Flooding '{key_display}' to stay in bootloader...")
                    found = self._flood_after_banner(key, banner, timeout=5.0)
                    if found:
                        break

        if not found:
            raise UpgradeError(
                "Failed to enter bootloader via debug interface. "
                "Ensure you reset the device while the tool is waiting."
            )

        self._echo = True  # bootloader echoes once active
        self._flush_input()
        self._log("Entered bootloader successfully")

    def _read_and_log(self, label: str, timeout: float) -> bytes:
        """Read all available serial data within timeout, log it, return it."""
        end_time = time.time() + timeout
        buf = b''
        while time.time() < end_time:
            chunk = self._ser.read(256)
            if chunk:
                buf += chunk
            elif buf:
                # Got data and now nothing more is arriving
                break
        if buf:
            # Show printable representation and hex for non-printable bytes
            display = buf.decode('utf-8', errors='replace').replace('\r', '\\r').replace('\n', '\\n')
            self._log(f"  [{label}] rx {len(buf)} bytes: {display}")
            self._log(f"  [{label}] hex: {buf.hex(' ')}")
        else:
            self._log(f"  [{label}] rx: (nothing)")
        return buf

    def _check_prompt_in(self, data: bytes) -> bool:
        """Check if bootloader prompt is present in data."""
        return BL_PROMPT[4:] in data  # match 'loader :>'

    # Bootloader entry keys by version (from generic-bootloader source):
    #
    # v0.1.x          : any keypress on debug port (250ms window)
    # 1.0.0 - 1.1.9   : any keypress on debug port; 'mts' on AT port
    # 1.2.0+           : 'mts' required on debug port for MAX32670;
    #                    any keypress on debug port for others;
    #                    'mts' on AT port
    # xdot_bootloader  : 'xdt' was used in intermediate builds,
    #   (branch)         changed back to 'mts' before any tagged release
    #
    # On the debug port we can read the version from the banner and pick
    # the right key.  On the AT port we can't, so we try both.
    BL_KEYS = [b'mts', b'xdt']

    # Regex to extract version from banner: "[INFO] MultiTech Bootloader 1.2.0"
    _BL_VERSION_RE = re.compile(rb'Bootloader\s+(\d+\.\d+\.\d+)')

    def _pick_debug_keys(self, banner: bytes) -> list:
        """
        Choose which bootloader key(s) to send on the debug port based
        on the version parsed from the banner.

        - v0.1.x:       any keypress (newlines suffice)
        - 1.0.0 - 1.1.9: any keypress (newlines suffice)
        - 1.2.0+ on MAX32670: 'mts' required
        - Unknown:       try 'mts' then 'xdt'
        """
        m = self._BL_VERSION_RE.search(banner)
        if not m:
            self._log(f"    Could not parse bootloader version, trying all keys")
            return self.BL_KEYS

        version_str = m.group(1).decode()
        parts = [int(x) for x in version_str.split('.')]
        version_tuple = tuple(parts)
        self._log(f"    Bootloader version: {version_str}")

        # v0.1.x and 1.0.0 - 1.1.9: any keypress enters on debug port
        if version_tuple < (1, 2, 0):
            self._log(f"    Version < 1.2.0: any keypress enters bootloader")
            return [NEWLINE]

        # 1.2.0+ requires 'mts' on debug port for MAX32670 (xDot-ES/AD)
        # For non-MAX32670 (mDot, xDot), any keypress still works
        if self.props.is_xdot_family and self.device_type in (
            DeviceType.XDOTES, DeviceType.XDOTAD
        ):
            self._log(f"    Version >= 1.2.0 on MAX32670: 'mts' required")
            return [b'mts']
        else:
            self._log(f"    Version >= 1.2.0 on non-MAX32670: any keypress enters bootloader")
            return [NEWLINE]

    def _break_and_enter(self) -> bool:
        """
        Send serial break, read the bootloader banner to determine
        the version, then pick the correct key(s) and flood.

        On the debug port we can see the banner and know the version.
        If the banner doesn't appear, fall back to trying all keys.

        Returns True if bootloader prompt is found.
        """
        self._log("  Sending break...")
        self._flush_input()
        self._ser.send_break(duration=0.25)

        found, banner = self._wait_for_banner(timeout=3.0)
        if found:
            # Already at prompt (e.g., device was in bootloader)
            return True

        if banner:
            # We saw the banner -- pick the right key(s) for this version
            keys = self._pick_debug_keys(banner)
            for key in keys:
                key_display = key.decode('ascii', errors='replace').replace('\r', '\\r').replace('\n', '\\n') or '(newline)'
                self._log(f"    Flooding '{key_display}' to stay in bootloader...")
                if self._flood_after_banner(key, banner, timeout=5.0):
                    return True
            return False

        # No banner seen -- try brute force with all keys
        self._log("    No banner seen on first break, retrying with each key...")
        for key in self.BL_KEYS:
            key_str = key.decode()
            self._log(f"  Sending break (key='{key_str}')...")
            self._flush_input()
            self._ser.send_break(duration=0.25)
            found, banner = self._wait_for_banner(timeout=3.0)
            if found:
                return True
            if banner:
                self._log(f"    Flooding '{key_str}' to stay in bootloader...")
                if self._flood_after_banner(key, banner, timeout=5.0):
                    return True
            time.sleep(0.5)

        self._log("  All break attempts exhausted.")
        return False

    def _wait_for_banner(self, timeout: float) -> Tuple[bool, bytes]:
        """
        Read serial byte-by-byte watching for the bootloader banner.

        Returns:
            (True, buf)  if the bootloader prompt was found directly
            (False, buf) if the banner was seen (buf contains it)
            (False, b'') if nothing useful was received
        """
        end_time = time.time() + timeout
        buf = b''
        banner_trigger = b'Bootloader'

        self._log("    Watching for bootloader banner...")
        while time.time() < end_time:
            if self._cancelled:
                raise UpgradeError("Cancelled")
            b = self._ser.read(1)
            if not b:
                continue
            buf += b

            if banner_trigger in buf:
                elapsed_ms = int((timeout - (end_time - time.time())) * 1000)
                self._log(f"    Saw 'Bootloader' banner after {elapsed_ms}ms")
                return (False, buf)

            if self._check_prompt_in(buf):
                self._log("    -> Bootloader prompt found while watching!")
                return (True, buf)

        # Nothing useful
        if buf:
            display = buf.decode('utf-8', errors='replace').replace('\r', '\\r').replace('\n', '\\n')
            self._log(f"    No banner seen. Received: {display}")
        else:
            self._log("    No data received (break may not reset this device).")
        return (False, b'')

    def _flood_after_banner(self, key: bytes, initial_buf: bytes,
                            timeout: float) -> bool:
        """
        After the bootloader banner has been detected, flood the given
        key aggressively and watch for the bootloader prompt.
        """
        end_time = time.time() + timeout
        buf = initial_buf
        burst_count = 0

        while time.time() < end_time:
            if self._cancelled:
                raise UpgradeError("Cancelled")

            self._ser.write(NEWLINE + key + NEWLINE)
            burst_count += 1

            # Read whatever is available (short timeout to keep flooding)
            chunk = self._ser.read(512)
            if chunk:
                buf += chunk
                if self._check_prompt_in(buf):
                    self._log_rx(buf, burst_count)
                    self._log("  -> Bootloader prompt found!")
                    return True

        # Did not find prompt
        self._log_rx(buf, burst_count)
        return False

    def _log_rx(self, buf: bytes, burst_count: int):
        """Log received data summary for diagnostics."""
        if buf:
            display = buf.decode('utf-8', errors='replace').replace('\r', '\\r').replace('\n', '\\n')
            if len(display) > 400:
                display = display[:400] + f"... ({len(buf)} bytes total)"
            self._log(f"    rx ({burst_count} bursts): {display}")
        else:
            self._log(f"    rx ({burst_count} bursts): (nothing)")

    # ---- Upgrade ----------------------------------------------------------

    def run_upgrade(self, image_path: str):
        """
        Execute the complete upgrade sequence.

        Args:
            image_path: Path to the prepared firmware image (already has CRC
                        appended if needed).
        """
        _require_xmodem()
        self._cancelled = False

        # Clear any pending bootloader state
        self._ser.write(b'x' + NEWLINE)
        time.sleep(0.2)
        self._flush_input()

        # Send the upgrade command
        cmd = self.props.upgrade_command
        self._log(f"Sending '{cmd}' command...")
        self._ser.write(cmd.encode() + NEWLINE)
        # Read echo (bootloader always echoes once active)
        if self._echo:
            self._ser.read(len(cmd) + 4)

        # Wait for YMODEM 'C' ready signal
        self._log("Waiting for device to be ready for transfer...")
        end_time = time.time() + self.props.transfer_setup_time + 5
        ready = False
        while time.time() < end_time:
            if self._cancelled:
                raise UpgradeError("Upgrade cancelled")
            resp = self._read(1)
            if resp == b'C':
                ready = True
                break

        if not ready:
            raise UpgradeError(
                "Device did not signal ready for YMODEM transfer. "
                "It may not be in bootloader mode."
            )

        # Transfer via YMODEM
        self._xfer_size = os.path.getsize(image_path)
        self._xferd = 0
        self._log(f"Transferring {self._xfer_size:,} bytes...")

        def getc(size, timeout=1):
            return self._read(size, timeout=timeout)

        def putc(data, timeout=1):
            return self._ser.write(data)

        def status_cb(total_packets, success_count, error_count):
            if total_packets == -1:
                self._log("  Setting up file transfer...")
            else:
                self._xferd += 1024
                xferd = min(self._xferd, self._xfer_size)
                self._progress(xferd, self._xfer_size)

        modem = YModem(getc, putc)
        result = modem.send(
            image_path, self.props.transfer_setup_time, status_cb
        )

        if not result:
            raise UpgradeError("YMODEM file transfer failed")

        self._log("File transfer complete")
        self._progress(self._xfer_size, self._xfer_size)

        # Wait for upgrade to be applied
        if self.props.upgrade_timeout > 0:
            self._log(
                f"Waiting for device to apply upgrade "
                f"(~{int(self.props.upgrade_timeout)}s)..."
            )
            wait_end = time.time() + self.props.upgrade_timeout + 10
            while time.time() < wait_end:
                if self._cancelled:
                    break
                time.sleep(1)
                elapsed = int(time.time() - (wait_end - self.props.upgrade_timeout - 10))
                self._progress(
                    min(elapsed, int(self.props.upgrade_timeout)),
                    int(self.props.upgrade_timeout)
                )
        else:
            self._log("Upgrade applied immediately by device")

        self._log("Upgrade complete!")


def do_serial_upgrade(port: str, device_type: DeviceType, image_path: Path,
                      baudrate: int = 115200,
                      interface: str = INTERFACE_AUTO,
                      log_cb: Optional[Callable] = None,
                      progress_cb: Optional[Callable] = None,
                      upgrader_cb: Optional[Callable] = None):
    """
    High-level function: prepare image and perform serial upgrade.

    Handles the full pipeline:
    1. Read the firmware file
    2. Detect if bootloader needs stripping
    3. Append CRC if needed
    4. Write prepared image to temp file
    5. Open serial port, enter bootloader, transfer, close

    Args:
        upgrader_cb: Optional callback, called with the SerialUpgrade
            instance after it is created (before opening the port).
            Allows callers (e.g. GUI) to hold a reference for
            cancellation.
    """
    if log_cb is None:
        log_cb = print

    iface_label = {'at': 'AT command', 'debug': 'Debug', 'auto': 'Auto-detect'}
    log_cb(f"Device:    {DEVICE_PROPS[device_type].name}")
    log_cb(f"Firmware:  {image_path.name}")
    log_cb(f"Port:      {port}")
    log_cb(f"Interface: {iface_label.get(interface, interface)}")
    log_cb("")

    # Read and prepare image
    with open(image_path, 'rb') as f:
        raw_image = f.read()

    log_cb(f"Raw image size: {len(raw_image):,} bytes")

    prepared, description = prepare_upgrade_image(
        raw_image, device_type, image_path
    )
    log_cb(f"Preparation: {description}")
    log_cb(f"Prepared image size: {len(prepared):,} bytes")
    log_cb("")

    # Write prepared image to temp file (YMODEM needs a file path)
    with tempfile.NamedTemporaryFile(
        suffix='.bin', prefix='dot_upgrade_', delete=False
    ) as tmp:
        tmp.write(prepared)
        tmp_path = tmp.name

    try:
        upgrader = SerialUpgrade(
            port=port,
            device_type=device_type,
            baudrate=baudrate,
            interface=interface,
            log_cb=log_cb,
            progress_cb=progress_cb,
        )
        if upgrader_cb:
            upgrader_cb(upgrader)
        upgrader.open()
        try:
            # Detect interface early so we can query ATI before entering
            # bootloader, and avoid probing twice.
            effective_iface = interface
            if interface == INTERFACE_AUTO:
                effective_iface = upgrader._detect_interface()
                log_cb(f"Detected interface: {effective_iface}")

            is_at = (effective_iface == INTERFACE_AT)

            # Query firmware version before upgrade (AT interface only)
            version_before = None
            if is_at:
                version_before = upgrader.query_device_info()
                if version_before:
                    log_cb(f"Firmware (before): {version_before}")
                    log_cb("")

            # Enter bootloader using the already-determined interface
            upgrader.enter_bootloader(interface_override=effective_iface)
            upgrader.run_upgrade(tmp_path)

            # Query firmware version after upgrade (AT interface only)
            if is_at:
                log_cb("")
                # Give device time to boot after upgrade
                extra_boot_time = 3.0
                time.sleep(extra_boot_time)
                if upgrader.wait_for_application(timeout=15):
                    version_after = upgrader.query_device_info()
                    if version_after:
                        log_cb(f"Firmware (after):  {version_after}")
                    else:
                        log_cb("Could not read ATI after upgrade")
                else:
                    log_cb("Device did not return to AT command mode")

                if version_before and version_after:
                    if version_before == version_after:
                        log_cb("WARNING: Firmware version unchanged after upgrade")
                    else:
                        log_cb("Firmware version updated successfully")
        finally:
            upgrader.close()
    finally:
        os.unlink(tmp_path)


# ===========================================================================
# Section 6: CLI Interface
# ===========================================================================

def cli_list(args):
    """List available firmware in the repository."""
    repo = FirmwareRepo(args.repo)

    device_filter = None
    if args.device:
        device_filter = get_device_type(args.device)
        if device_filter is None:
            print(f"Unknown device type: {args.device}")
            print(f"Valid types: {', '.join(dt.value for dt in DeviceType)}")
            sys.exit(1)

    firmwares = repo.scan(
        device_type=device_filter,
        apps_only=not args.all,
    )

    if not firmwares:
        print("No firmware files found.")
        if args.repo == REPO_DIR:
            ver = repo.get_current_version()
            if ver:
                print(f"Current repo version: {ver}")
            print("Firmware binaries may need to be checked out from a release tag.")
            print("Use 'versions' command to see available tags.")
        return

    current_device = None
    for fw in firmwares:
        if fw.device_type != current_device:
            current_device = fw.device_type
            props = DEVICE_PROPS[fw.device_type]
            print(f"\n{props.name} ({props.dir_name})")
            crc_note = " [CRC required]" if props.needs_crc else ""
            print(f"  Bootloader upgrade command: {props.upgrade_command}{crc_note}")
            print(f"  {'Version':<12} {'Freq Plan':<18} {'Type':<20} {'Path'}")
            print(f"  {'-'*11}  {'-'*17}  {'-'*19}  {'-'*30}")

        rel_path = fw.path.relative_to(repo.repo_path) if fw.path.is_relative_to(repo.repo_path) else fw.path
        marker = " *" if fw.build_type == "full" else ""
        print(f"  {fw.version:<12} {fw.freq_plan:<18} {fw.build_type:<20} {rel_path}{marker}")

    if not args.all:
        print("\n  Showing application images only (safe for bootloader upgrade).")
        print("  Use --all to include full and debug images.")
    else:
        print("\n  * = full image (contains bootloader) -- will be auto-stripped during upgrade")


def cli_versions(args):
    """List available firmware versions from git tags."""
    repo = FirmwareRepo(args.repo)
    versions = repo.get_versions()
    current = repo.get_current_version()

    if not versions:
        print("No version tags found. Is this a git repository?")
        return

    print("Available firmware versions:")
    for v in versions:
        marker = "  <-- current" if v == current else ""
        print(f"  {v}{marker}")

    print(f"\nTo switch versions: python {sys.argv[0]} checkout <version>")


def cli_checkout(args):
    """Checkout a specific firmware version."""
    repo = FirmwareRepo(args.repo)
    version = args.version

    if version not in repo.get_versions():
        print(f"Warning: version '{version}' not found in tags.")
        print("Attempting checkout anyway...")

    if repo.checkout_version(version):
        print(f"Checked out version {version}")
    else:
        print(f"Failed to checkout version {version}")
        sys.exit(1)


def cli_ports(args):
    """List available serial ports."""
    _require_serial()
    ports = SerialUpgrade.list_ports()
    if not ports:
        print("No serial ports found.")
        return
    print("Available serial ports:")
    for device, desc in ports:
        print(f"  {device:<20} {desc}")


def cli_upgrade(args):
    """Perform a firmware upgrade over serial."""
    repo = FirmwareRepo(args.repo)

    # Resolve device type first (before checking dependencies)
    device_type = get_device_type(args.device)
    if device_type is None:
        print(f"Unknown device type: {args.device}")
        print(f"Valid types: {', '.join(dt.value for dt in DeviceType)}")
        sys.exit(1)

    # Resolve firmware file
    if args.file:
        image_path = Path(args.file)
        if not image_path.exists():
            print(f"Firmware file not found: {image_path}")
            sys.exit(1)

        # Safety check: warn if it looks like a full image
        if detect_full_image(image_path, device_type):
            props = DEVICE_PROPS[device_type]
            print(f"WARNING: '{image_path.name}' appears to be a full image "
                  f"(bootloader + application).")
            print(f"  The bootloader will be stripped automatically "
                  f"(offset 0x{props.app_offset:X}).")
            if not args.yes:
                resp = input("  Continue? [y/N] ")
                if resp.lower() != 'y':
                    print("Aborted.")
                    sys.exit(0)
    else:
        # Find firmware from repo
        if not args.freq:
            plans = repo.get_freq_plans(device_type)
            if not plans:
                print(f"No firmware found for {device_type.value}.")
                print("Specify a file with --file or check repo version.")
                sys.exit(1)
            print(f"Available frequency plans for "
                  f"{DEVICE_PROPS[device_type].name}: {', '.join(plans)}")
            print("Specify with: --freq <PLAN>")
            sys.exit(1)

        fw = repo.find_firmware(device_type, args.freq, debug=args.debug)
        if fw is None:
            print(f"No {'debug ' if args.debug else ''}application firmware "
                  f"found for {device_type.value} {args.freq}")
            sys.exit(1)

        image_path = fw.path
        print(f"Selected: {fw.display_name}")
        print(f"  File: {image_path}")

    # Check dependencies now that all validation has passed
    _require_serial()
    _require_xmodem()

    # Progress display for CLI
    last_pct = [-1]

    def cli_progress(transferred, total):
        if total <= 0:
            return
        pct = int(transferred * 100 / total)
        if pct != last_pct[0]:
            last_pct[0] = pct
            bar_len = 40
            filled = int(bar_len * transferred / total)
            bar = '#' * filled + '-' * (bar_len - filled)
            kb_xfer = transferred // 1024
            kb_total = total // 1024
            sys.stdout.write(
                f'\r  [{bar}] {pct:3d}% ({kb_xfer}/{kb_total} KB)'
            )
            sys.stdout.flush()
            if transferred >= total:
                sys.stdout.write('\n')

    # Determine interface type
    if args.debug_port:
        interface = INTERFACE_DEBUG
    elif args.at_port:
        interface = INTERFACE_AT
    else:
        interface = INTERFACE_AUTO

    print("")
    try:
        do_serial_upgrade(
            port=args.port,
            device_type=device_type,
            image_path=image_path,
            baudrate=args.baudrate,
            interface=interface,
            log_cb=print,
            progress_cb=cli_progress,
        )
    except UpgradeError as e:
        print(f"\nERROR: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAborted by user.")
        sys.exit(1)


def cli_prepare(args):
    """Prepare an image for upgrade (strip bootloader, add CRC) without sending."""
    device_type = get_device_type(args.device)
    if device_type is None:
        print(f"Unknown device type: {args.device}")
        sys.exit(1)

    image_path = Path(args.file)
    if not image_path.exists():
        print(f"File not found: {image_path}")
        sys.exit(1)

    with open(image_path, 'rb') as f:
        raw = f.read()

    print(f"Input:  {image_path.name} ({len(raw):,} bytes)")

    prepared, description = prepare_upgrade_image(raw, device_type, image_path)
    print(f"Action: {description}")

    output = Path(args.output) if args.output else image_path.with_name(
        image_path.stem + '_upgrade.bin'
    )

    with open(output, 'wb') as f:
        f.write(prepared)

    print(f"Output: {output} ({len(prepared):,} bytes)")


def cli_gui(args):
    """Launch the GUI."""
    if not HAS_TK:
        print("ERROR: tkinter is required for the GUI.")
        print("  On Debian/Ubuntu: sudo apt install python3-tk")
        print("  On macOS: tkinter is included with python.org installer")
        sys.exit(1)
    _require_serial()
    _require_xmodem()

    app = DotUpgradeGUI(repo_path=args.repo)
    app.run()


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog='dot-upgrade',
        description='MultiTech Dot Firmware Upgrade Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s list                                 List available firmware
  %(prog)s list --device XDOTAD                 List firmware for xDot-AD
  %(prog)s upgrade XDOTAD US915 /dev/ttyUSB0    Upgrade xDot-AD with US915 firmware
  %(prog)s upgrade MDOT EU868 COM3              Upgrade mDot with EU868 firmware
  %(prog)s upgrade XDOT US915 /dev/ttyUSB0 --file custom.bin
  %(prog)s prepare MDOT firmware.bin            Prepare image (strip BL, add CRC)
  %(prog)s ports                                List serial ports
  %(prog)s versions                             List available firmware versions
  %(prog)s --gui                                Launch graphical interface
        """,
    )

    parser.add_argument(
        '--repo', type=Path, default=REPO_DIR,
        help='Path to Dot-AT-Firmware repository (default: auto-detected)',
    )
    parser.add_argument(
        '--gui', action='store_true', dest='gui',
        help='Launch the graphical interface',
    )

    subparsers = parser.add_subparsers(dest='command', metavar='COMMAND')

    # -- list --
    list_parser = subparsers.add_parser(
        'list', aliases=['ls'],
        help='List available firmware in the repository',
    )
    list_parser.add_argument(
        '--device', '-d', type=str,
        help='Filter by device type (MDOT, XDOT, XDOTES, XDOTAD)',
    )
    list_parser.add_argument(
        '--all', '-a', action='store_true',
        help='Show all build types (including full images and debug)',
    )
    list_parser.set_defaults(func=cli_list)

    # -- versions --
    ver_parser = subparsers.add_parser(
        'versions', aliases=['ver'],
        help='List available firmware versions from git tags',
    )
    ver_parser.set_defaults(func=cli_versions)

    # -- checkout --
    co_parser = subparsers.add_parser(
        'checkout', aliases=['co'],
        help='Checkout a specific firmware version',
    )
    co_parser.add_argument('version', type=str, help='Version to checkout')
    co_parser.set_defaults(func=cli_checkout)

    # -- ports --
    ports_parser = subparsers.add_parser(
        'ports',
        help='List available serial ports',
    )
    ports_parser.set_defaults(func=cli_ports)

    # -- upgrade --
    device_names = ', '.join(dt.value.upper() for dt in DeviceType)
    upgrade_parser = subparsers.add_parser(
        'upgrade', aliases=['up'],
        help='Upgrade device firmware over serial',
    )
    upgrade_parser.add_argument(
        'device', type=str,
        help=f'Device type ({device_names})',
    )
    upgrade_parser.add_argument(
        'freq', type=str, nargs='?',
        help='Frequency plan (e.g., US915, EU868). '
             'Not needed if --file is specified.',
    )
    upgrade_parser.add_argument(
        'port', type=str,
        help='Serial port (e.g., /dev/ttyUSB0, COM3)',
    )
    upgrade_parser.add_argument(
        '--file', '-f', type=str,
        help='Path to firmware file (overrides repo scan)',
    )
    upgrade_parser.add_argument(
        '--baudrate', '-r', type=int, default=115200,
        help='Serial baud rate (default: 115200)',
    )
    upgrade_parser.add_argument(
        '--debug', action='store_true',
        help='Use debug application firmware',
    )
    upgrade_parser.add_argument(
        '--yes', '-y', action='store_true',
        help='Skip confirmation prompts',
    )
    upgrade_parser.add_argument(
        '--debug-port', action='store_true',
        help='Serial port is the debug/log interface (requires manual device '
             'reset). Default behavior auto-detects the interface type.',
    )
    upgrade_parser.add_argument(
        '--at-port', action='store_true',
        help='Serial port is the AT command interface. '
             'Default behavior auto-detects the interface type.',
    )
    upgrade_parser.set_defaults(func=cli_upgrade)

    # -- prepare --
    prep_parser = subparsers.add_parser(
        'prepare', aliases=['prep'],
        help='Prepare an image file (strip bootloader, add CRC) without sending',
    )
    prep_parser.add_argument(
        'device', type=str,
        help=f'Device type ({device_names})',
    )
    prep_parser.add_argument(
        'file', type=str,
        help='Path to firmware image',
    )
    prep_parser.add_argument(
        '--output', '-o', type=str,
        help='Output file path (default: <input>_upgrade.bin)',
    )
    prep_parser.set_defaults(func=cli_prepare)

    return parser


# ===========================================================================
# Section 7: GUI Interface
# ===========================================================================

class DotUpgradeGUI:
    """Tkinter-based graphical interface for firmware upgrades."""

    def __init__(self, repo_path: Optional[Path] = None):
        self.repo = FirmwareRepo(repo_path)
        self.upgrader: Optional[SerialUpgrade] = None
        self._upgrade_thread: Optional[threading.Thread] = None

    def run(self):
        """Create and run the GUI."""
        self.root = tk.Tk()
        self.root.title("Dot Firmware Upgrade Tool")
        self.root.geometry("700x620")
        self.root.minsize(600, 550)

        self._build_ui()
        self._refresh_ports()
        self._on_device_changed()

        self.root.mainloop()

    def _build_ui(self):
        root = self.root

        # Apply a consistent style
        style = ttk.Style()
        style.configure('TLabel', padding=2)
        style.configure('TButton', padding=4)
        style.configure('Header.TLabel', font=('TkDefaultFont', 10, 'bold'))
        style.configure('Status.TLabel', font=('TkDefaultFont', 9))

        main = ttk.Frame(root, padding=12)
        main.pack(fill=tk.BOTH, expand=True)

        # ---- Device Selection ----
        dev_frame = ttk.LabelFrame(main, text="Device", padding=8)
        dev_frame.pack(fill=tk.X, pady=(0, 8))

        row = ttk.Frame(dev_frame)
        row.pack(fill=tk.X)

        ttk.Label(row, text="Device Type:").pack(side=tk.LEFT)
        self.device_var = tk.StringVar()
        device_names = [
            f"{DEVICE_PROPS[dt].name} ({dt.value.upper()})"
            for dt in DeviceType
        ]
        self.device_combo = ttk.Combobox(
            row, textvariable=self.device_var, values=device_names,
            state='readonly', width=22,
        )
        self.device_combo.pack(side=tk.LEFT, padx=(8, 16))
        self.device_combo.current(0)
        self.device_combo.bind('<<ComboboxSelected>>', self._on_device_changed)

        ttk.Label(row, text="Frequency:").pack(side=tk.LEFT)
        self.freq_var = tk.StringVar()
        self.freq_combo = ttk.Combobox(
            row, textvariable=self.freq_var, state='readonly', width=16,
        )
        self.freq_combo.pack(side=tk.LEFT, padx=(8, 0))
        self.freq_combo.bind('<<ComboboxSelected>>', self._on_freq_changed)

        # Firmware info row
        fw_row = ttk.Frame(dev_frame)
        fw_row.pack(fill=tk.X, pady=(6, 0))

        ttk.Label(fw_row, text="Firmware:").pack(side=tk.LEFT)
        self.fw_label = ttk.Label(fw_row, text="", style='Status.TLabel')
        self.fw_label.pack(side=tk.LEFT, padx=(8, 8))

        self.browse_btn = ttk.Button(
            fw_row, text="Browse...", command=self._browse_file,
        )
        self.browse_btn.pack(side=tk.RIGHT)

        self._custom_file: Optional[Path] = None

        # ---- Serial Port ----
        port_frame = ttk.LabelFrame(main, text="Serial Port", padding=8)
        port_frame.pack(fill=tk.X, pady=(0, 8))

        port_row = ttk.Frame(port_frame)
        port_row.pack(fill=tk.X)

        ttk.Label(port_row, text="Port:").pack(side=tk.LEFT)
        self.port_var = tk.StringVar()
        self.port_combo = ttk.Combobox(
            port_row, textvariable=self.port_var, width=30,
        )
        self.port_combo.pack(side=tk.LEFT, padx=(8, 8))

        self.refresh_btn = ttk.Button(
            port_row, text="Refresh", command=self._refresh_ports,
        )
        self.refresh_btn.pack(side=tk.LEFT)

        ttk.Label(port_row, text="Baud:").pack(side=tk.LEFT, padx=(16, 0))
        self.baud_var = tk.StringVar(value="115200")
        baud_combo = ttk.Combobox(
            port_row, textvariable=self.baud_var,
            values=["9600", "19200", "38400", "57600", "115200"],
            width=8,
        )
        baud_combo.pack(side=tk.LEFT, padx=(8, 0))

        # Interface type row
        iface_row = ttk.Frame(port_frame)
        iface_row.pack(fill=tk.X, pady=(6, 0))

        ttk.Label(iface_row, text="Interface:").pack(side=tk.LEFT)
        self.iface_var = tk.StringVar(value=INTERFACE_AUTO)
        for val, label in [(INTERFACE_AUTO, "Auto-detect"),
                           (INTERFACE_AT, "AT Command"),
                           (INTERFACE_DEBUG, "Debug (manual reset)")]:
            ttk.Radiobutton(
                iface_row, text=label, variable=self.iface_var, value=val,
            ).pack(side=tk.LEFT, padx=(8, 4))

        # ---- Progress ----
        prog_frame = ttk.Frame(main)
        prog_frame.pack(fill=tk.X, pady=(0, 8))

        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(
            prog_frame, variable=self.progress_var, maximum=100,
        )
        self.progress_bar.pack(fill=tk.X)

        self.progress_label = ttk.Label(
            prog_frame, text="Ready", style='Status.TLabel',
        )
        self.progress_label.pack(anchor=tk.W, pady=(2, 0))

        # ---- Log ----
        log_frame = ttk.LabelFrame(main, text="Log", padding=4)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        self.log_text = tk.Text(
            log_frame, height=12, wrap=tk.WORD, state=tk.DISABLED,
            font=('TkFixedFont', 9),
        )
        scrollbar = ttk.Scrollbar(
            log_frame, orient=tk.VERTICAL, command=self.log_text.yview,
        )
        self.log_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # ---- Buttons ----
        btn_frame = ttk.Frame(main)
        btn_frame.pack(fill=tk.X)

        self.upgrade_btn = ttk.Button(
            btn_frame, text="Upgrade", command=self._start_upgrade,
        )
        self.upgrade_btn.pack(side=tk.RIGHT, padx=(8, 0))

        self.cancel_btn = ttk.Button(
            btn_frame, text="Cancel", command=self._cancel_upgrade,
            state=tk.DISABLED,
        )
        self.cancel_btn.pack(side=tk.RIGHT)

        # Version info
        ver = self.repo.get_current_version()
        if ver:
            ver_label = ttk.Label(
                btn_frame, text=f"Repo: v{ver}", style='Status.TLabel',
            )
            ver_label.pack(side=tk.LEFT)

    # ---- UI Callbacks -----------------------------------------------------

    def _get_selected_device_type(self) -> DeviceType:
        idx = self.device_combo.current()
        return list(DeviceType)[idx]

    def _on_device_changed(self, event=None):
        """Update frequency plan dropdown when device changes."""
        dt = self._get_selected_device_type()
        plans = self.repo.get_freq_plans(dt)
        self.freq_combo['values'] = plans
        self._custom_file = None

        if plans:
            # Default to US915 if available, else first
            if 'US915' in plans:
                self.freq_combo.set('US915')
            else:
                self.freq_combo.current(0)
            self._on_freq_changed()
        else:
            self.freq_combo.set('')
            self.fw_label.configure(text="No firmware found for this device")

    def _on_freq_changed(self, event=None):
        """Update firmware label when frequency changes."""
        if self._custom_file:
            return

        dt = self._get_selected_device_type()
        freq = self.freq_var.get()
        if not freq:
            return

        fw = self.repo.find_firmware(dt, freq)
        if fw:
            props = DEVICE_PROPS[dt]
            notes = []
            if props.needs_crc:
                notes.append("CRC will be appended")
            note_str = f"  ({', '.join(notes)})" if notes else ""
            self.fw_label.configure(
                text=f"{fw.path.name}{note_str}"
            )
        else:
            self.fw_label.configure(text=f"No firmware found for {freq}")

    def _browse_file(self):
        """Open file browser to select a custom firmware file."""
        path = filedialog.askopenfilename(
            title="Select Firmware File",
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")],
        )
        if path:
            self._custom_file = Path(path)
            dt = self._get_selected_device_type()
            is_full = detect_full_image(self._custom_file, dt)
            warning = " (FULL IMAGE - bootloader will be stripped)" if is_full else ""
            self.fw_label.configure(
                text=f"{self._custom_file.name}{warning}"
            )

    def _refresh_ports(self):
        """Refresh the serial port dropdown."""
        try:
            ports = SerialUpgrade.list_ports()
            port_strings = [f"{dev} - {desc}" for dev, desc in ports]
            self.port_combo['values'] = port_strings
            if port_strings:
                self.port_combo.current(0)
        except Exception:
            self.port_combo['values'] = []

    def _get_selected_port(self) -> Optional[str]:
        """Extract the device name from the port dropdown selection."""
        val = self.port_var.get()
        if not val:
            return None
        # Format is "device - description"
        return val.split(' - ')[0].strip()

    # ---- Log / Progress ---------------------------------------------------

    def _log(self, msg: str):
        """Thread-safe log append."""
        def _append():
            self.log_text.configure(state=tk.NORMAL)
            self.log_text.insert(tk.END, msg + '\n')
            self.log_text.see(tk.END)
            self.log_text.configure(state=tk.DISABLED)
        self.root.after(0, _append)

    def _set_progress(self, transferred: int, total: int):
        """Thread-safe progress update."""
        def _update():
            if total > 0:
                pct = transferred * 100 / total
                self.progress_var.set(pct)
                kb_x = transferred // 1024
                kb_t = total // 1024
                self.progress_label.configure(
                    text=f"{pct:.0f}% ({kb_x}/{kb_t} KB)"
                )
            else:
                self.progress_var.set(0)
        self.root.after(0, _update)

    # ---- Upgrade ----------------------------------------------------------

    def _set_ui_state(self, upgrading: bool):
        """Enable/disable UI elements during upgrade."""
        state = tk.DISABLED if upgrading else tk.NORMAL
        for w in (self.device_combo, self.freq_combo, self.port_combo,
                  self.browse_btn, self.refresh_btn, self.upgrade_btn):
            w.configure(state=state)
        self.cancel_btn.configure(
            state=tk.NORMAL if upgrading else tk.DISABLED
        )

    def _start_upgrade(self):
        """Validate inputs and start upgrade in background thread."""
        dt = self._get_selected_device_type()
        port = self._get_selected_port()

        if not port:
            messagebox.showerror("Error", "No serial port selected.")
            return

        # Determine firmware file
        if self._custom_file:
            image_path = self._custom_file
            if not image_path.exists():
                messagebox.showerror("Error", f"File not found:\n{image_path}")
                return

            # Warn about full images
            if detect_full_image(image_path, dt):
                props = DEVICE_PROPS[dt]
                if not messagebox.askyesno(
                    "Full Image Detected",
                    f"'{image_path.name}' appears to be a full image "
                    f"(bootloader + application).\n\n"
                    f"The bootloader will be stripped automatically "
                    f"(offset 0x{props.app_offset:X}).\n\n"
                    f"Continue?",
                ):
                    return
        else:
            freq = self.freq_var.get()
            if not freq:
                messagebox.showerror("Error", "No frequency plan selected.")
                return

            fw = self.repo.find_firmware(dt, freq)
            if fw is None:
                messagebox.showerror(
                    "Error",
                    f"No application firmware found for "
                    f"{DEVICE_PROPS[dt].name} {freq}",
                )
                return
            image_path = fw.path

        # Clear log
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete('1.0', tk.END)
        self.log_text.configure(state=tk.DISABLED)
        self.progress_var.set(0)
        self.progress_label.configure(text="Starting...")

        self._set_ui_state(upgrading=True)

        baudrate = int(self.baud_var.get())
        interface = self.iface_var.get()

        def _run():
            try:
                do_serial_upgrade(
                    port=port,
                    device_type=dt,
                    image_path=image_path,
                    baudrate=baudrate,
                    interface=interface,
                    log_cb=self._log,
                    progress_cb=self._set_progress,
                    upgrader_cb=self._set_upgrader,
                )
                self.root.after(0, lambda: self._upgrade_finished(True))
            except Exception as e:
                self._log(f"\nERROR: {e}")
                self.root.after(0, lambda: self._upgrade_finished(False, str(e)))
            finally:
                self.upgrader = None

        self._upgrade_thread = threading.Thread(target=_run, daemon=True)
        self._upgrade_thread.start()

    def _set_upgrader(self, upgrader: SerialUpgrade):
        """Store a reference to the active upgrader for cancellation."""
        self.upgrader = upgrader

    def _cancel_upgrade(self):
        """Cancel an in-progress upgrade."""
        if self.upgrader:
            self.upgrader.cancel()
        self._log("Cancelling...")

    def _upgrade_finished(self, success: bool, error: str = ""):
        """Called on main thread when upgrade completes."""
        self._set_ui_state(upgrading=False)
        if success:
            self.progress_label.configure(text="Upgrade complete!")
            messagebox.showinfo("Success", "Firmware upgrade complete!")
        else:
            self.progress_label.configure(text="Upgrade failed")
            messagebox.showerror("Upgrade Failed", error)


# ===========================================================================
# Section 8: Entry Point
# ===========================================================================

def main():
    parser = build_parser()
    args = parser.parse_args()

    # --gui flag takes precedence
    if getattr(args, 'gui', False):
        cli_gui(args)
        return

    if args.command is None:
        parser.print_help()
        return

    args.func(args)


if __name__ == '__main__':
    main()
