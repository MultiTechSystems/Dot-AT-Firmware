# Bootloader Testing Notes

## Device: xDot-ES (MAX32670)

## Final Results - Bootloader 1.2.0-8 (8e38130)

This version includes:
- UART RX FIFO overflow fix (93bf7d8)
- Suppressed console output during YMODEM (8e38130)
- Reverted to working check_keypress timing

| Tool | AT Port (COM10) | Debug Port (COM8) |
|------|-----------------|-------------------|
| dot-upgrade.py (updated) | PASS | PASS |
| dot-serial-update.ttl | PASS | PASS (with mts after break) |

### Fix Applied to dot-upgrade.py
The bootloader provides a 250ms window after reset to receive the "mts" escape sequence.
Testing showed:
- 0-250ms delay after break: 100% success
- 275ms+ delay: 0% success

The original code waited to read the banner before sending "mts", missing this window.
The fix sends "mts" immediately after break (within 250ms), then reads the response.

## Test History

### Bootloader 1.1.9 (old - "xdt" key on AT port, ANY char on debug port)
| Tool | AT Port (COM10) | Debug Port (COM8) |
|------|-----------------|-------------------|
| dot-upgrade.py | PASS | BL entry OK, YMODEM FAIL (NAK - UART overflow) |
| dot-serial-update.ttl | PASS | PASS |

**Note:** In 1.1.9, the debug port (usb_port) only required ANY character to be received to enter bootloader - no "mts" sequence needed. The AT port (uart_port) required "mts". The original `dot-upgrade.py` could enter bootloader on debug port with 1.1.9, but YMODEM failed due to UART overflow (fixed in 93bf7d8).

### Bootloader 1.2.0 (00c66b1 - "mts" required)
| Tool | AT Port (COM10) | Debug Port (COM8) |
|------|-----------------|-------------------|
| dot-upgrade.py (original) | PASS | FAIL (timing window missed) |
| dot-upgrade-robust.py | PASS | BL entry OK, YMODEM FAIL (overflow) |
| dot-serial-update.ttl | PASS | PASS (after adding mts) |

### Bootloader 1.2.0-7 (93bf7d8 - overflow fix, with debug output)
| Tool | AT Port (COM10) | Debug Port (COM8) |
|------|-----------------|-------------------|
| dot-upgrade-robust.py | PASS | PASS (but xmodem lib confused by debug output) |
| test_ymodem_full.py | N/A | PASS (filters debug output) |

### Bootloader 1.2.0-8 (8e38130 - final)
| Tool | AT Port (COM10) | Debug Port (COM8) |
|------|-----------------|-------------------|
| dot-upgrade.py (original) | PASS | FAIL (timing) |
| dot-upgrade-robust.py | PASS | PASS |

## Issues Found & Fixed

### Issue 1: UART RX FIFO Overflow (FIXED in 93bf7d8)
- MAX32670 UART driver doesn't auto-recover from RX FIFO overflow
- During flash erase/write, YMODEM data packets were lost
- Fix: Clear overflow flag in UART driver during YMODEM

### Issue 2: Debug Output During YMODEM (FIXED in 8e38130)
- `pr_info()` messages during flash erase were going to USB port
- This confused YMODEM protocol (mixed with ACK/NAK)
- Fix: Suppress console output during YMODEM transfer

### Issue 3: dot-upgrade.py Debug Port Entry (Changed behavior in 1.2.0)
- In 1.1.9: Debug port only needed ANY character to enter bootloader (worked)
- In 1.2.0+ (00c66b1): Debug port requires "mts" sequence like AT port
- Original dot-upgrade.py waits for banner before flooding "mts"
- By then the 250ms escape window has passed
- Solution: Use dot-upgrade-robust.py which floods immediately

**Summary for debug port:**
- 1.1.9: BL entry OK (any char), YMODEM FAIL (overflow)
- 1.2.0+: BL entry FAIL (timing), YMODEM N/A
- 1.2.0-8 + robust.py: BL entry OK, YMODEM OK

### Issue 4: TTL Script Missing "mts" (FIXED in ttl)
- dot-serial-update.ttl only sent `sendbreak` for debug port
- Added `sendln "mts"` after break for debug port

## Files

- `dot-upgrade.py` - Updated version (works on both ports)
- `dot-serial-update.ttl` - Updated TTL script (works on both ports)

## Key Bootloader Commits (generic-bootloader)

| Commit | Description |
|--------|-------------|
| 1.1.9 (a336738) | Debug port: any char enters bootloader. AT port: "mts" required |
| 00c66b1 | Require "mts" on debug port too (breaking change for old dot-upgrade.py) |
| 3bc1e21 | Check both ports simultaneously (introduced timing bug) |
| 84d3dce | Fix timing regression (reset timer per character) |
| aae6092 | Set final_port early, only check initially-ready ports |
| 93bf7d8 | Fix UART RX FIFO overflow during flash ops |
| 8e38130 | Suppress console output during YMODEM |

## dot-upgrade.py Fix

Changed `_break_and_enter()` to:
1. Send escape key immediately after break (within 250ms window)
2. Try "mts" first (for 1.2.0+)
3. If that fails, try "xdt" (for 1.1.x)

The original code waited to read the banner before sending the key, missing the 250ms window.

## dot-serial-update.ttl Fix

Updated to try "mts" first, then fall back to "xdt" if bootloader prompt not found.
Works with both 1.1.x and 1.2.0+ bootloaders.
