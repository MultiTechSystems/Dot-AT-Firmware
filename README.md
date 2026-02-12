# Dot-AT-Firmware

Release binaries and latest builds of AT Firmware for mDot, xDot, xDot-ES, and xDot-AD hardware.

See [Change Log](https://github.com/MultiTechSystems/Dot-AT-Firmware/blob/master/changelog.txt) for release notes.


## Serial Firmware Upgrade Tool

A cross-platform Python tool is included for updating Dot devices over serial, replacing the TeraTerm/TTL script dependency.

### Requirements

* Python 3.7+
* Install dependencies: `pip install -r tools/requirements.txt`

### Quick Start

```bash
# List available firmware
python tools/dot-upgrade.py list

# List available serial ports
python tools/dot-upgrade.py ports

# Upgrade a device (auto-selects correct APPS/ file, handles CRC)
python tools/dot-upgrade.py upgrade XDOTAD US915 /dev/ttyUSB0
python tools/dot-upgrade.py upgrade MDOT EU868 COM3

# Launch the graphical interface
python tools/dot-upgrade.py --gui

# Prepare an image without sending (strip bootloader, add CRC)
python tools/dot-upgrade.py prepare MDOT firmware.bin

# List available firmware versions (from git tags)
python tools/dot-upgrade.py versions
```

The tool automatically:
* Selects application-only images from the `APPS/` directory (prevents the common mistake of flashing a full bootloader+application image via the bootloader)
* Appends CRC32 for devices that require it (mDot, xDot-AD)
* Strips the bootloader if a full image is provided
* Detects serial ports

See also: [Dot Development](https://multitechsystems.github.io/dot-development) for more details on serial firmware upgrades.


## Supported Devices

| Device  | Directory | CRC Required | Bootloader Command | Upgrade Timeout |
|---------|-----------|--------------|--------------------|--------------------|
| mDot    | `MDOT/`   | Yes          | `upgrade ymodem`   | ~30s               |
| xDot    | `XDOT/`   | No           | `upgrade`          | Immediate          |
| xDot-ES | `XDOTES/` | No           | `upgrade`          | Immediate          |
| xDot-AD | `XDOTAD/` | Yes          | `upgrade`          | ~90s               |


## Bootloader Entry

To enter the bootloader for serial firmware upgrades, the device must be reset and a specific key sequence must be received within 250ms of boot.  The upgrade tool handles this automatically, but the behavior varies by bootloader version and serial interface.

### Bootloader Key by Version

| Bootloader Version | AT/Command Port | Debug Port | Notes |
|--------------------|----------------|------------|-------|
| v0.1.x             | N/A            | Any keypress | Single port only (xDot mbed-os-5) |
| 1.0.0 - 1.1.9      | `mts`          | Any keypress | STM32 and MAX32670 targets |
| 1.2.0+             | `mts`          | `mts` (MAX32670) / Any keypress (others) | MAX32670 debug port now requires key |

> The key `xdt` was used in some intermediate xDot bootloader builds but was changed to `mts` before any tagged release.  The upgrade tool tries both keys for compatibility.

### How the Upgrade Tool Enters the Bootloader

**Debug port** (auto-detected or `--debug-port`):
1. Sends a serial break to reset the device
2. Watches for the `[INFO] MultiTech Bootloader x.x.x` banner on the debug output
3. Parses the bootloader version from the banner and selects the correct key:
   * Version < 1.2.0: any keypress (newlines) is sufficient
   * Version >= 1.2.0 on MAX32670 (xDot-ES/AD): sends `mts`
   * Version >= 1.2.0 on other devices: any keypress is sufficient
4. Floods the selected key immediately to catch the 250ms input window
5. If serial break does not work, prompts the user to manually reset the device

**AT command port** (auto-detected or `--at-port`):
1. Sends `ATZ` to reset the device
2. The bootloader version is not visible on the AT port, so the tool tries `mts` (then `xdt` as fallback) via echo-detection — the bootloader echoes each character, confirming it is running


## Build Types

### Normal (Full Image)

**mdot-firmware-x.x.x-ppppp-mbed-os-x.x.x.bin**

**xdot-firmware-x.x.x-ppppp-mbed-os-x.x.x.bin**

**xdotes-firmware-x.x.x-ppppp-xdot-max32670.bin**

**xdotad-firmware-x.x.x-ppppp-xdot-max32670.bin**

Full image with application and bootloader. Suitable for flashing via drag-and-drop or JTAG/SWD.

> **WARNING:** Do NOT use full images for bootloader serial upgrades. Use application-only images from the `APPS/` directory instead, or let the upgrade tool handle the conversion automatically.


### Application

**mdot-firmware-x.x.x-ppppp-mbed-os-x.x.x-application.bin**

**xdot-firmware-x.x.x-ppppp-mbed-os-x.x.x-application.bin**

**xdotes-firmware-x.x.x-ppppp-xdot-max32670-application.bin**

**xdotad-firmware-x.x.x-ppppp-xdot-max32670-application.bin**

Application-only builds (no bootloader). Used when updating firmware via the bootloader over serial or over-the-air (FOTA). These are located in the `APPS/` subdirectory of each device folder.


### Debug

Debug builds have additional functionality and log output for debug and trace levels. Suitable for flashing via drag-and-drop or JTAG/SWD.


#### xDot

**xdot-firmware-x.x.x-ppppp-mbed-os-x.x.x-debug.bin**

* No bootloader

**xdot-firmware-x.x.x-GLOBAL-mbed-os-x.x.x-debug.bin**

* Includes all channel plans
* Allows changing frequency bands

```
AT+DFREQ=AS923
AT&WP
ATZ
```

#### mDot

**mdot-firmware-x.x.x-ALL-PLANS-mbed-os-x.x.x-debug.bin**
**mdot-firmware-x.x.x-GLOBAL-mbed-os-x.x.x-debug.bin**

* Includes all channel plans
* Allows changing frequency bands

```
AT+DFREQ=AS923
AT&WP
ATZ
```


## Legacy Tools

The TeraTerm TTL script (`tools/dot-serial-update.ttl`) is still available for Windows users who prefer TeraTerm. The Python upgrade tool above is the recommended replacement.

