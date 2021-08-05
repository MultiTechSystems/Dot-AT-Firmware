# Dot-AT-Firmware

Release binaries and latest builds of AT Firmware for mDot and xDot hardware

See [Change Log](https://github.com/MultiTechSystems/Dot-AT-Firmware/blob/master/changelog.txt) for release notes.

## Build Types

### Normal

**xdot-firmware-x.x.x-ppppp-mbed-os-x.x.x.bin**

**mdot-firmware-x.x.x-ppppp-mbed-os-x.x.x.bin**

Normal builds are a full image with application and bootloader.  Suitable for flashing to an MDot/XDot via drag-and-drop or JTAG/SWD.


### Application

**xdot-firmware-x.x.x-ppppp-mbed-os-x.x.x-application.bin**

**mdot-firmware-x.x.x-ppppp-mbed-os-x.x.x-application.bin**


Application builds do not include a bootloader and are used when updating an MDot/XDot firmware via the bootloader or over-the-air.

See the Programming section in [Dot Development](https://multitechsystems.github.io/dot-development) for details on serial firmware upgrades.


### Debug

Debug builds have additional functionality and log output for debug and trace levels.  Suitable for flashing to an MDot/XDot via drag-and-drop or JTAG/SWD.


#### XDot

**xdot-firmware-x.x.x-ppppp-mbed-os-x.x.x-debug.bin**

* No bootloader


#### MDot

**mdot-firmware-x.x.x-ALL-PLANS-mbed-os-x.x.x-debug.bin**

* Includes all channel plans
* Allows changing frequency bands

```
AT+DFREQ=AS923
AT&WP
ATZ
```

