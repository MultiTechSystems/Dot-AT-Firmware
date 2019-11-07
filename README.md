# Dot-AT-Firmware

Release binaries and latest builds of AT Firmware for mDot and xDot hardware

See [Change Log](https://github.com/MultiTechSystems/Dot-AT-Firmware/blob/master/changelog.txt) for release notes.

## Debug firmware allows changing frequency bands
ALL-PLANS-mbed-os-X.X.XX-DEBUG

AT+DFREQ=AS923
AT&WP
ATZ

## Debug firmware allows setting DEVEUI

AT+DI=0011223344556677
AT&WP
ATZ

## Debug firmare also can set default AppEUI and AppKey

AT+NI=2,0011223344556677
AT+NK=2,00112233445566770011223344556677
AT&WP

These settings will be used when AT&F is issued to reset to default.

