# CI patches

Small patches applied to the Zephyr tree in CI before building, for upstream
bugs that block this module's boards until a fix lands in the pinned Zephyr
release.

## 0001-drivers-wifi-airoc-add-missing-log.h-include.patch

The in-tree AIROC Wi-Fi **SPI** HAL files
(`drivers/wifi/infineon/airoc_whd_hal_spi.c` and `airoc_whd_hal_common.c`) call
`LOG_MODULE_DECLARE()` / `LOG_ERR()` without including
`<zephyr/logging/log.h>`, so they fail to compile in any configuration. The
SPI/PIO bus path is the one the Raspberry Pi Pico W / Pico 2W use; no upstream
Zephyr CI builds it (only the SDIO `cy8cproto_062_4343w`), so it went unnoticed.

This blocks the `wifi_prov_console` build for `rpi_pico2/rp2350a/m33/w`. The
patch adds the missing include (one line per file). Present in Zephyr v4.4.x.

Applied idempotently in `.github/workflows/build.yml` for the Pico 2W build
job. Remove this patch once the fix is upstreamed and included in the Zephyr
revision pinned by `west.yml`.
