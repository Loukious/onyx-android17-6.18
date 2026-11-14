#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
MODDIR=${0%/*}
logmsg() { log -t onyx-nethunter-external-wifi "$*"; }
[ "$#" = 0 ] || { logmsg 'Unknown loader arguments'; exit 1; }
[ "$(uname -r)" = '@RELEASE@' ] || { logmsg 'Kernel mismatch; keeping installed drivers'; exit 1; }
cd "$MODDIR" || exit 1
sha256sum -c payload.sha256 >/dev/null 2>&1 || { logmsg 'Payload checksum failed'; exit 1; }
# /dev is recreated at boot; a killed loader must not leave a persistent lock
# that prevents the module from starting after the next reboot.
LOADER_LOCK=/dev/onyx-nethunter-external-wifi-loader.lock
mkdir "$LOADER_LOCK" 2>/dev/null || { logmsg 'Another loader is active'; exit 1; }
trap 'rmdir "$LOADER_LOCK" 2>/dev/null' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
while IFS= read -r driver; do
  "$MODDIR/module-abi" "$MODDIR/kernel-abi.tsv" "$MODDIR/drivers/$driver.ko" || {
    logmsg "Driver ABI verification failed: $driver"; exit 1;
  }
done < "$MODDIR/modules.load"
. "$MODDIR/firmware-overlay.sh"
fw_prepare || { logmsg 'Firmware setup failed; no additional drivers loaded'; exit 1; }
while IFS=: read -r driver dependencies; do
  if [ -d "/sys/module/$driver" ]; then
    logmsg "Keeping already loaded $driver"
    continue
  fi
  for dependency in $dependencies; do
    [ -d "/sys/module/$dependency" ] || {
      logmsg "Missing dependency $dependency for $driver; stopping"; exit 1;
    }
  done
  if ! insmod "$MODDIR/drivers/$driver.ko"; then
    # Another Android loader may have won the same registration race.
    [ -d "/sys/module/$driver" ] || { logmsg "Driver load failed: $driver"; exit 1; }
  fi
  [ -d "/sys/module/$driver" ] || { logmsg "Driver registration missing: $driver"; exit 1; }
  logmsg "Loaded matched $driver"
done < "$MODDIR/modules.dep"
logmsg 'USB Wi-Fi driver and firmware setup completed'
