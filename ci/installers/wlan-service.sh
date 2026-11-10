#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
MODDIR=${0%/*}
NAME=qca_cld3_wcn7750
KO="$MODDIR/wlan/$NAME.ko"
logmsg() { log -t nethunter-wlan-injection "$*"; }
mode=load
recover_stock=0
case "$#" in
  0) ;;
  1) [ "$1" = --check-radio-restore ] || { logmsg 'Unknown loader argument'; exit 1; }
     mode=check-radio-restore ;;
  *) logmsg 'Unknown loader arguments'; exit 1 ;;
esac

restore_radio() {
  restore_failed=0
  if [ "$wifi_on" = 1 ]; then
    /system/bin/svc wifi enable || restore_failed=1
  else
    /system/bin/svc wifi disable || restore_failed=1
  fi
  # Restore Wi-Fi first, then its independent scan-only preference.
  if [ "$scan_always" = 1 ]; then
    cmd wifi set-scan-always-available enabled || restore_failed=1
  else
    cmd wifi set-scan-always-available disabled || restore_failed=1
  fi
  for restore_attempt in $(seq 1 20); do
    if [ "$(settings get global wifi_on 2>/dev/null)" = "$wifi_on" ] &&
       [ "$(settings get global wifi_scan_always_enabled 2>/dev/null)" = "$scan_always" ]; then
      [ "$restore_failed" = 0 ] || return 1
      logmsg "Restored Wi-Fi=$wifi_on scan-always=$scan_always"
      return 0
    fi
    sleep 1
  done
  return 1
}
finish() {
  finish_status=$?
  trap - EXIT HUP INT TERM
  if [ "$recover_stock" = 1 ] && [ ! -d "/sys/module/$NAME" ]; then
    logmsg 'Restoring original driver before Android settings'
    if ! insmod "$stock"; then
      logmsg 'Original driver restore failed'
      finish_status=125
    fi
  fi
  if ! restore_radio; then
    logmsg 'Could not verify restoration of saved Wi-Fi/scan settings'
    finish_status=125
  fi
  exit "$finish_status"
}
framework_is_disabled() {
  [ "$(settings get global wifi_on 2>/dev/null)" = 0 ] &&
    [ "$(settings get global wifi_scan_always_enabled 2>/dev/null)" = 0 ] || return 1
  # cmd wifi status also says "disabled" during transitions. Require the
  # controller's completed state and no STA, scan-only, or SoftAP managers.
  # Stream the dump: Android printf may be external, so a full dump can
  # exceed the single-argument limit. The trailer also preserves dump errors
  # when the caller has not enabled pipefail.
  {
    if dumpsys -t 5 wifi 2>/dev/null; then
      echo
      echo '__onyx_framework_dump_status=0'
    else
      echo
      echo '__onyx_framework_dump_status=1'
    fi
  } | awk '
    { sub(/\r$/, "") }
    !seen && $0 == "Dump of WifiActiveModeWarden" {
      seen = 1; in_warden = 1; next
    }
    in_warden && $0 == "Current wifi mode: DisabledState" { disabled = 1 }
    in_warden && $0 == "NumActiveModeManagers: 0" { empty = 1 }
    in_warden && /^WifiController:/ { in_warden = 0; closed = 1 }
    END {
      exit !(seen && closed && disabled && empty &&
             $0 == "__onyx_framework_dump_status=0")
    }
  '
}
module_is_idle() {
  [ -d "/sys/module/$NAME" ] || return 1
  [ "$(cat /sys/module/$NAME/refcnt 2>/dev/null)" = 0 ] || return 1
  for holder in /sys/module/$NAME/holders/*; do
    if [ -e "$holder" ] || [ -L "$holder" ]; then return 1; fi
  done
  pidof bully reaver tcpdump airodump-ng aireplay-ng >/dev/null 2>&1 && return 1
  return 0
}
wait_for_idle() {
  idle_passes=0
  idle_deadline=$(( $(cut -d. -f1 /proc/uptime) + 30 ))
  while [ "$(cut -d. -f1 /proc/uptime)" -lt "$idle_deadline" ]; do
    if framework_is_disabled && module_is_idle; then
      idle_passes=$((idle_passes + 1))
      [ "$idle_passes" -ge 2 ] && return 0
    else
      idle_passes=0
    fi
    sleep 1
  done
  return 1
}

[ "$(uname -r)" = '@RELEASE@' ] || { logmsg 'Kernel mismatch; keeping installed WLAN'; exit 1; }
cd "$MODDIR" || exit 1
sha256sum -c payload.sha256 >/dev/null 2>&1 || { logmsg 'Payload checksum failed'; exit 1; }
ready=0
for attempt in $(seq 1 60); do
  ready=1
  for dep in @DEPS@; do
    [ -d "/sys/module/$dep" ] || ready=0
  done
  [ "$ready" = 1 ] && break
  sleep 1
done
[ "$ready" = 1 ] || { logmsg 'WLAN dependencies missing; keeping installed WLAN'; exit 1; }
"$MODDIR/module-abi" "$MODDIR/kernel-abi.tsv" "$KO" || { logmsg 'Replacement WLAN ABI check failed'; exit 1; }
stock=
for path in /vendor_dlkm/lib/modules/$NAME.ko /vendor/lib/modules/$NAME.ko; do
  [ -f "$path" ] && { stock=$path; break; }
done
if [ -d "/sys/module/$NAME" ]; then
  [ -n "$stock" ] || { logmsg 'Cannot locate rollback driver; keeping loaded WLAN'; exit 1; }
  # Only unload when the rollback binary belongs to this same verified ABI.
  "$MODDIR/module-abi" "$MODDIR/kernel-abi.tsv" "$stock" || exit 1
  if pidof bully reaver tcpdump airodump-ng aireplay-ng >/dev/null 2>&1; then
    logmsg 'WLAN test/capture process active; keeping loaded driver'
    exit 1
  fi
  # KernelSU starts services before Settings is ready.
  wifi_on=
  scan_always=
  for attempt in $(seq 1 90); do
    if [ "$(getprop sys.boot_completed)" = 1 ]; then
      wifi_on=$(settings get global wifi_on 2>/dev/null)
      scan_always=$(settings get global wifi_scan_always_enabled 2>/dev/null)
      case "$wifi_on:$scan_always" in 0:0|0:1|1:0|1:1) break ;; esac
    fi
    sleep 1
  done
  case "$wifi_on:$scan_always" in
    0:0|0:1|1:0|1:1) ;;
    *) logmsg 'Cannot determine Wi-Fi/scan state'; exit 1 ;;
  esac
  # Install cleanup before the first control change, including partial failure.
  trap finish EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  logmsg "Saved Wi-Fi=$wifi_on scan-always=$scan_always"
  cmd wifi set-scan-always-available disabled || { logmsg 'Cannot disable background scanning'; exit 1; }
  /system/bin/svc wifi disable || { logmsg 'Cannot disable Wi-Fi'; exit 1; }
  wait_for_idle || { logmsg 'WLAN/framework still in use; keeping loaded driver'; exit 1; }
  if [ "$mode" = check-radio-restore ]; then
    logmsg 'Radio stop verified; restoring settings without module replacement'
    exit 0
  fi
  # Cleanup also covers interruption after a successful removal.
  recover_stock=1
  rmmod "$NAME" || { logmsg 'Unload failed; keeping loaded driver'; exit 1; }
  if ! insmod "$KO"; then
    logmsg 'Injection driver load failed; restoring original driver'
    exit 1
  fi
  recover_stock=0
else
  [ "$mode" = load ] || { logmsg 'Radio restoration check requires an already loaded WLAN'; exit 1; }
  insmod "$KO" || { logmsg 'Injection driver load failed'; exit 1; }
fi
logmsg 'Loaded matched WCN7750 monitor/injection driver'
