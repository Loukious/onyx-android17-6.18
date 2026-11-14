#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
MODDIR=${0%/*}
logmsg() { log -t onyx-nethunter-external-wifi "$*"; }
LOADER_LOCK=/dev/onyx-nethunter-external-wifi-loader.lock
mkdir "$LOADER_LOCK" 2>/dev/null || { logmsg 'Loader is active; reboot to remove the firmware overlay'; exit 1; }
trap 'rmdir "$LOADER_LOCK" 2>/dev/null' EXIT
. "$MODDIR/firmware-overlay.sh"
fw_release
# Drivers may be in use by Android or an adapter. Reboot removes this module's
# additions without unloading shared providers or disturbing current users.
