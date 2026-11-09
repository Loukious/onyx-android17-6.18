#!/system/bin/sh
# Temporary driver replacement. No mounts, boot hooks or partition writes.
set -eu
KIT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$KIT"
. ./identity.conf
MOD=qca_cld3_wcn7750
SYS=/sys/module/$MOD
NOTE=$SYS/notes/.note.gnu.build-id
REMOVE_CANDIDATE_ON_ERROR=0

fail() { echo "$*" >&2; exit 1; }
restore_wifi() {
    if [ -f state/wifi-before ] && [ "$(cat state/wifi-before)" = 1 ]; then
        svc wifi enable || echo 'Could not restore the Android Wi-Fi setting.' >&2
    fi
}
loaded() {
    if [ ! -d "$SYS" ]; then
        echo absent
    elif cmp -s "$NOTE" candidate/build-id; then
        echo candidate
    elif cmp -s "$NOTE" original/build-id; then
        echo original
    else
        echo unknown
    fi
}
preflight() {
    [ "$(id -u)" = 0 ] || fail 'Run this script through Android su.'
    [ "$(uname -r)" = "$KERNEL_RELEASE" ] || fail 'Kernel release differs from this test bundle.'
    [ "$(getprop ro.product.device)" = onyx ] || fail 'This bundle is for the Onyx test device.'
    sha256sum -c SHA256SUMS >/dev/null || fail 'A bundle file failed its checksum.'
    [ "$(sha256sum /vendor_dlkm/lib/modules/$MOD.ko | cut -d ' ' -f1)" = "$ORIGINAL_SHA256" ] ||
        fail 'The installed original driver differs from this bundle.'
    [ "$(sha256sum /vendor_dlkm/lib/modules/cfg80211.ko | cut -d ' ' -f1)" = "$CFG80211_SHA256" ] ||
        fail 'The installed cfg80211 provider differs from this bundle.'
    [ "$(loaded)" != unknown ] || fail 'An unrecognized WLAN module is already loaded.'
}
wait_for_idle() {
    tries=0
    while [ -d "$SYS" ] && [ "$(cat "$SYS/refcnt")" != 0 ]; do
        [ "$tries" -lt 20 ] || return 1
        sleep 1
        tries=$((tries + 1))
    done
}
wait_for_interfaces() {
    # An intentionally disabled Android Wi-Fi service need not start the driver.
    [ -f state/wifi-before ] && [ "$(cat state/wifi-before)" = 1 ] || return 0
    tries=0
    while [ ! -d /sys/class/net/wlan0 ] && [ ! -d /sys/class/net/wlan0mon ]; do
        [ "$tries" -lt 20 ] || return 1
        sleep 1
        tries=$((tries + 1))
    done
}
prepare_memory() {
    # Hot reloads need large non-CMA buffers; let deferred frees settle first.
    sleep 1
    if [ "${WLAN_TEST_RECLAIM:-0}" = 1 ]; then
        printf '1\n' > /proc/sys/vm/drop_caches
    fi
    if [ -w /proc/sys/vm/compact_memory ]; then
        printf '1\n' > /proc/sys/vm/compact_memory
    fi
}
recover_on_exit() {
    status=$?
    trap - EXIT INT TERM
    if [ "$status" != 0 ]; then
        if [ "$REMOVE_CANDIDATE_ON_ERROR" = 1 ] && [ "$(loaded)" = candidate ]; then
            svc wifi disable || true
            if wait_for_idle; then
                rmmod "$MOD" || echo 'Could not remove the failed candidate normally.' >&2
            else
                echo 'Failed candidate remains busy; normal removal was not possible.' >&2
            fi
        fi
        if [ ! -d "$SYS" ]; then
            prepare_memory || true
            insmod "$KIT/original/$MOD.ko" || echo 'Original driver reload failed; reboot to reload the installed driver.' >&2
        fi
        restore_wifi
        wait_for_interfaces || echo 'Original driver interfaces did not become ready; inspect the probe log.' >&2
    fi
    exit "$status"
}
swap() {
    wanted=$1
    state=$(loaded)
    if [ "$state" = "$wanted" ]; then
        if [ "$wanted" = original ]; then restore_wifi; fi
        if wait_for_interfaces; then
            echo "$wanted driver is already loaded."
            return
        fi
        echo "The $wanted module has no ready WLAN interfaces; retrying its probe."
    fi
    if pidof reaver >/dev/null 2>&1; then fail 'Stop the running Reaver process before replacing the driver.'; fi
    mkdir -p state
    if [ "$wanted" = candidate ]; then
        settings get global wifi_on > state/wifi-before
    fi
    trap recover_on_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    svc wifi disable
    if [ -d /sys/class/net/wlan0mon ]; then
        ip link set wlan0mon down
    fi
    wait_for_idle || fail 'WLAN is still busy; the current module remains loaded.'
    if [ -d "$SYS" ]; then
        [ "$(loaded)" = "$state" ] || fail 'Loaded module changed during preparation.'
        rmmod "$MOD" || fail 'Normal module removal failed; no forced removal was attempted.'
    fi
    if [ "$wanted" = candidate ]; then REMOVE_CANDIDATE_ON_ERROR=1; fi
    prepare_memory
    insmod "$KIT/$wanted/$MOD.ko" || fail "$wanted module failed to load."
    cmp -s "$NOTE" "$wanted/build-id" || fail 'Loaded module build ID did not match.'
    restore_wifi
    wait_for_interfaces || fail "$wanted module loaded but its WLAN probe did not finish within 20 seconds."
    trap - EXIT INT TERM
    echo "$wanted WLAN driver loaded; build ID and requested Wi-Fi readiness verified."
}

case ${1:-check} in
    check)
        preflight
        echo "Preflight passed; loaded driver: $(loaded)"
        ;;
    load)
        preflight
        swap candidate
        ;;
    restore)
        preflight
        swap original
        ;;
    stats)
        if [ -r "$SYS/parameters/injection_stats" ]; then
            cat "$SYS/parameters/injection_stats"
        else
            echo 'The candidate driver is not loaded.'
            exit 1
        fi
        ;;
    *) fail 'Usage: driver.sh check|load|restore|stats' ;;
esac
