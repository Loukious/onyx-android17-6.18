#!/system/bin/sh
# One bounded transaction against the router configured in this private kit.
set -eu
KIT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$KIT"
sh ./driver.sh check
cmp -s /sys/module/qca_cld3_wcn7750/notes/.note.gnu.build-id candidate/build-id || {
    echo 'Load the candidate driver before this test.' >&2; exit 1;
}
. ./router.conf
KALI=/data/local/nhsystem/kali-arm64
[ -d "$KALI" ] || { echo 'Kali chroot not found.' >&2; exit 1; }
if pidof reaver >/dev/null 2>&1; then
    echo 'A Reaver process is already running.' >&2; exit 1
fi
case "$AP_PIN" in *[!0-9]*|'') echo 'Expected the known numeric AP PIN.' >&2; exit 1;; esac
[ "${#AP_PIN}" = 8 ] || { echo 'Expected an eight-digit AP PIN.' >&2; exit 1; }

CAPTURE=
WIFI_BEFORE=$(settings get global wifi_on)
stop_capture() {
    if [ -n "$CAPTURE" ]; then
        kill -INT "$CAPTURE" 2>/dev/null || true
        wait "$CAPTURE" 2>/dev/null || true
        CAPTURE=
    fi
}
cleanup() {
    stop_capture
    if [ "$WIFI_BEFORE" = 1 ]; then
        svc wifi enable || echo 'Could not restore the Android Wi-Fi setting.' >&2
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Firmware initialization can finish after insmod and svc wifi enable return.
tries=0
while [ ! -d /sys/class/net/wlan0 ] && [ ! -d /sys/class/net/wlan0mon ]; do
    [ "$tries" -lt 20 ] || {
        echo 'WLAN interfaces did not become ready within 20 seconds.' >&2
        exit 1
    }
    sleep 1
    tries=$((tries + 1))
done

# Android's supplicant must not manage the adapter during the monitor test.
if [ "$WIFI_BEFORE" = 1 ]; then
    svc wifi disable
    sleep 2
fi

# Use the existing monitor interface, or recreate it after the module reload.
if [ ! -d /sys/class/net/wlan0mon ]; then
    ip link set wlan0 down
    iw dev wlan0 interface add wlan0mon type monitor
fi
ip link set wlan0mon up
iw dev wlan0mon set channel "$CHANNEL"
RESULTS=$KIT/results/$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$RESULTS"
chmod 700 "$RESULTS"
iw dev > "$RESULTS/interfaces.txt"
cat /sys/module/qca_cld3_wcn7750/parameters/injection_stats > "$RESULTS/stats-before.txt"
SESSION=$(chroot "$KALI" /usr/bin/mktemp -d /tmp/onyx-wps-test.XXXXXX)

chroot "$KALI" /usr/bin/env PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    timeout -s INT -k 5 75 tcpdump --immediate-mode -i wlan0mon -s 0 -U -w - \
    "wlan host $BSSID" > "$RESULTS/traffic.pcap" 2> "$RESULTS/tcpdump.log" &
CAPTURE=$!
sleep 1
kill -0 "$CAPTURE" 2>/dev/null || { echo 'Packet capture failed; see tcpdump.log.' >&2; exit 1; }
echo "Testing one known PIN for at most 60 seconds; logs: $RESULTS"
# Use the netdev MAC and normal Reaver WPS handling to exercise the driver fix.
set +e
chroot "$KALI" /usr/bin/env PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    timeout -s INT -k 5 60 reaver -i wlan0mon -b "$BSSID" -c "$CHANNEL" \
    -p "$AP_PIN" -g 1 -s "$SESSION/session" -vv > "$RESULTS/reaver.log" 2>&1
REAVER_STATUS=$?
set -e
# Drain the final response burst before interrupting the capture process.
sleep 1
stop_capture
printf '%s\n' "$REAVER_STATUS" > "$RESULTS/reaver-exit.txt"
cat /sys/module/qca_cld3_wcn7750/parameters/injection_stats > "$RESULTS/stats-after.txt"
dmesg > "$RESULTS/dmesg.txt"
cat "$RESULTS/stats-before.txt" "$RESULTS/stats-after.txt"
echo "Results saved in $RESULTS"
echo 'Inspect AP EAP replies and WPS progression in reaver.log/traffic.pcap.'
exit "$REAVER_STATUS"
