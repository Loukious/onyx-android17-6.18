#!/system/bin/sh
MODDIR=${0%/*}
KSUD=/data/adb/ksud
STATUS="$MODDIR/runtime-status.txt"
EXPECTED=$(cat "$MODDIR/kernel.release")
ACTUAL=$(uname -r)
if [ "$EXPECTED" != "$ACTUAL" ]; then
    printf 'FAIL: expected %s, running %s\n' "$EXPECTED" "$ACTUAL" > "$STATUS"
    exit 1
fi
EXPECTED_NOTES=$(cat "$MODDIR/kernel.notes.sha256")
ACTUAL_NOTES=$(sha256sum /sys/kernel/notes 2>/dev/null)
case "$ACTUAL_NOTES" in
    "$EXPECTED_NOTES "*) ;;
    *) printf 'FAIL: SUSFS addon belongs to a different kernel/KernelSU build\n' > "$STATUS"; exit 1 ;;
esac
if [ ! -x "$KSUD" ]; then
    printf 'FAIL: KernelSU Next loader is unavailable\n' > "$STATUS"
    exit 1
fi
if ! "$KSUD" insmod "$MODDIR/susfs_guard_lkm.ko" > "$STATUS" 2>&1; then
    printf 'FAIL: SUSFS load failed\n' >> "$STATUS"
    exit 1
fi
if ! sh "$MODDIR/verify-runtime.sh" >> "$STATUS" 2>&1; then
    "$KSUD" susfs unload >> "$STATUS" 2>&1
    exit 1
fi
