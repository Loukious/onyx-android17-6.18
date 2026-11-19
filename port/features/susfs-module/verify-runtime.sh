#!/system/bin/sh
KSUD=/data/adb/ksud
FEATURES=$("$KSUD" susfs features 2>&1)
if [ $? -ne 0 ]; then
    printf 'FAIL: cannot query active SUSFS features: %s\n' "$FEATURES"
    exit 1
fi
for FEATURE in SUS_PATH SUS_MOUNT SUS_KSTAT SPOOF_UNAME ENABLE_LOG HIDE_KSU_SUSFS_SYMBOLS SPOOF_CMDLINE_OR_BOOTCONFIG OPEN_REDIRECT SUS_MAP; do
    case "$FEATURES" in
        *"CONFIG_KSU_SUSFS_$FEATURE"*) ;;
        *) printf 'FAIL: required SUSFS feature %s is inactive\n' "$FEATURE"; exit 1 ;;
    esac
done
printf 'PASS: all required SUSFS feature hooks report active\n'
printf 'Behavior and app-view verification require separate device tests.\n'
