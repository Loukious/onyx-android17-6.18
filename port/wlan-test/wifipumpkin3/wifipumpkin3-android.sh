#!/system/bin/sh
# Run from an Android root shell, outside the prepared NetHunter chroot.
# Leave an existing matching mount intact. A newly added bind mount is retained
# for subsequent launches; this helper never unmounts any filesystem.
set -eu
umask 077

KALI_ROOT=/data/local/nhsystem/kali-arm64
BPF_SOURCE=/sys/fs/bpf
BPF_TARGET=$KALI_ROOT/sys/fs/bpf

fail() { printf '%s\n' "wifipumpkin3-android: $*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage from an Android root shell:
  wifipumpkin3-android.sh check
  wifipumpkin3-android.sh prepare
  wifipumpkin3-android.sh run --ap AP_INTERFACE --upstream STA_INTERFACE -- [WFP arguments]

check verifies that Android's pinned xt_bpf programs are visible inside Kali.
prepare binds Android's bpffs into Kali only when required and the target is
empty and unmounted. The bind remains available for subsequent launches.
run prepares bpffs, then starts patched Wifipumpkin3 with --preserve-upstream.
Select the AP and upstream explicitly; prepare the AP/channel before launching.
EOF
}

# Return one exact mount's ID, device, root and filesystem type. Multiple exact
# mounts are ambiguous; refuse to cover or select between them.
mount_info() {
    mount_record=
    while IFS=' ' read -r mount_id mount_parent mount_device mount_root mount_path mount_options mount_tail; do
        [ "$mount_path" = "$1" ] || continue
        [ -z "$mount_record" ] || return 2
        mount_after=${mount_tail#*- }
        [ "$mount_after" != "$mount_tail" ] || return 2
        mount_type=${mount_after%% *}
        mount_record="$mount_id $mount_device $mount_root $mount_type"
    done < /proc/self/mountinfo
    [ -n "$mount_record" ] || return 1
    printf '%s\n' "$mount_record"
}

has_child_mount() {
    while IFS=' ' read -r child_id child_parent child_device child_root child_path child_rest; do
        case "$child_path" in "$1"/*) return 0 ;; esac
    done < /proc/self/mountinfo
    return 1
}

identity() { stat -L -c '%d:%i' "$1"; }

pins_match() {
    while IFS= read -r pin_path; do
        [ -n "$pin_path" ] || continue
        pin_android=$(identity "$pin_path") || return 1
        pin_kali=$(identity "$KALI_ROOT$pin_path" 2>/dev/null) || return 1
        [ "$pin_android" = "$pin_kali" ] || return 1
    done <<EOF
$required_pins
EOF
}

prepare_bpffs() {
    [ "$(id -u)" = 0 ] || fail "Run this helper from an Android root shell."
    [ -x "$KALI_ROOT/usr/bin/env" ] || fail "Prepare the NetHunter Kali chroot first."
    KALI_ROOT=$(readlink -f "$KALI_ROOT") || fail "Cannot resolve the NetHunter Kali root."
    [ -n "$KALI_ROOT" ] || fail "Cannot resolve the NetHunter Kali root."
    BPF_TARGET=$KALI_ROOT/sys/fs/bpf
    [ -x /system/bin/iptables-save ] || fail "Android's iptables-save is unavailable."

    # The native printer understands Android's extensions, including quota2.
    # Parse only pinned object paths; never print or rewrite the firewall rules.
    android_rules=$(/system/bin/iptables-save) || fail "Cannot inspect Android's pinned BPF rule paths."
    required_pins=
    set -f
    while IFS= read -r rule_line; do
        want_pin=false
        for rule_word in $rule_line; do
            if [ "$want_pin" = true ]; then
                case "$rule_word" in
                    "$BPF_SOURCE"/*) ;;
                    *) fail "A pinned BPF rule uses an unsupported object path." ;;
                esac
                case "$rule_word" in *[!A-Za-z0-9_./:-]*) fail "A pinned BPF path requires unsupported escaping." ;; esac
                [ "$(readlink -f "$rule_word")" = "$rule_word" ] || fail "A pinned BPF path is not canonical."
                identity "$rule_word" >/dev/null || fail "An Android pinned BPF object is missing."
                required_pins="${required_pins}${required_pins:+
}$rule_word"
                want_pin=false
            elif [ "$rule_word" = --object-pinned ]; then
                want_pin=true
            fi
        done
        [ "$want_pin" = false ] || fail "A pinned BPF rule has no object path."
    done <<EOF
$android_rules
EOF
    set +f
    if [ -z "$required_pins" ]; then
        printf '%s\n' "No current Android firewall rules require pinned BPF objects."
        return
    fi

    source_info=$(mount_info "$BPF_SOURCE") || fail "Android bpffs must have one unambiguous mount."
    IFS=' ' read -r source_id source_device source_root source_type <<EOF
$source_info
EOF
    [ "$source_type" = bpf ] && [ "$source_root" = / ] || fail "Android's BPF source is not the complete bpffs mount."
    [ "$(readlink -f "$BPF_SOURCE")" = "$BPF_SOURCE" ] || fail "Android's bpffs path is not canonical."
    has_child_mount "$BPF_SOURCE" && fail "Android bpffs has child mounts; this helper requires a single bpffs."
    [ -d "$BPF_TARGET" ] || fail "Prepare Kali's /sys mount before exposing bpffs."
    [ "$(readlink -f "$BPF_TARGET")" = "$BPF_TARGET" ] || fail "Kali's bpffs target is not canonical."

    target_info=
    if target_info=$(mount_info "$BPF_TARGET"); then
        IFS=' ' read -r target_id target_device target_root target_type <<EOF
$target_info
EOF
        [ "$target_type" = bpf ] && [ "$target_device" = "$source_device" ] &&
            [ "$target_root" = "$source_root" ] &&
            [ "$(identity "$BPF_SOURCE")" = "$(identity "$BPF_TARGET")" ] ||
            fail "Kali's bpffs target has a different existing mount."
    else
        mount_result=$?
        [ "$mount_result" = 1 ] || fail "Kali's bpffs target has ambiguous existing mounts."
    fi

    if pins_match; then
        printf '%s\n' "Android's pinned BPF programs are already visible inside Kali."
        return
    fi
    [ "$1" = prepare ] || fail "Run the prepare action to expose Android's pinned BPF programs."
    [ -z "$target_info" ] || fail "An existing bpffs mount is missing Android's pinned programs."
    has_child_mount "$BPF_TARGET" && fail "Kali's bpffs target contains existing child mounts."
    for target_entry in "$BPF_TARGET"/* "$BPF_TARGET"/.[!.]* "$BPF_TARGET"/..?*; do
        if [ -e "$target_entry" ] || [ -L "$target_entry" ]; then
            fail "Kali's bpffs target is not empty."
        fi
    done
    # Recheck immediately before the only preparation mutation.
    if mount_info "$BPF_TARGET" >/dev/null; then
        fail "Kali's bpffs target acquired a mount during preparation."
    else
        mount_result=$?
        [ "$mount_result" = 1 ] || fail "Kali's bpffs target became ambiguous."
    fi
    mount --bind "$BPF_SOURCE" "$BPF_TARGET" || fail "Cannot bind Android bpffs into Kali."
    [ "$(identity "$BPF_SOURCE")" = "$(identity "$BPF_TARGET")" ] && pins_match ||
        fail "The bind does not expose the same Android BPF objects; inspect the mount."
    printf '%s\n' "Android bpffs is now bound into Kali; the mount is retained for reuse."
}

case "${1:-}" in
    -h|--help|help|'') usage; exit 0 ;;
    check|prepare)
        action=$1
        [ "$#" = 1 ] || fail "The $action action accepts no arguments."
        prepare_bpffs "$action"
        exit 0
        ;;
    run) shift ;;
    *) usage >&2; exit 2 ;;
esac

ap_interface=
upstream_interface=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --ap)
            [ "$#" -ge 2 ] && [ -z "$ap_interface" ] || fail "Supply --ap exactly once with an interface."
            ap_interface=$2; shift 2 ;;
        --upstream)
            [ "$#" -ge 2 ] && [ -z "$upstream_interface" ] || fail "Supply --upstream exactly once with an interface."
            upstream_interface=$2; shift 2 ;;
        --) shift; break ;;
        *) fail "Use --ap and --upstream, then -- before WFP arguments." ;;
    esac
done
for interface_name in "$ap_interface" "$upstream_interface"; do
    case "$interface_name" in ''|*[!A-Za-z0-9_.:-]*) fail "Supply explicit valid AP and upstream interface names." ;; esac
    [ "${#interface_name}" -le 15 ] || fail "An interface name is too long."
    [ -r "/sys/class/net/$interface_name/ifindex" ] || fail "A selected interface does not exist."
done
[ "$ap_interface" != "$upstream_interface" ] || fail "The AP and upstream must be different interfaces."
for argument in "$@"; do
    case "$argument" in -i*|--interface|--interface=*) fail "Select interfaces with the helper's --ap and --upstream options." ;; esac
done
prepare_bpffs prepare
exec chroot "$KALI_ROOT" /usr/bin/env -u HOME -u LD_PRELOAD TMPDIR=/tmp \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    wifipumpkin3 --preserve-upstream -i "$ap_interface" -iNet "$upstream_interface" "$@"
