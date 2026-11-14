#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Sourced by the external Wi-Fi loader and uninstaller. Never changes the ROM
# firmware tree or firmware_class.path: bind a complete, labelled copy instead.

fw_context() {
  ls -Zd "$1" 2>/dev/null | awk '$1 ~ /^u:object_r:[A-Za-z0-9_]+:s0$/ { print $1; exit }'
}

fw_owned() {
  [ -d "$MODDIR/firmware-overlay" ] && [ -d "$1" ] || return 1
  local fw_source_id fw_target_id
  fw_source_id=$(stat -c '%d:%i' "$MODDIR/firmware-overlay" 2>/dev/null) || return 1
  fw_target_id=$(stat -c '%d:%i' "$1" 2>/dev/null) || return 1
  [ -n "$fw_source_id" ] && [ "$fw_source_id" = "$fw_target_id" ]
}

fw_select_target() {
  local fw_paths fw_candidate fw_saved_ifs
  fw_paths=$(cat /sys/module/firmware_class/parameters/path 2>/dev/null) || return 1
  fw_saved_ifs=$IFS
  IFS=,
  for fw_candidate in $fw_paths; do
    case "$fw_candidate" in
      /odm/firmware|/odm/firmware/*|/vendor/firmware|/vendor/firmware/*|/lib/firmware|/lib/firmware/*)
        if [ -d "$fw_candidate" ]; then
          IFS=$fw_saved_ifs
          printf '%s\n' "$fw_candidate"
          return 0
        fi ;;
    esac
  done
  IFS=$fw_saved_ifs
  # This is a real direct-loader default, unlike Android's ueventd paths.
  [ -d /lib/firmware ] || return 1
  printf '%s\n' /lib/firmware
}

fw_copy_contexts() {
  local fw_original=$1 fw_copy=$2 fw_label fw_child
  fw_label=$(fw_context "$fw_original")
  [ -n "$fw_label" ] || return 1
  chcon -h "$fw_label" "$fw_copy" || return 1
  [ "$(fw_context "$fw_copy")" = "$fw_label" ] || return 1
  if [ -d "$fw_original" ] && [ ! -L "$fw_original" ]; then
    for fw_child in "$fw_original"/* "$fw_original"/.[!.]* "$fw_original"/..?*; do
      [ -e "$fw_child" ] || [ -L "$fw_child" ] || continue
      fw_copy_contexts "$fw_child" "$fw_copy/${fw_child##*/}" || return 1
    done
  fi
}

fw_preflight() {
  FW_TARGET=$(fw_select_target) || { logmsg 'No accessible direct firmware-loader directory'; return 1; }
  FW_CONTEXT=$(fw_context "$FW_TARGET")
  [ -n "$FW_CONTEXT" ] || { logmsg 'Cannot determine ROM firmware SELinux context'; return 1; }
}

fw_prepare() {
  local fw_stage="$MODDIR/.firmware-overlay.pending" fw_rel fw_parent fw_destination fw_file_context
  fw_preflight || return 1
  if fw_owned "$FW_TARGET"; then
    # Re-execution must neither stack another bind nor copy the overlay onto itself.
    while IFS= read -r fw_rel; do
      cmp -s "$MODDIR/firmware/$fw_rel" "$FW_TARGET/$fw_rel" || return 1
    done < "$MODDIR/firmware.paths"
    printf '%s\n' "$FW_TARGET" > "$MODDIR/firmware-mount-target" || return 1
    logmsg 'Matched firmware overlay is already active'
    return 0
  fi
  rm -rf "$fw_stage" || return 1
  mkdir -p "$fw_stage" || return 1
  cp -a "$FW_TARGET/." "$fw_stage/" || return 1
  fw_copy_contexts "$FW_TARGET" "$fw_stage" || return 1
  chmod 0755 "$fw_stage" || return 1
  while IFS= read -r fw_rel; do
    case "$fw_rel" in
      rt2870.bin|rtlwifi/*.bin|ath9k_htc/*.fw) ;;
      *) logmsg 'Unexpected firmware filename'; return 1 ;;
    esac
    fw_parent=${fw_rel%/*}
    fw_file_context=$FW_CONTEXT
    if [ "$fw_parent" != "$fw_rel" ]; then
      # Existing symlinks must never lead a copy out of the staged tree.
      [ ! -L "$fw_stage/$fw_parent" ] || { logmsg "Firmware directory is a ROM symlink: $fw_parent"; return 1; }
      if [ -e "$fw_stage/$fw_parent" ]; then
        [ -d "$fw_stage/$fw_parent" ] || return 1
      else
        mkdir -p "$fw_stage/$fw_parent" || return 1
        chmod 0755 "$fw_stage/$fw_parent" || return 1
        chown 0:0 "$fw_stage/$fw_parent" || return 1
        chcon "$FW_CONTEXT" "$fw_stage/$fw_parent" || return 1
      fi
      fw_file_context=$(fw_context "$fw_stage/$fw_parent")
      [ -n "$fw_file_context" ] || return 1
    fi
    fw_destination="$fw_stage/$fw_rel"
    [ ! -L "$fw_destination" ] || { logmsg "Firmware file is a ROM symlink: $fw_rel"; return 1; }
    if [ -e "$fw_destination" ]; then
      [ -f "$fw_destination" ] && cmp -s "$MODDIR/firmware/$fw_rel" "$fw_destination" || {
        logmsg "Firmware filename conflicts with the ROM: $fw_rel"; return 1;
      }
      fw_file_context=$(fw_context "$fw_destination")
      [ -n "$fw_file_context" ] || return 1
    else
      cp "$MODDIR/firmware/$fw_rel" "$fw_destination" || return 1
      chown 0:0 "$fw_destination" || return 1
      chmod 0644 "$fw_destination" || return 1
      chcon "$fw_file_context" "$fw_destination" || return 1
    fi
    [ "$(fw_context "$fw_destination")" = "$fw_file_context" ] || return 1
  done < "$MODDIR/firmware.paths"
  rm -rf "$MODDIR/firmware-overlay" || return 1
  mv "$fw_stage" "$MODDIR/firmware-overlay" || return 1
  # Persist ownership before mounting, so a full /data filesystem cannot leave
  # an active bind which the uninstaller cannot locate.
  printf '%s\n' "$FW_TARGET" > "$MODDIR/firmware-mount-target" || return 1
  mount -o bind "$MODDIR/firmware-overlay" "$FW_TARGET" || {
    logmsg 'Firmware bind mount failed'; return 1;
  }
  if ! fw_owned "$FW_TARGET" || ! mount -o remount,bind,ro "$FW_TARGET"; then
    fw_owned "$FW_TARGET" && umount "$FW_TARGET"
    logmsg 'Cannot verify a read-only firmware bind mount'
    return 1
  fi
  logmsg "Firmware is available at the existing loader path $FW_TARGET"
}

fw_release() {
  local fw_target
  [ -f "$MODDIR/firmware-mount-target" ] || return 0
  fw_target=$(cat "$MODDIR/firmware-mount-target") || return 1
  if fw_owned "$fw_target"; then
    umount "$fw_target" || { logmsg 'Firmware overlay is busy; reboot to remove it'; return 1; }
    logmsg 'Removed this module firmware overlay'
  else
    logmsg 'Firmware mount belongs to another source; leaving it in place'
  fi
}
