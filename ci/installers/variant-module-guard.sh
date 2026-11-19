#!/bin/sh
# Format 3 kernel-only installs require the target profile's exact module bytes.
set -eu
installed_release="$1"
module_list="$2"
expected_table="$3"
case "$installed_release" in
  *-onyx-@VARIANT@) ;;
  *) echo "Use the @VARIANT@ Full Recovery installer to install or switch profiles." >&2; exit 1 ;;
esac
while IFS= read -r module; do
  [ -f "$module" ] || { echo "Installed module is missing: $module" >&2; exit 1; }
  name="${module##*/}"
  if [ -f "$module.original-name" ]; then
    name="$(cat "$module.original-name")"
  fi
  case "$name" in
    ''|*[!A-Za-z0-9_.-]*) echo "Invalid installed module filename" >&2; exit 1 ;;
  esac
  expected="$(awk -v name="$name" '$2 == name { print $1 }' "$expected_table")"
  [ "${#expected}" -eq 64 ] || { echo "Installed module is absent from this build: $name" >&2; exit 1; }
  actual="$(sha256sum "$module")"
  actual="${actual%% *}"
  [ "$actual" = "$expected" ] || {
    echo "Installed module differs from the target profile/source build: $name. Use Full Recovery." >&2
    exit 1
  }
done < "$module_list"
