SKIPUNZIP=0
[ "$BOOTMODE" = true ] || abort 'Install this module from KernelSU Next or Magisk in Android'
[ "$(getprop ro.product.device)" = onyx ] || abort 'This module is for Onyx'
[ "$(uname -r)" = '@RELEASE@' ] || abort 'Boot the matching Onyx kernel before installing this module'
set_perm_recursive "$MODPATH" 0 0 0755 0644
for executable in service.sh firmware-overlay.sh uninstall.sh module-abi; do
  set_perm "$MODPATH/$executable" 0 0 0755
done
cd "$MODPATH" || abort 'Cannot access module files'
sha256sum -c payload.sha256 || abort 'Module payload verification failed'
while IFS= read -r driver; do
  "$MODPATH/module-abi" "$MODPATH/kernel-abi.tsv" "$MODPATH/drivers/$driver.ko" || abort "Module ABI verification failed: $driver"
done < "$MODPATH/modules.load"
MODDIR=$MODPATH
logmsg() { ui_print "- $*"; }
. "$MODPATH/firmware-overlay.sh"
fw_preflight || abort 'ROM firmware-loader path or context is unsupported'
ui_print '- Matched Realtek, Ralink and Atheros USB Wi-Fi drivers and firmware'
ui_print '- Already loaded drivers are retained; no internal Wi-Fi driver replacement'
ui_print '- Reboot to activate; disconnect/reconnect your USB adapter after boot'
