# SPDX-License-Identifier: GPL-2.0-only
# Product configuration: copy firmware before Android freezes its file lists.
# Onyx enables firmware_class sysfs fallback, and ueventd searches /vendor/firmware.
ONYX_USB_WIFI_FIRMWARE_ROOT := $(dir $(lastword $(MAKEFILE_LIST)))../firmware
ONYX_USB_WIFI_FIRMWARE_FILES := \
    ath9k_htc/htc_7010-1.4.0.fw \
    ath9k_htc/htc_9271-1.4.0.fw \
    rt2870.bin \
    rtlwifi/rtl8188eufw.bin \
    rtlwifi/rtl8188fufw.bin \
    rtlwifi/rtl8192cufw_A.bin \
    rtlwifi/rtl8192cufw_B.bin \
    rtlwifi/rtl8192cufw_TMSC.bin \
    rtlwifi/rtl8192eu_nic.bin \
    rtlwifi/rtl8192fufw.bin \
    rtlwifi/rtl8710bufw_SMIC.bin \
    rtlwifi/rtl8710bufw_UMC.bin \
    rtlwifi/rtl8723aufw_A.bin \
    rtlwifi/rtl8723aufw_B.bin \
    rtlwifi/rtl8723aufw_B_NoBT.bin \
    rtlwifi/rtl8723bu_nic.bin

PRODUCT_COPY_FILES += $(foreach firmware,$(ONYX_USB_WIFI_FIRMWARE_FILES),\
    $(ONYX_USB_WIFI_FIRMWARE_ROOT)/firmware/$(firmware):$(TARGET_COPY_OUT_VENDOR)/firmware/$(firmware))

# Redistribute the original licenses, manifest and matching ATH firmware source.
ONYX_USB_WIFI_FIRMWARE_NOTICE_ROOT := $(TARGET_COPY_OUT_VENDOR)/etc/firmware-notices/onyx-usb-wifi
PRODUCT_COPY_FILES += \
    $(ONYX_USB_WIFI_FIRMWARE_ROOT)/README.md:$(ONYX_USB_WIFI_FIRMWARE_NOTICE_ROOT)/README.md \
    $(ONYX_USB_WIFI_FIRMWARE_ROOT)/manifest.json:$(ONYX_USB_WIFI_FIRMWARE_NOTICE_ROOT)/manifest.json \
    $(call find-copy-subdir-files,*,$(ONYX_USB_WIFI_FIRMWARE_ROOT)/licenses,$(ONYX_USB_WIFI_FIRMWARE_NOTICE_ROOT)/licenses) \
    $(call find-copy-subdir-files,*,$(ONYX_USB_WIFI_FIRMWARE_ROOT)/sources,$(ONYX_USB_WIFI_FIRMWARE_NOTICE_ROOT)/sources)
