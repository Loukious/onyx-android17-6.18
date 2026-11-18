/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef WLAN_HDD_WONDER_PEER_H
#define WLAN_HDD_WONDER_PEER_H

#include <linux/types.h>

struct hdd_adapter;
struct hdd_wonder_peer_state;
struct wlan_objmgr_psoc;
struct set_rx_mac_filter;
struct wma_wonder_helper_snapshot;
struct cdp_tx_injection_params;

#ifdef FEATURE_WLAN_WONDER
#include <wondertap.h>

struct hdd_wonder_peer_limits {
	u32 frequency;
	u32 phy_mode;
	u8 max_nss;
	enum wondertap_rate_bw bandwidth;
	bool ht_supported;
	bool vht_supported;
	bool he_supported;
};

struct hdd_wonder_peer_state *
hdd_wonder_peer_create(struct hdd_adapter *adapter);
int hdd_wonder_peer_prepare(struct hdd_wonder_peer_state *state,
			    u32 frequency, u64 generation);
/* CLEAR is submit-only. Rebinding waits for real helper deletion. */
int hdd_wonder_peer_clear(struct hdd_wonder_peer_state *state);
void hdd_wonder_peer_cancel(struct hdd_wonder_peer_state *state);
void hdd_wonder_peer_destroy(struct hdd_wonder_peer_state *state);
bool hdd_wonder_peer_ready(struct hdd_wonder_peer_state *state);
int hdd_wonder_peer_get_helper(struct hdd_wonder_peer_state *state,
			      struct wma_wonder_helper_snapshot *helper);
int hdd_wonder_peer_get_limits(struct hdd_wonder_peer_state *state,
			       struct hdd_wonder_peer_limits *limits);
int hdd_wonder_peer_validate_rate(struct hdd_wonder_peer_state *state,
				 const struct wondertap_fixed_tx_rate_params *rate);
void hdd_wonder_peer_tx_rate(struct hdd_wonder_peer_state *state,
		const u8 *destination, struct cdp_tx_injection_params *rate);
int hdd_wonder_peer_station(struct hdd_wonder_peer_state *state,
			    enum wondertap_station_action action,
			    struct wondertap_station_info *info);

/* Firmware callbacks never acquire the provider or operation mutex. */
bool hdd_wonder_peer_reply(struct wlan_objmgr_psoc *psoc, u32 id, u32 status);
bool hdd_wonder_peer_take_clear(struct wlan_objmgr_psoc *psoc, u8 id,
			       struct set_rx_mac_filter *param);
void hdd_wonder_peer_clear_result(struct wlan_objmgr_psoc *psoc, u8 id,
				 int error);
void hdd_wonder_peer_helper_deleted(struct wlan_objmgr_psoc *psoc, u8 id);
void hdd_wonder_peer_firmware_started(struct wlan_objmgr_psoc *psoc);
#endif

#endif /* WLAN_HDD_WONDER_PEER_H */
