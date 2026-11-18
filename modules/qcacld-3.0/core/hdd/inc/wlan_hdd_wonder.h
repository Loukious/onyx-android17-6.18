/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef WLAN_HDD_WONDER_H
#define WLAN_HDD_WONDER_H

#include <linux/types.h>

struct hdd_context;
struct hdd_adapter;
struct net_device;
struct sk_buff;
struct cdp_tx_injection_params;
struct wlan_channel;

#ifdef FEATURE_WLAN_WONDER
void hdd_wonder_register(struct hdd_context *hdd_ctx);
void hdd_wonder_unregister(struct hdd_context *hdd_ctx);
bool hdd_wonder_can_start(struct hdd_context *hdd_ctx);
bool hdd_wonder_transport_ready(struct hdd_adapter *adapter);
bool hdd_wonder_netdev_transport_ready(struct net_device *dev);
void hdd_wonder_note_rx_peer(struct net_device *dev, const struct sk_buff *skb);
bool hdd_wonder_netdev_is_owned(struct net_device *dev);
/* Nonblocking netdev admission; success transfers the skb to WMA. */
int hdd_wonder_injection_tx(struct hdd_adapter *adapter, struct sk_buff *skb,
		const struct cdp_tx_injection_params *params);
bool hdd_wonder_vdev_admission(struct hdd_adapter *adapter);
int hdd_wonder_add_monitor(struct hdd_context *hdd_ctx,
			   struct hdd_adapter **adapter, const char *name,
			   unsigned char *mac, bool *exclusive);
/* Init-only: caller holds RTNL, which pins the private provider session. */
bool hdd_wonder_get_init_channel(struct hdd_adapter *adapter,
				u32 *frequency, u32 *bandwidth);
int hdd_wonder_build_exclusive_channel(struct hdd_adapter *adapter,
				u32 frequency, u32 bandwidth,
				struct wlan_channel *channel);
#else
static inline void hdd_wonder_register(struct hdd_context *hdd_ctx) { }
static inline void hdd_wonder_unregister(struct hdd_context *hdd_ctx) { }
#endif

#endif /* WLAN_HDD_WONDER_H */
