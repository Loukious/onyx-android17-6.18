/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Google Wonder WiFi Virtual Soft-MAC Driver
 *
 * Core definitions for the Wonder driver.
 */

#ifndef __WONDER_CORE_H__
#define __WONDER_CORE_H__

#include <linux/nl80211.h>
#include <linux/atomic.h>

#include "wondertap_internal.h"

#define DRV_NAME "wonder"
#define PDEV_NAME "wondertap0"
#define VDEV_NAME "wonder0"

/* Vendor ID and Subcommands for NL80211 Vendor Command Registration */
#define OUI_GOOGLE 0x001A11
#define WONDER_VENDOR_ID OUI_GOOGLE /* Placeholder for Google Vendor ID */

#define WONDER_2GHZ_CHANNEL 6
#define WONDER_5GHZ_CHANNEL 149
#define WONDER_JP_CHANNEL 44
#define WONDER_NORMAL_MODE_MTU_SIZE 8000

struct wonder_stats {
	atomic64_t tx_entry_cnt;
	atomic64_t tx_success_cnt;
	atomic64_t tx_skb_cloned_cnt;
	atomic64_t tx_skb_clone_fail_cnt;
	atomic64_t tx_xmit_success_cnt;
	atomic64_t tx_xmit_drop_cnt;
	atomic64_t tx_xmit_cn_cnt;
	atomic64_t tx_xmit_err_cnt;
	atomic64_t rx_entry_cnt;
	atomic64_t rx_to_mac_cnt;
};

/**
 * enum wonder_mac_algo - MAC address generation algorithms
 * @MAC_ALGO_RANDOM_MAC: Always generate a new random MAC address
 * @MAC_ALGO_FIX_MAC: Keep the existing valid MAC address, otherwise generate a random one
 * @MAC_ALGO_SMART_MAC: Smart MAC allocation (e.g., based on specific rules or reserved for future)
 * @MAC_ALGO_MAX: Upper bound for the MAC algorithms
 */
enum wonder_mac_algo {
	MAC_ALGO_RANDOM_MAC = 0,
	MAC_ALGO_FIX_MAC = 1,
	MAC_ALGO_SMART_MAC = 2,
	MAC_ALGO_MAX,
};

struct wonder_data {
	struct ieee80211_hw *hw;
	struct ieee80211_vif *vif;
	struct net_device *pdev; /* Physical network device */
	struct net_device *cdev; /* Control network device */
	struct net_device *vdev; /* Virtual network device */
	/* Vendor Abstraction */
	void *vendor_handle; /* Opaque pointer to vendor's private data */
	u8 data_version;
	enum nl80211_iftype iftype;
	unsigned int config_filters;
	bool ampdu_enable;
	bool amsdu_enable;
	bool channel_hopping_enable;
	bool ra_enable;
	u8 perf_mode;
	u32 amsdu_threshold;
	u32 amsdu_delay;
	bool syna_support_enable;
	struct wondertap_data *wondertap_data;
	struct workqueue_struct *workqueue;
	struct work_struct pdev_down_work;
	struct notifier_block netdev_notifier;
	struct delayed_work tx_work;
	struct delayed_work channel_status_report_work;
	u32 channel_status_report_interval;
	struct delayed_work channel_schedule_request_work;
	u32 channel_schedule_request_interval;
	struct wonder_stats stats;
	u8 mac_algorithm;
	u32 mac_timer_interval_minutes;
	struct delayed_work mac_expire_work;
	bool mac_expired;
};

int wonder_set_mac_algorithm(struct wonder_data *wonder, u8 val);

#endif /* __WONDER_CORE_H__ */
