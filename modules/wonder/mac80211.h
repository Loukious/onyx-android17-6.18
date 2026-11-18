/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Google Wonder WiFi Virtual Soft-MAC Driver
 *
 * Shared definitions and function prototypes for the Wonder driver.
 */

#ifndef __WONDER_MAC80211_H__
#define __WONDER_MAC80211_H__

#include <net/mac80211.h>
#include <net/cfg80211.h>
#include <net/ieee80211_radiotap.h>
#include "core.h"

extern char *physical_name;
extern struct ieee80211_supported_band wonder_band_2ghz;
extern struct ieee80211_supported_band wonder_band_5ghz;

void *wonder_mac80211_init(struct device *dev, struct wondertap_data *wondertap);
void wonder_mac80211_exit(struct wonder_data *wonder);
#ifdef CONFIG_DEBUG_FS
int wonder_debugfs_init(struct wonder_data *wonder);
void wonder_debugfs_exit(struct wonder_data *wonder);
#else
static inline int wonder_debugfs_init(struct wonder_data *wonder) {}
static inline void wonder_debugfs_exit(struct wonder_data *wonder) {}
#endif
int wonder_features_init(struct wonder_data *wonder);
void wonder_features_exit(struct wonder_data *wonder);

#endif /* __WONDER_MAC80211_H__ */
