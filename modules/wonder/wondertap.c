// SPDX-License-Identifier: GPL-2.0
/*
 * Google Wonder WiFi Virtual Soft-MAC Driver
 *
 * Vendor interface implementation.
 */
#define LOG_MODULE_NAME "wondertap"
#define pr_fmt(fmt) "[wonder][wondertap] " fmt

#include <asm-generic/errno.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/etherdevice.h>
#include <wondertap.h>
#include <wondertap_monitor.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/math64.h>
#include <net/mac80211.h>

#include "wondertap_internal.h"

static bool wondertap_is_up(struct wondertap_data *wondertap)
{
	return wondertap->state == WONDERTAP_STATE_UP;
}

static void wondertap_dump_init_params(struct wondertap_init_params *params)
{
	pr_debug("========== [ Wondertap Vendor Init ] ==========\n");
	pr_debug("    Channel: Freq=%u, Bw=%u\n", params->channel.freq,
		params->channel.bandwidth);
	if (params->rate_adaptation_enable) {
		pr_debug("RA TxRate: Max Pre=%u, Max Mcs=%u, Max Bw=%u, Max Nss=%u\n",
				params->tx_rate_mask.max_preamble,
				params->tx_rate_mask.max_mcs,
				params->tx_rate_mask.max_bw,
				params->tx_rate_mask.max_nss);
	} else {
		pr_debug("    Fixed TxRate:  Pre=%u, Mcs=%u, Gi=%u, Bw=%u\n",
				params->tx_rate.preamble,
				params->tx_rate.mcs,
				params->tx_rate.gi,
				params->tx_rate.bw);
	}
	pr_debug("    Country: %.2s\n", params->country_code);
	pr_debug("    MAC: %02x:XX:XX:XX:XX:%02x\n", params->mac_addr[0],
		params->mac_addr[5]);
	pr_debug("    BSSID: %02x:XX:XX:XX:XX:%02x\n", params->bssid[0], params->bssid[5]);
	pr_debug("    Features: AMSDU %d, AMPDU %d, RA %d, CH %d\n", params->amsdu_enable,
		params->ampdu_enable, params->rate_adaptation_enable,
		params->channel_hopping_enable);
	pr_debug("    Notify: Perf Mode %d\n", params->perf_mode);
	pr_debug("===============================================\n");
}

int wondertap_replay_channel_schedule_locked(struct wondertap_data *wondertap,
					   bool first_start)
{
	struct channel_schedule_request schedule = wondertap->cached_channel_schedule;
	struct wondertap_capability caps = { 0 };
	u64 sampled_ns = 0, elapsed_us, now_ns;
	s64 replay_window_us;
	u32 mac_tsf = 0, elapsed_tsf_us;
	int ret;

	lockdep_assert_held(&wondertap->lock);
	if (!schedule.channel_list_len ||
	    !wondertap->init_params.channel_hopping_enable)
		return 0;
	if (!wondertap_is_up(wondertap) || !wondertap->vendor_handle)
		return -ENODEV;
	if (!wondertap->wonder_ops || !wondertap->wonder_ops->channel_schedule_request)
		return -EOPNOTSUPP;
	ret = wondertap_get_capabilities(wondertap, &caps);
	if (ret)
		return ret;
	if (!caps.bits.channel_hopping)
		return -EOPNOTSUPP;

	if (first_start) {
		/* A request cached while DOWN has no live TSF anchor yet. Only
		 * this initial application chooses a target from an actual sample.
		 */
		if (caps.maximum_channel_switch_time_us > INT_MAX)
			return -ERANGE;
		sampled_ns = ktime_get_boottime_ns();
		ret = wondertap_get_mac_tsf(wondertap, &mac_tsf);
		if (ret)
			return ret;
		schedule.target_switch_time_tsf = mac_tsf + caps.maximum_channel_switch_time_us;
	} else {
		/* The monitor provider first proves continuity of its real TSF
		 * clock across PM. Keep the accepted anchor and phase; reject an
		 * anchor too old to resolve safely through the shared 32-bit ABI.
		 */
		if (!wondertap->channel_schedule_accepted)
			return -ESTALE;
		now_ns = ktime_get_boottime_ns();
		if (now_ns < wondertap->channel_schedule_accepted_boottime_ns)
			return -ESTALE;
		elapsed_us = div_u64(now_ns - wondertap->channel_schedule_accepted_boottime_ns,
				     NSEC_PER_USEC);
		replay_window_us = (s64)INT_MAX + wondertap->channel_schedule_target_delta_us;
		if (replay_window_us < 0 || elapsed_us > INT_MAX ||
		    elapsed_us > (u64)replay_window_us)
			return -ESTALE;
		ret = wondertap_get_mac_tsf(wondertap, &mac_tsf);
		if (ret)
			return ret;
		elapsed_tsf_us = mac_tsf - (schedule.target_switch_time_tsf -
					   (u32)wondertap->channel_schedule_target_delta_us);
		if (elapsed_tsf_us > INT_MAX ||
		    (s64)wondertap->channel_schedule_target_delta_us - elapsed_tsf_us < -INT_MAX)
			return -ESTALE;
	}

	ret = wondertap->wonder_ops->channel_schedule_request(wondertap->vendor_handle,
							      &schedule);
	if (ret)
		return ret;
	if (first_start) {
		wondertap->cached_channel_schedule.target_switch_time_tsf =
			schedule.target_switch_time_tsf;
		wondertap->channel_schedule_accepted_boottime_ns = sampled_ns;
		wondertap->channel_schedule_target_delta_us =
			(s32)(schedule.target_switch_time_tsf - mac_tsf);
		wondertap->channel_schedule_accepted = true;
	}
	return 0;
}

int wondertap_init(struct wondertap_data *wondertap, const struct wondertap_init_params *_params)
{
	struct wondertap_init_params params = {};
	bool initialized_this_call = false;
	int ret = -EOPNOTSUPP;
	int retry;

	mutex_lock(&wondertap->lock);
	if (wondertap_is_up(wondertap)) {
		pr_warn("Already initialized\n");
		ret = -EBUSY;
		goto out;
	}

	if (!((wondertap->cache_flags & WONDERTAP_CACHE_FREQ_SET) &&
		(wondertap->cache_flags & WONDERTAP_CACHE_TX_RATE_SET) &&
		(wondertap->cache_flags & WONDERTAP_CACHE_BSSID_SET) &&
		(wondertap->cache_flags & WONDERTAP_CACHE_COUNTRY_CODE_SET))) {
		pr_err("Init failed: Missing cached settings. flags=0x%x\n",
						wondertap->cache_flags);
		ret = -EINVAL;
		goto out;
	}

	if (is_valid_ether_addr(_params->mac_addr))
		ether_addr_copy(wondertap->mac_addr, _params->mac_addr);
	else
		eth_random_addr(wondertap->mac_addr);

	params.channel = wondertap->cached_freq;
	params.tx_rate = wondertap->cached_tx_rate;
	ether_addr_copy(params.bssid, wondertap->cached_bssid);
	ether_addr_copy(params.mac_addr, wondertap->mac_addr);
	memcpy(params.country_code, wondertap->cached_country_code,
	       sizeof(wondertap->cached_country_code));

	params.rate_adaptation_enable = _params->rate_adaptation_enable;
	if (_params->rate_adaptation_enable) {
		params.tx_rate_mask.max_preamble = wondertap->cached_tx_rate.preamble;
		params.tx_rate_mask.max_bw = wondertap->cached_tx_rate.bw;
		params.tx_rate_mask.max_nss = wondertap->cached_tx_rate.nss;
		params.tx_rate_mask.max_mcs = wondertap->cached_tx_rate.mcs;
	}

	params.channel_hopping_enable = _params->channel_hopping_enable;
	params.ampdu_enable = _params->ampdu_enable;
	params.amsdu_enable = _params->amsdu_enable;
	params.perf_mode = _params->perf_mode;

	wondertap_dump_init_params(&params);
	for (retry = 0; retry <= WONDER_INIT_RETRY_CNT; retry++) {

		if (!wondertap->wonder_ops || !wondertap->wonder_ops->init ||
		    !wondertap->wonder_ops->deinit) {
			pr_err("Vendor init/deinit operations must be supplied as a pair\n");
			ret = -EOPNOTSUPP;
			goto out;
		}

		ret = wondertap->wonder_ops->init(&wondertap->vendor_handle, &params);
		if (ret == 0)
			break;

		if (retry < WONDER_INIT_RETRY_CNT) {
			pr_warn(
				"Vendor init failed: %d. Retrying in %d ms...(retry %d)\n",
				ret, WONDER_INIT_RETRY_WAIT, retry + 1);
			msleep(WONDER_INIT_RETRY_WAIT);
		}
	}

	if (ret == 0) {
		initialized_this_call = true;
		wondertap->state = WONDERTAP_STATE_UP;
		wondertap->init_params = params;
		pr_debug("Vendor init successful. State set to UP.\n");

		ret = wondertap_replay_channel_schedule_locked(wondertap, true);
		if (ret)
			goto out;
	} else {
		pr_err("Vendor init failed: %d\n", ret);
		goto out;
	}

out:
	if (ret && initialized_this_call) {
		struct wondertap_deinit_params deinit = { 0 };

		memcpy(deinit.country_code, params.country_code, sizeof(deinit.country_code));
		if (wondertap->wonder_ops->deinit)
			wondertap->wonder_ops->deinit(wondertap->vendor_handle, &deinit);
		wondertap->vendor_handle = NULL;
		wondertap->state = WONDERTAP_STATE_DOWN;
	}
	mutex_unlock(&wondertap->lock);
	return ret;
}

void wondertap_deinit(struct wondertap_data *wondertap)
{
	struct wondertap_deinit_params params;
	int i;

	mutex_lock(&wondertap->lock);

	/* Auto-flush active stations on interface deinit / shutdown */
	if (wondertap->vendor_handle && wondertap->wonder_ops &&
	    wondertap->wonder_ops->set_station_info) {
		for (i = 0; i < WONDERTAP_MAX_STATION_TABLE_SIZE; i++) {
			if (wondertap->station_table[i].in_use) {
				struct wondertap_station_info *info =
					&wondertap->station_table[i].info;

				pr_debug("%s: Auto-flushing station slot %d MAC %pM AID %u\n",
					__func__, i, info->mac, info->aid);
				wondertap->wonder_ops->set_station_info(
					wondertap->vendor_handle,
					WONDERTAP_STATION_STATE_DEL,
					info);
				wondertap->station_table[i].in_use = false;
				memset(info, 0, sizeof(*info));
			}
		}
	}

	if (wondertap->vendor_handle && wondertap->wonder_ops && wondertap->wonder_ops->deinit) {
		memset(&params, 0, sizeof(params));
		memcpy(params.country_code, wondertap->cached_country_code,
		       sizeof(wondertap->cached_country_code));
		pr_debug("========== [ Wondertap Vendor Deinit ] ==========\n");
		pr_debug("    Country: %.2s\n", params.country_code);
		pr_debug("=================================================\n");
		wondertap->wonder_ops->deinit(wondertap->vendor_handle, &params);
		wondertap->vendor_handle = NULL;
	} else if (!wondertap->wonder_ops || !wondertap->wonder_ops->deinit) {
		pr_err("Vendor operation 'deinit' is not implemented\n");
	}

	kfree(wondertap->cached_channel_schedule.channel_list);
	memset(&wondertap->cached_channel_schedule, 0, sizeof(wondertap->cached_channel_schedule));
	wondertap->channel_schedule_accepted = false;
	wondertap->channel_schedule_accepted_boottime_ns = 0;
	wondertap->channel_schedule_target_delta_us = 0;

	wondertap->state = WONDERTAP_STATE_DOWN;
	WRITE_ONCE(wondertap->monitor_pm_suspended, false);
	wondertap->monitor_pm_resume_pending = false;
	mutex_unlock(&wondertap->lock);
}

int wondertap_set_freq(struct wondertap_data *wondertap,
		       const struct wondertap_set_freq_params *params)
{
	int ret = -EOPNOTSUPP;
	unsigned long flags;

	mutex_lock(&wondertap->lock);
	if (READ_ONCE(wondertap->monitor_pm_suspended)) {
		ret = -EHOSTDOWN;
		goto out_unlock;
	}
	if (wondertap_is_up(wondertap)) {
		if (wondertap->wonder_ops && wondertap->wonder_ops->set_freq) {
			ret = wondertap->wonder_ops->set_freq(wondertap->vendor_handle, params);
		} else {
			pr_err("Vendor operation 'set_freq' is not implemented\n");
			ret = -EOPNOTSUPP;
		}
	} else {
		pr_warn("wondertap is not active; caching incoming channel settings.\n");
		ret = 0;
	}
	if (!ret) {
		spin_lock_irqsave(&wondertap->tx_config_lock, flags);
		wondertap->cached_freq = *params;
		spin_unlock_irqrestore(&wondertap->tx_config_lock, flags);
		wondertap->cache_flags |= WONDERTAP_CACHE_FREQ_SET;
		if (wondertap->monitor_backend) {
			kfree(wondertap->cached_channel_schedule.channel_list);
			memset(&wondertap->cached_channel_schedule, 0,
			       sizeof(wondertap->cached_channel_schedule));
			wondertap->channel_schedule_accepted = false;
			wondertap->channel_schedule_accepted_boottime_ns = 0;
			wondertap->channel_schedule_target_delta_us = 0;
		}
	}

out_unlock:
	mutex_unlock(&wondertap->lock);
	return ret;
}

int wondertap_set_filter(struct wondertap_data *wondertap,
			 enum wondertap_filter_type filter_type, const void *params)
{
	const struct wondertap_frame_filter_params *filter = params;
	unsigned long flags;
	int ret = 0;

	if (!params)
		return -EINVAL;
	if (wondertap->monitor_backend && filter_type != WONDERTAP_FILTER_TYPE_FRAME)
		return -EINVAL;
	if (wondertap->monitor_backend && filter->enabled &&
	    ((filter->frame_type & ~IEEE80211_FCTL_FTYPE) ||
	     (filter->frame_subtype & ~IEEE80211_FCTL_STYPE) ||
	     filter->frame_type == IEEE80211_FCTL_FTYPE))
		return -EINVAL;
	mutex_lock(&wondertap->lock);
	if (READ_ONCE(wondertap->monitor_pm_suspended)) {
		ret = -EHOSTDOWN;
		goto unlock;
	}
	if (wondertap_is_up(wondertap)) {
		if (!wondertap->wonder_ops || !wondertap->wonder_ops->set_filter)
			ret = -EOPNOTSUPP;
		else
			ret = wondertap->wonder_ops->set_filter(wondertap->vendor_handle, filter_type, params);
	} else if (!wondertap->monitor_backend) {
		ret = -ENODEV;
	}
	if (!ret && filter_type == WONDERTAP_FILTER_TYPE_FRAME) {
		spin_lock_irqsave(&wondertap->tx_config_lock, flags);
		wondertap->cached_frame_filter = *filter;
		spin_unlock_irqrestore(&wondertap->tx_config_lock, flags);
	}
unlock:
	mutex_unlock(&wondertap->lock);
	return ret;
}

int wondertap_set_fixed_tx_rate(struct wondertap_data *wondertap,
				const struct wondertap_fixed_tx_rate_params *params)
{
	int ret = -EOPNOTSUPP;
	unsigned long flags;

	if (wondertap->monitor_backend) {
		ret = wondertap_monitor_validate_rate(params);
		if (ret)
			return ret;
	}

	mutex_lock(&wondertap->lock);
	if (READ_ONCE(wondertap->monitor_pm_suspended)) {
		ret = -EHOSTDOWN;
		goto out_unlock;
	}
	if (wondertap_is_up(wondertap)) {
		if (wondertap->wonder_ops && wondertap->wonder_ops->set_fixed_tx_rate) {
			ret = wondertap->wonder_ops->set_fixed_tx_rate(wondertap->vendor_handle,
								       params);
		} else {
			pr_err("Vendor operation 'set_fixed_tx_rate' is not implemented\n");
			ret = -EOPNOTSUPP;
		}
	} else {
		pr_warn("wondertap is not active; caching incoming fixed TX rate settings.\n");
		ret = 0;
	}
	if (!ret) {
		spin_lock_irqsave(&wondertap->tx_config_lock, flags);
		wondertap->cached_tx_rate = *params;
		spin_unlock_irqrestore(&wondertap->tx_config_lock, flags);
		wondertap->cache_flags |= WONDERTAP_CACHE_TX_RATE_SET;
	}

out_unlock:
	mutex_unlock(&wondertap->lock);
	return ret;
}

int wondertap_set_tx_rate_mask(struct wondertap_data *wondertap,
			       const struct wondertap_tx_rate_mask_params *params)
{
	int ret = -EOPNOTSUPP;

	if (wondertap->monitor_backend)
		return -EOPNOTSUPP;

	mutex_lock(&wondertap->lock);
	wondertap->cached_tx_rate.preamble = params->max_preamble;
	wondertap->cached_tx_rate.mcs = params->max_mcs;
	wondertap->cached_tx_rate.bw = params->max_bw;
	wondertap->cached_tx_rate.nss = params->max_nss;
	wondertap->cached_tx_rate.gi = WONDERTAP_RATE_GI_DEFAULT;
	wondertap->cache_flags |= WONDERTAP_CACHE_TX_RATE_SET;
	if (wondertap_is_up(wondertap)) {
		if (wondertap->wonder_ops && wondertap->wonder_ops->set_tx_rate_mask) {
			ret = wondertap->wonder_ops->set_tx_rate_mask(wondertap->vendor_handle,
								      params);
		} else {
			pr_err("Vendor operation 'set_tx_rate_mask' is not implemented\n");
			ret = -EOPNOTSUPP;
		}
	} else {
		pr_warn("wondertap is not active; caching incoming TX rate settings.\n");
		ret = 0;
	}

	mutex_unlock(&wondertap->lock);
	return ret;
}

int wondertap_set_reg(struct wondertap_data *wondertap, const char *country_code)
{
	int ret = 0;

	if (!country_code || !country_code[0] || !country_code[1] || country_code[2])
		return -EINVAL;
	mutex_lock(&wondertap->lock);
	if (READ_ONCE(wondertap->monitor_pm_suspended))
		ret = -EHOSTDOWN;
	else if (wondertap->monitor_backend && wondertap_is_up(wondertap) &&
		 memcmp(wondertap->cached_country_code, country_code, 2))
		ret = -EOPNOTSUPP;
	else {
		memcpy(wondertap->cached_country_code, country_code,
		       sizeof(wondertap->cached_country_code));
		wondertap->cache_flags |= WONDERTAP_CACHE_COUNTRY_CODE_SET;
	}
	mutex_unlock(&wondertap->lock);
	return ret;
}

int wondertap_get_mac_tsf(struct wondertap_data *wondertap, u32 *mac_tsf)
{
	if (wondertap->wonder_ops && wondertap->wonder_ops->get_mac_tsf)
		return wondertap->wonder_ops->get_mac_tsf(wondertap->vendor_handle, mac_tsf);

	pr_err("Vendor operation 'get_mac_tsf' is not implemented\n");
	return -EOPNOTSUPP;
}

int wondertap_get_capabilities(struct wondertap_data *wondertap,
			       struct wondertap_capability *features)
{
	if (wondertap->wonder_ops && wondertap->wonder_ops->get_capabilities)
		return wondertap->wonder_ops->get_capabilities(wondertap->vendor_handle,
								features);

	pr_err("Vendor operation 'get_capabilities' is not implemented\n");
	return -EOPNOTSUPP;
}

int wondertap_get_interface_mac_address(struct wondertap_data *wondertap, u8 (*mac_addr)[ETH_ALEN])
{
	int ret = -EOPNOTSUPP;

	mutex_lock(&wondertap->lock);
	if (wondertap_is_up(wondertap)) {
		memcpy(*mac_addr, wondertap->mac_addr, sizeof(u8) * ETH_ALEN);
		ret = 0;
	} else {
		pr_err("wondertap is invalid or not up.\n");
		ret = -ENODEV;
	}

	mutex_unlock(&wondertap->lock);
	return ret;
}

int wondertap_set_bssid_filter(struct wondertap_data *wondertap, const u8 *bssid)
{
	int ret = 0;

	mutex_lock(&wondertap->lock);
	if (READ_ONCE(wondertap->monitor_pm_suspended)) {
		ret = -EHOSTDOWN;
		goto unlock;
	}
	memcpy(wondertap->cached_bssid, bssid, sizeof(u8) * ETH_ALEN);
	wondertap->cache_flags |= WONDERTAP_CACHE_BSSID_SET;
	pr_warn("Caching incoming BSSID filter settings.\n");
unlock:
	mutex_unlock(&wondertap->lock);
	return ret;
}

int wondertap_channel_schedule_request(struct wondertap_data *wondertap,
				       const struct channel_schedule_request *request)
{
	struct channel_schedule_request next;
	struct wondertap_channel_list_params *old;
	u64 sampled_ns = 0;
	u32 mac_tsf = 0;
	bool accepted = false;
	int i, ret = 0;

	if (!request || (request->channel_list_len &&
	    (!request->channel_list || !request->dwell_time_tu ||
	     request->next_channel_index >= request->channel_list_len)))
		return -EINVAL;
	next = *request;
	next.channel_list = NULL;
	for (i = 0; i < request->channel_list_len; i++) {
		if ((u32)request->channel_list[i].role >= WONDERTAP_ROLE_MAX ||
		    (u32)request->channel_list[i].bandwidth > WONDERTAP_RATE_BW_80)
			return -EINVAL;
	}
	if (request->channel_list_len) {
		next.channel_list = kmemdup(request->channel_list,
			request->channel_list_len * sizeof(*next.channel_list), GFP_KERNEL);
		if (!next.channel_list)
			return -ENOMEM;
	}
	mutex_lock(&wondertap->lock);
	if (READ_ONCE(wondertap->monitor_pm_suspended)) {
		ret = -EHOSTDOWN;
		goto unlock;
	}
	if (wondertap_is_up(wondertap)) {
		if (!wondertap->wonder_ops || !wondertap->wonder_ops->channel_schedule_request) {
			ret = -EOPNOTSUPP;
			goto unlock;
		}
		if (next.channel_list_len) {
			sampled_ns = ktime_get_boottime_ns();
			ret = wondertap_get_mac_tsf(wondertap, &mac_tsf);
			if (ret)
				goto unlock;
		}
		/* An empty list is a real cancellation request, including at the vendor. */
		ret = wondertap->wonder_ops->channel_schedule_request(wondertap->vendor_handle, &next);
		if (ret)
			goto unlock;
		accepted = next.channel_list_len != 0;
	}
	old = wondertap->cached_channel_schedule.channel_list;
	wondertap->cached_channel_schedule = next;
	wondertap->channel_schedule_accepted = accepted;
	wondertap->channel_schedule_accepted_boottime_ns = accepted ? sampled_ns : 0;
	wondertap->channel_schedule_target_delta_us =
		accepted ? (s32)(next.target_switch_time_tsf - mac_tsf) : 0;
	next.channel_list = NULL;
	kfree(old);
unlock:
	mutex_unlock(&wondertap->lock);
	kfree(next.channel_list);
	return ret;
}

int wondertap_get_channel_status_report(struct wondertap_data *wondertap,
				    struct wondertap_channel_status_report *report)
{
	int ret = 0;
	struct channel_schedule_request *cached_schedule = &wondertap->cached_channel_schedule;

	mutex_lock(&wondertap->lock);
	if (READ_ONCE(wondertap->monitor_pm_suspended)) {
		ret = -EHOSTDOWN;
		goto out_unlock;
	}

	if (!wondertap_is_up(wondertap)) {
		pr_warn("wondertap is inactive.\n");
		ret = -ENODEV;
		goto out_unlock;
	}

	if (!wondertap->wonder_ops || !wondertap->wonder_ops->get_channel_status_report) {
		pr_warn("wondertap ops is not supported.\n");
		ret = -EOPNOTSUPP;
		goto out_unlock;
	}

	if (!wondertap->cap.bits.channel_hopping ||
		!wondertap->init_params.channel_hopping_enable) {
		pr_warn("channel hopping is not enabled.\n");
		ret = -EOPNOTSUPP;
		goto out_unlock;
	}

	if (report->channel_status_len != cached_schedule->channel_list_len) {
		pr_warn("channel list len is not matched (%d, %d).\n",
			report->channel_status_len, cached_schedule->channel_list_len);
		ret = -EINVAL;
		goto out_unlock;
	}

	ret = wondertap->wonder_ops->get_channel_status_report(wondertap->vendor_handle, report);

	if (ret)
		pr_err("Get channel status report failed %d.\n", ret);

out_unlock:
	mutex_unlock(&wondertap->lock);
	return ret;
}

int wondertap_set_station_info(struct wondertap_data *wondertap,
		const enum wondertap_station_action action,
		struct wondertap_station_info *info)
{
	int ret = 0;
	int i, free_slot = -1;

	mutex_lock(&wondertap->lock);
	if (READ_ONCE(wondertap->monitor_pm_suspended)) {
		ret = -EHOSTDOWN;
		goto out_unlock;
	}

	if (!wondertap_is_up(wondertap)) {
		pr_warn("wondertap is inactive.\n");
		ret = -ENODEV;
		goto out_unlock;
	}

	if (!wondertap->wonder_ops || !wondertap->wonder_ops->set_station_info) {
		pr_warn("wondertap ops is not supported.\n");
		ret = -EOPNOTSUPP;
		goto out_unlock;
	}

	ret = wondertap->wonder_ops->set_station_info(
		wondertap->vendor_handle, action, info);

	if (ret == 0 && info) {
		if (action == WONDERTAP_STATION_STATE_NEW) {
			for (i = 0; i < WONDERTAP_MAX_STATION_TABLE_SIZE; i++) {
				if (wondertap->station_table[i].in_use &&
				    ether_addr_equal(wondertap->station_table[i].info.mac,
						     info->mac)) {
					wondertap->station_table[i].info = *info;
					free_slot = -2;
					break;
				}
				if (!wondertap->station_table[i].in_use &&
				    free_slot == -1) {
					free_slot = i;
				}
			}
			if (free_slot >= 0) {
				wondertap->station_table[free_slot].in_use = true;
				wondertap->station_table[free_slot].info = *info;
			}
		} else if (action == WONDERTAP_STATION_STATE_UPDATE) {
			for (i = 0; i < WONDERTAP_MAX_STATION_TABLE_SIZE; i++) {
				if (wondertap->station_table[i].in_use &&
				    ether_addr_equal(wondertap->station_table[i].info.mac,
						     info->mac)) {
					wondertap->station_table[i].info = *info;
					break;
				}
			}
		} else if (action == WONDERTAP_STATION_STATE_DEL) {
			for (i = 0; i < WONDERTAP_MAX_STATION_TABLE_SIZE; i++) {
				if (wondertap->station_table[i].in_use &&
				    ether_addr_equal(wondertap->station_table[i].info.mac,
						     info->mac)) {
					wondertap->station_table[i].in_use = false;
					memset(&wondertap->station_table[i].info, 0,
					       sizeof(struct wondertap_station_info));
					break;
				}
			}
		}
	}

out_unlock:
	mutex_unlock(&wondertap->lock);
	return ret;
}
