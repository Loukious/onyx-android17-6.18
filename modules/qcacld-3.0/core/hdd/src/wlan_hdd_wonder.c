// SPDX-License-Identifier: GPL-2.0-only
/* Experimental Wonder provider for Onyx's existing ICNSS2 WLAN transport. */
#include <linux/auxiliary_bus.h>
#include <linux/etherdevice.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rtnetlink.h>
#include <linux/rcupdate.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <net/cfg80211.h>
#include <wondertap.h>
#include <wondertap_monitor.h>
#include <wlan_hdd_includes.h>
#include <wlan_hdd_main.h>
#include <wlan_hdd_wonder.h>
#include <wlan_hdd_wonder_peer.h>
#include <wlan_hdd_wonder_sched.h>
#include <wlan_hdd_wonder_coex.h>
#include <wma_api.h>
#include "wlan_mlme_sta_mon.h"
#include <cdp_txrx_cmn.h>
#include <cdp_txrx_mon.h>
#include <cdp_txrx_injection.h>
#include "osif_psoc_sync.h"
#include "osif_vdev_sync.h"
#include "wlan_reg_ucfg_api.h"
#include "wlan_dp_ucfg_api.h"

#ifdef FEATURE_WLAN_WONDER

#define HDD_WONDER_NETDEV "wondertap0"
#define HDD_WONDER_MDNS_PEERS 16
#define HDD_WONDER_MDNS_PEER_LIFETIME (10 * HZ)

static const u8 hdd_wonder_awdl_bssid[] = { 0x00, 0x25, 0x00, 0xff, 0x94, 0x73 };
static const u8 hdd_wonder_mdns_group[] = { 0x33, 0x33, 0x00, 0x00, 0x00, 0xfb };

struct hdd_wonder_mdns_peer {
	unsigned long last_seen;
	u8 address[ETH_ALEN];
};

struct hdd_wonder_session {
	struct hdd_adapter *adapter;
	struct hdd_wonder_peer_state *peer;
	struct hdd_wonder_sched *sched;
	struct hdd_wonder_coex *coex;
	struct wondertap_set_freq_params channel;
	struct wondertap_fixed_tx_rate_params tx_rate;
	spinlock_t mdns_peers_lock;
	struct hdd_wonder_mdns_peer mdns_peers[HDD_WONDER_MDNS_PEERS];
	bool airtime_enabled;
	bool suspended;
	bool failed;
	bool native_group_ready;
	/* Only the init transaction reads this before the RCU session is live. */
	bool exclusive_bootstrap;
};

struct hdd_wonder_provider {
	struct wondertap_monitor_aux_dev monitor;
	struct hdd_context *hdd_ctx;
	struct hdd_wonder_session *session;
	bool removing;
};

/* The Wonder API's init callback has no provider argument. Onyx has one radio. */
static DEFINE_MUTEX(hdd_wonder_lock);
static DEFINE_MUTEX(hdd_wonder_lifecycle_lock);
static struct hdd_wonder_provider *hdd_wonder_provider;
static struct hdd_wonder_session __rcu *hdd_wonder_active;
static bool wonder_enabled = true;
static bool wonder_sta_offchan_probe;
static bool wonder_native_group_tx = true;
module_param_cb(wonder_native_group_tx, &param_ops_bool,
		&wonder_native_group_tx, 0444);
MODULE_PARM_DESC(wonder_native_group_tx,
	"Use native WMI multicast data TX on the exclusive AWDL channel (default on)");
static bool hdd_wonder_standalone_active;
module_param(wonder_enabled, bool, 0444);
MODULE_PARM_DESC(wonder_enabled,
	"Expose the Onyx Wonder/AWDL provider (default on)");
module_param(wonder_sta_offchan_probe, bool, 0444);
MODULE_PARM_DESC(wonder_sta_offchan_probe,
	"Enable experimental STA off-channel dwell probes (default off; normal Wonder TX options remain unsupported)");

static int hdd_wonder_lifecycle_revision_get(char *buffer,
					    const struct kernel_param *param)
{
	(void)param;
	return scnprintf(buffer, PAGE_SIZE, "1\n");
}

static const struct kernel_param_ops hdd_wonder_lifecycle_revision_ops = {
	.get = hdd_wonder_lifecycle_revision_get,
};
module_param_cb(wonder_lifecycle_revision, &hdd_wonder_lifecycle_revision_ops,
		NULL, 0444);
MODULE_PARM_DESC(wonder_lifecycle_revision,
	"Read-only Wonder monitor registration and synchronization revision");

static int hdd_wonder_coex_stats_get(char *buffer, const struct kernel_param *param)
{
	struct hdd_wonder_session *session;
	int length;

	(void)param;
	rcu_read_lock();
	session = rcu_dereference(hdd_wonder_active);
	if (session && session->coex)
		length = hdd_wonder_coex_format(session->coex, buffer, PAGE_SIZE);
	else
		length = scnprintf(buffer, PAGE_SIZE, "active=0\n");
	rcu_read_unlock();
	return length;
}

static const struct kernel_param_ops hdd_wonder_coex_stats_ops = {
	.get = hdd_wonder_coex_stats_get,
};
module_param_cb(wonder_coex_stats, &hdd_wonder_coex_stats_ops, NULL, 0444);
MODULE_PARM_DESC(wonder_coex_stats, "Wonder private scan ownership and target event observations");

static int hdd_wonder_validate_rate(
		const struct wondertap_fixed_tx_rate_params *rate)
{
	return wondertap_monitor_validate_rate(rate);
}

static int hdd_wonder_airtime(struct hdd_wonder_session *session, bool enabled)
{
	QDF_STATUS status;

	if (session->airtime_enabled == enabled)
		return 0;
	status = dp_mon_wonder_set_airtime(cds_get_context(QDF_MODULE_ID_SOC),
					session->adapter->deflink->vdev_id, enabled);
	/* Disable relinquishes the monitor owner even if the FW mask restore fails. */
	if (!enabled)
		session->airtime_enabled = false;
	if (QDF_IS_STATUS_ERROR(status))
		return qdf_status_to_os_return(status);
	session->airtime_enabled = enabled;
	return 0;
}

static int hdd_wonder_bind_clock(struct hdd_wonder_session *session, bool resume)
{
	struct wma_wonder_helper_snapshot helper;
	int ret;

	ret = hdd_wonder_peer_get_helper(session->peer, &helper);
	if (ret)
		return ret;
	if (resume)
		return hdd_wonder_sched_resume(session->sched, helper.vdev_id,
					       helper.cookie);
	return hdd_wonder_sched_bind_tsf(session->sched, helper.vdev_id,
					helper.cookie);
}

/* Caller holds RTNL and hdd_wonder_lock. No core RX handler may remain. */
static void hdd_wonder_close_session(struct hdd_wonder_provider *provider)
{
	struct hdd_wonder_session *session = provider->session;
	struct hdd_adapter *adapter;
	struct osif_vdev_sync *vdev_sync;

	ASSERT_RTNL();
	if (!session)
		return;
	provider->session = NULL;
	adapter = session->adapter;
	WRITE_ONCE(session->failed, true);
	if (adapter->sta_mon_coexist) {
		/* Revoke radio admission before removing the RCU provider gate. */
		wlan_mlme_sta_mon_update_begin(adapter->hdd_ctx->psoc);
		wlan_mlme_sta_mon_update_end(adapter->hdd_ctx->psoc);
	}
	rcu_assign_pointer(hdd_wonder_active, NULL);
	synchronize_rcu();
	hdd_wonder_coex_destroy(session->coex);
	session->coex = NULL;
	if (hdd_wonder_airtime(session, false))
		hdd_warn("Wonder airtime reporting could not be disabled before teardown");
	hdd_wonder_sched_destroy(session->sched);
	hdd_wonder_peer_destroy(session->peer);
	netif_tx_disable(adapter->dev);
	if (adapter->dev->flags & IFF_UP)
		dev_close(adapter->dev);

	/* SSR can already own the psoc transition, causing ndo_stop to reject it. */
	vdev_sync = osif_vdev_sync_unregister(adapter->dev);
	if (vdev_sync)
		osif_vdev_sync_wait_for_ops(vdev_sync);
	if (test_bit(DEVICE_IFACE_OPENED, &adapter->event_flags) ||
	    test_bit(SME_SESSION_OPENED, &adapter->deflink->link_flags)) {
		hdd_stop_adapter(provider->hdd_ctx, adapter);
		hdd_deinit_adapter(provider->hdd_ctx, adapter, true);
	}
	clear_bit(DEVICE_IFACE_OPENED, &adapter->event_flags);
	WRITE_ONCE(adapter->wonder_owned, false);
	/* cfg80211_unregister_netdevice requires the vendor wiphy mutex. */
	wiphy_lock(provider->hdd_ctx->wiphy);
	hdd_close_adapter(provider->hdd_ctx, adapter, true);
	/* Filter reset and native unbind need the monitor flags through cleanup. */
	ucfg_dp_set_mon_conf_flags(provider->hdd_ctx->psoc, 0);
	wiphy_unlock(provider->hdd_ctx->wiphy);
	if (vdev_sync)
		osif_vdev_sync_destroy(vdev_sync);
	WRITE_ONCE(hdd_wonder_standalone_active, false);
	kfree(session);
}

bool hdd_wonder_get_init_channel(struct hdd_adapter *adapter,
				u32 *frequency, u32 *bandwidth)
{
	struct hdd_wonder_provider *provider = READ_ONCE(hdd_wonder_provider);
	struct hdd_wonder_session *session;

	ASSERT_RTNL();
	if (!provider || !frequency || !bandwidth ||
	    !READ_ONCE(adapter->wonder_owned))
		return false;
	session = provider->session;
	if (!session || session->adapter != adapter ||
	    !session->exclusive_bootstrap)
		return false;
	*frequency = session->channel.freq;
	switch (session->channel.bandwidth) {
	case WONDERTAP_RATE_BW_20: *bandwidth = CH_WIDTH_20MHZ; break;
	case WONDERTAP_RATE_BW_40: *bandwidth = CH_WIDTH_40MHZ; break;
	case WONDERTAP_RATE_BW_80: *bandwidth = CH_WIDTH_80MHZ; break;
	default: return false;
	}
	return true;
}

static int hdd_wonder_bandwidth(enum wondertap_rate_bw bandwidth)
{
	switch (bandwidth) {
	case WONDERTAP_RATE_BW_20: return CH_WIDTH_20MHZ;
	case WONDERTAP_RATE_BW_40: return CH_WIDTH_40MHZ;
	case WONDERTAP_RATE_BW_80: return CH_WIDTH_80MHZ;
	default: return -EOPNOTSUPP;
	}
}

/* This is preflight only. In particular it never writes the live channel. */
static int hdd_wonder_validate_channel(void *context,
			       const struct wondertap_set_freq_params *params)
{
	struct hdd_wonder_session *session = context;
	struct hdd_adapter *adapter = session->adapter;
	struct hdd_context *hdd_ctx = adapter->hdd_ctx;
	struct ieee80211_channel *channel;
	struct wlan_channel shared;
	struct ch_params bonded = { 0 };
	int width, ret;

	if (!params || !params->freq)
		return -EINVAL;
	width = hdd_wonder_bandwidth(params->bandwidth);
	if (width < 0)
		return width;
	channel = ieee80211_get_channel(hdd_ctx->wiphy, params->freq);
	if (!channel || channel->flags & (IEEE80211_CHAN_DISABLED |
					 IEEE80211_CHAN_NO_IR | IEEE80211_CHAN_RADAR))
		return -EOPNOTSUPP;
	if (adapter->sta_mon_coexist) {
		ret = hdd_sta_mon_get_channel(adapter, &shared);
		if (ret)
			return ret;
		if (session->exclusive_bootstrap) {
			struct wlan_channel requested;

			return hdd_wonder_build_exclusive_channel(adapter,
						params->freq, width, &requested);
		}
		/* Shared ownership retains the real STA/AP's operating channel.
		 * No intentional-disconnect handoff is allowed from Wonder.
		 */
		if (shared.ch_freq != params->freq) {
			struct wlan_mlme_sta_mon_snapshot snapshot;
			u64 generation = wlan_mlme_sta_mon_epoch(hdd_ctx->psoc);

			/* Stock 7009 has no proven GI/NOSEQNO/NOACK encoding. Normal
			 * Wonder traffic requests these options, so only an explicit
			 * radio probe may reserve a foreign channel at this checkpoint.
			 */
			if (!READ_ONCE(wonder_sta_offchan_probe) || width != CH_WIDTH_20MHZ ||
			    !wlan_mlme_sta_mon_get_snapshot(hdd_ctx->psoc,
					adapter->deflink->vdev_id, generation, &snapshot) ||
			    snapshot.ap_owner || snapshot.exclusive)
				return -EOPNOTSUPP;
			bonded.ch_width = width;
			wlan_reg_set_channel_params_for_pwrmode(hdd_ctx->pdev, params->freq,
						       0, &bonded, REG_CURRENT_PWR_MODE);
			return bonded.ch_width == width ? 0 : -EOPNOTSUPP;
		}
		if (shared.ch_cfreq2 ||
		    shared.ch_width < width || shared.ch_width > CH_WIDTH_80MHZ)
			return -EBUSY;
		return 0;
	}
	ret = hdd_validate_channel_and_bandwidth(adapter, params->freq, 0, width);
	if (ret)
		return ret;
	bonded.ch_width = width;
	wlan_reg_set_channel_params_for_pwrmode(hdd_ctx->pdev, params->freq,
					       0, &bonded, REG_CURRENT_PWR_MODE);
	if (bonded.ch_width != width)
		return -EOPNOTSUPP;
	return 0;
}

static int hdd_wonder_set_channel(struct hdd_wonder_session *session,
				const struct wondertap_set_freq_params *params,
				u64 slot_end_ns, u64 duration_ns,
				u64 *completed_ns)
{
	struct hdd_adapter *adapter = session->adapter;
	struct hdd_context *hdd_ctx = adapter->hdd_ctx;
	struct hdd_monitor_ctx channel = { 0 };
	struct wlan_channel shared;
	u64 generation = 0;
	bool exclusive = !adapter->sta_mon_coexist;
	QDF_STATUS status;
	int ret;

	ret = hdd_wonder_validate_channel(session, params);
	if (ret)
		return ret;
	if (adapter->sta_mon_coexist) {
		struct wlan_mlme_sta_mon_snapshot snapshot;
		struct wma_wonder_helper_snapshot helper;

		ret = hdd_sta_mon_get_channel(adapter, &shared);
		if (ret)
			return ret;
		generation = wlan_mlme_sta_mon_epoch(hdd_ctx->psoc);
		if (!wlan_mlme_sta_mon_get_snapshot(hdd_ctx->psoc,
				adapter->deflink->vdev_id, generation, &snapshot))
			return -EAGAIN;
		exclusive = snapshot.exclusive;
		ret = hdd_wonder_peer_prepare(session->peer, shared.ch_freq, generation);
		if (ret)
			goto failed;
		if (!snapshot.ap_owner && !snapshot.exclusive && !session->coex) {
			ret = hdd_wonder_peer_get_helper(session->peer, &helper);
			if (ret)
				goto failed;
			session->coex = hdd_wonder_coex_create(adapter, shared.ch_freq,
							      generation, &helper);
			if (IS_ERR(session->coex)) {
				ret = PTR_ERR(session->coex);
				session->coex = NULL;
				goto failed;
			}
		}
		if (snapshot.exclusive) {
			struct wlan_channel requested;
			bool retuned = false;

			ret = hdd_wonder_build_exclusive_channel(adapter, params->freq,
					hdd_wonder_bandwidth(params->bandwidth), &requested);
			if (ret)
				return ret;
			if (shared.ch_freq != requested.ch_freq ||
			    shared.ch_width != requested.ch_width ||
			    shared.ch_cfreq1 != requested.ch_cfreq1 ||
			    shared.ch_cfreq2 != requested.ch_cfreq2) {
				hdd_wonder_sched_unbind_tsf(session->sched);
				ret = hdd_wonder_peer_clear(session->peer);
				if (ret)
					goto failed;
				ret = hdd_sta_mon_set_channel(adapter, &requested);
				if (ret)
					goto failed;
				generation = wlan_mlme_sta_mon_epoch(hdd_ctx->psoc);
				ret = hdd_wonder_peer_prepare(session->peer,
						params->freq, generation);
				if (ret)
					goto failed;
				retuned = true;
			}
			*completed_ns = retuned ?
				READ_ONCE(adapter->wonder_channel_complete_ns) : ktime_get_ns();
			if (!*completed_ns)
				*completed_ns = ktime_get_ns();
		} else if (shared.ch_freq != params->freq) {
			status = wma_wonder_offchan_prepare(adapter->deflink->vdev_id,
				shared.ch_freq, adapter->mac_addr.bytes, generation,
				hdd_wonder_coex_helper(session->coex));
			if (QDF_IS_STATUS_ERROR(status))
				return qdf_status_to_os_return(status);
			ret = hdd_wonder_coex_acquire(session->coex, params->freq,
						    slot_end_ns, duration_ns, completed_ns);
			if (ret)
				return ret;
		} else {
			if (session->coex) {
				ret = hdd_wonder_coex_home(session->coex);
				if (ret)
					return ret;
			}
			/* Shared HOME may be wider than Wonder's requested rate. */
			*completed_ns = ktime_get_ns();
		}
	} else {
		if (session->channel.freq != params->freq ||
		    session->channel.bandwidth != params->bandwidth) {
			hdd_wonder_sched_unbind_tsf(session->sched);
			ret = hdd_wonder_peer_clear(session->peer);
			if (ret)
				goto failed;
			status = wma_injection_channel_change_begin(
					adapter->deflink->vdev_id, params->freq);
			if (QDF_IS_STATUS_ERROR(status)) {
				ret = qdf_status_to_os_return(status);
				goto failed;
			}
			channel.freq = params->freq;
			channel.bandwidth = hdd_wonder_bandwidth(params->bandwidth);
			ret = wlan_hdd_validate_mon_params(adapter, &channel, 1);
			if (!ret)
				ret = wlan_hdd_set_mon_chan(adapter);
			wma_injection_channel_change_end();
			if (ret)
				goto failed;
			status = cdp_refresh_monitor_mode(cds_get_context(QDF_MODULE_ID_SOC),
					 OL_TXRX_PDEV_ID, adapter->deflink->vdev_id);
			if (QDF_IS_STATUS_ERROR(status)) {
				ret = qdf_status_to_os_return(status);
				goto failed;
			}
			*completed_ns = READ_ONCE(adapter->wonder_channel_complete_ns);
			if (!*completed_ns)
				*completed_ns = ktime_get_ns();
		} else {
			/* No retune completed: this dwell begins at the current instant. */
			*completed_ns = ktime_get_ns();
		}
	}
	/* The receiving AWDL MAC belongs to the actual raw-injection helper. */
	if (!adapter->sta_mon_coexist) {
		ret = hdd_wonder_peer_prepare(session->peer, params->freq, generation);
		if (ret)
			goto failed;
	}
	if (session->sched && !session->coex) {
		ret = hdd_wonder_bind_clock(session, false);
		if (ret)
			goto failed;
	}
	session->channel = *params;
	WRITE_ONCE(session->native_group_ready, false);
	if (exclusive && READ_ONCE(wonder_native_group_tx)) {
		struct wma_wonder_helper_snapshot helper;

		ret = hdd_wonder_peer_get_helper(session->peer, &helper);
		if (!ret) {
			status = wma_wonder_offchan_prepare(adapter->deflink->vdev_id,
				params->freq, adapter->mac_addr.bytes, generation, &helper);
			ret = qdf_status_to_os_return(status);
		}
		WRITE_ONCE(session->native_group_ready, !ret);
	}
	return 0;
failed:
	WRITE_ONCE(session->failed, true);
	netif_tx_disable(adapter->dev);
	return ret;
}

static int hdd_wonder_scheduled_channel(void *context,
				const struct wondertap_set_freq_params *channel,
				u64 generation, u64 slot_end_ns, u64 duration_ns,
				u64 *completed_ns)
{
	struct hdd_wonder_session *session = context;
	struct hdd_wonder_provider *provider;
	struct osif_vdev_sync *vdev_sync;
	int ret = -EAGAIN;

	/* Teardown may drain this worker while holding provider/RTNL locks. */
	if (!mutex_trylock(&hdd_wonder_lock))
		return -EAGAIN;
	provider = hdd_wonder_provider;
	if (!provider || provider->removing || provider->session != session ||
	    session->suspended || session->failed ||
	    !hdd_wonder_sched_generation_active(session->sched, generation)) {
		ret = -ESHUTDOWN;
		goto unlock;
	}
	if (!mutex_trylock(&provider->hdd_ctx->wiphy->mtx))
		goto unlock;
	ret = osif_vdev_sync_op_start(session->adapter->dev, &vdev_sync);
	if (!ret) {
		ret = hdd_wonder_set_channel(session, channel, slot_end_ns,
					     duration_ns, completed_ns);
		osif_vdev_sync_op_stop(vdev_sync);
	}
	wiphy_unlock(provider->hdd_ctx->wiphy);
unlock:
	mutex_unlock(&hdd_wonder_lock);
	return ret;
}

static const struct hdd_wonder_sched_ops hdd_wonder_sched_ops = {
	.set_channel = hdd_wonder_scheduled_channel,
	.validate_channel = hdd_wonder_validate_channel,
};

/* The standalone firmware helper has no objmgr vdev. Block competing vdev
 * creation until its real teardown, instead of allowing its ID to be reused.
 */
bool hdd_wonder_vdev_admission(struct hdd_adapter *adapter)
{
	return !wma_wonder_standalone_helper_reserved() &&
		(!READ_ONCE(hdd_wonder_standalone_active) || READ_ONCE(adapter->wonder_owned));
}

bool wlan_injection_wonder_vdev_admission(u8 opmode)
{
	return !wma_wonder_standalone_helper_reserved() &&
		(!READ_ONCE(hdd_wonder_standalone_active) || opmode == QDF_MONITOR_MODE);
}

bool hdd_wonder_transport_ready(struct hdd_adapter *adapter)
{
	struct hdd_wonder_session *session;
	bool ready;

	if (!READ_ONCE(adapter->wonder_owned))
		return true;
	rcu_read_lock();
	session = rcu_dereference(hdd_wonder_active);
	ready = session && session->adapter == adapter &&
		!smp_load_acquire(&session->suspended) && !READ_ONCE(session->failed) &&
		hdd_wonder_peer_ready(session->peer) &&
		(!session->coex || hdd_wonder_coex_ready(session->coex, 0));
	rcu_read_unlock();
	return ready;
}

bool hdd_wonder_netdev_is_owned(struct net_device *dev)
{
	struct hdd_adapter *adapter;

	if (!dev)
		return false;
	adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	return READ_ONCE(adapter->wonder_owned);
}

bool hdd_wonder_netdev_transport_ready(struct net_device *dev)
{
	struct hdd_adapter *adapter;
	struct hdd_wonder_session *session;
	bool ready;

	if (!dev)
		return false;
	adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	if (!READ_ONCE(adapter->wonder_owned))
		return true;
	/* RX enters here while final DP publication holds admission/dwell locks.
	 * DP already checked frequency and dwell; only provider lifetime remains.
	 */
	rcu_read_lock();
	session = rcu_dereference(hdd_wonder_active);
	ready = session && session->adapter == adapter &&
		!smp_load_acquire(&session->suspended) && !READ_ONCE(session->failed) &&
		hdd_wonder_peer_ready(session->peer);
	rcu_read_unlock();
	return ready;
}

static QDF_STATUS
hdd_wonder_queue_tx(struct hdd_wonder_session *session, struct sk_buff *skb,
		    const struct cdp_tx_injection_params *params)
{
	struct hdd_adapter *adapter = session->adapter;
	const struct ieee80211_hdr *hdr = (const void *)skb->data;
	struct cdp_tx_injection_params constrained = *params;
	QDF_STATUS status;
	void *token;

	hdd_wonder_peer_tx_rate(session->peer, hdr->addr1, &constrained);
	if (READ_ONCE(wonder_native_group_tx) && READ_ONCE(session->native_group_ready) &&
	    skb->len >= 24 && params->is_data &&
	    ieee80211_is_data_present(hdr->frame_control) &&
	    !ieee80211_has_protected(hdr->frame_control) &&
	    !ieee80211_has_tods(hdr->frame_control) &&
	    !ieee80211_has_fromds(hdr->frame_control) &&
	    !ieee80211_has_morefrags(hdr->frame_control) &&
	    !(le16_to_cpu(hdr->seq_ctrl) & IEEE80211_SCTL_FRAG) &&
	    is_multicast_ether_addr(hdr->addr1) &&
	    !memcmp(hdr->addr3, hdd_wonder_awdl_bssid, ETH_ALEN)) {
		struct wma_wonder_helper_snapshot helper;
		struct cdp_tx_injection_params native = constrained;
		u32 frequency = READ_ONCE(session->channel.freq);
		u64 generation = adapter->sta_mon_coexist ?
			wlan_mlme_sta_mon_epoch(adapter->hdd_ctx->psoc) : 0;

		if (!hdd_wonder_peer_get_helper(session->peer, &helper)) {
			/* This AWDL group-data route uses firmware-assigned outer 802.11
			 * sequence numbers and intrinsic group no-ACK behavior. Wonder's
			 * generated flags have no wire fields in that command; AWDL's own
			 * sequence and all packet addresses remain untouched.
			 * Keep every other override subject to WMI rejection and retain
			 * the original parameters for the HTT fallback.
			 */
			native.no_ack = false;
			native.tx_flags &= ~(IEEE80211_RADIOTAP_F_TX_NOACK |
					     IEEE80211_RADIOTAP_F_TX_NOSEQNO);
			status = wma_wonder_offchan_tx(skb, adapter->deflink->vdev_id,
				frequency, generation, &helper, frequency, &native,
				NULL, NULL, NULL, NULL);
			return status;
		}
	}
	if (!session->coex)
		return wma_injection_tx(skb, adapter->deflink->vdev_id, &constrained);

	token = hdd_wonder_coex_tx_token(session->coex, constrained.chanfreq);
	if (IS_ERR(token)) {
		if (PTR_ERR(token) == -EALREADY)
			return wma_injection_tx(skb, adapter->deflink->vdev_id,
						&constrained);
		return QDF_STATUS_E_AGAIN;
	}
	status = wma_wonder_offchan_tx(skb, adapter->deflink->vdev_id,
			hdd_wonder_coex_home_frequency(session->coex),
			hdd_wonder_coex_generation(session->coex),
			hdd_wonder_coex_helper(session->coex),
			hdd_wonder_coex_tx_frequency(token), &constrained,
			hdd_wonder_coex_tx_begin, hdd_wonder_coex_tx_end,
			hdd_wonder_coex_tx_release, token);
	if (QDF_IS_STATUS_ERROR(status))
		hdd_wonder_coex_tx_release(token);
	return status;
}

/*
 * Monitor RX has a radiotap header followed by the complete action frame.
 * A recent PSF or MIF gives the radio address needed to deliver mDNS to a peer.
 */
void hdd_wonder_note_rx_peer(struct net_device *dev, const struct sk_buff *skb)
{
	static const u8 awdl_action[] = { 0x7f, 0x00, 0x17, 0xf2, 0x08, 0x10 };
	struct ieee80211_radiotap_header radiotap;
	struct hdd_wonder_session *session;
	struct hdd_wonder_mdns_peer *entry;
	u8 frame[24 + 16] __aligned(2);
	unsigned long flags;
	unsigned int offset, i, slot = 0;
	const u8 *address = frame + 10;
	__le16 fc;

	rcu_read_lock();
	session = rcu_dereference(hdd_wonder_active);
	if (!session || session->adapter->dev != dev ||
	    skb_copy_bits(skb, 0, &radiotap, sizeof(radiotap)))
		goto out;
	offset = le16_to_cpu(radiotap.it_len);
	if (radiotap.it_version || offset < sizeof(radiotap) ||
	    skb_copy_bits(skb, offset, frame, sizeof(frame)))
		goto out;
	fc = cpu_to_le16(get_unaligned_le16(frame));
	if (!ieee80211_is_action(fc) || ieee80211_has_protected(fc) ||
	    ieee80211_has_morefrags(fc) ||
	    (get_unaligned_le16(frame + 22) & IEEE80211_SCTL_FRAG) ||
	    memcmp(frame + 16, hdd_wonder_awdl_bssid, ETH_ALEN) ||
	    memcmp(frame + 24, awdl_action, sizeof(awdl_action)) ||
	    (frame[30] != 0 && frame[30] != 3) ||
	    !is_valid_ether_addr(address) ||
	    !memcmp(address, dev->dev_addr, ETH_ALEN))
		goto out;

	spin_lock_irqsave(&session->mdns_peers_lock, flags);
	for (i = 0; i < ARRAY_SIZE(session->mdns_peers); i++) {
		entry = &session->mdns_peers[i];
		if (!memcmp(entry->address, address, ETH_ALEN)) {
			slot = i;
			break;
		}
		if (is_zero_ether_addr(entry->address) ||
		    time_before(entry->last_seen, session->mdns_peers[slot].last_seen))
			slot = i;
	}
	entry = &session->mdns_peers[slot];
	memcpy(entry->address, address, ETH_ALEN);
	entry->last_seen = jiffies;
	spin_unlock_irqrestore(&session->mdns_peers_lock, flags);
out:
	rcu_read_unlock();
}

/* Qualcomm's private RAW helper drops group data. Keep the mDNS packet and
 * its multicast IP destination intact, and use the radio address of each
 * recently heard AWDL peer. A-MSDU subframe addresses also stay intact.
 */
static bool hdd_wonder_tx_mdns(struct hdd_wonder_session *session,
			      struct sk_buff *skb,
			      const struct cdp_tx_injection_params *params)
{
	const struct ieee80211_hdr *hdr = (const void *)skb->data;
	u8 addresses[HDD_WONDER_MDNS_PEERS][ETH_ALEN];
	unsigned long flags, now = jiffies;
	unsigned int i, count = 0;
	bool sent = false;

	if (skb->len < 24 || !params->is_data ||
	    !ieee80211_is_data_present(hdr->frame_control) ||
	    ieee80211_has_tods(hdr->frame_control) ||
	    ieee80211_has_fromds(hdr->frame_control) ||
	    ieee80211_has_protected(hdr->frame_control) ||
	    ieee80211_has_morefrags(hdr->frame_control) ||
	    (le16_to_cpu(hdr->seq_ctrl) & IEEE80211_SCTL_FRAG) ||
	    memcmp(hdr->addr1, hdd_wonder_mdns_group, ETH_ALEN) ||
	    memcmp(hdr->addr2, session->adapter->dev->dev_addr, ETH_ALEN) ||
	    memcmp(hdr->addr3, hdd_wonder_awdl_bssid, ETH_ALEN))
		return false;

	spin_lock_irqsave(&session->mdns_peers_lock, flags);
	for (i = 0; i < ARRAY_SIZE(session->mdns_peers); i++) {
		const struct hdd_wonder_mdns_peer *peer = &session->mdns_peers[i];

		if (!is_zero_ether_addr(peer->address) &&
		    time_before(now, peer->last_seen + HDD_WONDER_MDNS_PEER_LIFETIME))
			memcpy(addresses[count++], peer->address, ETH_ALEN);
	}
	spin_unlock_irqrestore(&session->mdns_peers_lock, flags);

	for (i = 0; i < count; i++) {
		struct sk_buff *copy = skb_copy(skb, GFP_ATOMIC);

		if (!copy)
			break;
		memcpy(((struct ieee80211_hdr *)copy->data)->addr1,
		       addresses[i], ETH_ALEN);
		if (QDF_IS_STATUS_ERROR(hdd_wonder_queue_tx(session, copy, params)))
			dev_kfree_skb_any(copy);
		else
			sent = true;
	}
	if (sent)
		consume_skb(skb);
	return sent;
}

int hdd_wonder_injection_tx(struct hdd_adapter *adapter, struct sk_buff *skb,
		const struct cdp_tx_injection_params *params)
{
	struct hdd_wonder_session *session;
	QDF_STATUS status = QDF_STATUS_E_AGAIN;

	rcu_read_lock();
	session = rcu_dereference(hdd_wonder_active);
	if (!session || session->adapter != adapter ||
	    smp_load_acquire(&session->suspended) || READ_ONCE(session->failed))
		goto out;
	if (READ_ONCE(wonder_native_group_tx) &&
	    READ_ONCE(session->native_group_ready)) {
		status = hdd_wonder_queue_tx(session, skb, params);
		/* A rejected native send has not consumed skb. Preserve discovery
		 * when its bounded descriptor namespace or queue is exhausted.
		 */
		if (QDF_IS_STATUS_ERROR(status) &&
		    hdd_wonder_tx_mdns(session, skb, params))
			status = QDF_STATUS_SUCCESS;
	} else {
		status = hdd_wonder_tx_mdns(session, skb, params) ?
			QDF_STATUS_SUCCESS : hdd_wonder_queue_tx(session, skb, params);
	}
out:
	rcu_read_unlock();
	return qdf_status_to_os_return(status);
}

static bool hdd_wonder_publish_begin_locked(void *arg, u8 monitor_id,
		u64 generation, u32 frequency, u32 home_frequency, bool home_tx,
		struct cdp_wonder_rx_lease *lease)
{
	struct hdd_wonder_session *session;

	lease->coex = NULL;
	rcu_read_lock();
	session = rcu_dereference(hdd_wonder_active);
	if (!session || session->adapter->hdd_ctx->psoc != arg ||
	    session->adapter->deflink->vdev_id != monitor_id) {
		if (home_tx || !frequency || frequency == home_frequency)
			return true;
		goto deny;
	}
	if (smp_load_acquire(&session->suspended) || READ_ONCE(session->failed) ||
	    !hdd_wonder_peer_ready(session->peer))
		goto deny;
	if (session->coex) {
		if (home_tx)
			frequency = hdd_wonder_coex_home_frequency(session->coex);
		else if (!frequency)
			/* An unknown RX channel can only be treated as HOME. */
			frequency = hdd_wonder_coex_home_frequency(session->coex);
		if (!hdd_wonder_coex_rx_begin_locked(session->coex, generation, frequency))
			goto deny;
		lease->coex = session->coex;
	} else if (!home_tx && frequency &&
		   frequency != READ_ONCE(session->channel.freq)) {
		goto deny;
	}
	return true;
deny:
	rcu_read_unlock();
	return false;
}

bool wlan_injection_wonder_home_tx_begin_locked(void *arg, u8 monitor_id,
		u64 generation, struct cdp_wonder_rx_lease *lease)
{
	return hdd_wonder_publish_begin_locked(arg, monitor_id, generation,
					      0, 0, true, lease);
}

void wlan_injection_wonder_home_tx_end_locked(struct cdp_wonder_rx_lease *lease)
{
	if (lease->coex)
		hdd_wonder_coex_rx_end_locked(lease->coex);
	rcu_read_unlock();
}

bool wlan_injection_wonder_rx_begin(void *arg, u8 monitor_id, u64 generation,
		u32 measured_frequency, struct cdp_wonder_rx_lease *lease)
{
	struct wlan_mlme_sta_mon_snapshot snapshot;

	if (!arg || !lease ||
	    !wlan_mlme_sta_mon_get_snapshot(arg, monitor_id, generation, &snapshot))
		return false;
	if (!wlan_mlme_sta_mon_tx_begin(arg, monitor_id, generation, &lease->flags))
		return false;
	if (hdd_wonder_publish_begin_locked(arg, monitor_id, generation,
					    measured_frequency, snapshot.channel.ch_freq,
					    false, lease))
		return true;
	wlan_mlme_sta_mon_tx_end(lease->flags);
	return false;
}

void wlan_injection_wonder_rx_end(struct cdp_wonder_rx_lease *lease)
{
	wlan_injection_wonder_home_tx_end_locked(lease);
	wlan_mlme_sta_mon_tx_end(lease->flags);
}

void wlan_injection_wonder_note_airtime(u32 pdev_id, u32 lmac_id, u32 frequency,
				       u32 mac_tsf, bool tx, u32 duration_us)
{
	struct hdd_wonder_session *session;

	if (!frequency || !duration_us)
		return;
	rcu_read_lock();
	session = rcu_dereference(hdd_wonder_active);
	if (session && !smp_load_acquire(&session->suspended) &&
	    !READ_ONCE(session->failed) &&
	    wlan_objmgr_pdev_get_pdev_id(session->adapter->hdd_ctx->pdev) == pdev_id)
		hdd_wonder_sched_note_airtime(session->sched, lmac_id, frequency,
					      mac_tsf, tx, duration_us);
	rcu_read_unlock();
}

static int hdd_wonder_init(void **handle,
			   const struct wondertap_init_params *params)
{
	struct hdd_wonder_provider *provider;
	struct hdd_wonder_session *session;
	struct osif_psoc_sync *psoc_sync = NULL;
	struct osif_vdev_sync *create_sync, *vdev_sync;
	struct hdd_context *hdd_ctx;
	struct net_device *existing;
	u8 mac[ETH_ALEN];
	u8 country[3] = { 0 };
	int ret;
	u64 completed_ns;

	/* mac80211 start owns RTNL; never acquire it recursively here. */
	ASSERT_RTNL();
	if (!handle || !params)
		return -EINVAL;
	*handle = NULL;
	if (!is_valid_ether_addr(params->mac_addr) || !params->channel.freq)
		return -EINVAL;
	ret = hdd_wonder_validate_rate(&params->tx_rate);
	if (ret)
		return ret;
	if (hdd_wonder_bandwidth(params->channel.bandwidth) < 0 ||
	    params->tx_rate.bw > params->channel.bandwidth ||
	    params->amsdu_enable || params->ampdu_enable ||
	    params->rate_adaptation_enable || params->perf_mode >= WONDER_PERF_MODE_MAX)
		return -EOPNOTSUPP;

	mutex_lock(&hdd_wonder_lock);
	provider = hdd_wonder_provider;
	if (!provider || provider->removing) {
		ret = -ENODEV;
		goto unlock;
	}
	if (provider->session) {
		ret = -EBUSY;
		goto unlock;
	}
	hdd_ctx = provider->hdd_ctx;
	ret = osif_psoc_sync_op_start(hdd_ctx->parent_dev, &psoc_sync);
	if (ret)
		goto unlock;
	ret = wlan_hdd_validate_context(hdd_ctx);
	if (ret)
		goto stop_op;
	if (cds_is_driver_recovering() || cds_is_driver_unloading() ||
	    !cds_is_driver_loaded()) {
		ret = -EBUSY;
		goto stop_op;
	}
	ret = hdd_trigger_psoc_idle_restart(hdd_ctx);
	if (ret)
		goto stop_op;
	if (!hdd_wonder_can_start(hdd_ctx)) {
		ret = -EBUSY;
		goto restart_idle;
	}
	if (QDF_IS_STATUS_ERROR(ucfg_reg_get_current_country(hdd_ctx->psoc, country))) {
		ret = -EIO;
		goto restart_idle;
	}
	if (memcmp(country, params->country_code, 2)) {
		/* This backend preserves the existing global regulatory domain. */
		ret = -EOPNOTSUPP;
		goto restart_idle;
	}
	existing = dev_get_by_name(&init_net, HDD_WONDER_NETDEV);
	if (existing) {
		dev_put(existing);
		ret = -EEXIST;
		goto restart_idle;
	}
	session = kzalloc(sizeof(*session), GFP_KERNEL);
	if (!session) {
		ret = -ENOMEM;
		goto restart_idle;
	}
	spin_lock_init(&session->mdns_peers_lock);
	ether_addr_copy(mac, params->mac_addr);
	ret = osif_vdev_sync_create_and_trans(hdd_ctx->parent_dev, &create_sync);
	if (ret)
		goto free_session;
	if (!wlan_mlme_sta_mon_admission_begin(hdd_ctx->psoc)) {
		ret = -EBUSY;
		goto destroy_sync;
	}
	wiphy_lock(hdd_ctx->wiphy);
	ret = hdd_wonder_add_monitor(hdd_ctx, &session->adapter,
				     HDD_WONDER_NETDEV, mac,
				     &session->exclusive_bootstrap);
	wiphy_unlock(hdd_ctx->wiphy);
	wlan_mlme_sta_mon_admission_end(hdd_ctx->psoc);
	if (ret)
		goto destroy_sync;
	/* Match nl80211 monitor setup before ndo_open and native RX binding. */
	ucfg_dp_set_mon_conf_flags(hdd_ctx->psoc, QDF_MONITOR_FLAG_OTHER_BSS |
		(session->adapter->sta_mon_coexist ? QDF_MONITOR_FLAG_STA_COEX : 0));
	osif_vdev_sync_register(session->adapter->dev, create_sync);
	osif_vdev_sync_trans_stop(create_sync);
	provider->session = session;
	if (session->exclusive_bootstrap)
		session->channel = params->channel;
	WRITE_ONCE(session->adapter->wonder_owned, true);
	WRITE_ONCE(hdd_wonder_standalone_active,
		   !session->adapter->sta_mon_coexist);
	session->peer = hdd_wonder_peer_create(session->adapter);
	if (IS_ERR(session->peer)) {
		ret = PTR_ERR(session->peer);
		session->peer = NULL;
		goto close_session;
	}
	/* ndo_open drains parent operations; do not wait on our own psoc op. */
	osif_psoc_sync_op_stop(psoc_sync);
	psoc_sync = NULL;
	ret = dev_open(session->adapter->dev, NULL);
	if (ret)
		goto close_session;
	ret = osif_vdev_sync_op_start(session->adapter->dev, &vdev_sync);
	if (ret)
		goto close_session;
	wiphy_lock(hdd_ctx->wiphy);
	ret = hdd_wonder_set_channel(session, &params->channel,
			ktime_get_ns() + HDD_WONDER_COEX_MAX_DWELL_NS,
			HDD_WONDER_COEX_MAX_DWELL_NS, &completed_ns);
	wiphy_unlock(hdd_ctx->wiphy);
	if (ret)
		goto stop_vdev_close_session;
	ret = hdd_wonder_peer_validate_rate(session->peer, &params->tx_rate);
	if (ret)
		goto stop_vdev_close_session;
	session->tx_rate = params->tx_rate;
	session->sched = hdd_wonder_sched_create(session->adapter, session,
						&hdd_wonder_sched_ops);
	if (IS_ERR(session->sched)) {
		ret = PTR_ERR(session->sched);
		session->sched = NULL;
		goto stop_vdev_close_session;
	}
	ret = hdd_wonder_bind_clock(session, false);
	if (ret)
		goto stop_vdev_close_session;
	ret = hdd_wonder_airtime(session, true);
	if (ret)
		goto stop_vdev_close_session;
	hdd_wonder_sched_note_channel(session->sched, params->channel.freq,
				      params->channel.bandwidth, completed_ns);
	rcu_assign_pointer(hdd_wonder_active, session);
	*handle = session;
	hdd_info("Experimental Wonder monitor transport ready on %s, %u MHz",
		 HDD_WONDER_NETDEV, params->channel.freq);
	ret = 0;
	osif_vdev_sync_op_stop(vdev_sync);
	goto stop_op;

stop_vdev_close_session:
	osif_vdev_sync_op_stop(vdev_sync);
close_session:
	/* ndo_stop and sync teardown must not drain an operation owned here. */
	if (psoc_sync) {
		osif_psoc_sync_op_stop(psoc_sync);
		psoc_sync = NULL;
	}
	hdd_wonder_close_session(provider);
	goto restart_idle;
destroy_sync:
	osif_vdev_sync_trans_stop(create_sync);
	osif_vdev_sync_destroy(create_sync);
free_session:
	kfree(session);
restart_idle:
	if (!hdd_is_any_interface_open(hdd_ctx))
		hdd_psoc_idle_timer_start(hdd_ctx);
stop_op:
	if (psoc_sync)
		osif_psoc_sync_op_stop(psoc_sync);
unlock:
	mutex_unlock(&hdd_wonder_lock);
	return ret;
}

static void hdd_wonder_deinit(void *handle,
			      const struct wondertap_deinit_params *params)
{
	struct hdd_wonder_provider *provider;

	ASSERT_RTNL();
	mutex_lock(&hdd_wonder_lock);
	provider = hdd_wonder_provider;
	if (provider && handle && provider->session == handle) {
		hdd_wonder_close_session(provider);
		if (!provider->removing &&
		    !hdd_is_any_interface_open(provider->hdd_ctx))
			hdd_psoc_idle_timer_start(provider->hdd_ctx);
	}
	mutex_unlock(&hdd_wonder_lock);
}

/* Caller holds hdd_wonder_lock. No packet-path callback takes that lock. */
static struct hdd_wonder_session *hdd_wonder_session_get(void *handle)
{
	struct hdd_wonder_provider *provider = hdd_wonder_provider;
	struct hdd_wonder_session *session;

	if (!provider || provider->removing || !handle || provider->session != handle)
		return ERR_PTR(-ENODEV);
	session = provider->session;
	if (session->suspended)
		return ERR_PTR(-EHOSTDOWN);
	if (session->failed || !(session->adapter->dev->flags & IFF_UP))
		return ERR_PTR(-ENETDOWN);
	return session;
}

static int hdd_wonder_set_freq(void *handle,
			       const struct wondertap_set_freq_params *params)
{
	struct hdd_wonder_session *session;
	struct osif_vdev_sync *vdev_sync;
	struct channel_schedule_request cancel = { 0 };
	u64 completed_ns;
	int ret;

	mutex_lock(&hdd_wonder_lock);
	session = hdd_wonder_session_get(handle);
	if (IS_ERR(session)) {
		ret = PTR_ERR(session);
		goto unlock;
	}
	ret = osif_vdev_sync_op_start(session->adapter->dev, &vdev_sync);
	if (ret)
		goto unlock;
	wiphy_lock(session->adapter->hdd_ctx->wiphy);
	ret = hdd_wonder_validate_channel(session, params);
	if (!ret) {
		/* Manual frequency control replaces any accepted hopping plan. */
		ret = hdd_wonder_sched_request(session->sched, &cancel);
		if (!ret) {
			ret = hdd_wonder_set_channel(session, params,
				ktime_get_ns() + HDD_WONDER_COEX_MAX_DWELL_NS,
				HDD_WONDER_COEX_MAX_DWELL_NS, &completed_ns);
			/* The core retains its accepted cache after an error. A canceled
			 * provider plan must not later be replayed by resuming this session.
			 */
			if (ret) {
				WRITE_ONCE(session->failed, true);
				netif_tx_disable(session->adapter->dev);
			}
		}
		if (!ret)
			hdd_wonder_sched_note_channel(session->sched, params->freq,
						      params->bandwidth, completed_ns);
	}
	wiphy_unlock(session->adapter->hdd_ctx->wiphy);
	osif_vdev_sync_op_stop(vdev_sync);
unlock:
	mutex_unlock(&hdd_wonder_lock);
	return ret;
}

static int hdd_wonder_set_filter(void *handle,
				enum wondertap_filter_type type, const void *params)
{
	const struct wondertap_frame_filter_params *filter = params;
	struct hdd_wonder_session *session;
	int ret = 0;

	if (type != WONDERTAP_FILTER_TYPE_FRAME)
		return -EOPNOTSUPP;
	if (!filter || (filter->enabled &&
	    (filter->frame_type & ~IEEE80211_FCTL_FTYPE ||
	     filter->frame_subtype & ~IEEE80211_FCTL_STYPE ||
	     filter->frame_type == IEEE80211_FCTL_FTYPE)))
		return -EINVAL;
	mutex_lock(&hdd_wonder_lock);
	session = hdd_wonder_session_get(handle);
	if (IS_ERR(session))
		ret = PTR_ERR(session);
	/* Wonder applies the accepted frame filter to its mac80211 RX stream. */
	mutex_unlock(&hdd_wonder_lock);
	return ret;
}

static int hdd_wonder_set_fixed_rate(void *handle,
			const struct wondertap_fixed_tx_rate_params *params)
{
	struct hdd_wonder_session *session;
	int ret = hdd_wonder_validate_rate(params);

	if (ret)
		return ret;
	mutex_lock(&hdd_wonder_lock);
	session = hdd_wonder_session_get(handle);
	if (IS_ERR(session)) {
		ret = PTR_ERR(session);
		goto unlock;
	}
	if (params->bw > session->channel.bandwidth) {
		ret = -EOPNOTSUPP;
		goto unlock;
	}
	ret = hdd_wonder_peer_validate_rate(session->peer, params);
	if (!ret)
		session->tx_rate = *params;
unlock:
	mutex_unlock(&hdd_wonder_lock);
	return ret;
}

static int hdd_wonder_set_rate_mask(void *handle,
			const struct wondertap_tx_rate_mask_params *params)
{
	/* Raw per-packet exception descriptors do not run firmware rate control. */
	return -EOPNOTSUPP;
}

static int hdd_wonder_capabilities(void *handle, struct wondertap_capability *caps)
{
	struct hdd_wonder_provider *provider;
	struct hdd_wonder_peer_limits limits;

	if (!caps)
		return -EINVAL;
	memset(caps, 0, sizeof(*caps));
	caps->version = 0;
	caps->bits.nss = 2;
	caps->bits.dynamic_freq = 1;
	caps->bits.dynamic_fixed_tx_rate = 1;
	caps->bits.frame_type_filter = 1;
	caps->bits.channel_hopping = 1;
	caps->bits.fcs_not_support = 1;
	/* A firmware channel transition may wait for the genuine vdev-up event. */
	caps->maximum_channel_switch_time_us = WLAN_MONITOR_MODE_VDEV_UP_EVT * 1000;
	mutex_lock(&hdd_wonder_lock);
	provider = hdd_wonder_provider;
	if (handle && (!provider || provider->session != handle)) {
		mutex_unlock(&hdd_wonder_lock);
		return -ENODEV;
	}
	if (provider && provider->session &&
	    !hdd_wonder_peer_get_limits(provider->session->peer, &limits))
		caps->bits.nss = limits.max_nss;
	/* Scoped 20 MHz STA dwell remains experimental; firmware role eligibility
	 * and Apple interoperability require target radio measurements.
	 */
	mutex_unlock(&hdd_wonder_lock);
	return 0;
}

static int hdd_wonder_schedule(void *handle,
			     const struct channel_schedule_request *request)
{
	struct hdd_wonder_session *session;
	int ret;

	mutex_lock(&hdd_wonder_lock);
	session = hdd_wonder_session_get(handle);
	if (IS_ERR(session)) {
		ret = PTR_ERR(session);
		goto unlock;
	}
	wiphy_lock(session->adapter->hdd_ctx->wiphy);
	ret = hdd_wonder_sched_request(session->sched, request);
	wiphy_unlock(session->adapter->hdd_ctx->wiphy);
unlock:
	mutex_unlock(&hdd_wonder_lock);
	return ret;
}

static int hdd_wonder_tsf(void *handle, u32 *tsf)
{
	struct hdd_wonder_session *session;
	int ret;

	mutex_lock(&hdd_wonder_lock);
	session = hdd_wonder_session_get(handle);
	ret = IS_ERR(session) ? PTR_ERR(session) : hdd_wonder_sched_get_tsf(session->sched, tsf);
	mutex_unlock(&hdd_wonder_lock);
	return ret;
}

static int hdd_wonder_channel_status(void *handle,
				struct wondertap_channel_status_report *report)
{
	struct hdd_wonder_session *session;
	int ret;

	mutex_lock(&hdd_wonder_lock);
	session = hdd_wonder_session_get(handle);
	ret = IS_ERR(session) ? PTR_ERR(session) : hdd_wonder_sched_get_report(session->sched, report);
	mutex_unlock(&hdd_wonder_lock);
	return ret;
}

static int hdd_wonder_station(void *handle, enum wondertap_station_action action,
			    struct wondertap_station_info *info)
{
	struct hdd_wonder_session *session;
	int ret;

	mutex_lock(&hdd_wonder_lock);
	session = hdd_wonder_session_get(handle);
	ret = IS_ERR(session) ? PTR_ERR(session) : hdd_wonder_peer_station(session->peer, action, info);
	mutex_unlock(&hdd_wonder_lock);
	return ret;
}

/* Suspend retains the vendor netdev and RX registration; PM never owns RTNL. */
static int hdd_wonder_suspend(void *handle)
{
	struct hdd_wonder_session *session;
	int ret = 0;

	mutex_lock(&hdd_wonder_lock);
	session = hdd_wonder_session_get(handle);
	if (IS_ERR(session)) {
		ret = PTR_ERR(session);
		/* A repeated suspend on the same retained session is harmless. */
		if (ret == -EHOSTDOWN)
			ret = 0;
		goto unlock;
	}
	ret = hdd_wonder_airtime(session, false);
	if (ret) {
		/* An aborted suspend must restore the live reporting request too. */
		if (hdd_wonder_airtime(session, true)) {
			WRITE_ONCE(session->failed, true);
			netif_tx_disable(session->adapter->dev);
		}
		goto unlock;
	}
	WRITE_ONCE(session->suspended, true);
	hdd_wonder_coex_cancel(session->coex);
	netif_device_detach(session->adapter->dev);
	netif_tx_disable(session->adapter->dev);
	/* Retain the firmware clock witness so resume can prove TSF continuity. */
	synchronize_rcu();
	hdd_wonder_sched_suspend(session->sched);
	synchronize_net();
unlock:
	mutex_unlock(&hdd_wonder_lock);
	return ret;
}

static int hdd_wonder_resume(void *handle)
{
	struct hdd_wonder_provider *provider;
	struct hdd_wonder_session *session;
	struct osif_vdev_sync *vdev_sync;
	int ret = 0;

	mutex_lock(&hdd_wonder_lock);
	provider = hdd_wonder_provider;
	if (!provider || provider->removing || provider->session != handle || !handle) {
		ret = -ENODEV;
		goto unlock;
	}
	session = provider->session;
	if (!session->suspended)
		goto unlock;
	if (session->failed || !hdd_wonder_peer_ready(session->peer)) {
		ret = -ENETDOWN;
		goto unlock;
	}
	ret = osif_vdev_sync_op_start(session->adapter->dev, &vdev_sync);
	if (ret)
		goto unlock;
	ret = hdd_wonder_bind_clock(session, true);
	if (!ret)
		ret = hdd_wonder_airtime(session, true);
	if (ret)
		hdd_wonder_sched_suspend(session->sched);
	osif_vdev_sync_op_stop(vdev_sync);
	if (ret)
		goto unlock;
	hdd_wonder_sched_note_channel(session->sched, session->channel.freq,
				      session->channel.bandwidth, ktime_get_ns());
	smp_store_release(&session->suspended, false);
	netif_device_attach(session->adapter->dev);
	netif_tx_wake_all_queues(session->adapter->dev);
unlock:
	mutex_unlock(&hdd_wonder_lock);
	return ret;
}

static const struct wondertap_monitor_ops hdd_wonder_monitor_ops = {
	.suspend = hdd_wonder_suspend,
	.resume = hdd_wonder_resume,
};

static const struct wondertap_ops hdd_wonder_ops = {
	.init = hdd_wonder_init,
	.deinit = hdd_wonder_deinit,
	.set_freq = hdd_wonder_set_freq,
	.set_filter = hdd_wonder_set_filter,
	.set_fixed_tx_rate = hdd_wonder_set_fixed_rate,
	.set_tx_rate_mask = hdd_wonder_set_rate_mask,
	.get_capabilities = hdd_wonder_capabilities,
	.channel_schedule_request = hdd_wonder_schedule,
	.get_mac_tsf = hdd_wonder_tsf,
	.get_channel_status_report = hdd_wonder_channel_status,
	.set_station_info = hdd_wonder_station,
};

static void hdd_wonder_release(struct device *dev)
{
	struct auxiliary_device *adev = to_auxiliary_dev(dev);
	struct wondertap_aux_dev *tap = container_of(adev, struct wondertap_aux_dev, adev);
	struct wondertap_monitor_aux_dev *monitor =
		container_of(tap, struct wondertap_monitor_aux_dev, tap);
	struct hdd_wonder_provider *provider =
		container_of(monitor, struct hdd_wonder_provider, monitor);

	kfree(provider);
}

static void __hdd_wonder_register(struct hdd_context *hdd_ctx)
{
	struct hdd_wonder_provider *provider;
	int ret;

	if (!wonder_enabled || hdd_get_conparam() != QDF_GLOBAL_MISSION_MODE)
		return;
	provider = kzalloc(sizeof(*provider), GFP_KERNEL);
	if (!provider)
		return;
	provider->hdd_ctx = hdd_ctx;
	provider->monitor.tap.ver = WONDER_VERSION_3_6_6;
	provider->monitor.tap.wonder_ops = &hdd_wonder_ops;
	provider->monitor.monitor_ops = &hdd_wonder_monitor_ops;
	provider->monitor.tap.adev.name = "wondertap";
	provider->monitor.tap.adev.id = 0;
	provider->monitor.tap.adev.dev.parent = hdd_ctx->parent_dev;
	provider->monitor.tap.adev.dev.release = hdd_wonder_release;
	ret = auxiliary_device_init(&provider->monitor.tap.adev);
	if (ret) {
		kfree(provider);
		return;
	}
	mutex_lock(&hdd_wonder_lock);
	if (hdd_wonder_provider) {
		mutex_unlock(&hdd_wonder_lock);
		auxiliary_device_uninit(&provider->monitor.tap.adev);
		return;
	}
	hdd_wonder_provider = provider;
	mutex_unlock(&hdd_wonder_lock);
	/* Probing the core can query capabilities; never hold the callback lock. */
	ret = auxiliary_device_add(&provider->monitor.tap.adev);
	if (ret) {
		mutex_lock(&hdd_wonder_lock);
		hdd_wonder_provider = NULL;
		mutex_unlock(&hdd_wonder_lock);
		auxiliary_device_uninit(&provider->monitor.tap.adev);
		hdd_warn("Wonder auxiliary registration failed: %d", ret);
	}
}

static void __hdd_wonder_unregister(struct hdd_context *hdd_ctx)
{
	struct hdd_wonder_provider *provider;

	mutex_lock(&hdd_wonder_lock);
	provider = hdd_wonder_provider;
	if (!provider || provider->hdd_ctx != hdd_ctx || provider->removing) {
		mutex_unlock(&hdd_wonder_lock);
		return;
	}
	provider->removing = true;
	mutex_unlock(&hdd_wonder_lock);
	/* Core removal drains RX and releases its netdev reference before deinit. */
	auxiliary_device_delete(&provider->monitor.tap.adev);
	rtnl_lock();
	mutex_lock(&hdd_wonder_lock);
	hdd_wonder_close_session(provider);
	hdd_wonder_provider = NULL;
	mutex_unlock(&hdd_wonder_lock);
	rtnl_unlock();
	auxiliary_device_uninit(&provider->monitor.tap.adev);
}

void hdd_wonder_register(struct hdd_context *hdd_ctx)
{
	mutex_lock(&hdd_wonder_lifecycle_lock);
	__hdd_wonder_register(hdd_ctx);
	mutex_unlock(&hdd_wonder_lifecycle_lock);
}

void hdd_wonder_unregister(struct hdd_context *hdd_ctx)
{
	mutex_lock(&hdd_wonder_lifecycle_lock);
	__hdd_wonder_unregister(hdd_ctx);
	mutex_unlock(&hdd_wonder_lifecycle_lock);
}

#endif /* FEATURE_WLAN_WONDER */
