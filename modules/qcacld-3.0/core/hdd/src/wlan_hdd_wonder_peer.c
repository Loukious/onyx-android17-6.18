// SPDX-License-Identifier: GPL-2.0-only
/* AWDL peer bookkeeping and the real Onyx receive MAC matcher. */
#include <linux/completion.h>
#include <linux/etherdevice.h>
#include <linux/err.h>
#include <linux/jiffies.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <wlan_hdd_main.h>
#include <wlan_hdd_wonder_peer.h>
#include <wlan_hdd_wonder_rate.h>
#include <wlan_vdev_mgr_tgt_if_tx_defs.h>
#include <wma_api.h>
#include <wondertap_monitor.h>

#ifdef FEATURE_WLAN_WONDER

#define HDD_WONDER_MAX_PEERS 64
#define HDD_WONDER_MATCH_TIMEOUT msecs_to_jiffies(2000)

struct hdd_wonder_peer_entry {
	bool used;
	struct wondertap_station_info info;
};

struct hdd_wonder_peer_state {
	struct mutex operation_lock;
	spinlock_t peers_lock;
	struct completion reply_done;
	struct hdd_adapter *adapter;
	struct wlan_objmgr_psoc *psoc;
	struct hdd_wonder_peer_entry peers[HDD_WONDER_MAX_PEERS];
	u8 bound_id;
	u32 frequency;
	u64 generation;
	u64 helper_cookie;
	int error;
	bool stopping;
};

struct hdd_wonder_match {
	struct wlan_objmgr_psoc *psoc;
	struct hdd_wonder_peer_state *owner;
	u8 mac[ETH_ALEN];
	u32 frequency;
	u64 helper_cookie;
	int reply;
	bool used;
	bool pending;
	bool active;
	bool poisoned;
	bool clear_started;
	bool clear_submitted;
};

static DEFINE_SPINLOCK(hdd_wonder_match_lock);
static struct hdd_wonder_match hdd_wonder_matches[WLAN_UMAC_PSOC_MAX_VDEVS];
/* A reply has no MAC, frequency or token. Never retry an uncertain request. */
static struct wlan_objmgr_psoc *hdd_wonder_poisoned_psoc;

/* Caller holds hdd_wonder_match_lock. */
static void hdd_wonder_match_fault(struct hdd_wonder_match *match, int error)
{
	match->poisoned = true;
	match->active = false;
	match->pending = false;
	hdd_wonder_poisoned_psoc = match->psoc;
	if (match->owner) {
		if (!match->owner->error)
			match->owner->error = error;
		complete_all(&match->owner->reply_done);
	}
}

struct hdd_wonder_peer_state *
hdd_wonder_peer_create(struct hdd_adapter *adapter)
{
	struct hdd_wonder_peer_state *state;

	if (!adapter || !adapter->hdd_ctx || !adapter->hdd_ctx->psoc ||
	    !is_valid_ether_addr(adapter->mac_addr.bytes))
		return ERR_PTR(-EINVAL);
	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return ERR_PTR(-ENOMEM);
	mutex_init(&state->operation_lock);
	spin_lock_init(&state->peers_lock);
	init_completion(&state->reply_done);
	state->adapter = adapter;
	state->psoc = adapter->hdd_ctx->psoc;
	state->bound_id = WLAN_INVALID_VDEV_ID;
	return state;
}

bool hdd_wonder_peer_reply(struct wlan_objmgr_psoc *psoc, u32 id, u32 status)
{
	struct hdd_wonder_match *match;
	unsigned long flags;
	bool owned = false;

	if (id >= ARRAY_SIZE(hdd_wonder_matches))
		return false;
	spin_lock_irqsave(&hdd_wonder_match_lock, flags);
	match = &hdd_wonder_matches[id];
	if (!match->used || match->psoc != psoc)
		goto out;
	owned = true;
	if (!match->pending || match->poisoned || match->clear_started) {
		hdd_wonder_match_fault(match, -EPROTO);
		goto out;
	}
	match->pending = false;
	match->reply = status;
	/* Onyx's native P2P caller uses nonzero=accepted. The wire success is 1. */
	if (status > 1) {
		hdd_wonder_match_fault(match, -EPROTO);
		goto out;
	}
	match->active = status == 1;
	if (match->owner)
		complete_all(&match->owner->reply_done);
out:
	spin_unlock_irqrestore(&hdd_wonder_match_lock, flags);
	return owned;
}

int hdd_wonder_peer_prepare(struct hdd_wonder_peer_state *state,
			    u32 frequency, u64 generation)
{
	struct wma_wonder_helper_snapshot helper;
	struct hdd_wonder_match *match;
	unsigned long flags;
	QDF_STATUS status;
	int error;

	if (!state || !frequency)
		return -EINVAL;
	mutex_lock(&state->operation_lock);
	spin_lock_irqsave(&hdd_wonder_match_lock, flags);
	error = state->stopping ? -ESHUTDOWN : state->error;
	if (!error && hdd_wonder_poisoned_psoc == state->psoc)
		error = -EIO;
	spin_unlock_irqrestore(&hdd_wonder_match_lock, flags);
	if (error)
		goto out;
	status = wma_wonder_helper_prepare(state->adapter->deflink->vdev_id,
			frequency, state->adapter->mac_addr.bytes, generation, &helper);
	error = qdf_status_to_os_return(status);
	if (error)
		goto out;
	if (helper.vdev_id >= ARRAY_SIZE(hdd_wonder_matches)) {
		error = -EINVAL;
		goto out;
	}
	spin_lock_irqsave(&hdd_wonder_match_lock, flags);
	match = &hdd_wonder_matches[helper.vdev_id];
	if (state->stopping || state->error ||
	    hdd_wonder_poisoned_psoc == state->psoc) {
		error = state->error ? state->error : -ESHUTDOWN;
		goto unlock;
	}
	if (match->used) {
		/* One SET per actual helper lifetime; repeated same-channel calls reuse it. */
		error = match->owner == state && match->psoc == state->psoc &&
			match->helper_cookie == helper.cookie && match->active &&
			!match->clear_started && !match->poisoned &&
			match->frequency == frequency ? 0 : -EBUSY;
		goto unlock;
	}
	if (state->bound_id != WLAN_INVALID_VDEV_ID) {
		error = -EBUSY;
		goto unlock;
	}
	reinit_completion(&state->reply_done);
	memset(match, 0, sizeof(*match));
	match->used = true;
	match->pending = true;
	match->psoc = state->psoc;
	match->owner = state;
	match->frequency = frequency;
	match->helper_cookie = helper.cookie;
	match->reply = -EINPROGRESS;
	ether_addr_copy(match->mac, state->adapter->mac_addr.bytes);
	state->bound_id = helper.vdev_id;
	state->helper_cookie = helper.cookie;
	state->frequency = frequency;
	state->generation = generation;
	spin_unlock_irqrestore(&hdd_wonder_match_lock, flags);
	status = wma_wonder_helper_set_rx_mac(state->adapter->deflink->vdev_id,
			frequency, state->adapter->mac_addr.bytes, generation, &helper, true);
	if (QDF_IS_STATUS_ERROR(status)) {
		error = qdf_status_to_os_return(status);
		spin_lock_irqsave(&hdd_wonder_match_lock, flags);
		if (match->used && match->owner == state &&
		    match->helper_cookie == helper.cookie)
			hdd_wonder_match_fault(match, error);
		else if (!state->error)
			state->error = error;
		spin_unlock_irqrestore(&hdd_wonder_match_lock, flags);
		goto out;
	}
	if (!wait_for_completion_timeout(&state->reply_done, HDD_WONDER_MATCH_TIMEOUT)) {
		spin_lock_irqsave(&hdd_wonder_match_lock, flags);
		if (match->used && match->owner == state &&
		    match->helper_cookie == helper.cookie)
			hdd_wonder_match_fault(match, -ETIMEDOUT);
		else if (!state->error)
			state->error = -ETIMEDOUT;
		spin_unlock_irqrestore(&hdd_wonder_match_lock, flags);
	}
	spin_lock_irqsave(&hdd_wonder_match_lock, flags);
	if (state->stopping)
		error = -ESHUTDOWN;
	else if (state->error)
		error = state->error;
	else if (!match->used || match->owner != state || match->pending)
		error = -EIO;
	else
		error = match->active ? 0 : -ECANCELED;
unlock:
	spin_unlock_irqrestore(&hdd_wonder_match_lock, flags);
out:
	mutex_unlock(&state->operation_lock);
	return error;
}

bool hdd_wonder_peer_take_clear(struct wlan_objmgr_psoc *psoc, u8 id,
			       struct set_rx_mac_filter *param)
{
	struct hdd_wonder_match *match;
	unsigned long flags;
	bool submit = false;

	if (id >= ARRAY_SIZE(hdd_wonder_matches) || !param)
		return false;
	spin_lock_irqsave(&hdd_wonder_match_lock, flags);
	match = &hdd_wonder_matches[id];
	if (!match->used || match->psoc != psoc || match->clear_started)
		goto out;
	if (match->pending)
		hdd_wonder_match_fault(match, -ESHUTDOWN);
	match->active = false;
	match->clear_started = true;
	param->vdev_id = id;
	param->freq = match->frequency;
	ether_addr_copy(param->mac, match->mac);
	param->set = false;
	submit = true;
out:
	spin_unlock_irqrestore(&hdd_wonder_match_lock, flags);
	return submit;
}

void hdd_wonder_peer_clear_result(struct wlan_objmgr_psoc *psoc, u8 id,
				 int error)
{
	struct hdd_wonder_match *match;
	unsigned long flags;

	if (id >= ARRAY_SIZE(hdd_wonder_matches))
		return;
	spin_lock_irqsave(&hdd_wonder_match_lock, flags);
	match = &hdd_wonder_matches[id];
	if (match->used && match->psoc == psoc) {
		if (error)
			hdd_wonder_match_fault(match, error);
		else
			match->clear_submitted = true;
	}
	spin_unlock_irqrestore(&hdd_wonder_match_lock, flags);
}

int hdd_wonder_peer_clear(struct hdd_wonder_peer_state *state)
{
	struct wma_wonder_helper_snapshot helper;
	struct set_rx_mac_filter param = { 0 };
	unsigned long flags;
	QDF_STATUS status;
	int error = 0;

	if (!state)
		return 0;
	mutex_lock(&state->operation_lock);
	spin_lock_irqsave(&hdd_wonder_match_lock, flags);
	helper.vdev_id = state->bound_id;
	helper.cookie = state->helper_cookie;
	spin_unlock_irqrestore(&hdd_wonder_match_lock, flags);
	if (!hdd_wonder_peer_take_clear(state->psoc, helper.vdev_id, &param))
		goto out;
	status = wma_wonder_helper_set_rx_mac(state->adapter->deflink->vdev_id,
			param.freq, param.mac, state->generation, &helper, false);
	error = qdf_status_to_os_return(status);
	hdd_wonder_peer_clear_result(state->psoc, helper.vdev_id, error);
out:
	mutex_unlock(&state->operation_lock);
	return error;
}

void hdd_wonder_peer_helper_deleted(struct wlan_objmgr_psoc *psoc, u8 id)
{
	struct hdd_wonder_match *match;
	unsigned long flags;

	if (id >= ARRAY_SIZE(hdd_wonder_matches))
		return;
	spin_lock_irqsave(&hdd_wonder_match_lock, flags);
	match = &hdd_wonder_matches[id];
	if (match->used && match->psoc == psoc) {
		if (!match->clear_submitted || match->pending)
			hdd_wonder_match_fault(match, -EPROTO);
		if (match->owner) {
			match->owner->bound_id = WLAN_INVALID_VDEV_ID;
			complete_all(&match->owner->reply_done);
		}
		/* Only a real firmware DELETE retires routing. Session faults stay sticky. */
		memset(match, 0, sizeof(*match));
	}
	spin_unlock_irqrestore(&hdd_wonder_match_lock, flags);
}

void hdd_wonder_peer_firmware_started(struct wlan_objmgr_psoc *psoc)
{
	unsigned long flags;
	int i;

	spin_lock_irqsave(&hdd_wonder_match_lock, flags);
	for (i = 0; i < ARRAY_SIZE(hdd_wonder_matches); i++) {
		struct hdd_wonder_match *match = &hdd_wonder_matches[i];

		if (match->psoc && match->psoc != psoc)
			continue;
		if (match->owner) {
			match->owner->bound_id = WLAN_INVALID_VDEV_ID;
			match->owner->error = -ESHUTDOWN;
			complete_all(&match->owner->reply_done);
		}
		memset(match, 0, sizeof(*match));
	}
	if (hdd_wonder_poisoned_psoc == psoc)
		hdd_wonder_poisoned_psoc = NULL;
	spin_unlock_irqrestore(&hdd_wonder_match_lock, flags);
}

bool hdd_wonder_peer_ready(struct hdd_wonder_peer_state *state)
{
	struct hdd_wonder_match *match;
	unsigned long flags;
	bool ready = false;

	if (!state)
		return false;
	spin_lock_irqsave(&hdd_wonder_match_lock, flags);
	if (!state->stopping && !state->error &&
	    state->bound_id < ARRAY_SIZE(hdd_wonder_matches)) {
		match = &hdd_wonder_matches[state->bound_id];
		ready = match->used && match->psoc == state->psoc &&
			match->owner == state && match->active && !match->pending &&
			!match->poisoned && !match->clear_started &&
			match->helper_cookie == state->helper_cookie &&
			match->frequency == state->frequency;
	}
	spin_unlock_irqrestore(&hdd_wonder_match_lock, flags);
	return ready;
}

int hdd_wonder_peer_get_helper(struct hdd_wonder_peer_state *state,
			      struct wma_wonder_helper_snapshot *helper)
{
	struct hdd_wonder_match *match;
	unsigned long flags;
	int error = -EAGAIN;

	if (!state || !helper)
		return -EINVAL;
	spin_lock_irqsave(&hdd_wonder_match_lock, flags);
	if (state->stopping || state->error) {
		error = state->stopping ? -ESHUTDOWN : state->error;
		goto out;
	}
	if (state->bound_id >= ARRAY_SIZE(hdd_wonder_matches))
		goto out;
	match = &hdd_wonder_matches[state->bound_id];
	if (!match->used || match->psoc != state->psoc || match->owner != state ||
	    !match->active || match->pending || match->poisoned ||
	    match->clear_started || match->helper_cookie != state->helper_cookie ||
	    match->frequency != state->frequency)
		goto out;
	helper->vdev_id = state->bound_id;
	helper->cookie = state->helper_cookie;
	error = 0;
out:
	spin_unlock_irqrestore(&hdd_wonder_match_lock, flags);
	return error;
}

int hdd_wonder_peer_get_limits(struct hdd_wonder_peer_state *state,
			       struct hdd_wonder_peer_limits *limits)
{
	struct wma_wonder_helper_snapshot helper;
	struct wma_wonder_helper_limits prepared;
	unsigned long flags;
	QDF_STATUS status;
	int error;

	if (!state || !limits)
		return -EINVAL;
	mutex_lock(&state->operation_lock);
	if (!hdd_wonder_peer_ready(state)) {
		error = -EAGAIN;
		goto out;
	}
	spin_lock_irqsave(&hdd_wonder_match_lock, flags);
	helper.vdev_id = state->bound_id;
	helper.cookie = state->helper_cookie;
	spin_unlock_irqrestore(&hdd_wonder_match_lock, flags);
	status = wma_wonder_helper_get_limits(state->adapter->deflink->vdev_id,
			state->frequency, state->adapter->mac_addr.bytes,
			state->generation, &helper, &prepared);
	error = qdf_status_to_os_return(status);
	if (error)
		goto out;
	limits->frequency = prepared.frequency;
	limits->phy_mode = prepared.phy_mode;
	limits->max_nss = prepared.max_nss;
	limits->bandwidth = prepared.bandwidth_mask & BIT(4) ? WONDERTAP_RATE_BW_80 :
		prepared.bandwidth_mask & BIT(3) ? WONDERTAP_RATE_BW_40 : WONDERTAP_RATE_BW_20;
	limits->ht_supported = prepared.ht_supported;
	limits->vht_supported = prepared.vht_supported;
	limits->he_supported = prepared.he_supported;
out:
	mutex_unlock(&state->operation_lock);
	return error;
}

int hdd_wonder_peer_validate_rate(struct hdd_wonder_peer_state *state,
				 const struct wondertap_fixed_tx_rate_params *rate)
{
	struct hdd_wonder_peer_limits limits;
	int error;

	error = wondertap_monitor_validate_rate(rate);
	if (error)
		return error;
	error = hdd_wonder_peer_get_limits(state, &limits);
	if (error)
		return error;
	if (rate->nss > limits.max_nss || rate->bw > limits.bandwidth)
		return -EOPNOTSUPP;
	switch (rate->preamble) {
	case WONDERTAP_RATE_PREAMBLE_HT:
		return limits.ht_supported ? 0 : -EOPNOTSUPP;
	case WONDERTAP_RATE_PREAMBLE_VHT:
		return limits.vht_supported ? 0 : -EOPNOTSUPP;
	case WONDERTAP_RATE_PREAMBLE_HE:
		return limits.he_supported ? 0 : -EOPNOTSUPP;
	default:
		return -EOPNOTSUPP;
	}
}

void hdd_wonder_peer_cancel(struct hdd_wonder_peer_state *state)
{
	unsigned long flags;

	if (!state)
		return;
	spin_lock_irqsave(&hdd_wonder_match_lock, flags);
	state->stopping = true;
	complete_all(&state->reply_done);
	spin_unlock_irqrestore(&hdd_wonder_match_lock, flags);
}

void hdd_wonder_peer_destroy(struct hdd_wonder_peer_state *state)
{
	unsigned long flags;
	int i;

	if (!state)
		return;
	hdd_wonder_peer_cancel(state);
	hdd_wonder_peer_clear(state);
	mutex_lock(&state->operation_lock);
	spin_lock_irqsave(&hdd_wonder_match_lock, flags);
	for (i = 0; i < ARRAY_SIZE(hdd_wonder_matches); i++)
		if (hdd_wonder_matches[i].owner == state)
			hdd_wonder_matches[i].owner = NULL;
	spin_unlock_irqrestore(&hdd_wonder_match_lock, flags);
	mutex_unlock(&state->operation_lock);
	kfree(state);
}

/* Called in the packet path under the provider RCU lifetime. Never sleep. */
void hdd_wonder_peer_tx_rate(struct hdd_wonder_peer_state *state,
		const u8 *destination, struct cdp_tx_injection_params *rate)
{
	struct wondertap_station_info peer;
	unsigned long flags;
	bool found = false;
	int i;

	if (!state || !destination || !rate || !rate->is_data)
		return;
	if (!is_multicast_ether_addr(destination)) {
		spin_lock_irqsave(&state->peers_lock, flags);
		for (i = 0; i < ARRAY_SIZE(state->peers); i++) {
			if (state->peers[i].used &&
			    ether_addr_equal(state->peers[i].info.mac, destination)) {
				peer = state->peers[i].info;
				found = true;
				break;
			}
		}
		spin_unlock_irqrestore(&state->peers_lock, flags);
	}
	hdd_wonder_peer_constrain_rate(found ? &peer : NULL, rate);
}

int hdd_wonder_peer_station(struct hdd_wonder_peer_state *state,
			    enum wondertap_station_action action,
			    struct wondertap_station_info *info)
{
	struct hdd_wonder_peer_entry *entry = NULL, *free_entry = NULL;
	unsigned long flags;
	int i, error = 0;

	if (!state || !info || !is_valid_ether_addr(info->mac) ||
	    action < WONDERTAP_STATION_STATE_NEW || action >= WONDERTAP_STATION_MAX)
		return -EINVAL;
	if ((action == WONDERTAP_STATION_STATE_NEW ||
	     action == WONDERTAP_STATION_STATE_UPDATE) &&
	    ((info->capability_mask & ~GENMASK(WONDERTAP_STATION_CAP_MAX - 1, 0)) ||
	     info->he_capa_len > sizeof(info->he_capa)))
		return -EINVAL;
	mutex_lock(&state->operation_lock);
	if (READ_ONCE(state->stopping)) {
		error = -ESHUTDOWN;
		goto out;
	}
	spin_lock_irqsave(&state->peers_lock, flags);
	for (i = 0; i < ARRAY_SIZE(state->peers); i++) {
		if (!state->peers[i].used && !free_entry)
			free_entry = &state->peers[i];
		if (state->peers[i].used &&
		    ether_addr_equal(state->peers[i].info.mac, info->mac))
			entry = &state->peers[i];
	}
	/* Raw injection addresses the established helper self peer. Destination
	 * stations remain mac80211 peers; these records do not create FW peers.
	 */
	switch (action) {
	case WONDERTAP_STATION_STATE_NEW:
		if (entry) {
			error = -EEXIST;
			break;
		}
		if (!free_entry) {
			error = -ENOSPC;
			break;
		}
		free_entry->used = true;
		free_entry->info = *info;
		break;
	case WONDERTAP_STATION_STATE_UPDATE:
		if (!entry)
			error = -ENOENT;
		else
			entry->info = *info;
		break;
	case WONDERTAP_STATION_STATE_DEL:
		if (entry)
			memset(entry, 0, sizeof(*entry));
		break;
	case WONDERTAP_STATION_STATE_QUERY:
		if (!entry)
			error = -ENOENT;
		else
			*info = entry->info;
		break;
	default:
		error = -EINVAL;
	}
	spin_unlock_irqrestore(&state->peers_lock, flags);
out:
	mutex_unlock(&state->operation_lock);
	return error;
}
#endif /* FEATURE_WLAN_WONDER */
