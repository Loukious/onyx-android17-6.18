// SPDX-License-Identifier: GPL-2.0-only
/* A private SCM scan reserves airtime without rewriting the STA's HOME BSS. */
#include <linux/bitmap.h>
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/kref.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/math64.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <wlan_hdd_main.h>
#include <wlan_hdd_wonder_coex.h>
#include <wlan_hdd_wonder_dwell.h>
#include <wlan_mlme_sta_mon.h>
#include <wlan_scan_api.h>

#ifdef FEATURE_WLAN_WONDER

struct hdd_wonder_coex {
	struct kref ref;
	spinlock_t lock;
	struct wlan_objmgr_psoc *psoc;
	struct hdd_wonder_dwell dwell;
	struct hdd_wonder_dwell_owner owner;
	struct wma_wonder_helper_snapshot helper;
	struct completion entry;
	struct delayed_work expiry;
	struct work_struct free_work;
	DECLARE_BITMAP(scan_ids, 4096);
	u64 entry_ns;
	u64 event_count;
	u64 last_event_ns;
	u32 last_event_type;
	u32 last_event_reason;
	u32 last_event_frequency;
	u32 last_notice;
	u32 logical_frequency;
	u32 requester;
	u8 monitor_id;
	bool detached;
	bool scan_ref;
};

struct hdd_wonder_coex_tx_token {
	struct hdd_wonder_coex *coex;
	struct hdd_wonder_dwell_owner owner;
	struct hdd_wonder_dwell_scan scan;
	u64 deadline_ns;
};

static void hdd_wonder_coex_free_work(struct work_struct *work)
{
	struct hdd_wonder_coex *coex = container_of(work, struct hdd_wonder_coex,
						 free_work);

	if (coex->requester)
		wlan_scan_unregister_requester(coex->psoc, coex->requester);
	wlan_objmgr_psoc_release_ref(coex->psoc, WLAN_SCAN_ID);
	kfree(coex);
	module_put(THIS_MODULE);
}

static void hdd_wonder_coex_release(struct kref *ref)
{
	struct hdd_wonder_coex *coex = container_of(ref, struct hdd_wonder_coex, ref);

	/* The last reference can be released under the target admission lock. */
	schedule_work(&coex->free_work);
}

/* SCM synthetic completion is deliberately not a firmware drain witness. */
static void hdd_wonder_coex_scm_event(struct wlan_objmgr_vdev *vdev,
		struct scan_event *event, void *arg)
{
	(void)vdev;
	(void)event;
	(void)arg;
}

static void hdd_wonder_coex_notice(void *arg, const struct scan_event *event,
		enum wlan_mlme_sta_mon_scan_notice notice,
		u64 generation, u64 helper_cookie)
{
	struct hdd_wonder_coex *coex = arg;
	struct hdd_wonder_dwell_event observed = {
		.owner = { generation, helper_cookie },
		.vdev_id = event->vdev_id,
		.requester = event->requester,
		.scan_id = event->scan_id,
		.freq = event->chan_freq,
		.target_timestamp = event->timestamp,
		.target_timestamp_valid = true,
	};
	u64 now_ns = ktime_get_ns();
	bool retired = false;

	/* MLME admission is already held. Never call back into MLME here. */
	spin_lock(&coex->lock);
	coex->event_count++;
	coex->last_event_ns = now_ns;
	coex->last_event_type = event->type;
	coex->last_event_reason = event->reason;
	coex->last_event_frequency = event->chan_freq;
	coex->last_notice = notice;
	if (notice == WLAN_STA_MON_SCAN_NOT_SUBMITTED) {
		retired = hdd_wonder_dwell_not_submitted(&coex->dwell,
				&observed.owner, &coex->dwell.scan);
	} else {
		switch (event->type) {
		case SCAN_EVENT_TYPE_STARTED:
			observed.type = HDD_WONDER_DWELL_STARTED;
			break;
		case SCAN_EVENT_TYPE_FOREIGN_CHANNEL:
			observed.type = HDD_WONDER_DWELL_FOREIGN_CHANNEL;
			break;
		case SCAN_EVENT_TYPE_FOREIGN_CHANNEL_EXIT:
			observed.type = HDD_WONDER_DWELL_FOREIGN_CHANNEL_EXIT;
			break;
		case SCAN_EVENT_TYPE_BSS_CHANNEL:
			observed.type = HDD_WONDER_DWELL_BSS_CHANNEL;
			break;
		case SCAN_EVENT_TYPE_COMPLETED:
		case SCAN_EVENT_TYPE_START_FAILED:
		case SCAN_EVENT_TYPE_DEQUEUED:
			observed.type = HDD_WONDER_DWELL_TERMINAL;
			break;
		case SCAN_EVENT_TYPE_PREEMPTED:
			observed.type = HDD_WONDER_DWELL_PREEMPTED;
			break;
		case SCAN_EVENT_TYPE_SUSPENDED:
			observed.type = HDD_WONDER_DWELL_SUSPENDED;
			break;
		default:
			/* Resume/restart or unknown events cannot reopen an old lease. */
			observed.type = HDD_WONDER_DWELL_RESTARTED;
			break;
		}
		if (hdd_wonder_dwell_event(&coex->dwell, &observed, now_ns)) {
			retired = observed.type == HDD_WONDER_DWELL_TERMINAL;
			if (coex->dwell.phase == HDD_WONDER_DWELL_READY &&
			    !coex->entry_ns)
				coex->entry_ns = now_ns;
		}
	}
	if (coex->entry_ns || retired || coex->dwell.revoked)
		complete_all(&coex->entry);
	if (retired && coex->scan_ref)
		coex->scan_ref = false;
	else
		retired = false;
	spin_unlock(&coex->lock);
	if (retired)
		kref_put(&coex->ref, hdd_wonder_coex_release);
}

static void hdd_wonder_coex_send_cancel(struct hdd_wonder_coex *coex,
		const struct hdd_wonder_dwell_scan *scan)
{
	struct scan_cancel_request *req;
	struct wlan_objmgr_vdev *vdev;

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(coex->psoc,
			scan->vdev_id, WLAN_SCAN_ID);
	if (!vdev)
		return;
	req = qdf_mem_malloc(sizeof(*req));
	if (req) {
		req->vdev = vdev;
		req->cancel_req.scan_id = scan->scan_id;
		req->cancel_req.requester = scan->requester;
		req->cancel_req.vdev_id = scan->vdev_id;
		req->cancel_req.req_type = WLAN_SCAN_CANCEL_SINGLE;
		wlan_scan_cancel(req);
	}
	wlan_objmgr_vdev_release_ref(vdev, WLAN_SCAN_ID);
}

void hdd_wonder_coex_cancel(struct hdd_wonder_coex *coex)
{
	struct hdd_wonder_dwell_scan scan;
	unsigned long flags;
	bool cancel;

	if (!coex)
		return;
	spin_lock_irqsave(&coex->lock, flags);
	scan = coex->dwell.scan;
	cancel = hdd_wonder_dwell_cancel(&coex->dwell, &coex->owner, &scan);
	complete_all(&coex->entry);
	spin_unlock_irqrestore(&coex->lock, flags);
	if (cancel)
		hdd_wonder_coex_send_cancel(coex, &scan);
}

static void hdd_wonder_coex_expiry(struct work_struct *work)
{
	struct hdd_wonder_coex *coex = container_of(to_delayed_work(work),
						struct hdd_wonder_coex, expiry);

	struct hdd_wonder_dwell_scan scan;
	unsigned long flags;
	u64 now_ns = ktime_get_ns();
	bool cancel = false;

	spin_lock_irqsave(&coex->lock, flags);
	/* An earlier scan may complete before its expiry work runs. Only the
	 * current lease's unchanged deadline can cancel the current scan.
	 */
	if (!coex->detached && coex->dwell.phase != HDD_WONDER_DWELL_IDLE &&
	    now_ns >= coex->dwell.deadline_ns) {
		scan = coex->dwell.scan;
		cancel = hdd_wonder_dwell_cancel(&coex->dwell, &coex->owner, &scan);
		complete_all(&coex->entry);
	}
	spin_unlock_irqrestore(&coex->lock, flags);
	if (cancel)
		hdd_wonder_coex_send_cancel(coex, &scan);
}

struct hdd_wonder_coex *hdd_wonder_coex_create(struct hdd_adapter *adapter,
		u32 home_frequency, u64 generation,
		const struct wma_wonder_helper_snapshot *helper)
{
	struct hdd_wonder_coex *coex;
	struct wlan_objmgr_psoc *psoc = adapter->hdd_ctx->psoc;
	struct wlan_mlme_sta_mon_snapshot snapshot;

	if (!helper || !generation || !helper->cookie ||
	    !wlan_mlme_sta_mon_get_snapshot(psoc, adapter->deflink->vdev_id,
					  generation, &snapshot) ||
	    snapshot.ap_owner || snapshot.exclusive ||
	    snapshot.channel.ch_freq != home_frequency)
		return ERR_PTR(-EOPNOTSUPP);
	if (!try_module_get(THIS_MODULE))
		return ERR_PTR(-ESHUTDOWN);
	if (QDF_IS_STATUS_ERROR(wlan_objmgr_psoc_try_get_ref(psoc, WLAN_SCAN_ID))) {
		module_put(THIS_MODULE);
		return ERR_PTR(-ESHUTDOWN);
	}
	coex = kzalloc(sizeof(*coex), GFP_KERNEL);
	if (!coex) {
		wlan_objmgr_psoc_release_ref(psoc, WLAN_SCAN_ID);
		module_put(THIS_MODULE);
		return ERR_PTR(-ENOMEM);
	}
	kref_init(&coex->ref);
	spin_lock_init(&coex->lock);
	init_completion(&coex->entry);
	INIT_DELAYED_WORK(&coex->expiry, hdd_wonder_coex_expiry);
	INIT_WORK(&coex->free_work, hdd_wonder_coex_free_work);
	coex->psoc = psoc;
	coex->helper = *helper;
	coex->owner.generation = generation;
	coex->owner.helper_cookie = helper->cookie;
	coex->monitor_id = adapter->deflink->vdev_id;
	coex->logical_frequency = home_frequency;
	hdd_wonder_dwell_init(&coex->dwell, HDD_WONDER_COEX_MAX_DWELL_NS);
	hdd_wonder_dwell_set_home(&coex->dwell, snapshot.sta_vdev_id, home_frequency);
	coex->requester = wlan_scan_register_requester(psoc, (u8 *)"wonder-dwell",
					hdd_wonder_coex_scm_event, NULL);
	if (!coex->requester) {
		kref_put(&coex->ref, hdd_wonder_coex_release);
		return ERR_PTR(-ENOSPC);
	}
	return coex;
}

void hdd_wonder_coex_destroy(struct hdd_wonder_coex *coex)
{
	unsigned long flags;

	if (!coex)
		return;
	spin_lock_irqsave(&coex->lock, flags);
	coex->detached = true;
	hdd_wonder_dwell_invalidate(&coex->dwell);
	complete_all(&coex->entry);
	spin_unlock_irqrestore(&coex->lock, flags);
	cancel_delayed_work_sync(&coex->expiry);
	hdd_wonder_coex_cancel(coex);
	kref_put(&coex->ref, hdd_wonder_coex_release);
}

int hdd_wonder_coex_home(struct hdd_wonder_coex *coex)
{
	unsigned long flags;
	int ret;

	hdd_wonder_coex_cancel(coex);
	spin_lock_irqsave(&coex->lock, flags);
	coex->logical_frequency = coex->dwell.home_freq;
	ret = coex->detached ? -ESHUTDOWN :
		coex->dwell.phase == HDD_WONDER_DWELL_IDLE ? 0 : -EBUSY;
	spin_unlock_irqrestore(&coex->lock, flags);
	return ret;
}

int hdd_wonder_coex_acquire(struct hdd_wonder_coex *coex, u32 frequency,
		u64 slot_end_ns, u64 duration_ns, u64 *completion_ns)
{
	struct wlan_mlme_sta_mon_scan_reservation reservation;
	struct hdd_wonder_dwell_scan scan;
	struct scan_start_request *req;
	struct wlan_objmgr_vdev *vdev;
	unsigned long flags;
	u64 now_ns = ktime_get_ns(), deadline_ns, remaining_ns;
	QDF_STATUS status;
	int ret = -EBUSY;
	bool released = false;

	if (!coex || !frequency || !completion_ns || slot_end_ns <= now_ns)
		return -EINVAL;
	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(coex->psoc,
			coex->monitor_id, WLAN_SCAN_ID);
	if (!vdev)
		return -ESHUTDOWN;
	req = qdf_mem_malloc(sizeof(*req));
	if (!req) {
		ret = -ENOMEM;
		goto release_vdev;
	}
	status = wlan_scan_init_default_params(vdev, req);
	if (QDF_IS_STATUS_ERROR(status)) {
		ret = qdf_status_to_os_return(status);
		qdf_mem_free(req);
		goto release_vdev;
	}
	scan.vdev_id = coex->monitor_id;
	scan.requester = coex->requester;
	scan.scan_id = wlan_scan_get_scan_id(coex->psoc);
	scan.freq = frequency;
	spin_lock_irqsave(&coex->lock, flags);
	if (coex->detached || test_bit(scan.scan_id & 4095, coex->scan_ids) ||
	    !hdd_wonder_dwell_reserve(&coex->dwell, &coex->owner, &scan,
				now_ns, slot_end_ns, duration_ns)) {
		spin_unlock_irqrestore(&coex->lock, flags);
		qdf_mem_free(req);
		goto release_vdev;
	}
	set_bit(scan.scan_id & 4095, coex->scan_ids);
	coex->logical_frequency = frequency;
	deadline_ns = coex->dwell.deadline_ns;
	coex->entry_ns = 0;
	reinit_completion(&coex->entry);
	kref_get(&coex->ref);
	coex->scan_ref = true;
	spin_unlock_irqrestore(&coex->lock, flags);
	reservation.generation = coex->owner.generation;
	reservation.helper_cookie = coex->owner.helper_cookie;
	reservation.vdev_id = scan.vdev_id;
	reservation.scan_id = scan.scan_id;
	reservation.requester = scan.requester;
	reservation.frequency = frequency;
	if (!wlan_mlme_sta_mon_scan_reserve(coex->psoc, &reservation,
					 hdd_wonder_coex_notice, coex)) {
		qdf_mem_free(req);
		released = true;
		goto submission_failed;
	}
	req->vdev = vdev;
	req->scan_req.scan_id = scan.scan_id;
	req->scan_req.scan_req_id = scan.requester;
	req->scan_req.vdev_id = scan.vdev_id;
	req->scan_req.scan_type = SCAN_TYPE_DEFAULT;
	req->scan_req.chan_list.num_chan = 1;
	req->scan_req.chan_list.chan[0].freq = frequency;
	req->scan_req.scan_flags = 0;
	req->scan_req.scan_f_passive = true;
	req->scan_req.scan_f_offchan_data_tx = true;
	req->scan_req.scan_f_offchan_mgmt_tx = true;
	req->scan_req.scan_f_promisc_mode = true;
	req->scan_req.scan_ev_started = true;
	req->scan_req.scan_ev_completed = true;
	req->scan_req.scan_ev_bss_chan = true;
	req->scan_req.scan_ev_foreign_chan = true;
	req->scan_req.scan_ev_foreign_chn_exit = true;
	req->scan_req.scan_ev_dequeued = true;
	req->scan_req.scan_ev_preempted = true;
	req->scan_req.scan_ev_start_failed = true;
	req->scan_req.scan_ev_restarted = true;
	req->scan_req.scan_ev_suspended = true;
	req->scan_req.adaptive_dwell_time_mode = SCAN_DWELL_MODE_STATIC;
	/* Round down so firmware never receives a dwell longer than the lease. */
	req->scan_req.dwell_time_passive = div_u64(deadline_ns - now_ns, NSEC_PER_MSEC);
	req->scan_req.dwell_time_active = 0;
	req->scan_req.dwell_time_active_2g = 0;
	req->scan_req.dwell_time_active_6g = 0;
	req->scan_req.max_scan_time = req->scan_req.dwell_time_passive;
	req->scan_req.burst_duration = req->scan_req.dwell_time_passive;
	if (!req->scan_req.dwell_time_passive) {
		qdf_mem_free(req);
		released = wlan_mlme_sta_mon_scan_release_unsubmitted(coex->psoc,
							      &reservation);
		goto submission_failed;
	}
	status = wlan_scan_start(req); /* owns req on every return */
	if (QDF_IS_STATUS_ERROR(status)) {
		ret = qdf_status_to_os_return(status);
		released = wlan_mlme_sta_mon_scan_release_unsubmitted(coex->psoc,
							      &reservation);
		goto submission_failed;
	}
	wlan_objmgr_vdev_release_ref(vdev, WLAN_SCAN_ID);
	now_ns = ktime_get_ns();
	remaining_ns = deadline_ns > now_ns ? deadline_ns - now_ns : 0;
	mod_delayed_work(system_wq, &coex->expiry,
			nsecs_to_jiffies(remaining_ns) + 1);
	if (remaining_ns)
		wait_for_completion_timeout(&coex->entry,
			nsecs_to_jiffies(remaining_ns) + 1);
	spin_lock_irqsave(&coex->lock, flags);
	if (!coex->detached && hdd_wonder_dwell_ready(&coex->dwell,
			&coex->owner, &scan, ktime_get_ns())) {
		*completion_ns = coex->entry_ns;
		ret = 0;
	} else {
		ret = coex->detached ? -ESHUTDOWN : -EAGAIN;
	}
	spin_unlock_irqrestore(&coex->lock, flags);
	if (ret)
		hdd_wonder_coex_cancel(coex);
	return ret;

submission_failed:
	if (released) {
		spin_lock_irqsave(&coex->lock, flags);
		released = hdd_wonder_dwell_not_submitted(&coex->dwell,
						 &coex->owner, &scan) && coex->scan_ref;
		if (released)
			coex->scan_ref = false;
		spin_unlock_irqrestore(&coex->lock, flags);
		if (released)
			kref_put(&coex->ref, hdd_wonder_coex_release);
	}
release_vdev:
	wlan_objmgr_vdev_release_ref(vdev, WLAN_SCAN_ID);
	return ret;
}

static bool hdd_wonder_coex_ready_locked(struct hdd_wonder_coex *coex, u32 freq)
{
	if (coex->detached || !coex->dwell.home_valid)
		return false;
	if (!freq)
		freq = coex->logical_frequency;
	if (freq != coex->logical_frequency)
		return false;
	if (freq == coex->dwell.home_freq)
		return coex->dwell.phase == HDD_WONDER_DWELL_IDLE;
	return freq == coex->dwell.scan.freq &&
		hdd_wonder_dwell_ready(&coex->dwell, &coex->owner,
				       &coex->dwell.scan, ktime_get_ns());
}

bool hdd_wonder_coex_publish_begin(struct hdd_wonder_coex *coex,
		u32 packet_frequency, unsigned long *flags)
{
	if (!coex || !flags ||
	    !wlan_mlme_sta_mon_tx_begin(coex->psoc, coex->monitor_id,
				       coex->owner.generation, flags))
		return false;
	spin_lock(&coex->lock);
	if (hdd_wonder_coex_ready_locked(coex, packet_frequency))
		return true;
	spin_unlock(&coex->lock);
	wlan_mlme_sta_mon_tx_end(*flags);
	return false;
}

void hdd_wonder_coex_publish_end(struct hdd_wonder_coex *coex,
		unsigned long flags)
{
	spin_unlock(&coex->lock);
	wlan_mlme_sta_mon_tx_end(flags);
}

bool hdd_wonder_coex_ready(struct hdd_wonder_coex *coex, u32 frequency)
{
	unsigned long flags;

	if (!hdd_wonder_coex_publish_begin(coex, frequency, &flags))
		return false;
	hdd_wonder_coex_publish_end(coex, flags);
	return true;
}

void *hdd_wonder_coex_tx_token(struct hdd_wonder_coex *coex, u32 frequency)
{
	struct hdd_wonder_coex_tx_token *token;
	unsigned long flags;

	token = kzalloc(sizeof(*token), GFP_ATOMIC);
	if (!token)
		return ERR_PTR(-ENOMEM);
	if (!hdd_wonder_coex_publish_begin(coex, frequency, &flags)) {
		kfree(token);
		return ERR_PTR(-EAGAIN);
	}
	if (coex->logical_frequency == coex->dwell.home_freq) {
		hdd_wonder_coex_publish_end(coex, flags);
		kfree(token);
		return ERR_PTR(-EALREADY);
	}
	token->coex = coex;
	token->owner = coex->owner;
	token->scan = coex->dwell.scan;
	token->deadline_ns = coex->dwell.deadline_ns;
	kref_get(&coex->ref);
	hdd_wonder_coex_publish_end(coex, flags);
	return token;
}

bool hdd_wonder_coex_tx_begin(void *arg, unsigned long *flags)
{
	struct hdd_wonder_coex_tx_token *token = arg;
	struct hdd_wonder_coex *coex = token->coex;

	if (!hdd_wonder_coex_publish_begin(coex, token->scan.freq, flags))
		return false;
	if (coex->dwell.deadline_ns == token->deadline_ns &&
	    hdd_wonder_dwell_ready(&coex->dwell, &token->owner, &token->scan,
				  ktime_get_ns()))
		return true;
	hdd_wonder_coex_publish_end(coex, *flags);
	return false;
}

void hdd_wonder_coex_tx_end(void *arg, unsigned long flags)
{
	struct hdd_wonder_coex_tx_token *token = arg;

	hdd_wonder_coex_publish_end(token->coex, flags);
}

void hdd_wonder_coex_tx_release(void *arg)
{
	struct hdd_wonder_coex_tx_token *token = arg;

	kref_put(&token->coex->ref, hdd_wonder_coex_release);
	kfree(token);
}

u32 hdd_wonder_coex_tx_frequency(void *arg)
{
	struct hdd_wonder_coex_tx_token *token = arg;

	return token->scan.freq;
}

bool hdd_wonder_coex_rx_begin_locked(struct hdd_wonder_coex *coex,
		u64 generation, u32 frequency)
{
	if (!coex || coex->owner.generation != generation)
		return false;
	spin_lock(&coex->lock);
	if (hdd_wonder_coex_ready_locked(coex, frequency))
		return true;
	spin_unlock(&coex->lock);
	return false;
}

void hdd_wonder_coex_rx_end_locked(struct hdd_wonder_coex *coex)
{
	spin_unlock(&coex->lock);
}

u32 hdd_wonder_coex_home_frequency(struct hdd_wonder_coex *coex)
{
	return coex->dwell.home_freq;
}

const struct wma_wonder_helper_snapshot *
hdd_wonder_coex_helper(struct hdd_wonder_coex *coex)
{
	return &coex->helper;
}

u64 hdd_wonder_coex_generation(struct hdd_wonder_coex *coex)
{
	return coex->owner.generation;
}

int hdd_wonder_coex_format(struct hdd_wonder_coex *coex, char *buffer,
		size_t capacity)
{
	unsigned long flags;
	int length;

	spin_lock_irqsave(&coex->lock, flags);
	/* This is an observation, not a readiness claim or a firmware clock. */
	length = scnprintf(buffer, capacity,
		"home_vdev=%u home_mhz=%u monitor_vdev=%u helper_vdev=%u "
		"generation=%llu cookie=%llu requester=%u scan_id=%u scan_mhz=%u "
		"selected_mhz=%u phase=%u revoked=%u firmware_ref=%u "
		"deadline_host_ns=%llu entry_host_ns=%llu "
		"events=%llu last_type=%u last_reason=%u last_mhz=%u "
		"last_notice=%u last_event_host_ns=%llu target_timestamp_us=%u\n",
		coex->dwell.home_vdev_id, coex->dwell.home_freq,
		coex->monitor_id, coex->helper.vdev_id,
		coex->owner.generation, coex->owner.helper_cookie,
		coex->dwell.scan.requester, coex->dwell.scan.scan_id,
		coex->dwell.scan.freq, coex->logical_frequency,
		coex->dwell.phase, coex->dwell.revoked, coex->scan_ref,
		coex->dwell.deadline_ns, coex->entry_ns,
		coex->event_count, coex->last_event_type, coex->last_event_reason,
		coex->last_event_frequency, coex->last_notice, coex->last_event_ns,
		coex->dwell.target_timestamp);
	spin_unlock_irqrestore(&coex->lock, flags);
	return length;
}

#endif
