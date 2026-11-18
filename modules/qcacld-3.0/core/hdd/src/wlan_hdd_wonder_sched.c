// SPDX-License-Identifier: GPL-2.0-only
/* Host scheduling uses a measured firmware TSF/QTIMER pair, never host uptime. */
#include <linux/err.h>
#include <linux/hrtimer.h>
#include <linux/kref.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/math64.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <qdf_time.h>
#include <wlan_hdd_includes.h>
#include <wlan_hdd_main.h>
#include <wlan_hdd_wonder_sched.h>
#include <wma_wonder_tsf.h>
#include "osif_vdev_sync.h"

#ifdef FEATURE_WLAN_WONDER

#define HDD_WONDER_TSF_REFRESH_MS 2000
#define HDD_WONDER_TSF_MAX_AGE_NS (10ULL * NSEC_PER_SEC)
#define HDD_WONDER_TSF_MAX_CAPTURE_AGE_US 1000000ULL
#define HDD_WONDER_TSF_CLOCK_JUMP_US 2000ULL
#define HDD_WONDER_SWITCH_RETRY_NS (1000ULL * NSEC_PER_USEC)
#define HDD_WONDER_CHANNELS_MAX U8_MAX

struct hdd_wonder_slot {
	struct wondertap_channel_status status;
	u64 start_tsf;
	u64 end_tsf;
	u64 tx_us;
	u64 rx_us;
};

struct hdd_wonder_plan {
	struct kref ref;
	u64 generation;
	u64 dwell_us;
	u64 next_tsf;
	u64 next_host_ns;
	u64 switch_end_host_ns;
	u64 switch_duration_ns;
	u32 request_tsf;
	u32 next_index;
	u32 current_index;
	u8 count;
	bool slot_active;
	bool switch_pending;
	struct wondertap_channel_list_params channels[HDD_WONDER_CHANNELS_MAX];
	struct hdd_wonder_slot slots[HDD_WONDER_CHANNELS_MAX];
};

struct hdd_wonder_clock {
	struct wma_wonder_tsf_sample sample;
	u64 sample_host_ns;
	u64 helper_cookie;
	u8 vdev_id;
	bool valid;
};

struct hdd_wonder_sched {
	struct hdd_adapter *adapter;
	void *context;
	struct hdd_wonder_sched_ops ops;
	struct workqueue_struct *workqueue;
	struct work_struct switch_work;
	struct delayed_work sync_work;
	struct hrtimer timer;
	struct mutex sample_lock;
	spinlock_t lock;
	struct hdd_wonder_clock clock;
	/* Last proven pair survives an unbind and CLOCK_MONOTONIC suspension. */
	struct hdd_wonder_clock continuity;
	struct hdd_wonder_plan *plan;
	u64 generation;
	u64 identity_sequence;
	u64 current_host_ns;
	u32 current_freq;
	enum wondertap_rate_bw current_bandwidth;
	u8 tsf_vdev_id;
	u64 tsf_helper_cookie;
	int last_error;
	bool running;
	bool tsf_bound;
};

static void hdd_wonder_plan_release(struct kref *ref)
{
	kfree(container_of(ref, struct hdd_wonder_plan, ref));
}

static int hdd_wonder_clock_tsf(const struct hdd_wonder_clock *clock,
			       u64 host_ns, u64 *tsf)
{
	s64 delta_us;

	if (!clock->valid)
		return -ENODATA;
	delta_us = div_s64((s64)(host_ns - clock->sample_host_ns), NSEC_PER_USEC);
	if (delta_us < 0 && (u64)-delta_us > clock->sample.tsf_us)
		return -ERANGE;
	*tsf = clock->sample.tsf_us + delta_us;
	return 0;
}

static u64 hdd_wonder_clock_host(const struct hdd_wonder_clock *clock, u64 tsf)
{
	s64 delta_us = (s64)(tsf - clock->sample.tsf_us);

	/* A valid old MAC TSF can predate this kernel's monotonic clock epoch. */
	if (delta_us < 0 && (u64)-delta_us >
	    div64_u64(clock->sample_host_ns, NSEC_PER_USEC))
		return 0;
	return clock->sample_host_ns + delta_us * NSEC_PER_USEC;
}

static u16 hdd_wonder_traffic_index(u64 airtime_us, u64 elapsed_us)
{
	if (!elapsed_us)
		return 0;
	if (airtime_us >= elapsed_us)
		return 100;
	return div64_u64(airtime_us * 100, elapsed_us);
}

static void hdd_wonder_slot_end(struct hdd_wonder_plan *plan, u64 tsf)
{
	struct hdd_wonder_slot *slot;
	u64 duration;

	if (!plan->slot_active)
		return;
	slot = &plan->slots[plan->current_index];
	if (tsf < slot->start_tsf)
		return;
	slot->end_tsf = tsf;
	slot->status.channel_end_tsf = (u32)tsf;
	duration = tsf - slot->start_tsf;
	slot->status.tx_traffic_index = hdd_wonder_traffic_index(slot->tx_us, duration);
	slot->status.rx_traffic_index = hdd_wonder_traffic_index(slot->rx_us, duration);
	plan->slot_active = false;
}

/* sample_lock is held; explicit bind callers already hold a vdev/psoc op. */
static int hdd_wonder_sched_capture_clock(struct hdd_wonder_sched *sched,
					 bool operation_held,
					 bool strict_continuity)
{
	struct wma_wonder_tsf_sample sample = { 0 };
	struct hdd_wonder_clock previous;
	struct osif_vdev_sync *vdev_sync = NULL;
	u64 before_ns, after_ns, bridge_host_ns, qtimer_now_us;
	u64 sample_host_ns, tsf_delta, qtimer_delta, error_us;
	u64 helper_cookie, identity_sequence;
	unsigned long flags;
	bool discontinuity = false;
	u8 vdev_id;
	int ret;

	spin_lock_irqsave(&sched->lock, flags);
	if (!sched->running || !sched->tsf_bound) {
		ret = sched->running ? -ENODATA : -ESHUTDOWN;
		spin_unlock_irqrestore(&sched->lock, flags);
		return ret;
	}
	previous = sched->continuity;
	vdev_id = sched->tsf_vdev_id;
	helper_cookie = sched->tsf_helper_cookie;
	identity_sequence = sched->identity_sequence;
	strict_continuity |= sched->plan &&
			     sched->plan->generation == sched->generation;
	spin_unlock_irqrestore(&sched->lock, flags);

	if (!operation_held) {
		ret = osif_vdev_sync_op_start(sched->adapter->dev, &vdev_sync);
		if (ret)
			return ret;
	}
	/* Always ask FW for this helper's current register/LMAC identity. Cached
	 * scratch-register IDs can silently follow the wrong MAC after retuning.
	 */
	ret = wma_wonder_tsf_capture(sched->adapter->deflink->vdev_id, vdev_id,
				     helper_cookie, &sample);
	if (ret)
		goto stop_op;
	/* WCN7750 has MAC0/MAC1, each with TSF1/TSF2. tsf_id_valid is the
	 * firmware's register-pair validity, as in wlan_hdd_tsf_reg_update_details.
	 */
	if (!sample.ids_valid || sample.tsf_id > 1 || sample.mac_id > 1 ||
	    !sample.qtimer_us) {
		ret = -ENODATA;
		goto stop_op;
	}

	/* Measure the QTIMER-to-CLOCK_MONOTONIC bridge after response arrival.
	 * Firmware supplies capture QTIMER in microseconds, paired with MAC TSF.
	 */
	before_ns = ktime_get_ns();
	qtimer_now_us = qdf_get_log_timestamp_usecs();
	after_ns = ktime_get_ns();
	bridge_host_ns = before_ns + (after_ns - before_ns) / 2;
	if (sample.qtimer_us > qtimer_now_us ||
	    qtimer_now_us - sample.qtimer_us > HDD_WONDER_TSF_MAX_CAPTURE_AGE_US ||
	    (qtimer_now_us - sample.qtimer_us) * NSEC_PER_USEC > bridge_host_ns) {
		ret = -ERANGE;
		goto stop_op;
	}
	sample_host_ns = bridge_host_ns -
		(qtimer_now_us - sample.qtimer_us) * NSEC_PER_USEC;

	spin_lock_irqsave(&sched->lock, flags);
	if (!sched->running || !sched->tsf_bound ||
	    sched->identity_sequence != identity_sequence ||
	    sched->tsf_vdev_id != vdev_id ||
	    sched->tsf_helper_cookie != helper_cookie) {
		ret = -ESTALE;
		goto unlock_state;
	}
	if (previous.valid) {
		discontinuity = sample.tsf_id != previous.sample.tsf_id ||
				sample.mac_id != previous.sample.mac_id ||
				sample.qtimer_us < previous.sample.qtimer_us ||
				sample.tsf_us < previous.sample.tsf_us;
		if (!discontinuity) {
			/* QTIMER includes suspend; monotonic host time does not. */
			qtimer_delta = sample.qtimer_us - previous.sample.qtimer_us;
			tsf_delta = sample.tsf_us - previous.sample.tsf_us;
			error_us = tsf_delta > qtimer_delta ?
				tsf_delta - qtimer_delta : qtimer_delta - tsf_delta;
			discontinuity = error_us > HDD_WONDER_TSF_CLOCK_JUMP_US;
		}
	}
	if (discontinuity) {
		/* Even equal-valued counters on a new LMAC are a different epoch. */
		sched->generation++;
		if (strict_continuity) {
			sched->clock.valid = false;
			sched->last_error = -ESTALE;
			ret = -ESTALE;
			goto unlock_state;
		}
	}
	sched->clock.sample = sample;
	sched->clock.sample_host_ns = sample_host_ns;
	sched->clock.helper_cookie = helper_cookie;
	sched->clock.vdev_id = vdev_id;
	sched->clock.valid = true;
	sched->continuity = sched->clock;
	if (sched->plan && sched->plan->generation == sched->generation)
		sched->plan->next_host_ns =
			hdd_wonder_clock_host(&sched->clock, sched->plan->next_tsf);
	ret = 0;
unlock_state:
	spin_unlock_irqrestore(&sched->lock, flags);
stop_op:
	if (vdev_sync)
		osif_vdev_sync_op_stop(vdev_sync);
	return ret;
}

static int hdd_wonder_sched_refresh_clock(struct hdd_wonder_sched *sched)
{
	int ret;

	mutex_lock(&sched->sample_lock);
	ret = hdd_wonder_sched_capture_clock(sched, false, false);
	mutex_unlock(&sched->sample_lock);
	return ret;
}

static void hdd_wonder_sync_work(struct work_struct *work)
{
	struct hdd_wonder_sched *sched = container_of(to_delayed_work(work),
					struct hdd_wonder_sched, sync_work);
	unsigned long flags;
	int ret;

	ret = hdd_wonder_sched_refresh_clock(sched);
	spin_lock_irqsave(&sched->lock, flags);
	if (ret)
		sched->last_error = ret;
	if (sched->running) {
		queue_delayed_work(sched->workqueue, &sched->sync_work,
				   msecs_to_jiffies(HDD_WONDER_TSF_REFRESH_MS));
		if (!ret && sched->plan && sched->plan->generation == sched->generation)
			queue_work(sched->workqueue, &sched->switch_work);
	}
	spin_unlock_irqrestore(&sched->lock, flags);
}

static enum hrtimer_restart hdd_wonder_sched_timer(struct hrtimer *timer)
{
	struct hdd_wonder_sched *sched = container_of(timer, struct hdd_wonder_sched, timer);

	queue_work(sched->workqueue, &sched->switch_work);
	return HRTIMER_NORESTART;
}

bool hdd_wonder_sched_generation_active(struct hdd_wonder_sched *sched, u64 generation)
{
	unsigned long flags;
	bool active;

	if (!sched)
		return false;
	spin_lock_irqsave(&sched->lock, flags);
	active = sched->running && sched->plan &&
		 sched->plan->generation == generation && sched->generation == generation;
	spin_unlock_irqrestore(&sched->lock, flags);
	return active;
}

static void hdd_wonder_sched_switch_work(struct work_struct *work)
{
	struct hdd_wonder_sched *sched = container_of(work, struct hdd_wonder_sched, switch_work);
	struct wondertap_set_freq_params channel;
	struct hdd_wonder_plan *plan;
	struct hdd_wonder_slot *slot;
	struct hdd_wonder_clock clock;
	u64 now_ns = ktime_get_ns(), completion_ns = 0, completion_tsf, now_tsf;
	u64 skipped, target_tsf, generation, slot_end_host_ns, duration_ns;
	u64 next_ns = 0;
	unsigned long flags;
	u32 index;
	int ret;

	spin_lock_irqsave(&sched->lock, flags);
	plan = sched->plan;
	if (!sched->running || !plan || plan->generation != sched->generation)
		goto unlock;
	kref_get(&plan->ref);
	if (!plan->switch_pending && now_ns < plan->next_host_ns) {
		next_ns = plan->next_host_ns;
		goto release_locked;
	}
	/* A temporary acquisition conflict cannot advance or renew its slot. */
	if (plan->switch_pending && now_ns >= plan->switch_end_host_ns) {
		sched->last_error = -ETIMEDOUT;
		sched->generation++;
		goto release_locked;
	}
	clock = sched->clock;
	if (!sched->tsf_bound || !clock.valid ||
	    now_ns - clock.sample_host_ns > HDD_WONDER_TSF_MAX_AGE_NS) {
		sched->last_error = -ENODATA;
		if (plan->switch_pending)
			next_ns = plan->switch_end_host_ns;
		goto release_locked;
	}
	/* Skip elapsed slots only before starting an acquisition. */
	if (hdd_wonder_clock_tsf(&clock, now_ns, &now_tsf)) {
		sched->last_error = -ERANGE;
		goto release_locked;
	}
	if (!plan->switch_pending) {
		skipped = now_tsf > plan->next_tsf ?
			div64_u64(now_tsf - plan->next_tsf, plan->dwell_us) : 0;
		plan->next_index = (plan->next_index + skipped % plan->count) % plan->count;
		plan->next_tsf += skipped * plan->dwell_us;
		plan->next_host_ns = hdd_wonder_clock_host(&clock, plan->next_tsf);
		plan->switch_end_host_ns = hdd_wonder_clock_host(&clock,
						plan->next_tsf + plan->dwell_us);
		if (plan->switch_end_host_ns <= now_ns) {
			sched->last_error = -ETIMEDOUT;
			sched->generation++;
			goto release_locked;
		}
		plan->switch_duration_ns = plan->dwell_us * NSEC_PER_USEC;
		if (plan->switch_duration_ns > plan->switch_end_host_ns - now_ns)
			plan->switch_duration_ns = plan->switch_end_host_ns - now_ns;
		plan->switch_pending = true;
	}
	index = plan->next_index;
	target_tsf = plan->next_tsf;
	generation = plan->generation;
	slot_end_host_ns = plan->switch_end_host_ns;
	duration_ns = plan->switch_duration_ns;
	channel.freq = plan->channels[index].freq ?: sched->current_freq;
	channel.bandwidth = plan->channels[index].freq ?
		plan->channels[index].bandwidth : sched->current_bandwidth;
	spin_unlock_irqrestore(&sched->lock, flags);

	if (!hdd_wonder_sched_generation_active(sched, generation)) {
		ret = -ESTALE;
	} else {
		ret = sched->ops.set_channel(sched->context, &channel, generation,
					    slot_end_host_ns, duration_ns, &completion_ns);
	}
	if (!completion_ns)
		completion_ns = ktime_get_ns();
	spin_lock_irqsave(&sched->lock, flags);
	if (!sched->running || sched->plan != plan || generation != sched->generation)
		goto release_locked;
	/* Standalone retunes publish a fresh helper clock; shared dwell completion
	 * leaves the measured HOME clock intact. Use the provider's current anchor.
	 */
	clock = sched->clock;
	if (!ret && (!sched->tsf_bound || !clock.valid))
		ret = -ENODATA;
	if (!ret && completion_ns >= slot_end_host_ns)
		ret = -ETIMEDOUT;
	if (!ret)
		ret = hdd_wonder_clock_tsf(&clock, completion_ns, &completion_tsf);
	if (ret) {
		sched->last_error = ret;
		if (ret == -EAGAIN || ret == -EBUSY) {
			next_ns = ktime_get_ns() + HDD_WONDER_SWITCH_RETRY_NS;
			if (next_ns > slot_end_host_ns)
				next_ns = slot_end_host_ns;
			goto release_locked;
		}
		/* Keep the last known channel active, but stop a failed sequence. */
		sched->generation++;
		goto release_locked;
	}

	hdd_wonder_slot_end(plan, completion_tsf);
	slot = &plan->slots[index];
	memset(slot, 0, sizeof(*slot));
	slot->start_tsf = completion_tsf;
	slot->status.channel_switch_tsf = (u32)target_tsf;
	slot->status.freq = channel.freq;
	slot->status.channel_start_tsf = (u32)completion_tsf;
	plan->current_index = index;
	plan->slot_active = true;
	plan->switch_pending = false;
	sched->current_freq = channel.freq;
	sched->current_bandwidth = channel.bandwidth;
	sched->current_host_ns = completion_ns;
	sched->last_error = 0;
	plan->next_index = (index + 1) % plan->count;
	plan->next_tsf += plan->dwell_us;
	plan->next_host_ns = hdd_wonder_clock_host(&clock, plan->next_tsf);
	next_ns = plan->next_host_ns;
release_locked:
	/* Arm under the same lock as quiesce so no timer can be armed after its
	 * cancellation barrier. The timer callback only queues work.
	 */
	if (next_ns && sched->running && sched->plan == plan &&
	    sched->generation == plan->generation)
		hrtimer_start(&sched->timer, ns_to_ktime(next_ns), HRTIMER_MODE_ABS);
	spin_unlock_irqrestore(&sched->lock, flags);
	kref_put(&plan->ref, hdd_wonder_plan_release);
	return;
unlock:
	spin_unlock_irqrestore(&sched->lock, flags);
}

struct hdd_wonder_sched *
hdd_wonder_sched_create(struct hdd_adapter *adapter, void *context,
			const struct hdd_wonder_sched_ops *ops)
{
	struct hdd_wonder_sched *sched;

	if (!adapter || !ops || !ops->set_channel || !ops->validate_channel)
		return ERR_PTR(-EINVAL);
	sched = kzalloc(sizeof(*sched), GFP_KERNEL);
	if (!sched)
		return ERR_PTR(-ENOMEM);
	sched->adapter = adapter;
	sched->context = context;
	sched->ops = *ops;
	sched->tsf_vdev_id = U8_MAX;
	spin_lock_init(&sched->lock);
	mutex_init(&sched->sample_lock);
	INIT_WORK(&sched->switch_work, hdd_wonder_sched_switch_work);
	INIT_DELAYED_WORK(&sched->sync_work, hdd_wonder_sync_work);
	hrtimer_setup(&sched->timer, hdd_wonder_sched_timer, CLOCK_MONOTONIC,
		      HRTIMER_MODE_ABS);
	sched->workqueue = alloc_ordered_workqueue("wonder-channel", WQ_HIGHPRI | WQ_MEM_RECLAIM);
	if (!sched->workqueue) {
		kfree(sched);
		return ERR_PTR(-ENOMEM);
	}
	sched->running = true;
	return sched;
}

void hdd_wonder_sched_quiesce(struct hdd_wonder_sched *sched)
{
	unsigned long flags;

	if (!sched)
		return;
	spin_lock_irqsave(&sched->lock, flags);
	sched->running = false;
	sched->generation++;
	sched->identity_sequence++;
	sched->clock.valid = false;
	spin_unlock_irqrestore(&sched->lock, flags);
	hrtimer_cancel(&sched->timer);
	cancel_delayed_work(&sched->sync_work);
}

void hdd_wonder_sched_suspend(struct hdd_wonder_sched *sched)
{
	if (!sched)
		return;
	hdd_wonder_sched_quiesce(sched);
	/* Channel callbacks use provider/RTNL trylocks; TSF capture has no
	 * provider callback. Draining while the provider is locked cannot wait
	 * on that same lock from either worker.
	 */
	cancel_delayed_work_sync(&sched->sync_work);
	cancel_work_sync(&sched->switch_work);
}

void hdd_wonder_sched_destroy(struct hdd_wonder_sched *sched)
{
	if (!sched)
		return;
	hdd_wonder_sched_quiesce(sched);
	cancel_delayed_work_sync(&sched->sync_work);
	cancel_work_sync(&sched->switch_work);
	destroy_workqueue(sched->workqueue);
	if (sched->plan)
		kref_put(&sched->plan->ref, hdd_wonder_plan_release);
	kfree(sched);
}

int hdd_wonder_sched_get_tsf(struct hdd_wonder_sched *sched, u32 *tsf)
{
	struct hdd_wonder_clock clock;
	unsigned long flags;
	u64 value, now_ns;
	int ret;

	if (!sched || !tsf)
		return -EINVAL;
	spin_lock_irqsave(&sched->lock, flags);
	if (!sched->running) {
		spin_unlock_irqrestore(&sched->lock, flags);
		return -ESHUTDOWN;
	}
	clock = sched->clock;
	spin_unlock_irqrestore(&sched->lock, flags);
	now_ns = ktime_get_ns();
	if (!clock.valid || now_ns - clock.sample_host_ns > HDD_WONDER_TSF_MAX_AGE_NS) {
		ret = hdd_wonder_sched_refresh_clock(sched);
		if (ret)
			return ret;
		spin_lock_irqsave(&sched->lock, flags);
		clock = sched->clock;
		spin_unlock_irqrestore(&sched->lock, flags);
		now_ns = ktime_get_ns();
	}
	ret = hdd_wonder_clock_tsf(&clock, now_ns, &value);
	if (!ret)
		*tsf = (u32)value;
	return ret;
}

int hdd_wonder_sched_request(struct hdd_wonder_sched *sched,
			     const struct channel_schedule_request *request)
{
	struct hdd_wonder_plan *plan = NULL, *old;
	struct hdd_wonder_clock clock;
	struct wondertap_set_freq_params channel;
	u64 now_ns, now_tsf, target_tsf;
	s32 delta_us;
	u32 unused;
	unsigned long flags;
	int i, ret;

	if (!sched || !request)
		return -EINVAL;
	if (request->channel_list_len) {
		if (!request->channel_list || !request->dwell_time_tu ||
		    request->dwell_time_tu > INT_MAX / 1024 ||
		    request->next_channel_index >= request->channel_list_len)
			return -EINVAL;
		plan = kzalloc(sizeof(*plan), GFP_KERNEL);
		if (!plan)
			return -ENOMEM;
		kref_init(&plan->ref);
		plan->count = request->channel_list_len;
		plan->next_index = request->next_channel_index;
		plan->current_index = request->next_channel_index;
		plan->dwell_us = (u64)request->dwell_time_tu * 1024;
		plan->request_tsf = request->target_switch_time_tsf;
		memcpy(plan->channels, request->channel_list,
		       plan->count * sizeof(plan->channels[0]));
		for (i = 0; i < plan->count; i++) {
			if (plan->channels[i].role >= WONDERTAP_ROLE_MAX ||
			    (!plan->channels[i].freq && plan->channels[i].role != WONDERTAP_ROLE_NOP)) {
				ret = -EINVAL;
				goto free_plan;
			}
			if (!plan->channels[i].freq)
				continue;
			channel.freq = plan->channels[i].freq;
			channel.bandwidth = plan->channels[i].bandwidth;
			ret = sched->ops.validate_channel(sched->context, &channel);
			if (ret)
				goto free_plan;
		}
		ret = hdd_wonder_sched_get_tsf(sched, &unused);
		if (ret)
			goto free_plan;
	}

	spin_lock_irqsave(&sched->lock, flags);
	if (!sched->running) {
		ret = -ESHUTDOWN;
		goto unlock;
	}
	clock = sched->clock;
	now_ns = ktime_get_ns();
	if (plan) {
		ret = hdd_wonder_clock_tsf(&clock, now_ns, &now_tsf);
		if (ret)
			goto unlock;
		delta_us = (s32)(request->target_switch_time_tsf - (u32)now_tsf);
		if (delta_us < 0 && (u64)-((s64)delta_us) > now_tsf) {
			ret = -ERANGE;
			goto unlock;
		}
		target_tsf = now_tsf + delta_us;
		plan->next_tsf = target_tsf;
		plan->next_host_ns = hdd_wonder_clock_host(&clock, target_tsf);
		plan->generation = ++sched->generation;
	} else {
		sched->generation++;
	}
	old = sched->plan;
	if (old && clock.valid && !hdd_wonder_clock_tsf(&clock, now_ns, &now_tsf))
		hdd_wonder_slot_end(old, now_tsf);
	sched->plan = plan;
	sched->last_error = 0;
	spin_unlock_irqrestore(&sched->lock, flags);
	if (old)
		kref_put(&old->ref, hdd_wonder_plan_release);
	/* Queueing is safe even if an old timer fires: work always snapshots plan. */
	queue_work(sched->workqueue, &sched->switch_work);
	return 0;
unlock:
	spin_unlock_irqrestore(&sched->lock, flags);
free_plan:
	if (plan)
		kref_put(&plan->ref, hdd_wonder_plan_release);
	return ret;
}

int hdd_wonder_sched_get_report(struct hdd_wonder_sched *sched,
				struct wondertap_channel_status_report *report)
{
	struct hdd_wonder_plan *plan;
	struct hdd_wonder_slot *slot;
	u64 now_tsf, elapsed;
	unsigned long flags;
	int i, ret = 0;

	if (!sched || !report)
		return -EINVAL;
	spin_lock_irqsave(&sched->lock, flags);
	plan = sched->plan;
	if (!sched->running) {
		ret = -ESHUTDOWN;
		goto unlock;
	}
	if (!plan) {
		if (report->channel_status_len)
			ret = -ENODATA;
		else {
			report->current_channel_hopping_request_tsf = 0;
			report->current_channel_index = 0;
		}
		goto unlock;
	}
	if (report->channel_status_len != plan->count) {
		ret = -EINVAL;
		goto unlock;
	}
	if (plan->generation != sched->generation) {
		ret = sched->last_error ?: -ESTALE;
		goto unlock;
	}
	report->current_channel_hopping_request_tsf = plan->request_tsf;
	report->current_channel_index = plan->current_index;
	for (i = 0; i < plan->count; i++)
		report->status[i] = plan->slots[i].status;
	if (plan->slot_active &&
	    !hdd_wonder_clock_tsf(&sched->clock, ktime_get_ns(), &now_tsf)) {
		slot = &plan->slots[plan->current_index];
		if (now_tsf >= slot->start_tsf) {
			elapsed = now_tsf - slot->start_tsf;
			report->status[plan->current_index].tx_traffic_index =
				hdd_wonder_traffic_index(slot->tx_us, elapsed);
			report->status[plan->current_index].rx_traffic_index =
				hdd_wonder_traffic_index(slot->rx_us, elapsed);
		}
	}
unlock:
	spin_unlock_irqrestore(&sched->lock, flags);
	return ret;
}

void hdd_wonder_sched_note_channel(struct hdd_wonder_sched *sched, u32 freq,
				  enum wondertap_rate_bw bandwidth,
				  u64 completion_host_ns)
{
	unsigned long flags;

	if (!sched)
		return;
	spin_lock_irqsave(&sched->lock, flags);
	sched->current_freq = freq;
	sched->current_bandwidth = bandwidth;
	sched->current_host_ns = completion_host_ns;
	spin_unlock_irqrestore(&sched->lock, flags);
}

static int hdd_wonder_sched_bind_clock(struct hdd_wonder_sched *sched,
				      u8 vdev_id, u64 helper_cookie,
				      bool strict_continuity)
{
	unsigned long flags;
	int ret;

	if (!sched || !helper_cookie)
		return -EINVAL;
	mutex_lock(&sched->sample_lock);
	spin_lock_irqsave(&sched->lock, flags);
	if (!sched->running) {
		spin_unlock_irqrestore(&sched->lock, flags);
		ret = -ESHUTDOWN;
		goto unlock;
	}
	sched->tsf_vdev_id = vdev_id;
	sched->tsf_helper_cookie = helper_cookie;
	sched->tsf_bound = true;
	sched->identity_sequence++;
	sched->clock.valid = false;
	spin_unlock_irqrestore(&sched->lock, flags);
	ret = hdd_wonder_sched_capture_clock(sched, true, strict_continuity);
	spin_lock_irqsave(&sched->lock, flags);
	if (ret)
		sched->last_error = ret;
	else
		sched->last_error = 0;
	if (sched->running && (!strict_continuity || !ret)) {
		mod_delayed_work(sched->workqueue, &sched->sync_work,
				 ret ? 0 : msecs_to_jiffies(HDD_WONDER_TSF_REFRESH_MS));
		if (!ret && sched->plan && sched->plan->generation == sched->generation)
			queue_work(sched->workqueue, &sched->switch_work);
	}
	spin_unlock_irqrestore(&sched->lock, flags);
unlock:
	mutex_unlock(&sched->sample_lock);
	return ret;
}

int hdd_wonder_sched_bind_tsf(struct hdd_wonder_sched *sched, u8 vdev_id,
			      u64 helper_cookie)
{
	return hdd_wonder_sched_bind_clock(sched, vdev_id, helper_cookie, false);
}

void hdd_wonder_sched_unbind_tsf(struct hdd_wonder_sched *sched)
{
	unsigned long flags;

	if (!sched)
		return;
	spin_lock_irqsave(&sched->lock, flags);
	sched->tsf_bound = false;
	sched->identity_sequence++;
	sched->clock.valid = false;
	spin_unlock_irqrestore(&sched->lock, flags);
}

int hdd_wonder_sched_resume(struct hdd_wonder_sched *sched, u8 vdev_id,
			    u64 helper_cookie)
{
	unsigned long flags;
	int ret;

	if (!sched || !helper_cookie)
		return -EINVAL;
	spin_lock_irqsave(&sched->lock, flags);
	if (sched->running) {
		spin_unlock_irqrestore(&sched->lock, flags);
		return -EBUSY;
	}
	if (!sched->continuity.valid) {
		spin_unlock_irqrestore(&sched->lock, flags);
		return -ENODATA;
	}
	sched->running = true;
	spin_unlock_irqrestore(&sched->lock, flags);
	/* Preserve old QTIMER/TSF and counter IDs across PM before replay. */
	ret = hdd_wonder_sched_bind_clock(sched, vdev_id, helper_cookie, true);
	if (ret)
		hdd_wonder_sched_suspend(sched);
	return ret;
}

void hdd_wonder_sched_note_airtime(struct hdd_wonder_sched *sched, u32 lmac_id,
				  u32 freq, u32 tsf, bool tx, u32 duration_us)
{
	struct hdd_wonder_plan *plan;
	struct hdd_wonder_slot *slot;
	unsigned long flags;
	int i;

	if (!sched || !freq || !tsf || !duration_us)
		return;
	spin_lock_irqsave(&sched->lock, flags);
	plan = sched->plan;
	if (!sched->running || !sched->tsf_bound || !sched->clock.valid ||
	    !sched->clock.sample.ids_valid ||
	    sched->clock.sample.mac_id != lmac_id || !plan ||
	    plan->generation != sched->generation ||
	    ktime_get_ns() - sched->clock.sample_host_ns > HDD_WONDER_TSF_MAX_AGE_NS)
		goto unlock;
	/* A late PPDU report can still update a recently completed list entry. */
	for (i = 0; i < plan->count; i++) {
		slot = &plan->slots[i];
		if (slot->status.freq != freq || !slot->start_tsf ||
		    (s32)(tsf - (u32)slot->start_tsf) < 0 ||
		    (slot->end_tsf && (s32)(tsf - (u32)slot->end_tsf) >= 0))
			continue;
		if (tx)
			slot->tx_us += duration_us;
		else
			slot->rx_us += duration_us;
		if (slot->end_tsf) {
			slot->status.tx_traffic_index = hdd_wonder_traffic_index(
				slot->tx_us, slot->end_tsf - slot->start_tsf);
			slot->status.rx_traffic_index = hdd_wonder_traffic_index(
				slot->rx_us, slot->end_tsf - slot->start_tsf);
		}
		break;
	}
unlock:
	spin_unlock_irqrestore(&sched->lock, flags);
}

#endif /* FEATURE_WLAN_WONDER */
