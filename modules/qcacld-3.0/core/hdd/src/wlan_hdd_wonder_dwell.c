// SPDX-License-Identifier: GPL-2.0-only
/* Firmware-observed single dwell readiness; scan lifetime remains caller-owned. */
#include <linux/string.h>
#include <wlan_hdd_wonder_dwell.h>

static bool hdd_wonder_dwell_owner_matches(
	const struct hdd_wonder_dwell *dwell,
	const struct hdd_wonder_dwell_owner *owner)
{
	return owner && dwell->owner.generation == owner->generation &&
		dwell->owner.helper_cookie == owner->helper_cookie;
}

static bool hdd_wonder_dwell_scan_matches(
	const struct hdd_wonder_dwell *dwell,
	const struct hdd_wonder_dwell_scan *scan)
{
	return scan && dwell->scan.vdev_id == scan->vdev_id &&
		dwell->scan.requester == scan->requester &&
		dwell->scan.scan_id == scan->scan_id &&
		dwell->scan.freq == scan->freq;
}

static void hdd_wonder_dwell_revoke(struct hdd_wonder_dwell *dwell)
{
	if (dwell->phase == HDD_WONDER_DWELL_IDLE)
		return;
	dwell->revoked = true;
	if (dwell->phase == HDD_WONDER_DWELL_READY)
		dwell->phase = HDD_WONDER_DWELL_PENDING;
}

static bool hdd_wonder_dwell_advance(struct hdd_wonder_dwell *dwell, u64 now_ns)
{
	if (now_ns < dwell->last_now_ns) {
		hdd_wonder_dwell_revoke(dwell);
		return false;
	}
	dwell->last_now_ns = now_ns;
	if (dwell->phase != HDD_WONDER_DWELL_IDLE &&
	    now_ns >= dwell->deadline_ns)
		hdd_wonder_dwell_revoke(dwell);
	return true;
}

void hdd_wonder_dwell_init(struct hdd_wonder_dwell *dwell, u64 max_duration_ns)
{
	memset(dwell, 0, sizeof(*dwell));
	dwell->max_duration_ns = max_duration_ns;
}

bool hdd_wonder_dwell_set_home(struct hdd_wonder_dwell *dwell,
			     u32 vdev_id, u32 freq)
{
	if (vdev_id > 255 || !freq || freq > 65535)
		return false;
	if (dwell->home_valid && (dwell->home_vdev_id != vdev_id ||
				 dwell->home_freq != freq))
		hdd_wonder_dwell_revoke(dwell);
	dwell->home_vdev_id = vdev_id;
	dwell->home_freq = freq;
	dwell->home_valid = true;
	return true;
}

bool hdd_wonder_dwell_reserve(struct hdd_wonder_dwell *dwell,
			     const struct hdd_wonder_dwell_owner *owner,
			     const struct hdd_wonder_dwell_scan *scan,
			     u64 now_ns, u64 slot_end_ns,
			     u64 requested_duration_ns)
{
	u64 duration, deadline;

	if (dwell->phase != HDD_WONDER_DWELL_IDLE || !dwell->home_valid ||
	    !owner || !owner->generation || !owner->helper_cookie || !scan ||
	    scan->vdev_id > 255 || !scan->freq || scan->freq > 65535 ||
	    scan->scan_id >= 0xfffffffeU || !dwell->max_duration_ns ||
	    !requested_duration_ns || slot_end_ns <= now_ns ||
	    !hdd_wonder_dwell_advance(dwell, now_ns))
		return false;
	duration = requested_duration_ns;
	if (duration > dwell->max_duration_ns)
		duration = dwell->max_duration_ns;
	/* Reject overflow rather than silently wrap the readiness window. */
	if (duration > ~0ULL - now_ns)
		return false;
	deadline = now_ns + duration;
	if (slot_end_ns < deadline)
		deadline = slot_end_ns;
	dwell->owner = *owner;
	dwell->scan = *scan;
	dwell->deadline_ns = deadline;
	dwell->phase = HDD_WONDER_DWELL_PENDING;
	dwell->revoked = false;
	dwell->started = false;
	dwell->target_timestamp_valid = false;
	return true;
}

bool hdd_wonder_dwell_event(struct hdd_wonder_dwell *dwell,
			   const struct hdd_wonder_dwell_event *event,
			   u64 now_ns)
{
	bool time_valid, newer = true;

	if (!event || dwell->phase == HDD_WONDER_DWELL_IDLE ||
	    !hdd_wonder_dwell_owner_matches(dwell, &event->owner) ||
	    dwell->scan.vdev_id != event->vdev_id ||
	    dwell->scan.requester != event->requester ||
	    dwell->scan.scan_id != event->scan_id)
		return false;
	if ((event->type == HDD_WONDER_DWELL_FOREIGN_CHANNEL &&
	     event->freq != dwell->scan.freq) ||
	    (event->type == HDD_WONDER_DWELL_FOREIGN_CHANNEL_EXIT &&
	     event->freq && event->freq != dwell->scan.freq) ||
	    (event->type == HDD_WONDER_DWELL_BSS_CHANNEL &&
	     event->freq && event->freq != dwell->home_freq)) {
		/* This exact scan reported a contradictory measured channel.
		 * Reject the event and latch revocation until real retirement.
		 * A FOREIGN event without a frequency cannot authorize entry.
		 */
		if (event->freq)
			hdd_wonder_dwell_revoke(dwell);
		return false;
	}
	time_valid = hdd_wonder_dwell_advance(dwell, now_ns);
	if (event->target_timestamp_valid && dwell->target_timestamp_valid)
		newer = (s32)(event->target_timestamp -
			       dwell->target_timestamp) > 0;
	if (event->target_timestamp_valid && newer) {
		dwell->target_timestamp = event->target_timestamp;
		dwell->target_timestamp_valid = true;
	}
	switch (event->type) {
	case HDD_WONDER_DWELL_STARTED:
		dwell->started = true;
		break;
	case HDD_WONDER_DWELL_FOREIGN_CHANNEL:
		dwell->started = true;
		if (time_valid && newer && dwell->home_valid && !dwell->revoked &&
		    dwell->phase == HDD_WONDER_DWELL_PENDING)
			dwell->phase = HDD_WONDER_DWELL_READY;
		break;
	case HDD_WONDER_DWELL_TERMINAL:
		/* A real terminal drains even after invalidation or clock regression.
		 * Keep the old tuple for diagnostics; IDLE never authorizes traffic.
		 */
		dwell->revoked = true;
		dwell->phase = HDD_WONDER_DWELL_IDLE;
		break;
	case HDD_WONDER_DWELL_FOREIGN_CHANNEL_EXIT:
	case HDD_WONDER_DWELL_BSS_CHANNEL:
	case HDD_WONDER_DWELL_PREEMPTED:
	case HDD_WONDER_DWELL_SUSPENDED:
	case HDD_WONDER_DWELL_RESTARTED:
		hdd_wonder_dwell_revoke(dwell);
		break;
	default:
		/* Unknown attributed event may never leave readiness armed. */
		hdd_wonder_dwell_revoke(dwell);
		return false;
	}
	return true;
}

bool hdd_wonder_dwell_ready(struct hdd_wonder_dwell *dwell,
			   const struct hdd_wonder_dwell_owner *owner,
			   const struct hdd_wonder_dwell_scan *scan, u64 now_ns)
{
	return hdd_wonder_dwell_advance(dwell, now_ns) && dwell->home_valid &&
		dwell->phase == HDD_WONDER_DWELL_READY && !dwell->revoked &&
		hdd_wonder_dwell_owner_matches(dwell, owner) &&
		hdd_wonder_dwell_scan_matches(dwell, scan);
}

void hdd_wonder_dwell_expire(struct hdd_wonder_dwell *dwell, u64 now_ns)
{
	hdd_wonder_dwell_advance(dwell, now_ns);
}

bool hdd_wonder_dwell_cancel(struct hdd_wonder_dwell *dwell,
			    const struct hdd_wonder_dwell_owner *owner,
			    const struct hdd_wonder_dwell_scan *scan)
{
	if (dwell->phase == HDD_WONDER_DWELL_IDLE ||
	    !hdd_wonder_dwell_owner_matches(dwell, owner) ||
	    !hdd_wonder_dwell_scan_matches(dwell, scan))
		return false;
	hdd_wonder_dwell_revoke(dwell);
	dwell->phase = HDD_WONDER_DWELL_CANCEL_PENDING;
	return true;
}

void hdd_wonder_dwell_invalidate(struct hdd_wonder_dwell *dwell)
{
	dwell->home_valid = false;
	hdd_wonder_dwell_revoke(dwell);
	if (dwell->phase != HDD_WONDER_DWELL_IDLE)
		dwell->phase = HDD_WONDER_DWELL_CANCEL_PENDING;
}

bool hdd_wonder_dwell_submission_failed(struct hdd_wonder_dwell *dwell,
			 const struct hdd_wonder_dwell_owner *owner,
			 const struct hdd_wonder_dwell_scan *scan)
{
	if (dwell->phase != HDD_WONDER_DWELL_PENDING || dwell->started ||
	    dwell->revoked || !hdd_wonder_dwell_owner_matches(dwell, owner) ||
	    !hdd_wonder_dwell_scan_matches(dwell, scan))
		return false;
	dwell->revoked = true;
	dwell->phase = HDD_WONDER_DWELL_IDLE;
	return true;
}

bool hdd_wonder_dwell_not_submitted(struct hdd_wonder_dwell *dwell,
			 const struct hdd_wonder_dwell_owner *owner,
			 const struct hdd_wonder_dwell_scan *scan)
{
	if (dwell->phase == HDD_WONDER_DWELL_IDLE || dwell->started ||
	    !hdd_wonder_dwell_owner_matches(dwell, owner) ||
	    !hdd_wonder_dwell_scan_matches(dwell, scan))
		return false;
	dwell->revoked = true;
	dwell->phase = HDD_WONDER_DWELL_IDLE;
	return true;
}
