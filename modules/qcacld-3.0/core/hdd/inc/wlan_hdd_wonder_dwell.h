/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __WLAN_HDD_WONDER_DWELL_H
#define __WLAN_HDD_WONDER_DWELL_H

#include <linux/types.h>

/* All operations, including ready(), require the same caller-owned lock.
 * This core neither submits scans nor owns their callback context. The caller
 * must retain that context until real scan retirement, and attribute events to
 * its saved owner rather than sampling a newer helper's live identity.
 */
struct hdd_wonder_dwell_owner {
	u64 generation;
	u64 helper_cookie;
};

struct hdd_wonder_dwell_scan {
	u32 vdev_id;
	u32 requester;
	u32 scan_id;
	u32 freq;
};

enum hdd_wonder_dwell_phase {
	HDD_WONDER_DWELL_IDLE,
	HDD_WONDER_DWELL_PENDING,
	HDD_WONDER_DWELL_READY,
	HDD_WONDER_DWELL_CANCEL_PENDING,
};

enum hdd_wonder_dwell_event_type {
	HDD_WONDER_DWELL_STARTED,
	HDD_WONDER_DWELL_FOREIGN_CHANNEL,
	HDD_WONDER_DWELL_FOREIGN_CHANNEL_EXIT,
	HDD_WONDER_DWELL_BSS_CHANNEL,
	HDD_WONDER_DWELL_PREEMPTED,
	HDD_WONDER_DWELL_SUSPENDED,
	HDD_WONDER_DWELL_RESTARTED,
	HDD_WONDER_DWELL_TERMINAL,
};

struct hdd_wonder_dwell_event {
	struct hdd_wonder_dwell_owner owner;
	u32 vdev_id;
	u32 requester;
	u32 scan_id;
	u32 freq;
	enum hdd_wonder_dwell_event_type type;
	/* Optional target-local u32 microsecond observation. This is not TSF,
	 * QTIMER or the clock used for deadline_ns. Zero may be a valid value.
	 */
	u32 target_timestamp;
	bool target_timestamp_valid;
};

struct hdd_wonder_dwell {
	struct hdd_wonder_dwell_owner owner;
	struct hdd_wonder_dwell_scan scan;
	u64 max_duration_ns;
	u64 deadline_ns;
	u64 last_now_ns;
	u32 home_vdev_id;
	u32 home_freq;
	u32 target_timestamp;
	enum hdd_wonder_dwell_phase phase;
	bool home_valid;
	bool revoked;
	bool started;
	bool target_timestamp_valid;
};

/* init() is for a fresh object only: never use it to erase a pending scan. */
void hdd_wonder_dwell_init(struct hdd_wonder_dwell *dwell,
			  u64 max_duration_ns);
/* HOME changes revoke a pending dwell; HOME is never replaced by scan.freq. */
bool hdd_wonder_dwell_set_home(struct hdd_wonder_dwell *dwell,
			     u32 vdev_id, u32 freq);
/* Caller preflights regulatory/channel admission and uses a fresh callback
 * identity (owner plus scan tuple) for every accepted request. Success only
 * reserves: no traffic is authorized. Host time must be monotonic nanoseconds.
 * The deadline is min(slot_end_ns, now_ns + requested/max duration); duplicates
 * and delayed entry events never extend it.
 */
bool hdd_wonder_dwell_reserve(struct hdd_wonder_dwell *dwell,
			     const struct hdd_wonder_dwell_owner *owner,
			     const struct hdd_wonder_dwell_scan *scan,
			     u64 now_ns, u64 slot_end_ns,
			     u64 requested_duration_ns);
/* Returns true for an attributed/matching event, even if readiness is denied.
 * Terminal may omit frequency. EXIT accepts requested frequency or zero; BSS
 * accepts HOME or zero. A matching tuple with a conflicting nonzero FOREIGN,
 * EXIT or BSS frequency rejects the event and latches revocation. Unmatched
 * tuples remain ignored. All revocations latch until real terminal retirement.
 */
bool hdd_wonder_dwell_event(struct hdd_wonder_dwell *dwell,
			   const struct hdd_wonder_dwell_event *event,
			   u64 now_ns);
/* Both TX and RX use this same readiness predicate with packet attribution. */
bool hdd_wonder_dwell_ready(struct hdd_wonder_dwell *dwell,
			   const struct hdd_wonder_dwell_owner *owner,
			   const struct hdd_wonder_dwell_scan *scan,
			   u64 now_ns);
void hdd_wonder_dwell_expire(struct hdd_wonder_dwell *dwell, u64 now_ns);
bool hdd_wonder_dwell_cancel(struct hdd_wonder_dwell *dwell,
			    const struct hdd_wonder_dwell_owner *owner,
			    const struct hdd_wonder_dwell_scan *scan);
/* Teardown, SSR, PM or HOME loss: revoke and invalidate HOME, retain pending. */
void hdd_wonder_dwell_invalidate(struct hdd_wonder_dwell *dwell);
/* Only for a submission proven never accepted by scan management. Refuses an
 * observed STARTED/FOREIGN or a cancelled/invalidated reservation. This is not
 * a substitute for cancelling or waiting for completion of an accepted scan.
 */
bool hdd_wonder_dwell_submission_failed(struct hdd_wonder_dwell *dwell,
			 const struct hdd_wonder_dwell_owner *owner,
			 const struct hdd_wonder_dwell_scan *scan);
/* Trusted scan-manager proof that this tuple never reached the target. Unlike
 * submission_failed(), this may drain after local cancellation/invalidation.
 * A synthetic completion, cancel send or timeout cannot supply that proof.
 * Any observed STARTED/FOREIGN refuses this path; wait for real terminal then.
 */
bool hdd_wonder_dwell_not_submitted(struct hdd_wonder_dwell *dwell,
			 const struct hdd_wonder_dwell_owner *owner,
			 const struct hdd_wonder_dwell_scan *scan);

#endif /* __WLAN_HDD_WONDER_DWELL_H */
