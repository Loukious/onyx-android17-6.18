/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __WLAN_HDD_WONDER_SCHED_H
#define __WLAN_HDD_WONDER_SCHED_H

#include <wondertap.h>

struct hdd_adapter;
struct hdd_wonder_sched;

struct hdd_wonder_sched_ops {
	/* Must not wait on provider/RTNL locks held by quiesce or destroy.
	 * Check hdd_wonder_sched_generation_active() under the provider lock
	 * before submitting a switch; return -EAGAIN on a temporary lock conflict.
	 * slot_end_host_ns is an absolute CLOCK_MONOTONIC deadline derived from
	 * the paired firmware clock; duration_ns is bounded by that slot's remaining
	 * time. Both stay fixed across temporary retries. Success means firmware
	 * channel completion. Standalone retunes rebind the helper/peer and clock;
	 * shared off-channel acquisition must retain the HOME helper and TSF anchor.
	 */
	int (*set_channel)(void *context,
			   const struct wondertap_set_freq_params *channel,
			   u64 generation, u64 slot_end_host_ns,
			   u64 duration_ns, u64 *completion_host_ns);
	/* Pure preflight: do not change the live monitor channel here. */
	int (*validate_channel)(void *context,
				const struct wondertap_set_freq_params *channel);
};

struct hdd_wonder_sched *
hdd_wonder_sched_create(struct hdd_adapter *adapter, void *context,
			const struct hdd_wonder_sched_ops *ops);
/* Quiesce is nonblocking with respect to the channel callback; destroy drains.
 * The adapter/context must remain alive until destroy returns.
 */
void hdd_wonder_sched_quiesce(struct hdd_wonder_sched *sched);
/* Retain the paired firmware clock witness while draining all host work. */
void hdd_wonder_sched_suspend(struct hdd_wonder_sched *sched);
/* Caller holds a vdev/psoc operation; failure leaves the scheduler quiesced. */
int hdd_wonder_sched_resume(struct hdd_wonder_sched *sched, u8 vdev_id,
			    u64 helper_cookie);
void hdd_wonder_sched_destroy(struct hdd_wonder_sched *sched);
int hdd_wonder_sched_request(struct hdd_wonder_sched *sched,
			     const struct channel_schedule_request *request);
int hdd_wonder_sched_get_tsf(struct hdd_wonder_sched *sched, u32 *tsf);
int hdd_wonder_sched_get_report(struct hdd_wonder_sched *sched,
				struct wondertap_channel_status_report *report);
bool hdd_wonder_sched_generation_active(struct hdd_wonder_sched *sched,
					u64 generation);
/* Call after a successful manual switch; cancel an active plan first (len=0). */
void hdd_wonder_sched_note_channel(struct hdd_wonder_sched *sched, u32 freq,
				  enum wondertap_rate_bw bandwidth,
				  u64 completion_host_ns);
/* Caller holds a vdev/psoc operation and binds after helper preparation and
 * every completed standalone channel switch. Shared off-channel acquisition
 * keeps the HOME helper binding. A fresh FW capture verifies counter identity
 * and continuity before the plan can continue. No provider callback is made.
 */
int hdd_wonder_sched_bind_tsf(struct hdd_wonder_sched *sched, u8 vdev_id,
			      u64 helper_cookie);
/* Pause timing before helper retirement; keep the old pair only as a witness.
 * This does not cancel a plan during an intentional channel transition.
 */
void hdd_wonder_sched_unbind_tsf(struct hdd_wonder_sched *sched);
/* Feed real RX/TX PPDU airtime (microseconds), once per PPDU, from monitor DP.
 * tsf is the MAC TSF at PPDU start; zero frequency/timestamp is ignored.
 */
void hdd_wonder_sched_note_airtime(struct hdd_wonder_sched *sched, u32 lmac_id,
				  u32 freq, u32 tsf, bool tx, u32 duration_us);

#endif /* __WLAN_HDD_WONDER_SCHED_H */
