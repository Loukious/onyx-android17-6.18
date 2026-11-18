/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __WLAN_HDD_WONDER_COEX_H
#define __WLAN_HDD_WONDER_COEX_H

#include <linux/types.h>
#include <wma_api.h>

struct hdd_adapter;
struct hdd_wonder_coex;

#define HDD_WONDER_COEX_MAX_DWELL_NS (32ULL * 1000000ULL)

struct hdd_wonder_coex *hdd_wonder_coex_create(struct hdd_adapter *adapter,
		u32 home_frequency, u64 generation,
		const struct wma_wonder_helper_snapshot *helper);
/* Caller serializes process operations. No callback retains the adapter.
 * Destroy revokes and requests cancellation; a firmware-owned reservation
 * retains its context and module reference until a genuine terminal event.
 */
void hdd_wonder_coex_destroy(struct hdd_wonder_coex *coex);
void hdd_wonder_coex_cancel(struct hdd_wonder_coex *coex);
int hdd_wonder_coex_home(struct hdd_wonder_coex *coex);
int hdd_wonder_coex_acquire(struct hdd_wonder_coex *coex, u32 frequency,
		u64 slot_end_ns, u64 duration_ns, u64 *completion_ns);
/* Final packet publication only: admission lock -> dwell lock. No sleeping,
 * MLME reentry or helper mutation between successful begin and end.
 * A zero packet frequency uses the explicitly selected logical channel.
 */
bool hdd_wonder_coex_publish_begin(struct hdd_wonder_coex *coex,
		u32 packet_frequency, unsigned long *flags);
void hdd_wonder_coex_publish_end(struct hdd_wonder_coex *coex,
		unsigned long flags);
bool hdd_wonder_coex_ready(struct hdd_wonder_coex *coex, u32 frequency);
/* An immutable queued-packet token prevents a later dwell on the same
 * frequency from authorizing packets accepted for an earlier scan tuple.
 */
void *hdd_wonder_coex_tx_token(struct hdd_wonder_coex *coex, u32 frequency);
bool hdd_wonder_coex_tx_begin(void *token, unsigned long *flags);
void hdd_wonder_coex_tx_end(void *token, unsigned long flags);
void hdd_wonder_coex_tx_release(void *token);
u32 hdd_wonder_coex_tx_frequency(void *token);
/* Under MLME admission already, used by the measured monitor RX path. */
bool hdd_wonder_coex_rx_begin_locked(struct hdd_wonder_coex *coex,
		u64 generation, u32 frequency);
void hdd_wonder_coex_rx_end_locked(struct hdd_wonder_coex *coex);
u32 hdd_wonder_coex_home_frequency(struct hdd_wonder_coex *coex);
const struct wma_wonder_helper_snapshot *
hdd_wonder_coex_helper(struct hdd_wonder_coex *coex);
u64 hdd_wonder_coex_generation(struct hdd_wonder_coex *coex);
int hdd_wonder_coex_format(struct hdd_wonder_coex *coex, char *buffer,
		size_t capacity);

#endif
