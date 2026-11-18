// SPDX-License-Identifier: GPL-2.0-only
/* Reuse Onyx's existing paired TSF/QTIMER capture command. */
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <qdf_time.h>
#include "wma.h"
#include "wma_internal.h"
#include "wma_api.h"
#include "wma_wonder_tsf.h"
#include "cds_api.h"

#ifdef FEATURE_WLAN_WONDER

#define WMA_WONDER_TSF_TIMEOUT_MS 200

static DEFINE_MUTEX(wma_wonder_tsf_request_lock);
static DEFINE_SPINLOCK(wma_wonder_tsf_lock);
static DECLARE_COMPLETION(wma_wonder_tsf_completion);
static struct {
	struct wma_wonder_tsf_sample sample;
	u8 vdev_id;
	bool pending;
	bool waiting;
	bool received;
} wma_wonder_tsf;

bool wma_wonder_tsf_event(const struct stsf *event)
{
	unsigned long flags;
	bool consumed = false;

	/* mac_id_valid identifies unsolicited TSF auto reports in this WMI ABI.
	 * They must not release a pending command's late-response quarantine.
	 */
	if (!event || event->mac_id_valid)
		return false;

	spin_lock_irqsave(&wma_wonder_tsf_lock, flags);
	if (wma_wonder_tsf.pending && event->vdev_id == wma_wonder_tsf.vdev_id) {
		consumed = true;
		wma_wonder_tsf.pending = false;
		if (wma_wonder_tsf.waiting) {
			wma_wonder_tsf.sample.tsf_us =
				((u64)event->tsf_high << 32) | event->tsf_low;
			wma_wonder_tsf.sample.qtimer_us =
				((u64)event->soc_timer_high << 32) | event->soc_timer_low;
#ifndef WLAN_FEATURE_TSF_TIMER_SYNC
			wma_wonder_tsf.sample.qtimer_us = qdf_log_timestamp_to_usecs(
				wma_wonder_tsf.sample.qtimer_us);
#endif
			wma_wonder_tsf.sample.tsf_id = event->tsf_id;
			wma_wonder_tsf.sample.mac_id = event->mac_id;
			wma_wonder_tsf.sample.ids_valid =
				event->tsf_id_valid;
			wma_wonder_tsf.received = true;
			complete(&wma_wonder_tsf_completion);
		}
	}
	spin_unlock_irqrestore(&wma_wonder_tsf_lock, flags);
	return consumed;
}

int wma_wonder_tsf_capture(u8 monitor_id, u8 vdev_id, u64 helper_cookie,
			   struct wma_wonder_tsf_sample *sample)
{
	tp_wma_handle wma = cds_get_context(QDF_MODULE_ID_WMA);
	unsigned long flags;
	QDF_STATUS status;
	int ret;

	if (!sample || !wma || !helper_cookie || vdev_id >= wma->max_bssid)
		return -ENODEV;

	mutex_lock(&wma_wonder_tsf_request_lock);
	if (!wma_wonder_helper_identity_valid(monitor_id, vdev_id, helper_cookie)) {
		ret = -ESTALE;
		goto unlock;
	}
	spin_lock_irqsave(&wma_wonder_tsf_lock, flags);
	/* There is no transaction ID in this firmware response. A timed-out
	 * request stays quarantined until its late response or firmware reset.
	 */
	if (wma_wonder_tsf.pending) {
		spin_unlock_irqrestore(&wma_wonder_tsf_lock, flags);
		ret = -EAGAIN;
		goto unlock;
	}
	reinit_completion(&wma_wonder_tsf_completion);
	wma_wonder_tsf.vdev_id = vdev_id;
	wma_wonder_tsf.pending = true;
	wma_wonder_tsf.waiting = true;
	wma_wonder_tsf.received = false;
	spin_unlock_irqrestore(&wma_wonder_tsf_lock, flags);

	status = wma_capture_tsf(wma, vdev_id);
	if (QDF_IS_STATUS_ERROR(status)) {
		spin_lock_irqsave(&wma_wonder_tsf_lock, flags);
		wma_wonder_tsf.pending = false;
		wma_wonder_tsf.waiting = false;
		spin_unlock_irqrestore(&wma_wonder_tsf_lock, flags);
		ret = qdf_status_to_os_return(status);
		goto unlock;
	}

	wait_for_completion_timeout(&wma_wonder_tsf_completion,
				    msecs_to_jiffies(WMA_WONDER_TSF_TIMEOUT_MS));
	spin_lock_irqsave(&wma_wonder_tsf_lock, flags);
	if (wma_wonder_tsf.received) {
		*sample = wma_wonder_tsf.sample;
		ret = 0;
	} else {
		ret = -ETIMEDOUT;
	}
	wma_wonder_tsf.waiting = false;
	spin_unlock_irqrestore(&wma_wonder_tsf_lock, flags);
	/* Reject a capture that crossed deletion/reuse of the same numeric ID. */
	if (!ret && !wma_wonder_helper_identity_valid(monitor_id, vdev_id,
						     helper_cookie))
		ret = -ESTALE;
unlock:
	mutex_unlock(&wma_wonder_tsf_request_lock);
	return ret;
}

void wma_wonder_tsf_reset(void)
{
	unsigned long flags;

	mutex_lock(&wma_wonder_tsf_request_lock);
	spin_lock_irqsave(&wma_wonder_tsf_lock, flags);
	memset(&wma_wonder_tsf, 0, sizeof(wma_wonder_tsf));
	spin_unlock_irqrestore(&wma_wonder_tsf_lock, flags);
	mutex_unlock(&wma_wonder_tsf_request_lock);
}

#endif /* FEATURE_WLAN_WONDER */
