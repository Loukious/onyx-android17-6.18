/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __WMA_WONDER_TSF_H
#define __WMA_WONDER_TSF_H

#include <qdf_types.h>

struct stsf;

/* Firmware TSF and the SoC timer latched by the same capture operation. */
struct wma_wonder_tsf_sample {
	u64 tsf_us;
	u64 qtimer_us;
	u32 tsf_id;
	u32 mac_id;
	bool ids_valid;
};

#ifdef FEATURE_WLAN_WONDER
/* A helper cookie proves the standalone FW vdev, which has no objmgr vdev. */
int wma_wonder_tsf_capture(u8 monitor_id, u8 vdev_id, u64 helper_cookie,
			   struct wma_wonder_tsf_sample *sample);
bool wma_wonder_tsf_event(const struct stsf *event);
/* Only after the firmware/event queue has been drained across restart. */
void wma_wonder_tsf_reset(void);
#else
static inline bool wma_wonder_tsf_event(const struct stsf *event)
{
	return false;
}
#endif

#endif /* __WMA_WONDER_TSF_H */
