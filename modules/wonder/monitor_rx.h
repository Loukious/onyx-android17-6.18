/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __WONDER_MONITOR_RX_H__
#define __WONDER_MONITOR_RX_H__

#include <linux/errno.h>
#include <linux/ieee80211.h>
#include <linux/skbuff.h>
#include <net/ieee80211_radiotap.h>

/* Only normalize frames entering mac80211; raw monitor capture keeps its FCS. */
static inline int wonder_normalize_monitor_rx(struct sk_buff *skb,
		unsigned int hdrlen, u8 rtap_flags, bool fcs_not_support)
{
	unsigned int pad = 0;
	unsigned int fcs_len = 0;
	int ret;

	if (rtap_flags & IEEE80211_RADIOTAP_F_DATAPAD)
		pad = (4 - (hdrlen & 3)) & 3;
	if (rtap_flags & IEEE80211_RADIOTAP_F_FCS)
		fcs_len = FCS_LEN;

	/* The advertised padding and FCS must not consume the 802.11 header. */
	if (hdrlen > skb->len || pad > skb->len - hdrlen ||
	    fcs_len > skb->len - hdrlen - pad)
		return -EINVAL;

	/* Onyx mixes RAW MPDUs with FCS and management frames without FCS. */
	if (fcs_not_support && fcs_len) {
		ret = pskb_trim(skb, skb->len - fcs_len);
		if (ret)
			return ret;
	}

	if (pad) {
		ret = skb_ensure_writable(skb, hdrlen + pad);
		if (ret)
			return ret;
		/* Move only the header, leaving a possibly fragmented payload in place. */
		memmove(skb->data + pad, skb->data, hdrlen);
		skb_pull(skb, pad);
	}

	return 0;
}

#endif /* __WONDER_MONITOR_RX_H__ */
