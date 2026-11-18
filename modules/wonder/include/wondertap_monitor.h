/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __WONDERTAP_MONITOR_H__
#define __WONDERTAP_MONITOR_H__

#include <linux/unaligned.h>
#include <net/ieee80211_radiotap.h>
#include <wondertap.h>

/* Optional Onyx monitor lifecycle hooks, outside the shared vendor ABI.
 * mac80211 PM holds only the Wonder wiphy/control locks: these hooks must
 * retain the vendor session/netdev and must not acquire RTNL or create/delete
 * interfaces. A failed suspend must leave the session usable; a failed resume
 * must leave it suspended so that a later normal teardown remains possible.
 */
struct wondertap_monitor_ops {
	int (*suspend)(void *handle);
	int (*resume)(void *handle);
};

struct wondertap_monitor_aux_dev {
	struct wondertap_aux_dev tap;
	const struct wondertap_monitor_ops *monitor_ops;
};

/* Bounds for the existing Onyx monitor injection transport. */
#define WONDERTAP_MONITOR_RTAP_MAX 26

static inline int wondertap_monitor_validate_rate(
		const struct wondertap_fixed_tx_rate_params *rate)
{
	if (!rate)
		return -EINVAL;
	if (rate->nss < 1 || rate->nss > 2 ||
	    rate->bw < WONDERTAP_RATE_BW_20 || rate->bw > WONDERTAP_RATE_BW_80 ||
	    rate->gi < WONDERTAP_RATE_GI_DEFAULT || rate->gi > WONDERTAP_RATE_GI_3_2_US ||
	    rate->reserved[0] || rate->reserved[1])
		return -EOPNOTSUPP;
	switch (rate->preamble) {
	case WONDERTAP_RATE_PREAMBLE_HT:
		/* Accept per-stream MCS or a consistent combined HT MCS index. */
		if (rate->bw > WONDERTAP_RATE_BW_40 || rate->mcs > 15 ||
		    (rate->mcs > 7 && rate->nss != rate->mcs / 8 + 1) ||
		    rate->gi > WONDERTAP_RATE_GI_0_8_US)
			return -EOPNOTSUPP;
		break;
	case WONDERTAP_RATE_PREAMBLE_VHT:
		if (rate->mcs > 9 || rate->gi > WONDERTAP_RATE_GI_0_8_US ||
		    (rate->bw == WONDERTAP_RATE_BW_20 && rate->mcs == 9))
			return -EOPNOTSUPP;
		break;
	case WONDERTAP_RATE_PREAMBLE_HE:
		if (rate->mcs > 11 || rate->gi == WONDERTAP_RATE_GI_SHORT)
			return -EOPNOTSUPP;
		break;
	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

/* Emit only fields accepted by the production HDD radiotap parser. */
static inline int wondertap_monitor_radiotap(u8 *buffer, size_t size,
		const struct wondertap_fixed_tx_rate_params *rate, u32 freq,
		bool data, bool no_ack)
{
	struct ieee80211_radiotap_header *header;
	u32 present = BIT(IEEE80211_RADIOTAP_CHANNEL) |
		      BIT(IEEE80211_RADIOTAP_TX_FLAGS);
	u16 channel_flags, tx_flags = IEEE80211_RADIOTAP_F_TX_NOSEQNO;
	unsigned int offset = sizeof(*header);
	int ret;

	if (!buffer || size < WONDERTAP_MONITOR_RTAP_MAX ||
	    !freq || freq > 65535)
		return -EINVAL;
	ret = wondertap_monitor_validate_rate(rate);
	if (ret)
		return ret;

	memset(buffer, 0, WONDERTAP_MONITOR_RTAP_MAX);
	header = (struct ieee80211_radiotap_header *)buffer;
	channel_flags = IEEE80211_CHAN_OFDM |
		(freq < 3000 ? IEEE80211_CHAN_2GHZ : IEEE80211_CHAN_5GHZ);
	if (no_ack)
		tx_flags |= IEEE80211_RADIOTAP_F_TX_NOACK;
	if (!data) {
		/* Discovery/action frames use the mandatory 6 Mbps OFDM rate. */
		present |= BIT(IEEE80211_RADIOTAP_RATE);
		buffer[offset++] = 12;
		offset = ALIGN(offset, 2);
	} else {
		switch (rate->preamble) {
		case WONDERTAP_RATE_PREAMBLE_HT:
			present |= BIT(IEEE80211_RADIOTAP_MCS);
			break;
		case WONDERTAP_RATE_PREAMBLE_VHT:
			present |= BIT(IEEE80211_RADIOTAP_VHT);
			break;
		case WONDERTAP_RATE_PREAMBLE_HE:
			present |= BIT(IEEE80211_RADIOTAP_HE);
			break;
		default:
			return -EOPNOTSUPP;
		}
	}
	put_unaligned_le16(freq, buffer + offset);
	put_unaligned_le16(channel_flags, buffer + offset + 2);
	offset += 4;
	put_unaligned_le16(tx_flags, buffer + offset);
	offset += 2;
	if (data && rate->preamble == WONDERTAP_RATE_PREAMBLE_HT) {
		buffer[offset++] = IEEE80211_RADIOTAP_MCS_HAVE_BW |
			IEEE80211_RADIOTAP_MCS_HAVE_MCS |
			IEEE80211_RADIOTAP_MCS_HAVE_GI;
		buffer[offset++] =
			(rate->bw == WONDERTAP_RATE_BW_40 ? IEEE80211_RADIOTAP_MCS_BW_40 : 0) |
			(rate->gi == WONDERTAP_RATE_GI_SHORT ? IEEE80211_RADIOTAP_MCS_SGI : 0);
		buffer[offset++] = rate->mcs <= 7 ? rate->mcs + 8 * (rate->nss - 1) : rate->mcs;
	} else if (data && rate->preamble == WONDERTAP_RATE_PREAMBLE_VHT) {
		offset = ALIGN(offset, 2);
		put_unaligned_le16(IEEE80211_RADIOTAP_VHT_KNOWN_GI |
				   IEEE80211_RADIOTAP_VHT_KNOWN_BANDWIDTH, buffer + offset);
		buffer[offset + 2] = rate->gi == WONDERTAP_RATE_GI_SHORT ?
			IEEE80211_RADIOTAP_VHT_FLAG_SGI : 0;
		buffer[offset + 3] = rate->bw == WONDERTAP_RATE_BW_80 ? 4 :
			rate->bw == WONDERTAP_RATE_BW_40 ? 1 : 0;
		buffer[offset + 4] = (rate->mcs << 4) | rate->nss;
		offset += 12;
	} else if (data && rate->preamble == WONDERTAP_RATE_PREAMBLE_HE) {
		u16 gi = rate->gi == WONDERTAP_RATE_GI_3_2_US ? 2 :
			 rate->gi == WONDERTAP_RATE_GI_1_6_US ? 1 : 0;
		u16 ltf = gi == 2 ? IEEE80211_RADIOTAP_HE_DATA5_LTF_SIZE_4X :
			  IEEE80211_RADIOTAP_HE_DATA5_LTF_SIZE_2X;

		offset = ALIGN(offset, 2);
		put_unaligned_le16(IEEE80211_RADIOTAP_HE_DATA1_DATA_MCS_KNOWN |
				   IEEE80211_RADIOTAP_HE_DATA1_BW_RU_ALLOC_KNOWN, buffer + offset);
		put_unaligned_le16(IEEE80211_RADIOTAP_HE_DATA2_GI_KNOWN, buffer + offset + 2);
		put_unaligned_le16(rate->mcs << 8, buffer + offset + 4);
		put_unaligned_le16(rate->bw | (gi << 4) | (ltf << 6), buffer + offset + 8);
		put_unaligned_le16(rate->nss, buffer + offset + 10);
		offset += sizeof(struct ieee80211_radiotap_he);
	}
	header->it_len = cpu_to_le16(offset);
	header->it_present = cpu_to_le32(present);
	return offset;
}

#endif /* __WONDERTAP_MONITOR_H__ */
