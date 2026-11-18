/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef WLAN_HDD_WONDER_RATE_H
#define WLAN_HDD_WONDER_RATE_H

#include <cdp_txrx_injection.h>
#include <wondertap.h>

/* Wonder's fixed rate is shared by destinations. Its raw self-peer helper
 * cannot negotiate rates, so constrain each data packet to the destination's
 * advertised receive capabilities. No radio/session setting is changed.
 */
static inline void hdd_wonder_basic_data_rate(struct cdp_tx_injection_params *rate)
{
	rate->preamble = CDP_INJECTION_OFDM;
	rate->mcs_mask = BIT(4); /* mandatory 6 Mbps OFDM */
	rate->nss_mask = BIT(0);
	rate->bw_mask = BIT(2);
	rate->rate_valid = true;
	rate->bandwidth_valid = true;
	rate->gi_valid = false;
	rate->guard_interval = 0;
	rate->he_ltf = 0;
}

static inline void hdd_wonder_peer_constrain_rate(
		const struct wondertap_station_info *peer,
		struct cdp_tx_injection_params *rate)
{
	u16 mcs, supported, map;
	u32 capability;
	unsigned int nss, max_mcs, width;
	bool short_gi;

	if (!rate->is_data || !rate->rate_valid ||
	    rate->preamble == CDP_INJECTION_OFDM ||
	    rate->preamble == CDP_INJECTION_CCK)
		return;
	/* OFDM is not legal on 6 GHz. The station ABI contains no HE receive
 * MCS map, so leave that explicit configuration to existing validation.
 */
	if (rate->chanfreq >= 5925)
		return;
	if (!peer || !rate->mcs_mask || !rate->nss_mask) {
		hdd_wonder_basic_data_rate(rate);
		return;
	}
	max_mcs = fls(rate->mcs_mask) - 1;
	nss = min_t(unsigned int, fls(rate->nss_mask), 2);
	if (rate->preamble == CDP_INJECTION_HT &&
	    (peer->capability_mask & BIT(WONDERTAP_STATION_CAP_HT))) {
		capability = le16_to_cpu(peer->ht_capa.cap_info);
		width = capability & IEEE80211_HT_CAP_SUP_WIDTH_20_40 ? 3 : 2;
		for (; nss; nss--) {
			supported = peer->ht_capa.mcs.rx_mask[nss - 1];
			mcs = supported & rate->mcs_mask;
			if (!mcs)
				mcs = supported & GENMASK(min_t(unsigned int, max_mcs, 7), 0);
			if (mcs)
				break;
		}
		short_gi = capability &
			((rate->bw_mask & BIT(3)) && width == 3 ?
			 IEEE80211_HT_CAP_SGI_40 : IEEE80211_HT_CAP_SGI_20);
	} else if (rate->preamble == CDP_INJECTION_VHT &&
		   (peer->capability_mask & BIT(WONDERTAP_STATION_CAP_VHT))) {
		capability = le32_to_cpu(peer->vht_capa.vht_cap_info);
		map = le16_to_cpu(peer->vht_capa.supp_mcs.rx_mcs_map);
		width = 4; /* supported VHT baseline is 80 MHz */
		for (; nss; nss--) {
			unsigned int limit = (map >> (2 * (nss - 1))) & 3;

			if (limit == IEEE80211_VHT_MCS_NOT_SUPPORTED)
				continue;
			supported = GENMASK(7 + limit, 0);
			mcs = supported & rate->mcs_mask;
			if (!mcs)
				mcs = supported & GENMASK(min_t(unsigned int, max_mcs, 9), 0);
			if (mcs)
				break;
		}
		/* VHT uses HT capability bits for short GI at 20/40 MHz. */
		short_gi = rate->bw_mask & BIT(4) ?
			capability & IEEE80211_VHT_CAP_SHORT_GI_80 :
			(peer->capability_mask & BIT(WONDERTAP_STATION_CAP_HT)) &&
			(le16_to_cpu(peer->ht_capa.cap_info) &
			 (rate->bw_mask & BIT(3) ? IEEE80211_HT_CAP_SGI_40 :
						IEEE80211_HT_CAP_SGI_20));
	} else {
		hdd_wonder_basic_data_rate(rate);
		return;
	}
	if (!nss) {
		hdd_wonder_basic_data_rate(rate);
		return;
	}
	rate->nss_mask = BIT(nss - 1);
	rate->mcs_mask = mcs;
	if (rate->bandwidth_valid && (rate->bw_mask & ~GENMASK(width, 2)))
		rate->bw_mask = BIT(width);
	if (rate->gi_valid && !rate->guard_interval && !short_gi)
		rate->guard_interval = 1; /* long GI: 0.8 us */
}

#endif /* WLAN_HDD_WONDER_RATE_H */
