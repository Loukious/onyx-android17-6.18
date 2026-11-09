/* SPDX-License-Identifier: ISC */
/* Per-packet monitor TX settings shared by HDD, WMA and the raw datapath. */
#ifndef _CDP_TXRX_INJECTION_H_
#define _CDP_TXRX_INJECTION_H_

#include <qdf_nbuf.h>

#define CDP_TX_INJECTION_DESC_PREFIX 0xf000

enum cdp_tx_injection_preamble {
	CDP_INJECTION_OFDM,
	CDP_INJECTION_CCK,
	CDP_INJECTION_HT,
};

struct cdp_tx_injection_params {
	uint16_t mcs_mask;
	uint16_t tx_flags;
	uint16_t chanfreq;
	/* Owning netdev address, independent of the injected frame's transmitter. */
	uint8_t interface_mac[QDF_MAC_ADDR_SIZE];
	uint8_t nss_mask;
	uint8_t preamble;
	/* HTT bandwidth bitmap: bit 2 = 20 MHz, bit 3 = 40 MHz. */
	uint8_t bw_mask;
	/* HTT guard interval: 0 = 0.4 us, 1 = 0.8 us. */
	uint8_t guard_interval;
	/* Total attempts, including the initial transmission (1..15). */
	uint8_t retries;
	uint8_t tid;
	bool rate_valid;
	bool bandwidth_valid;
	bool gi_valid;
	bool retries_valid;
	bool no_ack;
	bool is_data;
	bool is_eapol;
};

static inline bool cdp_nbuf_is_injection(qdf_nbuf_t nbuf)
{
#ifdef FEATURE_FRAME_INJECTION_SUPPORT
	return (QDF_NBUF_CB_MGMT_TXRX_DESC_ID(nbuf) &
		CDP_TX_INJECTION_DESC_PREFIX) == CDP_TX_INJECTION_DESC_PREFIX;
#else
	return false;
#endif
}

#ifdef FEATURE_FRAME_INJECTION_SUPPORT
bool wma_injection_get_tx_params(qdf_nbuf_t nbuf,
				struct cdp_tx_injection_params *params);
#endif

#endif /* _CDP_TXRX_INJECTION_H_ */
