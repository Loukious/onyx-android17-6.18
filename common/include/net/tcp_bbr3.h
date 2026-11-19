/* SPDX-License-Identifier: GPL-2.0 */
/* BBRv3 private state. Not in include/net/tcp.h: a type there moves every
 * exported symbol of net/ipv4/tcp.c on gendefaultksyms kernels. */
#ifndef _NET_TCP_BBR3_H
#define _NET_TCP_BBR3_H

#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/list.h>

struct tcp_bbr3_info {
	__u32 bw_lo, bw_hi;
	__u32 min_rtt_us;
	__u32 pacing_gain, cwnd_gain;
	__u32 mode, phase, version;
	__u32 inflight_lo, inflight_hi, extra_acked;
};

struct bbr3_tx_stamp {
	u32 seq; /* skb end_seq: the key */
	u32 in_flight;
	u32 lost;
};

#define BBR3_TX_STAMP_RING 64

struct bbr3 {
	struct hlist_node diag_node;
	struct rcu_head rcu;
	const struct sock *sk;
	u8 is_acking_tlp_retrans_seq : 1;
	u8 fast_ack_mode : 2;

	/* exact per-skb transmit state, upstream keeps this in
	 * tcp_skb_cb; here it is private so no CRC moves. */
	struct bbr3_tx_stamp tx_stamp[BBR3_TX_STAMP_RING];
	u64 tx_stamp_head; /* TLP repaired a loss */
	u32 min_rtt_us; /* min RTT in min_rtt_win_sec window */
	u32 min_rtt_stamp; /* timestamp of min_rtt_us */
	u32 probe_rtt_done_stamp; /* end time for BBR_PROBE_RTT mode */
	u32 probe_rtt_min_us; /* min RTT in probe_rtt_win_ms win */
	u32 probe_rtt_min_stamp; /* timestamp of probe_rtt_min_us*/
	u32 next_rtt_delivered; /* scb->tx.delivered at end of round */
	u64 cycle_mstamp; /* time of this cycle phase start */
	u32 mode : 2, /* current bbr_mode in state machine */
		prev_ca_state : 3, /* CA state on previous ACK */
		round_start : 1, /* start of packet-timed tx->ack round? */
		ce_state : 1, /* If most recent data has CE bit set */
		bw_probe_up_rounds : 5, /* cwnd-limited rounds in PROBE_UP */
		try_fast_path : 1, /* can we take fast path? */
		idle_restart : 1, /* restarting after idle? */
		probe_rtt_round_done : 1, /* a BBR_PROBE_RTT round at 4 pkts? */
		init_cwnd : 7, /* initial cwnd */
		unused_1 : 10;
	u32 pacing_gain : 10, /* current gain for setting pacing rate */
		cwnd_gain : 10, /* current gain for setting cwnd */
		full_bw_reached : 1, /* reached full bw in Startup? */
		full_bw_cnt : 2, /* number of rounds without large bw gains */
		cycle_idx : 2, /* current index in pacing_gain cycle array */
		has_seen_rtt : 1, /* have we seen an RTT sample yet? */
		unused_2 : 6;
	u32 prior_cwnd; /* prior cwnd upon entering loss recovery */
	u32 full_bw; /* recent bw, to estimate if pipe is full */

	/* For tracking ACK aggregation: */
	u64 ack_epoch_mstamp; /* start of ACK sampling epoch */
	u16 extra_acked[2]; /* max excess data ACKed in epoch */
	u32 ack_epoch_acked : 20, /* packets (S)ACKed in sampling epoch */
		extra_acked_win_rtts
		: 5, /* age of extra_acked, in round trips */
		extra_acked_win_idx
		: 1, /* current index in extra_acked array */
		/* BBR v3 state: */
		full_bw_now : 1, /* recently reached full bw plateau? */
		startup_ecn_rounds : 2, /* consecutive hi ECN STARTUP rounds */
		loss_in_cycle : 1, /* packet loss in this cycle? */
		ecn_in_cycle : 1, /* ECN in this cycle? */
		unused_3 : 1;
	u32 loss_round_delivered; /* scb->tx.delivered ending loss round */
	u32 undo_bw_lo; /* bw_lo before latest losses */
	u32 undo_inflight_lo; /* inflight_lo before latest losses */
	u32 undo_inflight_hi; /* inflight_hi before latest losses */
	u32 bw_latest; /* max delivered bw in last round trip */
	u32 bw_lo; /* lower bound on sending bandwidth */
	u32 bw_hi[2]; /* max recent measured bw sample */
	u32 inflight_latest; /* max delivered data in last round trip */
	u32 inflight_lo; /* lower bound of inflight data range */
	u32 inflight_hi; /* upper bound of inflight data range */
	u32 bw_probe_up_cnt; /* packets delivered per inflight_hi incr */
	u32 bw_probe_up_acks; /* packets (S)ACKed since inflight_hi incr */
	u32 probe_wait_us; /* PROBE_DOWN until next clock-driven probe */
	u32 prior_rcv_nxt; /* tp->rcv_nxt when CE state last changed */
	u32 ecn_eligible : 1, /* sender can use ECN (RTT, handshake)? */
		ecn_alpha : 9, /* EWMA delivered_ce/delivered; 0..256 */
		bw_probe_samples : 1, /* rate samples reflect bw probing? */
		prev_probe_too_high : 1, /* did last PROBE_UP go too high? */
		stopped_risky_probe
		: 1, /* last PROBE_UP stopped due to risk? */
		rounds_since_probe
		: 8, /* packet-timed rounds since probed bw */
		loss_round_start : 1, /* loss_round_delivered round trip? */
		loss_in_round : 1, /* loss marked in this round trip? */
		ecn_in_round : 1, /* ECN marked in this round trip? */
		ack_phase : 3, /* bbr_ack_phase: meaning of ACKs */
		loss_events_in_round : 4, /* losses in STARTUP round */
		initialized : 1; /* has bbr_init() been called? */
	u32 alpha_last_delivered; /* tp->delivered    at alpha update */
	u32 alpha_last_delivered_ce; /* tp->delivered_ce at alpha update */

	u8 unused_4; /* to preserve alignment */
	struct tcp_plb_state plb;

	/* react to a specific lost skb (optional) */
	void (*skb_marked_lost)(struct sock *sk, const struct sk_buff *skb);
};

#endif /* _NET_TCP_BBR3_H */
