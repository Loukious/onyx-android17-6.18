/* Production Wonder serializer -> HDD parser -> HTT metadata integration. */
static void wonder_modern_rate_roundtrip(struct wondertap_fixed_tx_rate_params rate,
    unsigned int expected_preamble, unsigned int expected_mcs, unsigned int expected_nss,
    unsigned int expected_bw, unsigned int expected_gi, unsigned int expected_ltf)
{
    uint8_t bytes[128], normalized[128];
    struct cdp_tx_injection_params parsed;
    unsigned int frame_length;
    for (unsigned int skew = 0; skew < 2; skew++) {
        int size = wondertap_monitor_radiotap(bytes, sizeof(bytes), &rate, 5745, true, true);
        CHECK(size == (rate.preamble == WONDERTAP_RATE_PREAMBLE_HT ? 17 : 26));
        unsigned int length = frame(bytes + size, 0x0088, true);
        CHECK(parse(bytes, size + length, skew, &parsed, normalized, &frame_length) == 0);
        CHECK(frame_length == length && !memcmp(normalized, bytes + size, length));
        if (!parsed.rate_valid || parsed.preamble != expected_preamble) fprintf(stderr, "rate=%u actual=%u expected=%u valid=%d\n", rate.preamble, parsed.preamble, expected_preamble, parsed.rate_valid);
        CHECK(parsed.rate_valid && parsed.preamble == expected_preamble);
        CHECK(parsed.mcs_mask == BIT(expected_mcs) && parsed.nss_mask == BIT(expected_nss - 1));
        CHECK(parsed.bandwidth_valid && parsed.bw_mask == expected_bw);
        CHECK(parsed.gi_valid && parsed.guard_interval == expected_gi);
        CHECK(parsed.no_ack && parsed.chanfreq == 5745);
        queued_params = parsed;
        struct sk_buff skb = {.data = normalized, .len = frame_length};
        struct dp_tx_msdu_info_s msdu = {0};
        queued_nbuf = &skb;
        CHECK(dp_tx_add_injection_metadata(&skb, &msdu));
        struct htt_tx_msdu_desc_ext2_t *meta = (void *)msdu.meta_data;
        CHECK(meta->valid_mcs_mask && meta->mcs_mask == BIT(expected_mcs));
        CHECK(meta->valid_nss_mask && meta->nss_mask == BIT(expected_nss - 1));
        CHECK(meta->valid_preamble_type && meta->pream_type == expected_preamble);
        CHECK(meta->valid_bw_info && meta->bw_mask == expected_bw && !meta->dyn_bw);
        CHECK(meta->valid_guard_interval && meta->guard_interval == expected_gi);
        CHECK(!meta->update_peer_cache);
        if (rate.preamble == WONDERTAP_RATE_PREAMBLE_HE)
            CHECK(meta->ltf_subtype_11ax == expected_ltf && !meta->use_dcm_11ax);
    }
    queued_nbuf = NULL;
}

static void wonder_transport_fixtures(void)
{
    static const uint8_t awdl_snap[] = {0xaa, 0xaa, 3, 0, 0x17, 0xf2, 8, 0};
    struct wondertap_fixed_tx_rate_params rate = {
        .preamble = WONDERTAP_RATE_PREAMBLE_HT,
        .bw = WONDERTAP_RATE_BW_20, .nss = 1, .mcs = 7,
    };
    struct cdp_tx_injection_params p;
    uint8_t bytes[128], normalized[128];
    unsigned int frame_length;
    for (unsigned int mcs = 0; mcs < 8; mcs++) {
        for (unsigned int gi = 0; gi <= WONDERTAP_RATE_GI_0_8_US; gi++) {
            for (unsigned int skew = 0; skew < 2; skew++) {
                rate.mcs = mcs; rate.gi = gi;
                memset(bytes, 0xa5, sizeof(bytes));
                int size = wondertap_monitor_radiotap(bytes, sizeof(bytes),
                    &rate, 5745, true, false);
                CHECK(size == 17);
                unsigned int length = frame(bytes + size, 0x0088, false);
                bytes[size + 24] = 5;
                memcpy(bytes + size + length, awdl_snap, sizeof(awdl_snap));
                length += sizeof(awdl_snap);
                CHECK(parse(bytes, size + length, skew, &p,
                            normalized, &frame_length) == 0);
                CHECK(frame_length == length && !memcmp(normalized, bytes + size, length));
                CHECK(p.is_data && !p.is_eapol && p.tid == 5);
                CHECK(p.chanfreq == 5745 && p.preamble == CDP_INJECTION_HT);
                CHECK(p.rate_valid && p.mcs_mask == BIT(mcs) && p.nss_mask == 1);
                CHECK(p.gi_valid && p.guard_interval == (gi != WONDERTAP_RATE_GI_SHORT));
                CHECK(p.bandwidth_valid && p.bw_mask == BIT(2));
                CHECK(!p.no_ack && (p.tx_flags & IEEE80211_RADIOTAP_F_TX_NOSEQNO));
                queued_params = p;
                struct sk_buff skb = {.data = normalized, .len = frame_length};
                struct dp_tx_msdu_info_s msdu = {0};
                queued_nbuf = &skb;
                dp_tx_add_injection_metadata(&skb, &msdu);
                struct htt_tx_msdu_desc_ext2_t *meta = (void *)msdu.meta_data;
                CHECK(meta->valid_mcs_mask && meta->mcs_mask == BIT(mcs));
                CHECK(meta->valid_nss_mask && meta->nss_mask == 1);
            }
        }
    }
    for (unsigned int no_ack = 0; no_ack < 2; no_ack++) {
        int size = wondertap_monitor_radiotap(bytes, sizeof(bytes),
            &rate, 2437, false, no_ack);
        CHECK(size == 16 && bytes[9] == 0); /* Alignment padding is initialized. */
        unsigned int length = frame(bytes + size, 0x00d0, false);
        CHECK(parse(bytes, size + length, 0, &p, NULL, NULL) == 0);
        CHECK(!p.is_data && p.preamble == CDP_INJECTION_OFDM && p.mcs_mask == BIT(4));
        CHECK(p.chanfreq == 2437 && p.no_ack == !!no_ack);
    }
    rate.mcs = 16;
    CHECK(wondertap_monitor_validate_rate(&rate) == -EOPNOTSUPP);
    rate.mcs = 7; rate.nss = 3;
    CHECK(wondertap_monitor_validate_rate(&rate) == -EOPNOTSUPP);
    rate.nss = 1; rate.bw = WONDERTAP_RATE_BW_80;
    CHECK(wondertap_monitor_validate_rate(&rate) == -EOPNOTSUPP);
    rate.bw = WONDERTAP_RATE_BW_20; rate.preamble = WONDERTAP_RATE_PREAMBLE_VHT; rate.mcs = 9;
    CHECK(wondertap_monitor_validate_rate(&rate) == -EOPNOTSUPP);
    rate.preamble = WONDERTAP_RATE_PREAMBLE_HT; rate.mcs = 7;
    CHECK(wondertap_monitor_radiotap(bytes, 16, &rate, 5745, true, false) == -EINVAL);
    CHECK(wondertap_monitor_radiotap(bytes, sizeof(bytes), &rate, 0, true, false) == -EINVAL);
    CHECK(wondertap_monitor_radiotap(bytes, sizeof(bytes), &rate, 65536, true, false) == -EINVAL);

    rate = (struct wondertap_fixed_tx_rate_params){.preamble = WONDERTAP_RATE_PREAMBLE_HT,
        .bw = WONDERTAP_RATE_BW_40, .nss = 2, .mcs = 15, .gi = WONDERTAP_RATE_GI_SHORT};
    wonder_modern_rate_roundtrip(rate, CDP_INJECTION_HT, 7, 2, BIT(3), 0, 0);
    rate.nss = 1; /* Combined HT MCS15 must agree with its two streams. */
    CHECK(wondertap_monitor_validate_rate(&rate) == -EOPNOTSUPP);
    rate = (struct wondertap_fixed_tx_rate_params){.preamble = WONDERTAP_RATE_PREAMBLE_VHT,
        .bw = WONDERTAP_RATE_BW_80, .nss = 2, .mcs = 9, .gi = WONDERTAP_RATE_GI_0_8_US};
    wonder_modern_rate_roundtrip(rate, CDP_INJECTION_VHT, 9, 2, BIT(4), 1, 0);
    rate.mcs = 10;
    CHECK(wondertap_monitor_validate_rate(&rate) == -EOPNOTSUPP);
    rate = (struct wondertap_fixed_tx_rate_params){.preamble = WONDERTAP_RATE_PREAMBLE_HE,
        .bw = WONDERTAP_RATE_BW_80, .nss = 2, .mcs = 11, .gi = WONDERTAP_RATE_GI_3_2_US};
    wonder_modern_rate_roundtrip(rate, CDP_INJECTION_HE_SU, 11, 2, BIT(4), 3, 2);
    rate.bw = WONDERTAP_RATE_BW_40; rate.nss = 1; rate.mcs = 8; rate.gi = WONDERTAP_RATE_GI_1_6_US;
    wonder_modern_rate_roundtrip(rate, CDP_INJECTION_HE_SU, 8, 1, BIT(3), 2, 1);
    rate.bw = WONDERTAP_RATE_BW_20; rate.mcs = 0; rate.gi = WONDERTAP_RATE_GI_DEFAULT;
    wonder_modern_rate_roundtrip(rate, CDP_INJECTION_HE_SU, 0, 1, BIT(2), 1, 1);
    rate.mcs = 12;
    CHECK(wondertap_monitor_validate_rate(&rate) == -EOPNOTSUPP);
    rate.mcs = 11; rate.gi = WONDERTAP_RATE_GI_SHORT;
    CHECK(wondertap_monitor_validate_rate(&rate) == -EOPNOTSUPP);
    rate.gi = WONDERTAP_RATE_GI_3_2_US; rate.bw = WONDERTAP_RATE_BW_160;
    CHECK(wondertap_monitor_validate_rate(&rate) == -EOPNOTSUPP);
}
