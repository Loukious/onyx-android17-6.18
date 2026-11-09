/* Host fixtures for the production radiotap/frame parser and HTT encoder. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

typedef uint8_t u8;
typedef uint16_t __le16;
typedef uint32_t __le32;
typedef uint32_t A_UINT32;
#define PREPACK
#define POSTPACK __attribute__((packed))
#define __packed __attribute__((packed))
#ifndef __attribute_const__
#define __attribute_const__ __attribute__((const))
#endif
#define EXPORT_SYMBOL(x)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define BIT(n) (UINT32_C(1) << (n))
#define GENMASK(h, l) ((UINT32_MAX >> (31 - (h))) & (UINT32_MAX << (l)))
#define ALIGN(n, a) (((n) + (a) - 1) & ~((a) - 1))
#define cpu_to_le16(x) ((uint16_t)(x))
#define le16_to_cpu(x) ((uint16_t)(x))
#define le32_to_cpu(x) ((uint32_t)(x))
#define HDD_IEEE80211_FCS_LEN 4

static uint16_t get_unaligned_le16(const void *p)
{
    const uint8_t *b = p;
    return b[0] | ((uint16_t)b[1] << 8);
}
static uint16_t get_unaligned_be16(const void *p)
{
    const uint8_t *b = p;
    return ((uint16_t)b[0] << 8) | b[1];
}
static uint32_t get_unaligned_le32(const void *p)
{
    const uint8_t *b = p;
    return b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
}
static void put16(uint8_t *b, uint16_t value)
{
    b[0] = value;
    b[1] = value >> 8;
}
static void put32(uint8_t *b, uint32_t value)
{
    put16(b, value);
    put16(b + 2, value >> 16);
}

/* The buffer mocks are deliberately allocation-bounded for ASan. */
struct sk_buff { uint8_t *data; unsigned int len; };
typedef struct sk_buff *qdf_nbuf_t;
static void skb_pull(struct sk_buff *skb, unsigned int size)
{
    assert(size <= skb->len);
    skb->data += size;
    skb->len -= size;
}
static void skb_trim(struct sk_buff *skb, unsigned int size)
{
    assert(size <= skb->len);
    skb->len = size;
}
struct ieee80211_hdr {
    __le16 frame_control, duration_id;
    uint8_t addr1[6], addr2[6], addr3[6];
    __le16 seq_ctrl;
    uint8_t addr4[6];
} __packed;
struct ieee80211_radiotap_header {
    uint8_t it_version, it_pad;
    __le16 it_len;
    __le32 it_present;
    __le32 it_optional[];
} __packed;

/* INSERT_KERNEL_DEFINITIONS */
#define QDF_MAC_ADDR_SIZE 6
/* INSERT_PARAMS */
/* INSERT_RADIOTAP */
/* INSERT_PARSER */
/* INSERT_HTT_DEFINITIONS */

struct dp_tx_msdu_info_s { uint32_t meta_data[9]; };
static struct cdp_tx_injection_params queued_params;
static qdf_nbuf_t queued_nbuf;
static bool wma_injection_get_tx_params(qdf_nbuf_t nbuf,
                                       struct cdp_tx_injection_params *params)
{
    if (nbuf != queued_nbuf)
        return false;
    *params = queued_params;
    return true;
}
/* INSERT_ENCODER */

static unsigned int cases;
#define CHECK(condition) do { assert(condition); cases++; } while (0)

static const uint8_t eapol[] = {
    0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e, 1, 1, 0, 0
};
static const uint8_t reaver_rtap[] = {0, 0, 10, 0, 0, 0x80, 0, 0, 0x18, 0};

static unsigned int frame(uint8_t *b, uint16_t fc, bool with_eapol)
{
    unsigned int length = ieee80211_hdrlen(fc);
    memset(b, 0, length);
    put16(b, fc);
    if (!ieee80211_is_ctl(fc) && !ieee80211_is_ext(fc))
        put16(b + 22, 0x1230);
    if (with_eapol) {
        memcpy(b + length, eapol, sizeof(eapol));
        length += sizeof(eapol);
    }
    return length;
}

static int parse(const uint8_t *bytes, unsigned int length, unsigned int skew,
                 struct cdp_tx_injection_params *params,
                 uint8_t *normalized, unsigned int *frame_length)
{
    uint8_t *allocation = malloc(length + skew + 1);
    assert(allocation);
    memcpy(allocation + skew, bytes, length);
    struct sk_buff skb = {.data = allocation + skew, .len = length};
    uint8_t flags = 0;
    memset(params, 0, sizeof(*params));
    int ret = hdd_parse_injection_radiotap(&skb, params, &flags);
    if (!ret)
        ret = hdd_injection_frame(&skb, flags, params);
    if (!ret && normalized) {
        memcpy(normalized, skb.data, skb.len);
        *frame_length = skb.len;
    }
    free(allocation);
    return ret;
}

static void protocol_fixtures(void)
{
    uint8_t b[512] = {0}, normalized[512];
    unsigned int n, out_length;
    struct cdp_tx_injection_params p;
    memcpy(b, reaver_rtap, sizeof(reaver_rtap));
    n = 10 + frame(b + 10, 0x0108, true);
    CHECK(n == 46);
    for (unsigned int skew = 0; skew < 2; skew++) {
        CHECK(parse(b, n, skew, &p, normalized, &out_length) == 0);
        CHECK(p.is_data && p.is_eapol && p.tx_flags == 0x18);
        CHECK(p.no_ack && p.retries_valid && p.retries == 1);
        CHECK(out_length == 36 && !memcmp(normalized, b + 10, 36));
    }
    for (unsigned int len = 0; len < 34; len++)
        CHECK(parse(b, len, len & 1, &p, NULL, NULL) < 0);
    for (unsigned int len = 42; len < 46; len++)
        CHECK(parse(b, len, 0, &p, NULL, NULL) == -EINVAL);
    b[n - 1] = 1; /* EAPOL claims a missing payload byte. */
    CHECK(parse(b, n, 0, &p, NULL, NULL) == -EINVAL);
    b[n - 1] = 0;
    b[10] |= 1; /* Nonzero 802.11 protocol version. */
    CHECK(parse(b, n, 0, &p, NULL, NULL) == -EINVAL);
    b[10] &= ~1;
    b[0] = 1;
    CHECK(parse(b, n, 0, &p, NULL, NULL) == -EINVAL);
    b[0] = 0;
    for (uint16_t fc = 0x0188; fc <= 0x8388; fc += 0x0200) {
        if (fc != 0x0188 && fc != 0x0388 && fc != 0x8188 && fc != 0x8388)
            continue;
        n = 10 + frame(b + 10, fc, true);
        b[10 + (ieee80211_has_a4(fc) ? 30 : 24)] = 13;
        CHECK(parse(b, n, 1, &p, normalized, &out_length) == 0);
        CHECK(p.is_eapol && p.tid == 13);
        CHECK(!memcmp(normalized, b + 10, out_length));
        CHECK(parse(b, 10 + ieee80211_hdrlen(fc) - 1, 0, &p, NULL, NULL) < 0);
    }
    n = 10 + frame(b + 10, 0x0000, false); /* Association header. */
    CHECK(parse(b, n, 0, &p, NULL, NULL) == 0 && !p.is_data);
    n = 10 + frame(b + 10, 0x4108, true); /* Opaque protected payload. */
    b[n - 1] = 0xff;
    CHECK(parse(b, n, 0, &p, NULL, NULL) == 0 && !p.is_eapol);
    n = 10 + frame(b + 10, 0x0508, true); /* Partial fragment. */
    b[n - 1] = 0xff;
    CHECK(parse(b, n, 0, &p, NULL, NULL) == 0 && !p.is_eapol);
}

static void control_fixtures(void)
{
    uint8_t b[256] = {0};
    struct cdp_tx_injection_params p;
    memcpy(b, reaver_rtap, sizeof(reaver_rtap));
    const uint16_t controls[] = {0x00d4, 0x00c4, 0x00b4, 0x00a4, 0x00e4, 0x00f4};
    for (unsigned int i = 0; i < ARRAY_SIZE(controls); i++) {
        unsigned int n = 10 + frame(b + 10, controls[i], false);
        CHECK(parse(b, n, 1, &p, NULL, NULL) == 0 && !p.is_data);
        CHECK(parse(b, n - 1, 0, &p, NULL, NULL) == -EINVAL);
    }
    frame(b + 10, 0x0084, false); /* Single-TID BAR. */
    memset(b + 26, 0, 150);
    CHECK(parse(b, 30, 0, &p, NULL, NULL) == 0);
    CHECK(parse(b, 29, 0, &p, NULL, NULL) == -EINVAL);
    b[26] = 2; /* Multi-TID BAR is explicitly unsupported. */
    CHECK(parse(b, 30, 0, &p, NULL, NULL) == -EOPNOTSUPP);
    frame(b + 10, 0x0094, false);
    b[26] = 4; /* Compressed BA bitmap. */
    CHECK(parse(b, 38, 0, &p, NULL, NULL) == 0);
    CHECK(parse(b, 37, 0, &p, NULL, NULL) == -EINVAL);
    b[26] = 0; /* Basic BA needs the full 128-byte bitmap. */
    CHECK(parse(b, 38, 0, &p, NULL, NULL) == -EINVAL);
    CHECK(parse(b, 158, 0, &p, NULL, NULL) == 0);
}

static void radiotap_fixtures(void)
{
    uint8_t b[512] = {0}, normalized[512];
    unsigned int n, out_length;
    struct cdp_tx_injection_params p;
    const uint8_t rates[] = {2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108};
    put16(b + 2, 9);
    put32(b + 4, BIT(2));
    n = 9 + frame(b + 9, 0x0108, true);
    for (unsigned int i = 0; i < ARRAY_SIZE(rates); i++) {
        b[8] = rates[i];
        CHECK(parse(b, n, 1, &p, NULL, NULL) == 0);
        CHECK(p.rate_valid && p.mcs_mask == BIT(i) && p.nss_mask == 1);
        CHECK(p.preamble == (i < 4 ? CDP_INJECTION_CCK : CDP_INJECTION_OFDM));
    }
    b[8] = 0x80;
    CHECK(parse(b, n, 0, &p, NULL, NULL) == -EOPNOTSUPP);

    memset(b, 0, sizeof(b));
    put16(b + 2, 11); put32(b + 4, BIT(19));
    b[8] = 7; b[9] = 5; b[10] = 7; /* MCS7, 40 MHz, short GI. */
    n = 11 + frame(b + 11, 0x0108, true);
    CHECK(parse(b, n, 1, &p, NULL, NULL) == 0);
    CHECK(p.preamble == CDP_INJECTION_HT && p.mcs_mask == 0x80);
    CHECK(p.bandwidth_valid && p.bw_mask == 8 && p.gi_valid && p.guard_interval == 0);
    b[9] = 0;
    CHECK(parse(b, n, 0, &p, NULL, NULL) == 0 && p.guard_interval == 1 && p.bw_mask == 4);
    b[10] = 8;
    CHECK(parse(b, n, 0, &p, NULL, NULL) == -EOPNOTSUPP);
    b[10] = 7; b[8] |= 8; b[9] = 8; /* Greenfield. */
    CHECK(parse(b, n, 0, &p, NULL, NULL) == -EOPNOTSUPP);
    b[8] = 7; b[9] = 2; /* 20L selection. */
    CHECK(parse(b, n, 0, &p, NULL, NULL) == -EOPNOTSUPP);

    memset(b, 0, sizeof(b));
    put16(b + 2, 26); put32(b + 4, BIT(0) | BIT(1) | BIT(2) | BIT(31));
    b[24] = 0; b[25] = 12; /* Extended mask, aligned TSFT, FLAGS, RATE. */
    n = 26 + frame(b + 26, 0x0108, true);
    CHECK(parse(b, n, 1, &p, NULL, NULL) == 0 && p.mcs_mask == 16);
    put16(b + 2, 12); /* Header no longer covers the advertised TSFT. */
    CHECK(parse(b, n, 0, &p, NULL, NULL) == -EINVAL);
    memset(b, 0, sizeof(b));
    put16(b + 2, 13); put32(b + 4, BIT(29) | BIT(31));
    put32(b + 8, BIT(2)); b[12] = 2;
    n = 13 + frame(b + 13, 0x0108, true);
    CHECK(parse(b, n, 0, &p, NULL, NULL) == 0 && p.mcs_mask == 1);
    put32(b + 4, BIT(31)); /* Bit 34 is not a standard RATE field. */
    CHECK(parse(b, n, 0, &p, NULL, NULL) == -EOPNOTSUPP);
    put32(b + 4, BIT(18));
    CHECK(parse(b, n, 0, &p, NULL, NULL) == -EOPNOTSUPP);
    put32(b + 4, BIT(30));
    CHECK(parse(b, n, 0, &p, NULL, NULL) == -EOPNOTSUPP);

    memset(b, 0, sizeof(b));
    memcpy(b, reaver_rtap, sizeof(reaver_rtap));
    n = 10 + frame(b + 10, 0x0108, true);
    for (unsigned int flag = 1; flag <= 0x20; flag <<= 1) {
        b[8] = flag;
        int ret = parse(b, n, 0, &p, NULL, NULL);
        CHECK(ret == ((flag == 8 || flag == 16) ? 0 : -EOPNOTSUPP));
    }
    put16(b + 2, 11); put32(b + 4, BIT(15) | BIT(17));
    b[8] = 0x18; b[9] = 0; b[10] = 9;
    n = 11 + frame(b + 11, 0x0108, true);
    CHECK(parse(b, n, 0, &p, NULL, NULL) == 0 && p.retries == 1);
    b[8] = 0;
    CHECK(parse(b, n, 0, &p, NULL, NULL) == 0 && p.retries == 10);
    b[10] = 15;
    CHECK(parse(b, n, 0, &p, NULL, NULL) == -EOPNOTSUPP);

    memset(b, 0, sizeof(b));
    put16(b + 2, 9); put32(b + 4, BIT(1));
    b[8] = IEEE80211_RADIOTAP_F_FCS | IEEE80211_RADIOTAP_F_DATAPAD;
    unsigned int header = frame(b + 9, 0x0188, false);
    memset(b + 9 + header, 0, 2);
    memcpy(b + 9 + header + 2, eapol, sizeof(eapol));
    n = 9 + header + 2 + sizeof(eapol) + 4;
    CHECK(parse(b, n, 1, &p, normalized, &out_length) == 0);
    CHECK(p.is_eapol && out_length == header + sizeof(eapol));
    CHECK(!memcmp(normalized + header, eapol, sizeof(eapol)));
}

static void metadata_fixtures(void)
{
    struct sk_buff skb = {0}, other = {0};
    struct dp_tx_msdu_info_s info = {0};
    queued_nbuf = &skb;
    queued_params = (struct cdp_tx_injection_params){
        .is_data = true, .is_eapol = true, .chanfreq = 2447,
        .rate_valid = true, .preamble = CDP_INJECTION_CCK,
        .mcs_mask = 1, .nss_mask = 1,
        .bandwidth_valid = true, .bw_mask = 4,
        .retries_valid = true, .retries = 1,
    };
    info.meta_data[5] = 6; /* Standalone and valid host cookie. */
    info.meta_data[6] = 0xf123;
    CHECK(dp_tx_add_injection_metadata(&skb, &info));
    CHECK(info.meta_data[5] == 6 && info.meta_data[6] == 0xf123);
    CHECK((info.meta_data[0] & 0x80000b3e) == 0x8000093e);
    CHECK(((info.meta_data[0] >> 17) & 15) == 1);
    CHECK(info.meta_data[1] == 0x10100100); /* CCK, NSS1, MCS mask 1. */
    CHECK(info.meta_data[2] == (2447U << 16));
    CHECK(!(info.meta_data[1] & 0x80000000)); /* No persistent rate override. */
    struct dp_tx_msdu_info_s saved = info;
    CHECK(!dp_tx_add_injection_metadata(&other, &info));
    CHECK(!memcmp(&saved, &info, sizeof(info)));

    memset(&info, 0, sizeof(info));
    queued_params.preamble = CDP_INJECTION_HT;
    queued_params.mcs_mask = 0x80;
    queued_params.bw_mask = 8;
    queued_params.gi_valid = true;
    queued_params.guard_interval = 0;
    CHECK(dp_tx_add_injection_metadata(&skb, &info));
    CHECK((info.meta_data[0] & BIT(6)) && ((info.meta_data[0] >> 25) & 63) == 8);
    CHECK(info.meta_data[1] == 0x20108000); /* HT MCS7, one stream. */
    CHECK(((info.meta_data[0] >> 13) & 3) == 0);
    queued_nbuf = NULL;
}

static void malformed_corpus(void)
{
    uint8_t seed[64] = {0}, b[128];
    uint32_t state = 0x7750888e;
    struct cdp_tx_injection_params p;
    memcpy(seed, reaver_rtap, sizeof(reaver_rtap));
    unsigned int seed_len = 10 + frame(seed + 10, 0x0108, true);
    for (unsigned int i = 0; i < 12000; i++) {
        state = state * 1664525 + 1013904223;
        unsigned int len = state % sizeof(b);
        for (unsigned int j = 0; j < len; j++) {
            state = state * 1664525 + 1013904223;
            b[j] = state >> 24;
        }
        if (i & 1) {
            len = seed_len;
            memcpy(b, seed, len);
            b[(state >> 8) % len] ^= (state >> 24) | 1;
        }
        (void)parse(b, len, i & 1, &p, NULL, NULL);
    }
}

int main(void)
{
    protocol_fixtures();
    control_fixtures();
    radiotap_fixtures();
    metadata_fixtures();
    malformed_corpus();
    printf("%u\n", cases);
    return 0;
}
