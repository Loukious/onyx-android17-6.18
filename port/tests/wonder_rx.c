/* Production RX handlers with allocation-bounded linear/nonlinear SKB mocks. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

typedef uint8_t u8;
typedef int8_t s8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef unsigned long long u64;
typedef uint16_t __le16;
typedef uint32_t __le32;
typedef int64_t ktime_t;
#define __packed __attribute__((packed))
#define __aligned(n) __attribute__((aligned(n)))
#define __struct_group(TAG, NAME, ATTRS, ...) \
    union { struct { __VA_ARGS__ } ATTRS; struct TAG { __VA_ARGS__ } ATTRS NAME; } ATTRS
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define BIT(n) (UINT32_C(1) << (n))
#define ETH_ALEN 6
#define EXPORT_SYMBOL(x)
#define IS_ENABLED(x) 0
#define pr_warn(...) ((void)0)
#define pr_debug(...) ((void)0)
#define pr_err(...) ((void)0)
#define pr_err_ratelimited(...) ((void)0)
#define print_hex_dump(...) ((void)0)
#define le16_to_cpu(x) ((uint16_t)(x))
#define cpu_to_le16(x) ((uint16_t)(x))

static u16 get_unaligned_le16(const void *p)
{
    const u8 *b = p;
    return b[0] | ((u16)b[1] << 8);
}
static u32 get_unaligned_le32(const void *p)
{
    const u8 *b = p;
    return b[0] | ((u32)b[1] << 8) | ((u32)b[2] << 16) | ((u32)b[3] << 24);
}
static u64 get_unaligned_le64(const void *p)
{
    const u8 *b = p;
    return get_unaligned_le32(b) | ((u64)get_unaligned_le32(b + 4) << 32);
}
static void put16(u8 *b, u16 value)
{
    b[0] = value;
    b[1] = value >> 8;
}
static void put32(u8 *b, u32 value)
{
    put16(b, value);
    put16(b + 2, value >> 16);
}

/* INSERT_DEFINITIONS */
/* INSERT_RADIOTAP */

typedef enum { RX_HANDLER_CONSUMED } rx_handler_result_t;
enum { WONDER_DATA_80211_RADIOTAP, WONDER_DATA_80211, WONDER_DATA_8023 };
enum { PACKET_HOST, PACKET_OTHERHOST };
struct net_device {
    const char *name;
    struct { unsigned int rx_length_errors, rx_packets, rx_bytes; } stats;
};
struct wondertap_data {
    struct { struct { bool fcs_not_support; } bits; } cap;
    bool monitor_backend;
};
struct wonder_data {
    struct net_device *vdev;
    void *hw;
    struct wondertap_data *wondertap_data;
    u8 data_version;
    bool syna_support_enable;
    struct { unsigned int rx_to_mac_cnt; } stats;
};
struct sk_buff {
    u8 *allocation, *data, *frag_allocation, *frag;
    u8 *shared_head;
    unsigned int len, headlen, fraglen;
    bool fail_trim, fail_write, fail_pull;
    unsigned int trim_calls, write_calls;
    struct ieee80211_rx_status cb;
    struct net_device *dev;
    unsigned int protocol, pkt_type;
};
#define IEEE80211_SKB_RXCB(skb) (&(skb)->cb)

static unsigned int cases, delivered, dropped, delivery_len;
static u8 delivery_bytes[256];
static struct ieee80211_rx_status delivery_status;
#define CHECK(condition) do { assert(condition); cases++; } while (0)

static void skb_release(struct sk_buff *skb)
{
    if (skb->shared_head != skb->allocation)
        free(skb->shared_head);
    free(skb->allocation);
    free(skb->frag_allocation);
    memset(skb, 0, sizeof(*skb));
}
static struct sk_buff skb_make(const u8 *bytes, unsigned int len, unsigned int headlen)
{
    assert(headlen <= len);
    struct sk_buff skb = {.len = len, .headlen = headlen, .fraglen = len - headlen};
    skb.allocation = malloc(headlen ? headlen : 1);
    skb.data = skb.allocation;
    assert(skb.data);
    memcpy(skb.data, bytes, headlen);
    skb.frag_allocation = malloc(skb.fraglen ? skb.fraglen : 1);
    skb.frag = skb.frag_allocation;
    assert(skb.frag);
    memcpy(skb.frag, bytes + headlen, skb.fraglen);
    return skb;
}
static bool pskb_may_pull(struct sk_buff *skb, unsigned int len)
{
    assert(skb->len == skb->headlen + skb->fraglen);
    if (len > skb->len || skb->fail_pull)
        return false;
    if (len <= skb->headlen)
        return true;
    unsigned int pull = len - skb->headlen;
    u8 *head = malloc(len);
    assert(head);
    memcpy(head, skb->data, skb->headlen);
    memcpy(head + skb->headlen, skb->frag, pull);
    if (skb->allocation != skb->shared_head)
        free(skb->allocation);
    skb->allocation = skb->data = head;
    skb->headlen = len;
    skb->frag += pull;
    skb->fraglen -= pull;
    return true;
}
static int pskb_trim(struct sk_buff *skb, unsigned int len)
{
    assert(len <= skb->len);
    skb->trim_calls++;
    if (skb->fail_trim)
        return -ENOMEM;
    if (len < skb->headlen) {
        skb->headlen = len;
        skb->fraglen = 0;
    } else {
        skb->fraglen = len - skb->headlen;
    }
    skb->len = len;
    return 0;
}
static int skb_ensure_writable(struct sk_buff *skb, unsigned int len)
{
    skb->write_calls++;
    if (skb->fail_write || !pskb_may_pull(skb, len))
        return -ENOMEM;
    if (skb->shared_head) {
        u8 *head = malloc(skb->headlen ? skb->headlen : 1);
        assert(head);
        memcpy(head, skb->data, skb->headlen);
        if (skb->allocation != skb->shared_head)
            free(skb->allocation);
        skb->allocation = skb->data = head;
    }
    return 0;
}
static void skb_pull(struct sk_buff *skb, unsigned int len)
{
    assert(len <= skb->headlen && len <= skb->len);
    skb->data += len;
    skb->headlen -= len;
    skb->len -= len;
}
static void deliver(struct sk_buff *skb)
{
    assert(skb->len == skb->headlen + skb->fraglen);
    assert(skb->len <= sizeof(delivery_bytes));
    memcpy(delivery_bytes, skb->data, skb->headlen);
    memcpy(delivery_bytes + skb->headlen, skb->frag, skb->fraglen);
    delivery_len = skb->len;
    delivery_status = skb->cb;
    delivered++;
}
static void ieee80211_rx_ni(void *hw, struct sk_buff *skb) { (void)hw; deliver(skb); }
static void netif_receive_skb(struct sk_buff *skb) { deliver(skb); }
static void kfree_skb(struct sk_buff *skb) { (void)skb; dropped++; }
static void atomic64_inc(unsigned int *value) { (*value)++; }
static void dev_sw_netstats_rx_add(struct net_device *dev, unsigned int len)
{ (void)dev; (void)len; }
static void dev_core_stats_rx_dropped_inc(struct net_device *dev) { (void)dev; }
static bool wonder_80211_filter(struct ieee80211_hdr_3addr *hdr) { (void)hdr; return true; }
static bool wonder_80211_common_filter(struct wonder_data *wonder,
                                      struct ieee80211_hdr_3addr *hdr)
{ (void)wonder; (void)hdr; return true; }
/* Software filter decision is a witness here; normalization/delivery is real. */
static bool filter_accept = true;
static unsigned int filter_calls;
static bool wonder_monitor_frame_filter(struct wondertap_data *tap, __le16 fc)
{ (void)tap; (void)fc; filter_calls++; return filter_accept; }
static void syna_rx_handler(struct wonder_data *wonder, struct sk_buff *skb)
{ (void)wonder; (void)skb; assert(false); }
/* Raw handler casts this pointer but uses the shared prefix only. */
#define ieee80211_hdr ieee80211_hdr_3addr

/* INSERT_FUNCTIONS */

static struct net_device vdev = {.name = "wonder0"};
static struct wondertap_data tap = {.cap.bits.fcs_not_support = true};
static struct wonder_data wonder = {.vdev = &vdev, .wondertap_data = &tap};

static void run_adhoc(struct sk_buff *skb, bool success)
{
    unsigned int before_delivered = delivered, before_dropped = dropped;
    skb->dev = &vdev;
    CHECK(wonder_rx_adhoc_handler(&wonder, &skb) == RX_HANDLER_CONSUMED);
    CHECK(delivered == before_delivered + success);
    CHECK(dropped == before_dropped + !success);
}

static unsigned int packet(u8 *bytes, u16 fc, u8 flags, unsigned int payload)
{
    unsigned int hdrlen = ieee80211_hdrlen(fc);
    unsigned int pad = (flags & IEEE80211_RADIOTAP_F_DATAPAD) ? ((4 - hdrlen % 4) % 4) : 0;
    unsigned int fcs = (flags & IEEE80211_RADIOTAP_F_FCS) ? FCS_LEN : 0;
    /* Include one trailing radiotap byte so the 802.11 header is aligned. */
    memset(bytes, 0, 10);
    put16(bytes + 2, 10);
    put32(bytes + 4, BIT(IEEE80211_RADIOTAP_FLAGS));
    bytes[8] = flags;
    for (unsigned int i = 0; i < hdrlen; i++) bytes[10 + i] = (u8)(0x40 + i);
    put16(bytes + 10, fc);
    memset(bytes + 10 + hdrlen, 0xde, pad);
    for (unsigned int i = 0; i < payload; i++) bytes[10 + hdrlen + pad + i] = (u8)(0xa0 + i);
    memset(bytes + 10 + hdrlen + pad + payload, 0xf1, fcs);
    return 10 + hdrlen + pad + payload + fcs;
}

static void successful_frames(void)
{
    u8 bytes[128], expected[128];
    const u16 controls[] = {0x00d0, 0x0008, 0x0088, 0x0388, 0x8388};
    for (unsigned int type = 0; type < ARRAY_SIZE(controls); type++) {
        unsigned int hdrlen = ieee80211_hdrlen(controls[type]);
        for (unsigned int bits = 0; bits < 8; bits++) {
            u8 flags = ((bits & 1) ? IEEE80211_RADIOTAP_F_FCS : 0) |
                       ((bits & 2) ? IEEE80211_RADIOTAP_F_DATAPAD : 0) |
                       ((bits & 4) ? IEEE80211_RADIOTAP_F_BADFCS : 0);
            unsigned int len = packet(bytes, controls[type], flags, 17);
            unsigned int pad = (bits & 2) ? ((4 - hdrlen % 4) % 4) : 0;
            memcpy(expected, bytes + 10, hdrlen);
            memcpy(expected + hdrlen, bytes + 10 + hdrlen + pad, 17);
            for (unsigned int split = 0; split <= len; split++) {
                struct sk_buff skb = skb_make(bytes, len, split);
                run_adhoc(&skb, true);
                CHECK(delivery_len == hdrlen + 17);
                CHECK(!memcmp(delivery_bytes, expected, delivery_len));
                CHECK(!!(delivery_status.flag & RX_FLAG_FAILED_FCS_CRC) == !!(bits & 4));
                CHECK(skb.trim_calls == !!(bits & 1));
                CHECK(skb.write_calls == !!pad);
                CHECK(skb.pkt_type == PACKET_HOST);
                skb_release(&skb);
            }
            /* The actual raw monitor handlers preserve RTAP, padding and FCS. */
            struct sk_buff skb = skb_make(bytes, len, 1);
            skb.dev = &vdev;
            CHECK(wonder_rx_monitor_handler(&wonder, &(struct sk_buff *){&skb}) == RX_HANDLER_CONSUMED);
            CHECK(delivery_len == len && !memcmp(delivery_bytes, bytes, len));
            CHECK(!skb.trim_calls && !skb.write_calls);
            skb_release(&skb);
        }
    }
    /* A provider using mac80211's global FCS contract retains flagged FCS. */
    unsigned int len = packet(bytes, 0x0088, IEEE80211_RADIOTAP_F_FCS, 17);
    tap.cap.bits.fcs_not_support = false;
    struct sk_buff skb = skb_make(bytes, len, 36);
    run_adhoc(&skb, true);
    CHECK(delivery_len == len - 10 && !memcmp(delivery_bytes, bytes + 10, delivery_len));
    CHECK(skb.trim_calls == 0);
    skb_release(&skb);
    tap.cap.bits.fcs_not_support = true;
}

static void malformed_and_failures(void)
{
    u8 bytes[128];
    unsigned int len = packet(bytes, 0x0088,
        IEEE80211_RADIOTAP_F_FCS | IEEE80211_RADIOTAP_F_DATAPAD, 0);
    for (unsigned int n = 0; n < len; n++) {
        struct sk_buff skb = skb_make(bytes, n, n / 2);
        run_adhoc(&skb, false);
        skb_release(&skb);
    }
    for (unsigned int failure = 0; failure < 3; failure++) {
        struct sk_buff skb = skb_make(bytes, len, 36);
        skb.fail_trim = failure == 0;
        skb.fail_write = failure == 1;
        skb.fail_pull = failure == 2;
        run_adhoc(&skb, false);
        skb_release(&skb);
    }
    len = packet(bytes, 0x0088, IEEE80211_RADIOTAP_F_FCS, 17);
    /* A later malformed field must fail even after FLAGS was parsed. */
    put32(bytes + 4, BIT(IEEE80211_RADIOTAP_FLAGS) | BIT(IEEE80211_RADIOTAP_CHANNEL));
    struct sk_buff skb = skb_make(bytes, len, len);
    run_adhoc(&skb, false);
    CHECK(!skb.trim_calls);
    skb_release(&skb);
    len = packet(bytes, 0x0088, 0, 17);
    bytes[0] = 1;
    skb = skb_make(bytes, len, len);
    run_adhoc(&skb, false);
    skb_release(&skb);
    /* FLAGS absent means preserve all payload bytes, including FCS-like tails. */
    len = packet(bytes, 0x0088, 0, 17);
    put32(bytes + 4, 0);
    skb = skb_make(bytes, len, 36);
    run_adhoc(&skb, true);
    CHECK(delivery_len == len - 10 && !memcmp(delivery_bytes, bytes + 10, delivery_len));
    CHECK(!skb.trim_calls);
    skb_release(&skb);
    /* Padding write uses an unshared head; original capture stays intact. */
    len = packet(bytes, 0x0088, IEEE80211_RADIOTAP_F_DATAPAD, 17);
    skb = skb_make(bytes + 10, len - 10, 28);
    skb.shared_head = skb.allocation;
    CHECK(wonder_normalize_monitor_rx(&skb, 26, IEEE80211_RADIOTAP_F_DATAPAD, true) == 0);
    CHECK(skb.shared_head != skb.allocation);
    CHECK(!memcmp(skb.shared_head, bytes + 10, 28));
    CHECK(skb.fraglen == 17 && !memcmp(skb.frag, bytes + 38, 17));
    skb_release(&skb);
    skb = skb_make(bytes, 8, 8);
    CHECK(wonder_normalize_monitor_rx(&skb, UINT_MAX,
        IEEE80211_RADIOTAP_F_DATAPAD | IEEE80211_RADIOTAP_F_FCS, true) == -EINVAL);
    skb_release(&skb);
}

static void iterator_alignment(void)
{
    /* The exact status parser and iterator must support unaligned RTAP bases. */
    for (unsigned int skew = 0; skew < 8; skew++) {
        u8 *allocation = calloc(1, 24 + skew);
        assert(allocation);
        u8 *bytes = allocation + skew;
        put16(bytes + 2, 24);
        put32(bytes + 4, BIT(IEEE80211_RADIOTAP_TSFT) |
            BIT(IEEE80211_RADIOTAP_FLAGS) | BIT(IEEE80211_RADIOTAP_CHANNEL) |
            BIT(IEEE80211_RADIOTAP_DBM_ANTSIGNAL) | BIT(IEEE80211_RADIOTAP_ANTENNA));
        for (unsigned int i = 0; i < 8; i++) bytes[8 + i] = i + 1;
        bytes[16] = IEEE80211_RADIOTAP_F_FCS | IEEE80211_RADIOTAP_F_BADFCS |
                    IEEE80211_RADIOTAP_F_SHORTPRE;
        put16(bytes + 18, 5745);
        put16(bytes + 20, IEEE80211_CHAN_5GHZ);
        bytes[22] = (u8)-42;
        bytes[23] = 1;
        struct ieee80211_rx_status status = {0};
        u8 flags = 0;
        CHECK(wonder_fill_rx_status((void *)bytes, &status, &flags) == 0);
        CHECK(flags == bytes[16]);
        CHECK(status.mactime == 0x0807060504030201ULL);
        CHECK((status.flag & (RX_FLAG_MACTIME_START | RX_FLAG_FAILED_FCS_CRC)) ==
              (RX_FLAG_MACTIME_START | RX_FLAG_FAILED_FCS_CRC));
        CHECK(status.freq == 5745 && status.band == NL80211_BAND_5GHZ);
        CHECK(status.signal == -42 && status.antenna == 1);
        CHECK(status.enc_flags & RX_ENC_FLAG_SHORTPRE);
        free(allocation);
    }
}

static void monitor_filter_dispatch(void)
{
    u8 bytes[128];
    unsigned int len = packet(bytes, 0x0088, IEEE80211_RADIOTAP_F_DATAPAD, 17);
    tap.monitor_backend = true;
    filter_accept = false;
    unsigned int before = filter_calls;
    struct sk_buff skb = skb_make(bytes, len, 36);
    run_adhoc(&skb, false);
    CHECK(filter_calls == before + 1 && skb.write_calls == 1);
    skb_release(&skb);
    /* Generic provider input keeps its prior common-filter path. */
    tap.monitor_backend = false;
    skb = skb_make(bytes, len, 36);
    run_adhoc(&skb, true);
    CHECK(filter_calls == before + 1);
    skb_release(&skb);
    /* The raw monitor path preserves the original capture unfiltered. */
    tap.monitor_backend = true;
    unsigned int before_delivered = delivered;
    skb = skb_make(bytes, len, 1);
    CHECK(wonder_rx_monitor_handler(&wonder, &(struct sk_buff *){&skb}) == RX_HANDLER_CONSUMED);
    CHECK(delivered == before_delivered + 1 && filter_calls == before + 1);
    CHECK(delivery_len == len && !memcmp(delivery_bytes, bytes, len));
    skb_release(&skb);
    tap.monitor_backend = false; filter_accept = true;
}

int main(void)
{
    successful_frames();
    malformed_and_failures();
    iterator_alignment();
    monitor_filter_dispatch();
    printf("%u\n", cases);
    return 0;
}
