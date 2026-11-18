/* Production PPDU decoding and reporting transactions with bounded host mocks. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define FEATURE_WLAN_WONDER
#define WIFI_MONITOR_SUPPORT
#define WDI_EVENT_ENABLE
#define MAX_NUM_LMAC_HW 2
#define QDF_STATUS_SUCCESS 0
#define QDF_STATUS_E_FAILURE 1
#define QDF_STATUS_E_NOMEM 2
#define QDF_STATUS_E_BUSY 3
#define QDF_IS_STATUS_ERROR(value) ((value) != QDF_STATUS_SUCCESS)
typedef int QDF_STATUS;
#define READ_ONCE(value) (*(volatile __typeof__(value) *)&(value))
#define WRITE_ONCE(value, input) ((value) = (input))
#define qdf_mem_zero memset_zero
static void memset_zero(void *ptr, size_t size) { memset(ptr, 0, size); }
#define qdf_assert(value) ((void)(value))
#define dp_htt_err(...) ((void)0)
#define HTT_CHECK_SET_VAL(field, value) ((void)(value))
#define HTT_H2T_MSG_TYPE_PPDU_STATS_CFG 0x11
#define HTC_HEADER_LEN 0
#define HTC_HDR_ALIGNMENT_PADDING 0
#define HTT_MSG_BUF_SIZE(size) (size)
#define HTC_TX_PACKET_TAG_RUNTIME_PUT 0
/* INSERT_DEFINITIONS */

static unsigned int cases, observations;
#define CHECK(condition) do { assert(condition); cases++; } while (0)
static pthread_mutex_t dp_wonder_airtime_config_lock = PTHREAD_MUTEX_INITIALIZER;
#define spin_lock_bh(lock) assert(pthread_mutex_lock(lock) == 0)
#define spin_unlock_bh(lock) assert(pthread_mutex_unlock(lock) == 0)
#define qdf_spin_lock_bh spin_lock_bh
#define qdf_spin_unlock_bh spin_unlock_bh

struct dp_mon_pdev {
    pthread_mutex_t ppdu_stats_lock;
    /* INSERT_FIELDS */
};
struct dp_soc;
struct htt_soc { struct dp_soc *dp_soc; void *osdev; uint8_t htc_endpoint; };
struct dp_pdev { struct dp_mon_pdev *monitor_pdev; struct dp_soc *soc; uint8_t pdev_id; };
struct dp_soc { struct dp_pdev *pdev; struct htt_soc *htt_handle; };
struct hal_rx_ppdu_info {
    struct { uint32_t ppdu_id; } com_info;
    struct { uint32_t chan_freq, duration; uint64_t tsft; } rx_status;
};

struct nbuf { uint8_t *data; size_t len, capacity; };
typedef struct nbuf *qdf_nbuf_t;
static unsigned int qdf_nbuf_len(qdf_nbuf_t nbuf) { return nbuf->len; }
static void *qdf_nbuf_data(qdf_nbuf_t nbuf) { return nbuf->data; }
static bool fail_submit, fail_alloc;
static qdf_nbuf_t dp_htt_htc_msg_alloc(void *osdev, size_t size,
                                      int reserve, int align, bool priority)
{
    if (fail_alloc) return NULL;
    qdf_nbuf_t nbuf = calloc(1, sizeof(*nbuf));
    assert(nbuf);
    nbuf->data = calloc(1, size);
    assert(nbuf->data);
    nbuf->capacity = size;
    return nbuf;
}
static void *qdf_nbuf_put_tail(qdf_nbuf_t nbuf, unsigned int length)
{
    if (nbuf->len + length > nbuf->capacity) return NULL;
    void *data = nbuf->data + nbuf->len;
    nbuf->len += length;
    return data;
}
static void qdf_nbuf_push_head(qdf_nbuf_t nbuf, unsigned int length) { assert(!length); }
static void qdf_nbuf_free(qdf_nbuf_t nbuf) { free(nbuf->data); free(nbuf); }
struct mock_htc_packet { qdf_nbuf_t nbuf; };
struct dp_htt_htc_pkt { void *soc_ctxt; struct mock_htc_packet htc_pkt; };
static struct dp_htt_htc_pkt *htt_htc_pkt_alloc(struct htt_soc *soc)
{
    struct dp_htt_htc_pkt *pkt = calloc(1, sizeof(*pkt));
    assert(pkt);
    return pkt;
}
static void htt_htc_pkt_free(struct htt_soc *soc, struct dp_htt_htc_pkt *pkt) { free(pkt); }
#define SET_HTC_PACKET_INFO_TX(...) ((void)0)
#define SET_HTC_PACKET_NET_BUF_CONTEXT(packet, buffer) ((packet)->nbuf = (buffer))
static uint32_t uploaded_mask, uploaded_pdev;
static unsigned int submissions;
static QDF_STATUS DP_HTT_SEND_HTC_PKT(struct htt_soc *soc,
                                    struct dp_htt_htc_pkt *pkt,
                                    uint8_t command, uint8_t *bytes)
{
    assert(command == HTT_H2T_MSG_TYPE_PPDU_STATS_CFG);
    uint32_t word;
    memcpy(&word, bytes, sizeof(word));
    if (soc->dp_soc->pdev->monitor_pdev->wonder_airtime_enabled)
        assert(HTT_H2T_PPDU_STATS_CFG_TLV_BITMASK_GET(word) & 1);
    if (fail_submit) return QDF_STATUS_E_FAILURE;
    uploaded_mask = HTT_H2T_PPDU_STATS_CFG_TLV_BITMASK_GET(word);
    uploaded_pdev = HTT_H2T_PPDU_STATS_CFG_PDEV_MASK_GET(word);
    submissions++;
    qdf_nbuf_free(pkt->htc_pkt.nbuf);
    free(pkt);
    return QDF_STATUS_SUCCESS;
}
static uint8_t dp_get_target_pdev_id_for_host_pdev_id(struct dp_soc *soc, uint8_t id)
{ return id + 1; }
static uint8_t dp_get_host_pdev_id_for_target_pdev_id(struct dp_soc *soc, uint8_t id)
{ return id ? id - 1 : UINT8_MAX; }
static struct dp_pdev *dp_get_pdev_from_soc_pdev_id_wifi3(struct dp_soc *soc, uint8_t id)
{ return id == soc->pdev->pdev_id ? soc->pdev : NULL; }
static struct { uint32_t pdev, mac, freq, tsf, duration; bool tx; } last;
static void wlan_injection_wonder_note_airtime(uint32_t pdev, uint32_t mac,
                                             uint32_t freq, uint32_t tsf,
                                             bool tx, uint32_t duration)
{
    observations++;
    last.pdev = pdev; last.mac = mac; last.freq = freq; last.tsf = tsf;
    last.tx = tx; last.duration = duration;
}
/* INSERT_FUNCTIONS */

static void fixture(uint32_t *words, uint8_t mac, uint32_t ppdu,
                    uint64_t tsf, uint32_t duration)
{
    memset(words, 0, 19 * sizeof(*words));
    HTT_T2H_PPDU_STATS_MAC_ID_SET(words[0], mac);
    HTT_T2H_PPDU_STATS_PDEV_ID_SET(words[0], 1);
    HTT_T2H_PPDU_STATS_PAYLOAD_SIZE_SET(words[0], 60);
    HTT_T2H_PPDU_STATS_PPDU_ID_SET(words[1], ppdu);
    HTT_STATS_TLV_TAG_SET(words[4], HTT_PPDU_STATS_COMMON_TLV);
    HTT_STATS_TLV_LENGTH_SET(words[4], 56);
    words[4 + HTT_GET_STATS_CMN_INDEX(START_TSTMP_L32_US)] = tsf;
    words[4 + HTT_GET_STATS_CMN_INDEX(START_TSTMP_U32_US)] = tsf >> 32;
    HTT_PPDU_STATS_COMMON_TLV_CHAN_MHZ_SET(
        words[4 + HTT_GET_STATS_CMN_INDEX(CHAN_MHZ_PHY_MODE)], 5180);
    HTT_PPDU_STATS_COMMON_TLV_PHY_PPDU_TX_TIME_US_SET(
        words[4 + HTT_GET_STATS_CMN_INDEX(RESV_NUM_UL_BEAM)], duration);
    words[4 + HTT_GET_STATS_CMN_INDEX(FES_DUR_US)] = 9999;
}

static void *toggle(void *arg)
{
    struct dp_pdev *pdev = arg;
    for (unsigned int i = 0; i < 100; i++) {
        assert(!dp_htt_wonder_set_airtime(pdev, 7, true));
        assert(!dp_htt_wonder_set_airtime(pdev, 7, false));
    }
    return NULL;
}
static void *update(void *arg)
{
    struct dp_pdev *pdev = arg;
    for (unsigned int i = 0; i < 100; i++)
        assert(!dp_h2t_cfg_stats_msg_send(pdev, 0x200 + 2 * i, 0));
    return NULL;
}

int main(void)
{
    struct dp_mon_pdev mon = {.ppdu_stats_lock = PTHREAD_MUTEX_INITIALIZER};
    struct dp_soc soc = {0};
    struct htt_soc htt = {.dp_soc = &soc};
    struct dp_pdev pdev = {.monitor_pdev = &mon, .soc = &soc};
    soc.pdev = &pdev; soc.htt_handle = &htt;
    CHECK(!dp_h2t_cfg_stats_msg_send(&pdev, 0xaa, 0));
    CHECK(uploaded_mask == 0xaa && uploaded_pdev == 2);
    CHECK(!dp_htt_wonder_set_airtime(&pdev, 7, true));
    CHECK(uploaded_mask == 0xab && mon.wonder_airtime_base_mask == 0xaa);
    CHECK(dp_htt_wonder_set_airtime(&pdev, 8, false) == QDF_STATUS_E_BUSY);
    CHECK(!dp_h2t_cfg_stats_msg_send(&pdev, 0x220, 0));
    CHECK(uploaded_mask == 0x221 && mon.wonder_airtime_base_mask == 0x220);
    fail_submit = true;
    CHECK(dp_h2t_cfg_stats_msg_send(&pdev, 0x440, 0) == QDF_STATUS_E_FAILURE);
    CHECK(mon.wonder_airtime_base_mask == 0x220);
    fail_submit = false;

    uint32_t words[19];
    struct nbuf buffer = {.data = (uint8_t *)words, .len = sizeof(words)};
    fixture(words, 0, 1, UINT64_C(0xfffffffe), 100);
    dp_mon_wonder_tx_ppdu(&htt, words, &buffer);
    CHECK(observations == 1 && last.freq == 5180 && last.mac == 0 &&
          last.tsf == 0xfffffffe && last.duration == 100 && last.tx);
    for (unsigned int i = 0; i < 8; i++) dp_mon_wonder_tx_ppdu(&htt, words, &buffer);
    CHECK(observations == 1);
    fixture(words, 0, 2, UINT64_C(0x100000001), 33);
    dp_mon_wonder_tx_ppdu(&htt, words, &buffer);
    CHECK(observations == 2 && last.tsf == 1 && last.duration == 33);
    fixture(words, 0, 1, UINT64_C(0xfffffffe), 100);
    dp_mon_wonder_tx_ppdu(&htt, words, &buffer);
    CHECK(observations == 2);
    fixture(words, 1, 1, 10, 77);
    dp_mon_wonder_tx_ppdu(&htt, words, &buffer);
    CHECK(observations == 3 && last.mac == 1 && last.duration == 77);
    struct hal_rx_ppdu_info rx = {.com_info.ppdu_id = 3,
        .rx_status = {.chan_freq = 5180, .duration = 40, .tsft = 20}};
    dp_mon_wonder_rx_ppdu(&pdev, 1, &rx);
    dp_mon_wonder_rx_ppdu(&pdev, 1, &rx);
    CHECK(observations == 4 && !last.tx && last.duration == 40);
    rx.rx_status.chan_freq = 0;
    dp_mon_wonder_rx_ppdu(&pdev, 1, &rx);
    dp_mon_wonder_rx_ppdu(&pdev, MAX_NUM_LMAC_HW, &rx);
    CHECK(observations == 4);
    for (unsigned int len = 0; len < sizeof(words); len++) {
        buffer.len = len;
        dp_mon_wonder_tx_ppdu(&htt, words, &buffer);
        CHECK(observations == 4);
    }
    buffer.len = sizeof(words);
    fixture(words, 0, 4, UINT64_C(0x100000100), 0);
    dp_mon_wonder_tx_ppdu(&htt, words, &buffer);
    CHECK(observations == 4);
    fixture(words, 3, 4, UINT64_C(0x100000100), 30);
    dp_mon_wonder_tx_ppdu(&htt, words, &buffer);
    CHECK(observations == 4);
    fixture(words, 0, 4, UINT64_C(0x100000100), 30);
    words[0] &= ~HTT_T2H_PPDU_STATS_PDEV_ID_M;
    dp_mon_wonder_tx_ppdu(&htt, words, &buffer);
    CHECK(observations == 4);
    fixture(words, 0, 4, UINT64_C(0x100000100), 30);
    words[4] = 0; HTT_STATS_TLV_LENGTH_SET(words[4], 55);
    dp_mon_wonder_tx_ppdu(&htt, words, &buffer);
    CHECK(observations == 4);
    CHECK(!dp_htt_wonder_set_airtime(&pdev, 7, false));
    CHECK(!mon.wonder_airtime_enabled && uploaded_mask == 0x220);
    fixture(words, 0, 5, UINT64_C(0x100000200), 30);
    dp_mon_wonder_tx_ppdu(&htt, words, &buffer);
    CHECK(observations == 4);
    fail_alloc = true;
    CHECK(dp_htt_wonder_set_airtime(&pdev, 7, true) == QDF_STATUS_E_NOMEM);
    CHECK(!mon.wonder_airtime_enabled);
    fail_alloc = false;
    CHECK(!dp_htt_wonder_set_airtime(&pdev, 7, true));
    fail_submit = true;
    CHECK(dp_htt_wonder_set_airtime(&pdev, 7, false) == QDF_STATUS_E_FAILURE);
    CHECK(!mon.wonder_airtime_enabled);
    fail_submit = false;
    CHECK(!dp_h2t_cfg_stats_msg_send(&pdev, 0x600, 0) && uploaded_mask == 0x600);
    pthread_t toggler, updater;
    CHECK(!pthread_create(&toggler, NULL, toggle, &pdev));
    CHECK(!pthread_create(&updater, NULL, update, &pdev));
    CHECK(!pthread_join(toggler, NULL));
    CHECK(!pthread_join(updater, NULL));
    CHECK(!mon.wonder_airtime_enabled && uploaded_mask == mon.wonder_airtime_base_mask);
    CHECK(submissions >= 300);
    printf("%u\n", cases);
    return 0;
}
