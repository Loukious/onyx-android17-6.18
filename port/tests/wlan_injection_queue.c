/* Actual WMA queue/lookup/completion/teardown with mocked scheduling and DP. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

typedef int QDF_STATUS;
typedef void *tp_wma_handle;
#define QDF_STATUS_SUCCESS 0
#define QDF_STATUS_E_AGAIN 1
#define QDF_STATUS_E_BUSY 2
#define QDF_STATUS_E_FAILURE 3
#define QDF_IS_STATUS_ERROR(s) ((s) != 0)
#define WMA_INJECTION_SLOT_COUNT 256
#define WMA_INJECTION_QUEUE_LIMIT 256
#define WMA_INJECTION_DESC_BASE 0xf000
#define WMA_INJECTION_DESC_MASK 0x0fff
#define CDP_TX_INJECTION_DESC_PREFIX 0xf000
#define QDF_MAC_ADDR_SIZE 6
#define BUILD_BUG_ON(c) _Static_assert(!(c), "build assertion")
#define qdf_mem_zero(p, n) memset(p, 0, n)
#define qdf_mem_copy(p, s, n) memcpy(p, s, n)
#define qdf_mem_cmp(p, s, n) memcmp(p, s, n)
#define READ_ONCE(v) (v)
#define smp_load_acquire(p) (*(p))
#define wma_err_rl(...) ((void)0)
#define wma_warn(...) ((void)0)

struct sk_buff {
    struct sk_buff *next;
    uint8_t cb[48];
    uint16_t desc_id;
    unsigned int freed, sent;
    bool reset;
};
typedef struct sk_buff *qdf_nbuf_t;
#define QDF_NBUF_CB_MGMT_TXRX_DESC_ID(nbuf) ((nbuf)->desc_id)
struct queue { qdf_nbuf_t head, tail; unsigned int len; };
static unsigned int qdf_nbuf_queue_len(struct queue *q) { return q->len; }
static void qdf_nbuf_queue_add(struct queue *q, qdf_nbuf_t skb)
{
    skb->next = NULL;
    if (q->tail) q->tail->next = skb;
    else q->head = skb;
    q->tail = skb;
    q->len++;
}
static void qdf_nbuf_queue_insert_head(struct queue *q, qdf_nbuf_t skb)
{
    skb->next = q->head;
    if (!q->head) q->tail = skb;
    q->head = skb;
    q->len++;
}
static qdf_nbuf_t qdf_nbuf_queue_remove(struct queue *q)
{
    qdf_nbuf_t skb = q->head;
    if (skb) {
        q->head = skb->next;
        if (!q->head) q->tail = NULL;
        skb->next = NULL;
        q->len--;
    }
    return skb;
}
static void qdf_nbuf_reset_ctxt(qdf_nbuf_t skb)
{
    memset(skb->cb, 0, sizeof(skb->cb));
    skb->desc_id = 0;
    skb->reset = true;
}
static void qdf_nbuf_free(qdf_nbuf_t skb)
{
    const uint8_t zero[48] = {0};
    assert(skb->reset && !memcmp(skb->cb, zero, sizeof(zero)));
    assert(skb->freed++ == 0);
}
static int atomic_cmpxchg_acquire(int *p, int old, int value)
{
    int result = *p;
    if (result == old) *p = value;
    return result;
}
#define atomic_set_release(p, v) (*(p) = (v))
#define atomic_read_acquire(p) (*(p))
#define atomic64_inc(p) (++*(p))
#define spin_lock_irqsave(p, f) do { (f) = 0; assert(!*(p)); *(p) = 1; } while (0)
#define spin_unlock_irqrestore(p, f) do { (void)(f); assert(*(p)); *(p) = 0; } while (0)
#define spin_lock_bh(p) do { assert(!*(p)); *(p) = 1; } while (0)
#define spin_unlock_bh(p) do { assert(*(p)); *(p) = 0; } while (0)
#define mutex_lock(p) spin_lock_bh(p)
#define mutex_unlock(p) spin_unlock_bh(p)
#define wake_up_all(p) ((void)(p))
#define cancel_work_sync(p) ((void)(p))
#define cancel_delayed_work_sync(p) ((void)(p))
#define wait_event(w, cond) do { (void)(w); assert(cond); } while (0)

/* INSERT_PARAMS */
/* INSERT_SLOT */
/* INSERT_CB */
/* INSERT_HELPER */
/* INSERT_SNAPSHOT */
static struct {
    int lock, helper_lock, lifecycle_lock, work, reaper, refill_wait, refill_busy;
    struct queue pending;
    struct wma_injection_slot slots[WMA_INJECTION_SLOT_COUNT];
    struct wma_injection_helper helper;
    unsigned int in_flight;
    bool active, paused, channel_change_paused;
    tp_wma_handle wma;
} wma_injection_ctx;
/* INSERT_SELECT_MAC */
/* INSERT_GET_SNAPSHOT */
static unsigned long injection_accepted, injection_send_failed, injection_completed;
static unsigned long injection_completion_failed, injection_completion_unknown;
static unsigned int kicks, submits, destroyed;
static struct cdp_tx_injection_params submitted_params[32];
static uint8_t submitted_vdev[32];
static QDF_STATUS send_result;

static bool cdp_nbuf_is_injection(qdf_nbuf_t nbuf)
{
    return (nbuf->desc_id & 0xf000) == 0xf000;
}
static void wma_injection_queue_work(void) { kicks++; }
static unsigned int wma_injection_inflight_limit(void) { return 4; }
static bool wma_injection_wait_for_refill(void) { return !wma_injection_ctx.refill_busy; }
static bool wma_injection_wait_for_idle(void) { return !wma_injection_ctx.in_flight; }
static void __wma_injection_destroy_helper(tp_wma_handle wma) { (void)wma; destroyed++; }
static void wma_injection_unmap_free(tp_wma_handle wma, qdf_nbuf_t nbuf)
{
    (void)wma;
    qdf_nbuf_free(nbuf);
}

static QDF_STATUS wma_injection_send(tp_wma_handle wma, qdf_nbuf_t nbuf,
                                     uint8_t vdev,
                                     const struct cdp_tx_injection_params *params,
                                     bool allow_setup)
{
    const uint8_t zero[48] = {0};
    (void)wma; (void)allow_setup;
    assert(!memcmp(nbuf->cb, zero, sizeof(zero)));
    if (send_result) return send_result;
    assert(submits < 32);
    submitted_params[submits] = *params;
    submitted_vdev[submits] = vdev;
    submits++;
    nbuf->sent++;
    nbuf->desc_id = 0xf000 | submits;
    struct wma_injection_slot *slot = &wma_injection_ctx.slots[submits];
    *slot = (struct wma_injection_slot){
        .nbuf = nbuf, .desc_id = nbuf->desc_id, .params = *params,
        .direct_dp = true,
    };
    wma_injection_ctx.in_flight++;
    return QDF_STATUS_SUCCESS;
}
/* INSERT_REFILL */
/* INSERT_TX */
/* INSERT_LOOKUP */
/* INSERT_COMPLETE */
/* INSERT_DEINIT */

static unsigned int cases;
#define CHECK(c) do { assert(c); cases++; } while (0)

static void test_helper_mac(void)
{
    const uint8_t netdev_mac[] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x85};
    const uint8_t link_mac[] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x05};
    const uint8_t other_mac[] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x86};
    uint8_t helper_mac[6];
    struct wma_injection_helper_snapshot snapshot = {0};
    struct wma_injection_helper *helper = &wma_injection_ctx.helper;

    wma_injection_select_mac(helper_mac, netdev_mac, link_mac);
    CHECK(!memcmp(helper_mac, netdev_mac, 6));
    CHECK(memcmp(helper_mac, link_mac, 6));
    wma_injection_select_mac(helper_mac, link_mac, link_mac);
    CHECK(memcmp(helper_mac, link_mac, 6) && (helper_mac[0] & 3) == 2);

    *helper = (struct wma_injection_helper){
        .created = true, .monitor_vdev_id = 3, .vdev_id = 9,
        .peer_id = 42, .chanfreq = 2422, .dp_attached = true,
        .dp_peer_attached = true, .wmi_started = true, .wmi_up = true,
    };
    memcpy(helper->interface_mac, netdev_mac, 6);
    CHECK(wma_injection_get_helper_snapshot(3, 2422, netdev_mac, &snapshot));
    CHECK(snapshot.vdev_id == 9 && snapshot.peer_id == 42 && snapshot.direct_dp);
    CHECK(!wma_injection_get_helper_snapshot(3, 2422, other_mac, &snapshot));
    CHECK(!wma_injection_get_helper_snapshot(4, 2422, netdev_mac, &snapshot));
    CHECK(!wma_injection_get_helper_snapshot(3, 2412, netdev_mac, &snapshot));
    helper->created = false;
    CHECK(!wma_injection_get_helper_snapshot(3, 2422, netdev_mac, &snapshot));
    memset(helper, 0, sizeof(*helper));
}

int main(void)
{
    struct sk_buff packets[8] = {0};
    struct cdp_tx_injection_params p = {
        .mcs_mask = 0x80, .nss_mask = 1, .preamble = CDP_INJECTION_HT,
        .tx_flags = 0x18, .retries = 1, .retries_valid = true,
        .is_data = true, .is_eapol = true, .tid = 13,
        .interface_mac = {0x02, 0x11, 0x22, 0x33, 0x44, 0x85},
    }, got;
    test_helper_mac();
    for (unsigned int i = 0; i < 8; i++) qdf_nbuf_reset_ctxt(&packets[i]);
    CHECK(wma_injection_tx(&packets[0], 3, &p) == QDF_STATUS_E_AGAIN);
    CHECK(!packets[0].freed && !wma_injection_ctx.pending.len);
    wma_injection_ctx.active = true;
    wma_injection_ctx.pending.len = WMA_INJECTION_QUEUE_LIMIT;
    CHECK(wma_injection_tx(&packets[0], 3, &p) == QDF_STATUS_E_BUSY);
    wma_injection_ctx.pending.len = 0;
    CHECK(wma_injection_tx(&packets[0], 3, &p) == 0);
    packets[0].reset = false; /* Queued CB is WMA-owned now. */
    send_result = QDF_STATUS_E_AGAIN;
    wma_injection_refill(false);
    CHECK(wma_injection_ctx.pending.head == &packets[0] && !packets[0].freed);
    CHECK(!submits && !wma_injection_ctx.refill_busy && kicks > 0);
    send_result = 0;
    wma_injection_refill(true);
    CHECK(submits == 1 && submitted_vdev[0] == 3 && packets[0].sent == 1);
    CHECK(!memcmp(&p, &submitted_params[0], sizeof(p)));
    CHECK(wma_injection_get_tx_params(&packets[0], &got) && !memcmp(&p, &got, sizeof(p)));
    packets[7].desc_id = packets[0].desc_id;
    CHECK(!wma_injection_get_tx_params(&packets[7], &got));
    CHECK(!wma_injection_dp_complete(NULL, &packets[7], 0));
    CHECK(wma_injection_dp_complete(NULL, &packets[0], 0));
    CHECK(!wma_injection_dp_complete(NULL, &packets[0], 0));
    CHECK(injection_completed == 1 && !packets[0].freed);
    CHECK(cdp_nbuf_is_injection(&packets[0]) && !wma_injection_get_tx_params(&packets[0], &got));

    for (unsigned int i = 1; i <= 5; i++) {
        p.mcs_mask = 1U << i; p.tid = i;
        p.interface_mac[5] = i;
        CHECK(wma_injection_tx(&packets[i], i, &p) == 0);
        packets[i].reset = false;
    }
    wma_injection_refill(true);
    CHECK(wma_injection_ctx.in_flight == 4 && wma_injection_ctx.pending.len == 1);
    CHECK(wma_injection_dp_complete(NULL, &packets[1], -ENODATA));
    CHECK(!wma_injection_ctx.pending.len && packets[5].sent == 1);
    CHECK(injection_completion_unknown == 1);
    for (unsigned int i = 1; i <= 5; i++) {
        CHECK(submitted_vdev[i] == i && submitted_params[i].tid == i);
        CHECK(submitted_params[i].mcs_mask == 1U << i);
        CHECK(submitted_params[i].interface_mac[5] == i);
    }
    CHECK(wma_injection_dp_complete(NULL, &packets[2], 1));
    CHECK(injection_completion_failed == 1);
    CHECK(wma_injection_dp_complete(NULL, &packets[3], 0));
    CHECK(wma_injection_dp_complete(NULL, &packets[4], 0));
    CHECK(wma_injection_dp_complete(NULL, &packets[5], 0));

    CHECK(wma_injection_tx(&packets[6], 7, &p) == 0);
    send_result = QDF_STATUS_E_FAILURE;
    wma_injection_refill(true);
    CHECK(packets[6].freed == 1 && injection_send_failed == 1);
    CHECK(wma_injection_tx(&packets[7], 9, &p) == 0);
    packets[7].reset = false;
    wma_injection_deinit(NULL);
    CHECK(packets[7].freed == 1 && destroyed == 1);
    CHECK(!wma_injection_ctx.pending.len && !wma_injection_ctx.active);
    printf("%u\n", cases);
    return 0;
}
