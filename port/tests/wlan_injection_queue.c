/* Production queue, generation and restart guards; transport/firmware are mocked. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

typedef int QDF_STATUS;
typedef int spinlock_t;
typedef int atomic_t;
typedef int wait_queue_head_t;
struct mutex { int locked; };
struct work_struct { int unused; };
struct delayed_work { int unused; };
/* Opaque native lifecycle fields are not exercised as firmware objects. */
struct completion { int done; };
struct vdev_start_params { int unused; };
enum phy_ch_width { CH_WIDTH_20MHZ, CH_WIDTH_40MHZ, CH_WIDTH_80MHZ,
                    CH_WIDTH_160MHZ, CH_WIDTH_80P80MHZ };
enum qdf_opmode { QDF_STA_MODE, QDF_SAP_MODE, QDF_MONITOR_MODE };
enum channel_state { CHANNEL_STATE_DISABLE, CHANNEL_STATE_PASSIVE, CHANNEL_STATE_DFS,
                     CHANNEL_STATE_ENABLE, CHANNEL_STATE_INVALID };
struct wlan_channel {
    uint32_t ch_freq, ch_cfreq1, ch_cfreq2;
    enum phy_ch_width ch_width;
    uint16_t puncture_bitmap;
};
struct wlan_mlme_sta_mon_control;
struct cdp_soc_t {
    struct wlan_mlme_sta_mon_control *control;
    bool enabled, paused;
    unsigned int unpause_calls;
};
struct wlan_objmgr_psoc {
    struct wlan_mlme_sta_mon_control *control;
    bool ext_tpc;
    void *dp_handle;
};
struct wlan_objmgr_pdev {
    struct wlan_objmgr_psoc *psoc;
    uint8_t reg_power, exception_power;
    uint32_t exception_freq;
    enum channel_state state, bonded_state, exception_state;
    uint32_t state_exception_freq;
};
struct wlan_objmgr_vdev {
    struct wlan_objmgr_psoc *psoc;
    uint8_t id;
    enum qdf_opmode opmode;
    struct wlan_channel channel;
    bool fw_uncertain;
    bool injection_helper;
};
struct vdev_mlme_obj { struct wlan_objmgr_vdev *vdev; };
struct vdev_up_params { uint8_t vdev_id; };
struct wma_handle {
    struct wlan_objmgr_psoc *psoc;
    struct wlan_objmgr_pdev *pdev;
    void *wmi_handle;
    unsigned int max_bssid;
    struct { struct wlan_objmgr_vdev *vdev; uint32_t ch_freq; } interfaces[16];
};
typedef struct wma_handle *tp_wma_handle;
#define QDF_STATUS_SUCCESS 0
#define QDF_STATUS_E_AGAIN 1
#define QDF_STATUS_E_BUSY 2
#define QDF_STATUS_E_FAILURE 3
#define QDF_STATUS_E_CANCELED 4
#define QDF_STATUS_E_NOSUPPORT 5
#define QDF_IS_STATUS_ERROR(s) ((s) != 0)
#define QDF_IS_STATUS_SUCCESS(s) ((s) == 0)
#define WLAN_INVALID_VDEV_ID 0xff
#define U32_MAX UINT32_MAX
#define HZ 100
#define WMA_INJECTION_SLOT_COUNT 256
#define WMA_INJECTION_QUEUE_LIMIT 256
#define WMA_INJECTION_DESC_BASE 0xf000
#define WMA_INJECTION_DESC_MASK 0x0fff
#define CDP_TX_INJECTION_DESC_PREFIX 0xf000
#define QDF_MAC_ADDR_SIZE 6
#define WLAN_UMAC_PSOC_MAX_VDEVS 51
#define MAX_NUM_PWR_LEVEL 16
#define MAX_NUM_EIRP_PWR_LEVEL 5
#define REG_INVALID_TXPOWER 255
#define REG_CURRENT_PWR_MODE 0
#define WLAN_FEATURE_11BE 1
#define QDF_MIN(a, b) ((a) < (b) ? (a) : (b))
typedef uint32_t qdf_freq_t;
/* INSERT_POWER_TYPES */
struct wlan_lmac_if_reg_tx_ops {
    QDF_STATUS (*set_tpc_power)(struct wlan_objmgr_psoc *, uint8_t,
                                struct reg_tpc_power_info *);
};
#define BUILD_BUG_ON(c) _Static_assert(!(c), "build assertion")
#define qdf_mem_zero(p, n) memset(p, 0, n)
#define qdf_mem_copy(p, s, n) memcpy(p, s, n)
#define qdf_mem_cmp(p, s, n) memcmp(p, s, n)
#define READ_ONCE(v) (v)
#define smp_load_acquire(p) (*(p))
#define wma_err_rl(...) ((void)0)
#define wma_err(...) ((void)0)
#define wma_info(...) ((void)0)
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
typedef struct queue qdf_nbuf_queue_t;
static void qdf_nbuf_queue_init(struct queue *q) { memset(q, 0, sizeof(*q)); }
static void qdf_nbuf_queue_append(struct queue *dest, struct queue *src)
{
    if (!src->head) return;
    if (dest->tail) dest->tail->next = src->head;
    else dest->head = src->head;
    dest->tail = src->tail;
    dest->len += src->len;
}
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
#define atomic_set(p, v) (*(p) = (v))
#define atomic_read_acquire(p) (*(p))
#define atomic64_inc(p) (++*(p))
#define spin_lock_irqsave(p, f) do { (f) = 0; assert(!*(p)); *(p) = 1; } while (0)
#define spin_unlock_irqrestore(p, f) do { (void)(f); assert(*(p)); *(p) = 0; } while (0)
#define spin_lock_bh(p) do { assert(!*(p)); *(p) = 1; } while (0)
#define spin_unlock_bh(p) do { assert(*(p)); *(p) = 0; } while (0)
#define mutex_lock(p) spin_lock_bh(&(p)->locked)
#define mutex_unlock(p) spin_unlock_bh(&(p)->locked)
#define mutex_init(p) ((p)->locked = 0)
#define spin_lock_init(p) (*(p) = 0)
#define DEFINE_SPINLOCK(name) spinlock_t name
#define init_waitqueue_head(p) (*(p) = 0)
#define INIT_WORK(p, callback) ((void)(p))
#define INIT_DELAYED_WORK(p, callback) ((void)(p))
#define schedule_delayed_work(p, delay) ((void)(p), (void)(delay))
#define wake_up_all(p) ((void)(p))
#define flush_work(p) ((void)(p))
#define cancel_work_sync(p) ((void)(p))
#define cancel_delayed_work_sync(p) ((void)(p))
#define wait_event(w, cond) do { (void)(w); assert(cond); } while (0)

/* INSERT_STA_MON_TYPES */
static int sta_mon_lock;
static bool driver_recovering, driver_unloading, firmware_down;
static bool cds_is_driver_recovering(void) { return driver_recovering; }
static bool cds_is_driver_unloading(void) { return driver_unloading; }
static bool cds_is_fw_down(void) { return firmware_down; }
static struct wlan_mlme_sta_mon_control *sta_mon_control(struct wlan_objmgr_psoc *psoc)
{
    return psoc ? psoc->control : NULL;
}
static void *wlan_psoc_get_dp_handle(struct wlan_objmgr_psoc *psoc)
{
    return psoc->dp_handle;
}
static void dp_mon_sta_coex_unpause(struct cdp_soc_t *soc)
{
    assert(sta_mon_lock);
    if (!soc) return;
    assert(soc->control && soc->control->state == WLAN_STA_MON_QUIESCED);
    soc->unpause_calls++;
    if (soc->enabled) soc->paused = false;
}
/* INSERT_STA_MON_FUNCTIONS */
static struct wlan_mlme_sta_mon_control control;
static struct cdp_soc_t monitor_dp = { .control = &control, .enabled = true };
static struct wlan_objmgr_psoc psoc = {
    .control = &control, .ext_tpc = true, .dp_handle = &monitor_dp,
};
static struct wlan_objmgr_pdev pdev = { .psoc = &psoc, .reg_power = 23,
    .state = CHANNEL_STATE_ENABLE, .bonded_state = CHANNEL_STATE_ENABLE };
static struct wlan_objmgr_vdev monitor_vdev;
static struct wma_handle fake_wma = {
    .psoc = &psoc, .pdev = &pdev, .wmi_handle = &psoc, .max_bssid = 16,
};
static struct wlan_objmgr_psoc *wlan_vdev_get_psoc(struct wlan_objmgr_vdev *v)
{
    return v->psoc;
}
static struct wlan_objmgr_psoc *wlan_pdev_get_psoc(struct wlan_objmgr_pdev *p)
{
    return p->psoc;
}
static uint8_t wlan_vdev_get_id(struct wlan_objmgr_vdev *v) { return v->id; }
static enum qdf_opmode wlan_vdev_mlme_get_opmode(struct wlan_objmgr_vdev *v)
{
    return v->opmode;
}
static bool wlan_vdev_is_injection_helper(struct wlan_objmgr_vdev *v)
{
    return v->injection_helper;
}
static struct wlan_channel *wlan_vdev_mlme_get_bss_chan(struct wlan_objmgr_vdev *v)
{
    return &v->channel;
}
static bool wlan_reg_is_24ghz_ch_freq(uint32_t f) { return f >= 2412 && f <= 2484; }
static bool wlan_reg_is_5ghz_ch_freq(uint32_t f) { return f >= 4900 && f < 5925; }
static bool wlan_reg_is_ext_tpc_supported(struct wlan_objmgr_psoc *p) { return p->ext_tpc; }
static uint8_t wlan_reg_get_channel_reg_power_for_freq(struct wlan_objmgr_pdev *p,
                                                      uint32_t f)
{
    return f == p->exception_freq ? p->exception_power : p->reg_power;
}
static enum channel_state wlan_reg_get_bonded_channel_state_for_pwrmode(
    struct wlan_objmgr_pdev *p, uint32_t freq, enum phy_ch_width width,
    uint32_t secondary, int power_mode)
{
    assert(power_mode == REG_CURRENT_PWR_MODE);
    if (width == CH_WIDTH_40MHZ && wlan_reg_is_24ghz_ch_freq(freq))
        assert(secondary + 20 == freq || secondary == freq + 20);
    else
        assert(!secondary);
    if (width != CH_WIDTH_20MHZ) return p->bonded_state;
    return freq == p->state_exception_freq ? p->exception_state : p->state;
}

/* INSERT_PARAMS */
/* INSERT_SLOT */
/* INSERT_CB */
/* INSERT_HELPER */
/* INSERT_SNAPSHOT */
/* INSERT_CONTEXT */
/* INSERT_POWER */

static bool tpc_ops_missing;
static QDF_STATUS native_tpc_status, native_up_status;
static unsigned int native_tpc_sends, native_up_sends, native_start_events;
static struct wlan_objmgr_vdev *invalidate_during_tpc;
static struct reg_tpc_power_info native_sent_power;
static struct wlan_lmac_if_reg_tx_ops native_reg_ops;
static struct wlan_lmac_if_reg_tx_ops *wlan_reg_get_tx_ops(struct wlan_objmgr_psoc *p)
{
    assert(p == &psoc);
    return tpc_ops_missing ? NULL : &native_reg_ops;
}
static bool wlan_vdev_injection_fw_uncertain(struct wlan_objmgr_vdev *v)
{
    return v->fw_uncertain;
}
static void complete_all(struct completion *done) { done->done++; }
#define WLAN_VDEV_SM_EV_START_SUCCESS 1
static QDF_STATUS wlan_vdev_mlme_sm_deliver_evt(struct wlan_objmgr_vdev *v,
                                                int event, uint16_t len, void *data)
{
    assert(v == wma_injection_ctx.helper.vdev);
    assert(event == WLAN_VDEV_SM_EV_START_SUCCESS && !len && !data);
    assert(wma_injection_ctx.helper.power_programmed && native_tpc_sends == 1);
    native_start_events++;
    return QDF_STATUS_SUCCESS;
}
static QDF_STATUS tgt_vdev_mgr_up_send(struct vdev_mlme_obj *mlme,
                                       struct vdev_up_params *up)
{
    assert(mlme->vdev == wma_injection_ctx.helper.vdev);
    assert(up->vdev_id == mlme->vdev->id && native_start_events == 1);
    assert(wma_injection_ctx.helper.power_programmed && native_tpc_sends == 1);
    native_up_sends++;
    return native_up_status;
}
/* Kernel callbacks intentionally ignore the generic SM payload. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
/* INSERT_NATIVE_POWER_START */
#pragma GCC diagnostic pop

static QDF_STATUS send_native_tpc(struct wlan_objmgr_psoc *p, uint8_t id,
                                   struct reg_tpc_power_info *power)
{
    assert(p == &psoc && id == wma_injection_ctx.helper.vdev_id);
    assert(!native_up_sends && !native_start_events);
    native_tpc_sends++;
    native_sent_power = *power;
    if (invalidate_during_tpc) wma_injection_power_reset(invalidate_during_tpc);
    return native_tpc_status;
}
/* INSERT_SELECT_MAC */
/* INSERT_GET_SNAPSHOT */
static unsigned long injection_accepted, injection_send_failed, injection_completed;
static unsigned long injection_completion_failed, injection_completion_unknown;
static unsigned int kicks, submits, destroyed;
static struct cdp_tx_injection_params submitted_params[32];
static uint8_t submitted_vdev[32];
static uint64_t submitted_generation[32];
static QDF_STATUS send_result;
static bool retain_helper;

static bool cdp_nbuf_is_injection(qdf_nbuf_t nbuf)
{
    return (nbuf->desc_id & 0xf000) == 0xf000;
}
static void wma_injection_queue_work(void) { kicks++; }
static unsigned int wma_injection_inflight_limit(void) { return 4; }
static bool wma_injection_wait_for_refill(void) { return !wma_injection_ctx.refill_busy; }
static bool wma_injection_wait_for_idle(void) { return !wma_injection_ctx.in_flight; }
static void __wma_injection_destroy_helper(tp_wma_handle wma)
{
    (void)wma;
    destroyed++;
    if (!retain_helper) memset(&wma_injection_ctx.helper, 0, sizeof(wma_injection_ctx.helper));
}
static void wma_injection_unmap_free(tp_wma_handle wma, qdf_nbuf_t nbuf)
{
    (void)wma;
    qdf_nbuf_free(nbuf);
}

static QDF_STATUS wma_injection_send(tp_wma_handle wma, qdf_nbuf_t nbuf,
                                     uint8_t vdev,
                                     const struct cdp_tx_injection_params *params,
                                     uint64_t generation,
                                     bool allow_setup)
{
    const uint8_t zero[48] = {0};
    (void)wma; (void)allow_setup;
    assert(!memcmp(nbuf->cb, zero, sizeof(zero)));
    if (send_result) return send_result;
    assert(submits < 32);
    submitted_params[submits] = *params;
    submitted_vdev[submits] = vdev;
    submitted_generation[submits] = generation;
    submits++;
    nbuf->sent++;
    nbuf->desc_id = 0xf000 | submits;
    struct wma_injection_slot *slot = &wma_injection_ctx.slots[submits];
    *slot = (struct wma_injection_slot){
        .nbuf = nbuf, .desc_id = nbuf->desc_id, .params = *params,
        .direct_dp = true, .generation = generation, .monitor_vdev_id = vdev,
        .completion_status = -ENODATA,
    };
    wma_injection_ctx.in_flight++;
    return QDF_STATUS_SUCCESS;
}
/* INSERT_REFILL */
/* INSERT_TX */
/* INSERT_LOOKUP */
/* INSERT_COMPLETE */
/* INSERT_RELEASE */
/* INSERT_RESUME */
/* INSERT_PRE_STOP */
/* INSERT_INIT */
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
    CHECK(wma_injection_get_helper_snapshot(3, 2422, netdev_mac, 0, &snapshot));
    CHECK(snapshot.vdev_id == 9 && snapshot.peer_id == 42 && snapshot.direct_dp);
    CHECK(!wma_injection_get_helper_snapshot(3, 2422, other_mac, 0, &snapshot));
    CHECK(!wma_injection_get_helper_snapshot(4, 2422, netdev_mac, 0, &snapshot));
    CHECK(!wma_injection_get_helper_snapshot(3, 2412, netdev_mac, 0, &snapshot));
    helper->native = true;
    helper->generation = 41;
    CHECK(wma_injection_get_helper_snapshot(3, 2422, netdev_mac, 41, &snapshot));
    CHECK(!wma_injection_get_helper_snapshot(3, 2422, netdev_mac, 42, &snapshot));
    CHECK(!wma_injection_get_helper_snapshot(3, 2422, netdev_mac, 0, &snapshot));
    helper->created = false;
    CHECK(!wma_injection_get_helper_snapshot(3, 2422, netdev_mac, 41, &snapshot));
    memset(helper, 0, sizeof(*helper));
}

static unsigned int stop_notifications;

static void notify_stop(void *arg)
{
    assert(arg == &stop_notifications && sta_mon_lock);
    stop_notifications++;
}

static void init_coex_fixture(void)
{
    /* Every preceding case must return its simulated DMA/queue ownership. */
    assert(!wma_injection_ctx.in_flight && !wma_injection_ctx.pending.len);
    assert(!wma_injection_ctx.helper.native);
    memset(&control, 0, sizeof(control));
    psoc.control = &control;
    monitor_dp = (struct cdp_soc_t){
        .control = &control, .enabled = true, .paused = true,
    };
    psoc.dp_handle = &monitor_dp;
    fake_wma = (struct wma_handle){
        .psoc = &psoc, .pdev = &pdev, .wmi_handle = &psoc, .max_bssid = 16,
        .interfaces[3] = { .vdev = &monitor_vdev, .ch_freq = 5260 },
    };
    driver_recovering = driver_unloading = firmware_down = false;
    injection_accepted = injection_send_failed = injection_completed = 0;
    injection_completion_failed = injection_completion_unknown = 0;
    kicks = submits = destroyed = stop_notifications = 0;
    send_result = QDF_STATUS_SUCCESS;
    retain_helper = false;
    wma_injection_init(&fake_wma);
    CHECK(wma_injection_ctx.active && !wma_injection_ctx.paused);
    CHECK(wma_injection_ctx.coex_resume_ready && wma_injection_ctx.wma == &fake_wma);
}

static void ready_coex_fixture(uint64_t generation)
{
    /* HDD channel acquisition/arming is an input; READY/token checks are real. */
    control = (struct wlan_mlme_sta_mon_control){
        .attached = true, .state = WLAN_STA_MON_ARMING,
        .stop = notify_stop, .arg = &stop_notifications,
        .snapshot = { .generation = generation, .sta_vdev_id = 0,
                      .mon_vdev_id = 3, .channel.ch_freq = 5260 },
    };
    CHECK(wlan_mlme_sta_mon_set_ready(&psoc, generation));
    CHECK(wlan_mlme_sta_mon_token_valid(&psoc, 3, generation));
}

static struct wlan_mlme_sta_mon_snapshot quiesced_ap_fixture(uint64_t generation)
{
    /* Owner/channel acquisition is an input; arming and later gates are real. */
    control = (struct wlan_mlme_sta_mon_control){
        .attached = true, .state = WLAN_STA_MON_QUIESCED,
        .stop = notify_stop, .arg = &stop_notifications,
        .snapshot = { .generation = generation,
                      .sta_vdev_id = WLAN_INVALID_VDEV_ID,
                      .mon_vdev_id = WLAN_INVALID_VDEV_ID },
    };
    return (struct wlan_mlme_sta_mon_snapshot){
        .generation = generation, .sta_vdev_id = 0, .mon_vdev_id = 3,
        .ap_owner = true,
        .channel = { .ch_freq = 5260, .ch_cfreq1 = 5290, .ch_width = CH_WIDTH_80MHZ },
    };
}

static void ready_ap_fixture(uint64_t generation)
{
    struct wlan_mlme_sta_mon_snapshot snapshot = quiesced_ap_fixture(generation - 1);
    CHECK(wlan_mlme_sta_mon_arm(&psoc, &snapshot));
    CHECK(snapshot.generation == generation && control.state == WLAN_STA_MON_ARMING);
    CHECK(wlan_mlme_sta_mon_set_ready(&psoc, generation));
    CHECK(wlan_mlme_sta_mon_token_valid(&psoc, 3, generation));
}

static struct wlan_mlme_sta_mon_snapshot quiesced_triple_fixture(uint64_t generation)
{
    struct wlan_mlme_sta_mon_snapshot snapshot = quiesced_ap_fixture(generation);
    snapshot.sta_ap_coexist = true;
    snapshot.companion_sta_vdev_id = 1;
    return snapshot;
}

static void ready_triple_fixture(uint64_t generation)
{
    struct wlan_mlme_sta_mon_snapshot snapshot = quiesced_triple_fixture(generation - 1);
    CHECK(wlan_mlme_sta_mon_arm(&psoc, &snapshot));
    CHECK(wlan_mlme_sta_mon_set_ready(&psoc, generation));
    CHECK(wlan_mlme_sta_mon_token_valid(&psoc, 3, generation));
}

static void resume_rejected(uint8_t vdev, uint64_t generation, QDF_STATUS status)
{
    unsigned char before[sizeof(wma_injection_ctx)];
    unsigned int before_kicks = kicks;
    memcpy(before, &wma_injection_ctx, sizeof(before));
    CHECK(wma_injection_coex_resume(vdev, generation) == status);
    CHECK(!memcmp(before, &wma_injection_ctx, sizeof(before)));
    CHECK(kicks == before_kicks && !sta_mon_lock);
}

static void tx_rejected(const struct cdp_tx_injection_params *params)
{
    struct sk_buff packet = {0};
    const uint8_t unchanged[48] = {0};
    unsigned long accepted = injection_accepted;
    unsigned int before_kicks = kicks;
    CHECK(wma_injection_tx(&packet, 3, params) == QDF_STATUS_E_AGAIN);
    CHECK(injection_accepted == accepted && kicks == before_kicks);
    CHECK(!packet.freed && !packet.sent && !wma_injection_ctx.pending.len);
    CHECK(!memcmp(packet.cb, unchanged, sizeof(unchanged)));
}

static void test_coex_restart(const struct cdp_tx_injection_params *params)
{
    struct sk_buff packet = {0};
    init_coex_fixture();
    ready_coex_fixture(41);
    CHECK(wma_injection_coex_resume(3, 41) == QDF_STATUS_SUCCESS);
    CHECK(!wma_injection_ctx.paused && !wma_injection_ctx.coex_resume_ready && kicks == 1);
    resume_rejected(3, 41, QDF_STATUS_E_BUSY);

    /* A passive session stops with no TX helper and no descriptor completion. */
    wlan_mlme_sta_mon_invalidate_owner(&psoc, 4);
    CHECK(control.snapshot.generation == 41 && !stop_notifications);
    wlan_mlme_sta_mon_invalidate_owner(&psoc, 3);
    CHECK(control.snapshot.generation == 42 && stop_notifications == 1);
    CHECK(control.state == WLAN_STA_MON_QUIESCING);
    wma_injection_pre_stop_cleanup();
    CHECK(wma_injection_ctx.paused && wma_injection_ctx.coex_resume_ready);
    CHECK(!submits && !wma_injection_ctx.in_flight && destroyed == 1);

    ready_coex_fixture(43);
    tx_rejected(params); /* READY alone must not admit TX while still paused. */
    CHECK(wma_injection_coex_resume(3, 43) == QDF_STATUS_SUCCESS);
    CHECK(!wma_injection_ctx.paused && !wma_injection_ctx.coex_resume_ready && kicks == 2);
    CHECK(wma_injection_tx(&packet, 3, params) == QDF_STATUS_SUCCESS);
    CHECK(injection_accepted == 1 && wma_injection_ctx.pending.len == 1);
    wma_injection_refill(true);
    CHECK(submits == 1 && submitted_generation[0] == 43 && submitted_vdev[0] == 3);
    CHECK(packet.sent == 1 && !packet.freed && wma_injection_ctx.in_flight == 1);
    CHECK(wma_injection_dp_complete(NULL, &packet, 0));
    wma_injection_dp_release(&packet, 1);
    CHECK(injection_completed == 1 && !wma_injection_ctx.in_flight);
    wma_injection_deinit(&fake_wma);
}

static void test_pending_stop(const struct cdp_tx_injection_params *params)
{
    struct sk_buff packets[3] = {0};
    init_coex_fixture();
    ready_coex_fixture(51);
    CHECK(wma_injection_coex_resume(3, 51) == QDF_STATUS_SUCCESS);
    for (unsigned int i = 0; i < 2; i++)
        CHECK(wma_injection_tx(&packets[i], 3, params) == QDF_STATUS_SUCCESS);
    CHECK(wma_injection_ctx.pending.len == 2 && injection_accepted == 2 && !submits);
    wlan_mlme_sta_mon_invalidate_owner(&psoc, 3);
    wma_injection_pre_stop_cleanup();
    CHECK(!wma_injection_ctx.pending.len && wma_injection_ctx.coex_resume_ready);
    CHECK(packets[0].freed == 1 && packets[1].freed == 1);

    ready_coex_fixture(53);
    CHECK(wma_injection_coex_resume(3, 53) == QDF_STATUS_SUCCESS);
    wma_injection_refill(true);
    CHECK(!submits && !packets[0].sent && !packets[1].sent);
    CHECK(wma_injection_tx(&packets[2], 3, params) == QDF_STATUS_SUCCESS);
    wma_injection_refill(true);
    CHECK(submits == 1 && submitted_generation[0] == 53 && packets[2].sent == 1);
    CHECK(wma_injection_dp_complete(NULL, &packets[2], 0));
    wma_injection_dp_release(&packets[2], 1);
    wma_injection_deinit(&fake_wma);
}

static void test_coex_admission(const struct cdp_tx_injection_params *params)
{
    const enum wlan_mlme_sta_mon_state not_ready[] = {
        WLAN_STA_MON_OFF, WLAN_STA_MON_ARMING, WLAN_STA_MON_QUIESCING,
        WLAN_STA_MON_QUIESCED,
    };
    struct sk_buff packet = {0};
    init_coex_fixture();
    ready_coex_fixture(61);
    for (unsigned int i = 0; i < sizeof(not_ready) / sizeof(not_ready[0]); i++) {
        control.state = not_ready[i];
        tx_rejected(params);
    }
    control.state = WLAN_STA_MON_READY;
    bool *unavailable[] = { &control.fw_uncertain, &driver_recovering,
                           &driver_unloading, &firmware_down };
    for (unsigned int i = 0; i < sizeof(unavailable) / sizeof(unavailable[0]); i++) {
        *unavailable[i] = true;
        tx_rejected(params);
        *unavailable[i] = false;
    }
    CHECK(wma_injection_coex_resume(3, 61) == QDF_STATUS_SUCCESS);
    CHECK(wma_injection_tx(&packet, 3, params) == QDF_STATUS_SUCCESS);
    CHECK(injection_accepted == 1 && !wma_injection_ctx.coex_resume_ready);
    wma_injection_deinit(&fake_wma);
    CHECK(packet.freed == 1);
}

static void test_resume_guards(void)
{
    const enum wlan_mlme_sta_mon_state not_ready[] = {
        WLAN_STA_MON_OFF, WLAN_STA_MON_ARMING, WLAN_STA_MON_QUIESCING,
        WLAN_STA_MON_QUIESCED,
    };
    struct sk_buff pending = {0};
    init_coex_fixture();
    wma_injection_pre_stop_cleanup();
    ready_coex_fixture(71);
    resume_rejected(3, 0, QDF_STATUS_E_AGAIN);
    resume_rejected(3, 70, QDF_STATUS_E_CANCELED);
    fake_wma.interfaces[4] = fake_wma.interfaces[3];
    resume_rejected(4, 71, QDF_STATUS_E_CANCELED);
    resume_rejected(16, 71, QDF_STATUS_E_CANCELED);
    for (unsigned int i = 0; i < sizeof(not_ready) / sizeof(not_ready[0]); i++) {
        control.state = not_ready[i];
        resume_rejected(3, 71, QDF_STATUS_E_CANCELED);
    }
    control.state = WLAN_STA_MON_READY;
    control.attached = false;
    resume_rejected(3, 71, QDF_STATUS_E_CANCELED);
    control.attached = true;
    bool *unavailable[] = { &control.fw_uncertain, &driver_recovering,
                           &driver_unloading, &firmware_down };
    for (unsigned int i = 0; i < sizeof(unavailable) / sizeof(unavailable[0]); i++) {
        *unavailable[i] = true;
        resume_rejected(3, 71, QDF_STATUS_E_CANCELED);
        *unavailable[i] = false;
    }
    fake_wma.interfaces[3].ch_freq = 5180;
    resume_rejected(3, 71, QDF_STATUS_E_CANCELED);
    fake_wma.interfaces[3].ch_freq = 5260;
    fake_wma.interfaces[3].vdev = NULL;
    resume_rejected(3, 71, QDF_STATUS_E_CANCELED);
    fake_wma.interfaces[3].vdev = &monitor_vdev;
    psoc.control = NULL;
    resume_rejected(3, 71, QDF_STATUS_E_CANCELED);
    psoc.control = &control;
    fake_wma.wmi_handle = NULL;
    resume_rejected(3, 71, QDF_STATUS_E_BUSY);
    fake_wma.wmi_handle = &psoc;
    wma_injection_ctx.wma = NULL;
    resume_rejected(3, 71, QDF_STATUS_E_BUSY);
    wma_injection_ctx.wma = &fake_wma;
    wma_injection_ctx.active = false;
    resume_rejected(3, 71, QDF_STATUS_E_AGAIN);
    wma_injection_ctx.active = true;
    wma_injection_ctx.coex_resume_ready = false;
    resume_rejected(3, 71, QDF_STATUS_E_BUSY);
    wma_injection_ctx.coex_resume_ready = true;
    wma_injection_ctx.channel_change_paused = true;
    resume_rejected(3, 71, QDF_STATUS_E_BUSY);
    wma_injection_ctx.channel_change_paused = false;
    wma_injection_ctx.refill_busy = 1;
    resume_rejected(3, 71, QDF_STATUS_E_BUSY);
    wma_injection_ctx.refill_busy = 0;
    wma_injection_ctx.in_flight = 1;
    resume_rejected(3, 71, QDF_STATUS_E_BUSY);
    wma_injection_ctx.in_flight = 0;
    bool *retained[] = { &wma_injection_ctx.helper.native,
                        &wma_injection_ctx.helper.created,
                        &wma_injection_ctx.helper.wmi_created,
                        &wma_injection_ctx.helper.dp_attached };
    for (unsigned int i = 0; i < sizeof(retained) / sizeof(retained[0]); i++) {
        *retained[i] = true;
        resume_rejected(3, 71, QDF_STATUS_E_BUSY);
        *retained[i] = false;
    }
    qdf_nbuf_queue_add(&wma_injection_ctx.pending, &pending);
    resume_rejected(3, 71, QDF_STATUS_E_BUSY);
    CHECK(qdf_nbuf_queue_remove(&wma_injection_ctx.pending) == &pending);
    CHECK(wma_injection_coex_resume(3, 71) == QDF_STATUS_SUCCESS);
    CHECK(!wma_injection_ctx.paused && !wma_injection_ctx.coex_resume_ready);
    wma_injection_deinit(&fake_wma);
}

static void test_failed_drain(const struct cdp_tx_injection_params *params)
{
    struct sk_buff packets[3] = {0};
    struct wma_handle other_wma = {0};
    struct wma_injection_helper *helper = &wma_injection_ctx.helper;
    init_coex_fixture();
    ready_coex_fixture(81);
    wma_injection_ctx.refill_busy = 1;
    wma_injection_pre_stop_cleanup();
    CHECK(wma_injection_ctx.paused && !wma_injection_ctx.coex_resume_ready);
    CHECK(wma_injection_ctx.refill_busy == 1 && !destroyed);
    wma_injection_ctx.refill_busy = 0;
    resume_rejected(3, 81, QDF_STATUS_E_BUSY);
    wma_injection_pre_stop_cleanup();
    CHECK(wma_injection_ctx.coex_resume_ready && destroyed == 1);
    CHECK(wma_injection_coex_resume(3, 81) == QDF_STATUS_SUCCESS);

    CHECK(wma_injection_tx(&packets[0], 3, params) == QDF_STATUS_SUCCESS);
    wma_injection_refill(true);
    CHECK(submits == 1 && wma_injection_ctx.in_flight == 1);
    wma_injection_init(&other_wma);
    CHECK(wma_injection_ctx.wma == &fake_wma && wma_injection_ctx.in_flight == 1);
    CHECK(wma_injection_ctx.slots[1].nbuf == &packets[0]);
    *helper = (struct wma_injection_helper){
        .native = true, .created = true, .dp_attached = true,
        .vdev = &monitor_vdev, .monitor_vdev_id = 3, .generation = 81,
    };
    CHECK(wma_injection_tx(&packets[1], 3, params) == QDF_STATUS_SUCCESS);
    wlan_mlme_sta_mon_invalidate_owner(&psoc, 3);
    wma_injection_pre_stop_cleanup();
    CHECK(wma_injection_ctx.in_flight == 1 && !wma_injection_ctx.coex_resume_ready);
    CHECK(helper->native && helper->vdev == &monitor_vdev && destroyed == 1);
    CHECK(!packets[0].freed && packets[1].freed == 1 && !wma_injection_ctx.pending.len);
    CHECK(wma_injection_dp_complete(NULL, &packets[0], 0));
    wma_injection_pre_stop_cleanup();
    CHECK(wma_injection_ctx.in_flight == 1 && destroyed == 1 && !injection_completed);
    CHECK(helper->native && wma_injection_ctx.slots[1].nbuf == &packets[0]);

    /* Release owns the saved slot index; status and recycled skb->cb do not. */
    wma_injection_dp_release(&packets[2], 1);
    wma_injection_dp_release(&packets[0], 2);
    CHECK(wma_injection_ctx.in_flight == 1 && !injection_completed);
    qdf_nbuf_reset_ctxt(&packets[0]);
    wma_injection_dp_release(&packets[0], 1);
    CHECK(!wma_injection_ctx.in_flight && injection_completed == 1 && !packets[0].freed);
    CHECK(!wma_injection_ctx.coex_resume_ready && helper->native);
    retain_helper = true;
    wma_injection_pre_stop_cleanup();
    CHECK(!wma_injection_ctx.coex_resume_ready && helper->native && destroyed == 2);
    wma_injection_init(&other_wma);
    CHECK(wma_injection_ctx.wma == &fake_wma && helper->vdev == &monitor_vdev);
    CHECK(helper->native && helper->generation == 81);
    ready_coex_fixture(83);
    resume_rejected(3, 83, QDF_STATUS_E_BUSY);
    retain_helper = false;
    wma_injection_pre_stop_cleanup();
    CHECK(wma_injection_ctx.coex_resume_ready && !helper->native && destroyed == 3);
    CHECK(wma_injection_coex_resume(3, 83) == QDF_STATUS_SUCCESS);
    CHECK(!wma_injection_ctx.paused && submits == 1);
    wma_injection_deinit(&fake_wma);
}

static void test_deinit_dma_ownership(const struct cdp_tx_injection_params *params)
{
    struct sk_buff packet = {0};
    struct wma_handle other_wma = {0};
    init_coex_fixture();
    ready_coex_fixture(91);
    CHECK(wma_injection_coex_resume(3, 91) == QDF_STATUS_SUCCESS);
    CHECK(wma_injection_tx(&packet, 3, params) == QDF_STATUS_SUCCESS);
    wma_injection_refill(true);
    wma_injection_deinit(&fake_wma);
    CHECK(!wma_injection_ctx.active && !wma_injection_ctx.coex_resume_ready);
    CHECK(wma_injection_ctx.in_flight == 1 && wma_injection_ctx.slots[1].nbuf == &packet);
    CHECK(!packet.freed && !destroyed);
    wma_injection_init(&other_wma);
    CHECK(!wma_injection_ctx.active && wma_injection_ctx.wma == &fake_wma);
    /* A returned descriptor without a status report has unknown completion. */
    qdf_nbuf_reset_ctxt(&packet);
    wma_injection_dp_release(&packet, 1);
    CHECK(!wma_injection_ctx.in_flight && injection_completion_unknown == 1);
    CHECK(!packet.freed && injection_completed == 1);
    wma_injection_init(&fake_wma);
    CHECK(wma_injection_ctx.active && wma_injection_ctx.coex_resume_ready);
    wma_injection_deinit(&fake_wma);
}

static void check_ap_admissions(void)
{
    CHECK(wlan_mlme_sta_mon_ap_is_owner(&psoc, 0));
    CHECK(wlan_mlme_sta_mon_ap_is_owner(&psoc, WLAN_INVALID_VDEV_ID));
    CHECK(!wlan_mlme_sta_mon_ap_is_owner(&psoc, 3));
    CHECK(!wlan_mlme_sta_mon_ap_is_owner(&psoc, 4));
    CHECK(!wlan_mlme_sta_mon_admission_begin(&psoc));
    CHECK(!wlan_mlme_sta_mon_ap_csa_admission_begin(&psoc, 0));
    CHECK(wlan_mlme_sta_mon_mgmt_admission_begin(&psoc, 0, 5260, false));
    CHECK(control.admissions == 1);
    wlan_mlme_sta_mon_admission_end(&psoc);
    CHECK(wlan_mlme_sta_mon_mgmt_admission_begin(&psoc, 0, 0, false));
    wlan_mlme_sta_mon_admission_end(&psoc);
    CHECK(!wlan_mlme_sta_mon_mgmt_admission_begin(&psoc, 0, 5180, false));
    CHECK(!wlan_mlme_sta_mon_mgmt_admission_begin(&psoc, 0, 5260, true));
    CHECK(!wlan_mlme_sta_mon_mgmt_admission_begin(&psoc, 4, 5260, false));
    CHECK(wlan_mlme_sta_mon_mgmt_tx_begin(&psoc, 0, false));
    wlan_mlme_sta_mon_admission_end(&psoc);
    CHECK(wlan_mlme_sta_mon_mgmt_tx_begin(&psoc, 0, true));
    wlan_mlme_sta_mon_admission_end(&psoc);
    CHECK(!wlan_mlme_sta_mon_mgmt_tx_begin(&psoc, 3, false));
    CHECK(!wlan_mlme_sta_mon_mgmt_tx_begin(&psoc, 4, true));
    CHECK(!control.admissions && !sta_mon_lock);
}

static void test_ap_admissions(void)
{
    struct wlan_mlme_sta_mon_snapshot snapshot, active;
    init_coex_fixture();
    snapshot = quiesced_ap_fixture(401);
    CHECK(!wlan_mlme_sta_mon_ap_is_owner(&psoc, WLAN_INVALID_VDEV_ID));

    /* A scan/connect or already admitted management send must finish first. */
    CHECK(wlan_mlme_sta_mon_admission_begin(&psoc));
    CHECK(wlan_mlme_sta_mon_mgmt_admission_begin(&psoc, 4, 5180, true));
    CHECK(control.admissions == 2 && !wlan_mlme_sta_mon_arm(&psoc, &snapshot));
    wlan_mlme_sta_mon_admission_end(&psoc);
    CHECK(control.admissions == 1 && !wlan_mlme_sta_mon_arm(&psoc, &snapshot));
    CHECK(snapshot.generation == 401 && control.snapshot.generation == 401);
    CHECK(control.state == WLAN_STA_MON_QUIESCED && !control.snapshot.ap_owner);
    wlan_mlme_sta_mon_admission_end(&psoc);
    snapshot.exclusive = true;
    CHECK(!wlan_mlme_sta_mon_arm(&psoc, &snapshot));
    snapshot.exclusive = false;
    CHECK(wlan_mlme_sta_mon_arm(&psoc, &snapshot));
    CHECK(snapshot.generation == 402 && control.state == WLAN_STA_MON_ARMING);
    check_ap_admissions();

    CHECK(wlan_mlme_sta_mon_set_ready(&psoc, snapshot.generation));
    CHECK(wlan_mlme_sta_mon_get_snapshot(&psoc, 3, snapshot.generation, &active));
    CHECK(active.ap_owner && !active.exclusive && active.sta_vdev_id == 0);
    CHECK(!active.sta_ap_coexist && active.companion_sta_vdev_id == WLAN_INVALID_VDEV_ID);
    check_ap_admissions();
    CHECK(!wlan_mlme_sta_mon_exclusive_reserve(&psoc, 3, snapshot.generation));
    CHECK(!control.exclusive_lease && !control.handoff_generation);
    CHECK(wlan_mlme_sta_mon_token_valid(&psoc, 3, snapshot.generation));

    wlan_mlme_sta_mon_disconnect_ind(&psoc, 4, false);
    CHECK(wlan_mlme_sta_mon_token_valid(&psoc, 3, snapshot.generation));
    CHECK(!stop_notifications);
    wlan_mlme_sta_mon_invalidate(&psoc, 0);
    CHECK(control.state == WLAN_STA_MON_QUIESCING && stop_notifications == 1);
    CHECK(!wlan_mlme_sta_mon_token_valid(&psoc, 3, snapshot.generation));
    check_ap_admissions();
    wlan_mlme_sta_mon_update_begin(&psoc);
    CHECK(control.updates == 1 && control.state == WLAN_STA_MON_QUIESCING);
    CHECK(!wlan_mlme_sta_mon_ap_csa_admission_begin(&psoc, 4));
    CHECK(wlan_mlme_sta_mon_ap_csa_admission_begin(&psoc, 0));
    CHECK(control.admissions == 1);
    wlan_mlme_sta_mon_admission_end(&psoc);
    wlan_mlme_sta_mon_update_end(&psoc);
    CHECK(!control.updates && !control.admissions);
    CHECK(!wlan_mlme_sta_mon_ap_csa_admission_begin(&psoc, 0));
    CHECK(wlan_mlme_sta_mon_ap_is_owner(&psoc, 0));
    wma_injection_pre_stop_cleanup();
    CHECK(wma_injection_ctx.coex_resume_ready && !wma_injection_ctx.in_flight);
    CHECK(wlan_mlme_sta_mon_quiesced(&psoc));
    CHECK(!wlan_mlme_sta_mon_ap_is_owner(&psoc, WLAN_INVALID_VDEV_ID));
    CHECK(wlan_mlme_sta_mon_admission_begin(&psoc));
    wlan_mlme_sta_mon_admission_end(&psoc);
    CHECK(wlan_mlme_sta_mon_mgmt_admission_begin(&psoc, 4, 5180, true));
    wlan_mlme_sta_mon_admission_end(&psoc);
    CHECK(wlan_mlme_sta_mon_ap_csa_admission_begin(&psoc, 4));
    wlan_mlme_sta_mon_admission_end(&psoc);
    CHECK(!control.admissions);
    wma_injection_deinit(&fake_wma);
}

static void test_ap_handoff_guards(void)
{
    struct wlan_mlme_sta_mon_snapshot next;
    init_coex_fixture();
    ready_ap_fixture(421);
    CHECK(!wlan_mlme_sta_mon_exclusive_reserve(&psoc, 3, 421));

    /* Even a stale reservation cannot hand off an AP's still-owned channel. */
    control.exclusive_lease = true;
    control.handoff_generation = 421;
    control.handoff_phase = WLAN_STA_MON_HANDOFF_DISCONNECTED;
    control.handoff_disconnect_seen = true;
    control.state = WLAN_STA_MON_HANDOFF;
    next = control.snapshot;
    next.exclusive = true;
    next.ap_owner = false;
    next.sta_vdev_id = WLAN_INVALID_VDEV_ID;
    CHECK(!wlan_mlme_sta_mon_handoff_valid(&psoc, 421));
    CHECK(!wlan_mlme_sta_mon_handoff_start(&psoc, &next));
    CHECK(control.state == WLAN_STA_MON_HANDOFF && control.snapshot.ap_owner);
    control.state = WLAN_STA_MON_ARMING;
    control.handoff_phase = WLAN_STA_MON_HANDOFF_RESTART;
    CHECK(!wlan_mlme_sta_mon_handoff_ready(&psoc, &next));
    CHECK(control.state == WLAN_STA_MON_ARMING && control.snapshot.ap_owner);

    /* An otherwise valid STA handoff must also reject an AP destination. */
    control.snapshot.ap_owner = false;
    control.state = WLAN_STA_MON_HANDOFF;
    control.handoff_phase = WLAN_STA_MON_HANDOFF_DISCONNECTED;
    next.ap_owner = true;
    CHECK(wlan_mlme_sta_mon_handoff_valid(&psoc, 421));
    CHECK(!wlan_mlme_sta_mon_handoff_start(&psoc, &next));
    next.ap_owner = false;
    CHECK(wlan_mlme_sta_mon_handoff_start(&psoc, &next));
    next.ap_owner = true;
    CHECK(!wlan_mlme_sta_mon_handoff_ready(&psoc, &next));
    CHECK(control.state == WLAN_STA_MON_ARMING && !control.snapshot.ap_owner);
    next.ap_owner = false;
    CHECK(wlan_mlme_sta_mon_handoff_ready(&psoc, &next));
    CHECK(control.state == WLAN_STA_MON_READY && control.snapshot.exclusive);
    wma_injection_deinit(&fake_wma);
}

static void test_triple_arm(void)
{
    struct wlan_mlme_sta_mon_snapshot snapshot, before;
    struct wlan_mlme_sta_mon_control control_before;

    /* Reject malformed ownership before publishing or changing a generation. */
    for (unsigned int malformed = 0; malformed < 7; malformed++) {
        init_coex_fixture();
        snapshot = quiesced_triple_fixture(601);
        switch (malformed) {
        case 0: snapshot.ap_owner = false; break;
        case 1: snapshot.exclusive = true; break;
        case 2: snapshot.sta_vdev_id = WLAN_INVALID_VDEV_ID; break;
        case 3: snapshot.companion_sta_vdev_id = WLAN_INVALID_VDEV_ID; break;
        case 4: snapshot.companion_sta_vdev_id = snapshot.sta_vdev_id; break;
        case 5: snapshot.companion_sta_vdev_id = snapshot.mon_vdev_id; break;
        case 6: snapshot.sta_vdev_id = snapshot.mon_vdev_id; break;
        }
        before = snapshot;
        control_before = control;
        CHECK(!wlan_mlme_sta_mon_arm(&psoc, &snapshot));
        CHECK(monitor_dp.paused && !monitor_dp.unpause_calls);
        CHECK(!memcmp(&snapshot, &before, sizeof(snapshot)));
        CHECK(!memcmp(&control, &control_before, sizeof(control)));
        CHECK(!stop_notifications && !control.admissions && !sta_mon_lock);
        wma_injection_deinit(&fake_wma);
    }

    /* Monitor vdev creation follows arming; its missing ID is not an owner. */
    init_coex_fixture();
    snapshot = quiesced_triple_fixture(611);
    snapshot.mon_vdev_id = WLAN_INVALID_VDEV_ID;
    CHECK(wlan_mlme_sta_mon_arm(&psoc, &snapshot));
    CHECK(!wlan_mlme_sta_mon_set_ready(&psoc, snapshot.generation));
    wlan_mlme_sta_mon_vdev_created(&psoc, 3);
    CHECK(wlan_mlme_sta_mon_set_ready(&psoc, snapshot.generation));
    CHECK(wlan_mlme_sta_mon_token_valid(&psoc, 3, snapshot.generation));
    wma_injection_deinit(&fake_wma);
}

static void test_arm_pause_reset(void)
{
    /* Teardown may leave RX paused; rejected arms must not reactivate it. */
    for (unsigned int owner = 0; owner < 3; owner++) {
        struct wlan_mlme_sta_mon_snapshot snapshot;
        struct wlan_mlme_sta_mon_control before;
        init_coex_fixture();
        snapshot = owner == 2 ? quiesced_triple_fixture(701) :
                               quiesced_ap_fixture(701);
        if (!owner) snapshot.ap_owner = false;
        before = control;
        for (unsigned int blocked = 0; blocked < 8; blocked++) {
            control = before;
            snapshot.generation = 701;
            switch (blocked) {
            case 0: control.admissions = 1; break;
            case 1: control.updates = 1; break;
            case 2: control.fw_uncertain = true; break;
            case 3: snapshot.generation++; break;
            case 4: control.state = WLAN_STA_MON_ARMING; break;
            case 5: control.state = WLAN_STA_MON_QUIESCING; break;
            case 6: control.attached = false; break;
            case 7: control.stop = NULL; break;
            }
            CHECK(!wlan_mlme_sta_mon_arm(&psoc, &snapshot));
            CHECK(monitor_dp.paused && !monitor_dp.unpause_calls);
            CHECK(!sta_mon_lock);
        }
        control = before;
        snapshot.generation = 701;
        CHECK(wlan_mlme_sta_mon_arm(&psoc, &snapshot));
        CHECK(!monitor_dp.paused && monitor_dp.unpause_calls == 1);
        CHECK(snapshot.generation == 702 && control.state == WLAN_STA_MON_ARMING);
        monitor_dp.paused = true;
        CHECK(!wlan_mlme_sta_mon_arm(&psoc, &snapshot));
        CHECK(monitor_dp.paused && monitor_dp.unpause_calls == 1);
        wma_injection_deinit(&fake_wma);
    }
}

static void check_triple_admissions(void)
{
    const uint8_t owners[] = { 0, 1 };
    const uint8_t others[] = { 3, 4, WLAN_INVALID_VDEV_ID };

    CHECK(wlan_mlme_sta_mon_ap_is_owner(&psoc, 0));
    CHECK(!wlan_mlme_sta_mon_ap_is_owner(&psoc, 1));
    CHECK(!wlan_mlme_sta_mon_sta_is_companion(&psoc, 0));
    CHECK(wlan_mlme_sta_mon_sta_is_companion(&psoc, 1));
    CHECK(!wlan_mlme_sta_mon_admission_begin(&psoc));
    for (unsigned int i = 0; i < sizeof(owners) / sizeof(owners[0]); i++) {
        CHECK(wlan_mlme_sta_mon_mgmt_admission_begin(&psoc, owners[i], 5260, false));
        CHECK(control.admissions == 1);
        wlan_mlme_sta_mon_admission_end(&psoc);
        CHECK(wlan_mlme_sta_mon_mgmt_admission_begin(&psoc, owners[i], 0, false));
        wlan_mlme_sta_mon_admission_end(&psoc);
        CHECK(!wlan_mlme_sta_mon_mgmt_admission_begin(&psoc, owners[i], 5180, false));
        CHECK(!wlan_mlme_sta_mon_mgmt_admission_begin(&psoc, owners[i], 5260, true));
        CHECK(wlan_mlme_sta_mon_mgmt_tx_begin(&psoc, owners[i], false));
        wlan_mlme_sta_mon_admission_end(&psoc);
        CHECK(wlan_mlme_sta_mon_mgmt_tx_begin(&psoc, owners[i], true));
        wlan_mlme_sta_mon_admission_end(&psoc);
    }
    for (unsigned int i = 0; i < sizeof(others) / sizeof(others[0]); i++) {
        CHECK(!wlan_mlme_sta_mon_sta_is_companion(&psoc, others[i]));
        CHECK(!wlan_mlme_sta_mon_mgmt_admission_begin(&psoc, others[i], 5260, false));
        CHECK(!wlan_mlme_sta_mon_mgmt_tx_begin(&psoc, others[i], false));
        CHECK(!wlan_mlme_sta_mon_mgmt_tx_begin(&psoc, others[i], true));
    }
    CHECK(!control.admissions && !sta_mon_lock);
}

static void test_triple_admissions_and_csa(void)
{
    struct wlan_mlme_sta_mon_snapshot snapshot, active;
    init_coex_fixture();
    snapshot = quiesced_triple_fixture(621);
    CHECK(wlan_mlme_sta_mon_admission_begin(&psoc));
    CHECK(!wlan_mlme_sta_mon_arm(&psoc, &snapshot));
    wlan_mlme_sta_mon_admission_end(&psoc);
    CHECK(wlan_mlme_sta_mon_arm(&psoc, &snapshot));
    check_triple_admissions();
    CHECK(!wlan_mlme_sta_mon_sta_csa_admission_begin(&psoc, 1));
    CHECK(wlan_mlme_sta_mon_set_ready(&psoc, snapshot.generation));
    CHECK(wlan_mlme_sta_mon_get_snapshot(&psoc, 3, snapshot.generation, &active));
    CHECK(active.ap_owner && active.sta_ap_coexist && !active.exclusive);
    CHECK(active.sta_vdev_id == 0 && active.companion_sta_vdev_id == 1);
    check_triple_admissions();
    CHECK(!wlan_mlme_sta_mon_sta_csa_admission_begin(&psoc, 1));
    CHECK(!wlan_mlme_sta_mon_exclusive_reserve(&psoc, 3, snapshot.generation));
    CHECK(!control.exclusive_lease && !control.handoff_generation);
    CHECK(wlan_mlme_sta_mon_token_valid(&psoc, 3, snapshot.generation));

    /* Revoke optional injection first, then allow only the upstream STA CSA. */
    wlan_mlme_sta_mon_invalidate(&psoc, 1);
    CHECK(control.state == WLAN_STA_MON_QUIESCING && stop_notifications == 1);
    CHECK(!wlan_mlme_sta_mon_token_valid(&psoc, 3, snapshot.generation));
    check_triple_admissions();
    CHECK(!wlan_mlme_sta_mon_sta_csa_admission_begin(&psoc, 0));
    CHECK(!wlan_mlme_sta_mon_sta_csa_admission_begin(&psoc, 3));
    CHECK(!wlan_mlme_sta_mon_sta_csa_admission_begin(&psoc, 4));
    CHECK(wlan_mlme_sta_mon_sta_csa_admission_begin(&psoc, 1));
    CHECK(control.admissions == 1 && !control.updates);
    wlan_mlme_sta_mon_admission_end(&psoc);
    wlan_mlme_sta_mon_update_begin(&psoc);
    CHECK(wlan_mlme_sta_mon_sta_csa_admission_begin(&psoc, 1));
    wlan_mlme_sta_mon_admission_end(&psoc);
    CHECK(!wlan_mlme_sta_mon_ap_csa_admission_begin(&psoc, 1));
    CHECK(wlan_mlme_sta_mon_ap_csa_admission_begin(&psoc, 0));
    wlan_mlme_sta_mon_admission_end(&psoc);
    wlan_mlme_sta_mon_update_end(&psoc);
    /* Deferred policy work need not retain the synchronous update reference. */
    CHECK(wlan_mlme_sta_mon_sta_csa_admission_begin(&psoc, 1));
    wlan_mlme_sta_mon_admission_end(&psoc);
    control.admissions = U32_MAX;
    CHECK(!wlan_mlme_sta_mon_sta_csa_admission_begin(&psoc, 1));
    control.admissions = 0;
    CHECK(!wlan_mlme_sta_mon_admission_begin(&psoc));

    wma_injection_pre_stop_cleanup();
    CHECK(wlan_mlme_sta_mon_quiesced(&psoc));
    CHECK(!wlan_mlme_sta_mon_sta_is_companion(&psoc, 1));
    CHECK(!control.snapshot.sta_ap_coexist &&
          control.snapshot.companion_sta_vdev_id == WLAN_INVALID_VDEV_ID);
    CHECK(wlan_mlme_sta_mon_admission_begin(&psoc));
    wlan_mlme_sta_mon_admission_end(&psoc);
    CHECK(wlan_mlme_sta_mon_sta_csa_admission_begin(&psoc, 4));
    wlan_mlme_sta_mon_admission_end(&psoc);
    CHECK(!control.admissions && !control.updates);
    wma_injection_deinit(&fake_wma);
}

static void trigger_triple_owner_event(unsigned int event, uint8_t vdev_id)
{
    const struct wlan_channel channel = {
        .ch_freq = 5180, .ch_cfreq1 = 5210, .ch_width = CH_WIDTH_80MHZ,
    };
    switch (event) {
    case 0: wlan_mlme_sta_mon_invalidate(&psoc, vdev_id); break;
    case 1: wlan_mlme_sta_mon_power_changed(&psoc, vdev_id); break;
    case 2: wlan_mlme_sta_mon_channel_changed(&psoc, vdev_id, &channel); break;
    case 3: wlan_mlme_sta_mon_disconnect_ind(&psoc, vdev_id, false); break;
    case 4: wlan_mlme_sta_mon_disconnect_ind(&psoc, vdev_id, true); break;
    default: assert(false);
    }
}

static void test_triple_owner_events(void)
{
    for (uint8_t owner = 0; owner < 2; owner++) {
        for (unsigned int event = 0; event < 5; event++) {
            init_coex_fixture();
            ready_triple_fixture(641);
            trigger_triple_owner_event(event, 4);
            CHECK(wlan_mlme_sta_mon_token_valid(&psoc, 3, 641));
            CHECK(!stop_notifications && control.snapshot.generation == 641);
            trigger_triple_owner_event(event, owner);
            CHECK(!wlan_mlme_sta_mon_token_valid(&psoc, 3, 641));
            CHECK(control.state == WLAN_STA_MON_QUIESCING);
            CHECK(control.snapshot.generation == 642 && stop_notifications == 1);
            trigger_triple_owner_event(event, owner);
            CHECK(control.snapshot.generation == 643 && stop_notifications == 1);
            check_triple_admissions();
            wma_injection_pre_stop_cleanup();
            CHECK(wma_injection_ctx.coex_resume_ready);
            CHECK(wlan_mlme_sta_mon_quiesced(&psoc));
            CHECK(!wlan_mlme_sta_mon_ap_is_owner(&psoc, 0));
            CHECK(!wlan_mlme_sta_mon_sta_is_companion(&psoc, 1));
            CHECK(wlan_mlme_sta_mon_admission_begin(&psoc));
            wlan_mlme_sta_mon_admission_end(&psoc);
            wma_injection_deinit(&fake_wma);
        }
    }
}

static void test_triple_handoff_guards(void)
{
    struct wlan_mlme_sta_mon_snapshot next;
    init_coex_fixture();
    ready_triple_fixture(661);
    CHECK(!wlan_mlme_sta_mon_exclusive_reserve(&psoc, 3, 661));
    CHECK(wlan_mlme_sta_mon_token_valid(&psoc, 3, 661));

    /* The companion flag also rejects a malformed source without AP ownership. */
    control.snapshot.ap_owner = false;
    CHECK(!wlan_mlme_sta_mon_exclusive_reserve(&psoc, 3, 661));
    CHECK(!control.exclusive_lease && !control.handoff_generation);
    control.exclusive_lease = true;
    control.handoff_generation = 661;
    control.handoff_phase = WLAN_STA_MON_HANDOFF_DISCONNECTED;
    control.handoff_disconnect_seen = true;
    control.state = WLAN_STA_MON_HANDOFF;
    next = control.snapshot;
    next.exclusive = true;
    next.sta_ap_coexist = false;
    next.sta_vdev_id = next.companion_sta_vdev_id = WLAN_INVALID_VDEV_ID;
    CHECK(!wlan_mlme_sta_mon_handoff_valid(&psoc, 661));
    CHECK(!wlan_mlme_sta_mon_handoff_start(&psoc, &next));
    CHECK(control.state == WLAN_STA_MON_HANDOFF && control.snapshot.sta_ap_coexist);
    control.state = WLAN_STA_MON_ARMING;
    control.handoff_phase = WLAN_STA_MON_HANDOFF_RESTART;
    CHECK(!wlan_mlme_sta_mon_handoff_ready(&psoc, &next));
    CHECK(control.state == WLAN_STA_MON_ARMING && control.snapshot.sta_ap_coexist);

    /* A valid STA handoff cannot install a triple destination at either step. */
    control.snapshot.sta_ap_coexist = false;
    control.snapshot.companion_sta_vdev_id = WLAN_INVALID_VDEV_ID;
    control.state = WLAN_STA_MON_HANDOFF;
    control.handoff_phase = WLAN_STA_MON_HANDOFF_DISCONNECTED;
    CHECK(wlan_mlme_sta_mon_handoff_valid(&psoc, 661));
    next.sta_ap_coexist = true;
    next.companion_sta_vdev_id = 1;
    CHECK(!wlan_mlme_sta_mon_handoff_start(&psoc, &next));
    next.sta_ap_coexist = false;
    next.companion_sta_vdev_id = WLAN_INVALID_VDEV_ID;
    CHECK(wlan_mlme_sta_mon_handoff_start(&psoc, &next));
    next.sta_ap_coexist = true;
    next.companion_sta_vdev_id = 1;
    CHECK(!wlan_mlme_sta_mon_handoff_ready(&psoc, &next));
    CHECK(control.state == WLAN_STA_MON_ARMING && !control.snapshot.sta_ap_coexist);
    next.sta_ap_coexist = false;
    next.companion_sta_vdev_id = WLAN_INVALID_VDEV_ID;
    CHECK(wlan_mlme_sta_mon_handoff_ready(&psoc, &next));
    CHECK(control.state == WLAN_STA_MON_READY && control.snapshot.exclusive);
    wma_injection_deinit(&fake_wma);
}

static void test_ap_invalidation_ownership(const struct cdp_tx_injection_params *params,
                                         bool triple)
{
    struct sk_buff packets[3] = {0};
    struct wma_injection_helper *helper = &wma_injection_ctx.helper;
    init_coex_fixture();
    if (triple)
        ready_triple_fixture(441);
    else
        ready_ap_fixture(441);
    CHECK(wma_injection_coex_resume(3, 441) == QDF_STATUS_SUCCESS);
    CHECK(wma_injection_tx(&packets[0], 3, params) == QDF_STATUS_SUCCESS);
    wma_injection_refill(true);
    *helper = (struct wma_injection_helper){
        .native = true, .created = true, .dp_attached = true,
        .vdev = &monitor_vdev, .monitor_vdev_id = 3, .generation = 441,
    };
    CHECK(wma_injection_tx(&packets[1], 3, params) == QDF_STATUS_SUCCESS);
    wlan_mlme_sta_mon_invalidate(&psoc, triple ? 1 : 0);
    CHECK(control.state == WLAN_STA_MON_QUIESCING && stop_notifications == 1);
    CHECK(!wma_injection_ctx.paused); /* The stop mock only records notification. */
    CHECK(wma_injection_tx(&packets[2], 3, params) == QDF_STATUS_E_AGAIN);
    CHECK(injection_accepted == 2 && wma_injection_ctx.pending.len == 1);
    CHECK(!packets[2].freed && !packets[2].sent && !packets[2].reset);
    wma_injection_pre_stop_cleanup();
    CHECK(packets[1].freed == 1 && !packets[1].sent && !wma_injection_ctx.pending.len);
    CHECK(helper->native && !destroyed && !wma_injection_ctx.coex_resume_ready);
    CHECK(wma_injection_ctx.in_flight == 1 && wma_injection_ctx.slots[1].nbuf == &packets[0]);
    CHECK(wlan_mlme_sta_mon_ap_is_owner(&psoc, 0));
    CHECK(!triple || wlan_mlme_sta_mon_sta_is_companion(&psoc, 1));
    CHECK(!wlan_mlme_sta_mon_admission_begin(&psoc));
    tx_rejected(params);

    /* A status report cannot release the DMA slot or native AP lease. */
    CHECK(wma_injection_dp_complete(NULL, &packets[0], 0));
    wma_injection_pre_stop_cleanup();
    CHECK(wma_injection_ctx.in_flight == 1 && !injection_completed && !destroyed);
    CHECK(helper->native && !packets[0].freed);
    CHECK(wlan_mlme_sta_mon_ap_is_owner(&psoc, 0));
    CHECK(!triple || wlan_mlme_sta_mon_sta_is_companion(&psoc, 1));
    wma_injection_dp_release(&packets[0], 1);
    CHECK(!wma_injection_ctx.in_flight && !wma_injection_ctx.slots[1].nbuf);
    CHECK(injection_completed == 1 && helper->native && !packets[0].freed);
    retain_helper = true;
    wma_injection_pre_stop_cleanup();
    CHECK(helper->native && !wma_injection_ctx.coex_resume_ready && destroyed == 1);
    CHECK(wlan_mlme_sta_mon_ap_is_owner(&psoc, 0));
    CHECK(!triple || wlan_mlme_sta_mon_sta_is_companion(&psoc, 1));
    CHECK(!wlan_mlme_sta_mon_admission_begin(&psoc));
    retain_helper = false;
    wma_injection_pre_stop_cleanup();
    CHECK(!helper->native && wma_injection_ctx.coex_resume_ready && destroyed == 2);
    CHECK(wlan_mlme_sta_mon_ap_is_owner(&psoc, 0));
    CHECK(!triple || wlan_mlme_sta_mon_sta_is_companion(&psoc, 1));
    /* Only now does the fixture have the teardown proof expected from HDD. */
    CHECK(wlan_mlme_sta_mon_quiesced(&psoc));
    CHECK(!wlan_mlme_sta_mon_ap_is_owner(&psoc, WLAN_INVALID_VDEV_ID));
    CHECK(!wlan_mlme_sta_mon_sta_is_companion(&psoc, 1));
    CHECK(!control.snapshot.sta_ap_coexist &&
          control.snapshot.companion_sta_vdev_id == WLAN_INVALID_VDEV_ID);
    CHECK(wlan_mlme_sta_mon_admission_begin(&psoc));
    wlan_mlme_sta_mon_admission_end(&psoc);
    wma_injection_deinit(&fake_wma);
}

static void test_ap_firmware_uncertainty(const struct cdp_tx_injection_params *params,
                                       bool triple)
{
    init_coex_fixture();
    if (triple)
        ready_triple_fixture(461);
    else
        ready_ap_fixture(461);
    wlan_mlme_sta_mon_fw_timeout(&psoc, 4);
    CHECK(!control.fw_uncertain && wlan_mlme_sta_mon_token_valid(&psoc, 3, 461));
    wlan_mlme_sta_mon_fw_timeout(&psoc, 3);
    CHECK(control.fw_uncertain && control.state == WLAN_STA_MON_QUIESCING);
    tx_rejected(params);
    wma_injection_pre_stop_cleanup();
    CHECK(wma_injection_ctx.coex_resume_ready && !wma_injection_ctx.in_flight);
    CHECK(!wlan_mlme_sta_mon_quiesced(&psoc));
    CHECK(wlan_mlme_sta_mon_ap_is_owner(&psoc, 0));
    CHECK(!triple || wlan_mlme_sta_mon_sta_is_companion(&psoc, 1));
    wlan_mlme_sta_mon_detach(&psoc);
    CHECK(!control.attached && control.state == WLAN_STA_MON_OFF);
    CHECK(wlan_mlme_sta_mon_ap_is_owner(&psoc, WLAN_INVALID_VDEV_ID));
    CHECK(!triple || wlan_mlme_sta_mon_sta_is_companion(&psoc, 1));
    CHECK(!wlan_mlme_sta_mon_admission_begin(&psoc));
    CHECK(!wlan_mlme_sta_mon_mgmt_admission_begin(&psoc, 4, 5260, false));
    CHECK(!control.admissions);
    wma_injection_deinit(&fake_wma);
}

static struct wlan_objmgr_vdev power_sta, power_helper;

static struct reg_tpc_power_info power_fixture(void)
{
    struct reg_tpc_power_info power = { .num_pwr_levels = 3, .eirp_power = 23 };
    init_coex_fixture();
    psoc.ext_tpc = true;
    pdev = (struct wlan_objmgr_pdev){ .psoc = &psoc, .reg_power = 23,
        .state = CHANNEL_STATE_ENABLE, .bonded_state = CHANNEL_STATE_ENABLE };
    power_sta = (struct wlan_objmgr_vdev){
        .psoc = &psoc, .id = 0, .opmode = QDF_STA_MODE,
        .channel = { .ch_freq = 5260, .ch_cfreq1 = 5290, .ch_width = CH_WIDTH_80MHZ },
    };
    power_helper = (struct wlan_objmgr_vdev){ .psoc = &psoc, .id = 4,
        .opmode = QDF_SAP_MODE, .injection_helper = true };
    wma_injection_power_set_owner(&power_sta, true);
    wma_injection_power_set_owner(&power_helper, true);
    for (unsigned int i = 0; i < power.num_pwr_levels; i++)
        power.chan_power_info[i] = (struct chan_power_info){ 5260, 23 };
    return power;
}

static void power_send(struct reg_tpc_power_info *power, QDF_STATUS status)
{
    uint64_t ticket = wma_injection_tpc_begin(&power_sta, power);
    CHECK(ticket && wma_injection_power.entry[0].pending == 1);
    wma_injection_tpc_end(&power_sta, ticket, status);
    CHECK(!wma_injection_power.entry[0].pending);
}

static QDF_STATUS power_acquire(struct wma_injection_helper *helper, int8_t *limit)
{
    return wma_injection_native_power(&fake_wma, helper, &power_sta,
                                      &power_sta.channel, false, limit);
}

static QDF_STATUS ap_power_acquire(struct wma_injection_helper *helper, int8_t *limit)
{
    return wma_injection_native_power(&fake_wma, helper, &power_sta,
                                      &power_sta.channel, true, limit);
}

static void test_ap_power_owner(void)
{
    struct reg_tpc_power_info power = power_fixture();
    struct wma_injection_helper helper = { .vdev = &power_helper };
    struct wma_injection_power_entry *entry = &wma_injection_power.entry[0];
    const enum channel_state forbidden[] = {
        CHANNEL_STATE_DFS, CHANNEL_STATE_PASSIVE, CHANNEL_STATE_DISABLE,
        CHANNEL_STATE_INVALID,
    };
    uint64_t ticket, revision;
    int8_t limit = 99;

    wma_injection_power_set_owner(&power_sta, false);
    CHECK(!entry->owner);
    power_sta.opmode = QDF_SAP_MODE;
    wma_injection_power_set_owner(&power_sta, true);
    CHECK(entry->owner == &power_sta && !entry->valid);
    CHECK(!wma_injection_power.entry[power_helper.id].owner);
    CHECK(!wma_injection_tpc_begin(&power_helper, &power));
    CHECK(ap_power_acquire(&helper, &limit) == QDF_STATUS_E_NOSUPPORT && limit == 99);
    power.chan_power_info[1].tx_power = 17;
    power_send(&power, QDF_STATUS_SUCCESS);
    CHECK(ap_power_acquire(&helper, &limit) == QDF_STATUS_SUCCESS && limit == 17);
    CHECK(helper.power_owner == &power_sta && helper.power_owner_id == power_sta.id);
    CHECK(wma_injection_native_power_valid(&helper) && helper.power.eirp_power == 17);
    for (unsigned int i = 0; i < 3; i++) CHECK(helper.power.chan_power_info[i].tx_power == 17);
    CHECK(!memcmp(&entry->power, &power, sizeof(power)));
    CHECK(power.chan_power_info[0].tx_power == 23 && power.chan_power_info[2].tx_power == 23);

    /* AP power admission requires both the bond and every constituent enabled. */
    for (unsigned int i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); i++) {
        limit = 99;
        pdev.bonded_state = forbidden[i];
        CHECK(ap_power_acquire(&helper, &limit) == QDF_STATUS_E_NOSUPPORT && limit == 99);
        pdev.bonded_state = CHANNEL_STATE_ENABLE;
        pdev.state_exception_freq = 5320;
        pdev.exception_state = forbidden[i];
        CHECK(ap_power_acquire(&helper, &limit) == QDF_STATUS_E_NOSUPPORT && limit == 99);
        pdev.state_exception_freq = 0;
    }
    CHECK(ap_power_acquire(&helper, &limit) == QDF_STATUS_SUCCESS && limit == 17);
    CHECK(!memcmp(&entry->power, &power, sizeof(power)));
    revision = helper.power_revision;
    ready_ap_fixture(501);

    /* The helper cannot publish its own TPC table or invalidate the real AP. */
    CHECK(!wma_injection_tpc_begin(&power_helper, &power));
    wma_injection_power_override(power_helper.id);
    CHECK(wlan_mlme_sta_mon_token_valid(&psoc, 3, 501) && !stop_notifications);
    CHECK(!wma_injection_power.entry[power_helper.id].owner);
    CHECK(entry->valid && !entry->overridden && entry->revision == revision);

    ticket = wma_injection_tpc_begin(&power_sta, &power);
    CHECK(ticket && !wma_injection_native_power_valid(&helper));
    CHECK(wlan_mlme_sta_mon_token_valid(&psoc, 3, 501) && !stop_notifications);
    wma_injection_tpc_end(&power_sta, ticket, QDF_STATUS_SUCCESS);
    CHECK(wma_injection_native_power_valid(&helper) && entry->revision == revision);
    power.chan_power_info[1].tx_power = 11;
    ticket = wma_injection_tpc_begin(&power_sta, &power);
    CHECK(ticket && !wlan_mlme_sta_mon_token_valid(&psoc, 3, 501));
    CHECK(control.state == WLAN_STA_MON_QUIESCING && stop_notifications == 1);
    CHECK(wlan_mlme_sta_mon_ap_is_owner(&psoc, 0));
    CHECK(!wlan_mlme_sta_mon_admission_begin(&psoc));
    wma_injection_tpc_end(&power_sta, ticket, QDF_STATUS_SUCCESS);
    CHECK(entry->valid && !wma_injection_native_power_valid(&helper));
    CHECK(!memcmp(&entry->power, &power, sizeof(power)));
    wma_injection_pre_stop_cleanup();
    CHECK(wma_injection_ctx.coex_resume_ready);
    CHECK(wlan_mlme_sta_mon_quiesced(&psoc));
    wma_injection_deinit(&fake_wma);
}

static void test_power_limits(void)
{
    struct reg_tpc_power_info power = power_fixture();
    struct wma_injection_helper helper = { .vdev = &power_helper };
    int8_t limit = 99;
    int16_t layout_limit;
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_E_NOSUPPORT && limit == 99);
    power_send(&power, QDF_STATUS_SUCCESS);
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_SUCCESS && limit == 23);
    CHECK(wma_injection_native_power_valid(&helper));

    /* AP/TPE's smaller limit and regulatory 0 dBm are real ceilings. */
    power.chan_power_info[1].tx_power = 0;
    power_send(&power, QDF_STATUS_SUCCESS);
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_SUCCESS && limit == 0);
    for (unsigned int i = 0; i < 3; i++) CHECK(helper.power.chan_power_info[i].tx_power == 0);
    CHECK(power.chan_power_info[0].tx_power == 23); /* never change STA's table */
    power.chan_power_info[1].tx_power = -7;
    power_send(&power, QDF_STATUS_SUCCESS);
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_SUCCESS && limit == -7);
    power.chan_power_info[1].tx_power = 23;
    power_send(&power, QDF_STATUS_SUCCESS);
    pdev.exception_freq = 5320;
    pdev.exception_power = 0;
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_SUCCESS && limit == 0);
    pdev.exception_power = REG_INVALID_TXPOWER;
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_E_NOSUPPORT);
    pdev.exception_power = 128;
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_E_NOSUPPORT);
    pdev.exception_freq = 0;
    /* Numeric power remains sane on a disabled constituent/bonded channel. */
    pdev.state_exception_freq = 5320;
    pdev.exception_state = CHANNEL_STATE_DISABLE;
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_E_NOSUPPORT);
    pdev.exception_state = CHANNEL_STATE_INVALID;
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_E_NOSUPPORT);
    pdev.state_exception_freq = 0;
    pdev.bonded_state = CHANNEL_STATE_DISABLE;
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_E_NOSUPPORT);
    pdev.bonded_state = CHANNEL_STATE_INVALID;
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_E_NOSUPPORT);
    pdev.state = pdev.bonded_state = CHANNEL_STATE_DFS;
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_SUCCESS && limit == 23);
    pdev.state = pdev.bonded_state = CHANNEL_STATE_PASSIVE;
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_SUCCESS && limit == 23);
    pdev.state = pdev.bonded_state = CHANNEL_STATE_ENABLE;
    psoc.ext_tpc = false;
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_E_NOSUPPORT);
    psoc.ext_tpc = true;

    /* Both existing PE layouts are accepted at each primary position. */
    for (unsigned int p = 0; p < 4; p++) {
        power_sta.channel.ch_freq = 5260 + p * 20;
        for (unsigned int i = 0; i < 3; i++)
            power.chan_power_info[i].chan_cfreq = power_sta.channel.ch_freq;
        CHECK(wma_injection_power_layout(&power, &power_sta.channel, &layout_limit));
        power.chan_power_info[1].chan_cfreq = 5270 + (p / 2) * 40;
        power.chan_power_info[2].chan_cfreq = 5290;
        CHECK(wma_injection_power_layout(&power, &power_sta.channel, &layout_limit));
    }
    power_sta.channel.ch_freq = 5260;
    power.chan_power_info[0].chan_cfreq = 5260;
    power.chan_power_info[1].chan_cfreq = 5270;
    power.chan_power_info[2].chan_cfreq = 5290;
    for (int invalid = 0; invalid < 11; invalid++) {
        struct reg_tpc_power_info bad = power;
        struct wlan_channel channel = power_sta.channel;
        switch (invalid) {
        case 0: bad.num_pwr_levels = 2; break;
        case 1: bad.num_pwr_levels = MAX_NUM_PWR_LEVEL + 1; break;
        case 2: bad.is_psd_power = true; break;
        case 3: bad.is_power_type_client_sp = true; break;
        case 4: bad.power_type_6g = 1; break;
        case 5: bad.chan_power_info[2].tx_power = 249; break;
        case 6: bad.chan_power_info[2].tx_power = -129; break;
        case 7: channel.ch_width = CH_WIDTH_160MHZ; break;
        case 8: channel.ch_cfreq2 = 5775; break;
        case 9: channel.puncture_bitmap = 1; break;
        case 10: channel.ch_freq = 5975; break;
        }
        CHECK(!wma_injection_power_layout(&bad, &channel, &layout_limit));
    }
    power.chan_power_info[1].chan_cfreq = 5260; /* mixed layout */
    CHECK(!wma_injection_power_layout(&power, &power_sta.channel, &layout_limit));
    power.num_pwr_levels = 2;
    power_sta.channel = (struct wlan_channel){ .ch_freq = 2412, .ch_cfreq1 = 2422,
                                               .ch_width = CH_WIDTH_40MHZ };
    power.chan_power_info[0].chan_cfreq = 2412;
    power.chan_power_info[1].chan_cfreq = 2422;
    CHECK(wma_injection_power_layout(&power, &power_sta.channel, &layout_limit));
    power_send(&power, QDF_STATUS_SUCCESS);
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_SUCCESS && limit == 23);
    power.num_pwr_levels = 1;
    power_sta.channel.ch_cfreq1 = 2412;
    power_sta.channel.ch_width = CH_WIDTH_20MHZ;
    CHECK(wma_injection_power_layout(&power, &power_sta.channel, &layout_limit));
    power_send(&power, QDF_STATUS_SUCCESS);
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_SUCCESS && limit == 23);
    wma_injection_deinit(&fake_wma);
}

static void test_power_update_order(void)
{
    struct reg_tpc_power_info power = power_fixture(), changed;
    struct wma_injection_helper helper = { .vdev = &power_helper };
    struct wma_injection_power_entry *entry = &wma_injection_power.entry[0];
    int8_t limit;
    uint64_t a, b, c, revision;
    power_send(&power, QDF_STATUS_SUCCESS);
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_SUCCESS);
    revision = helper.power_revision;
    ready_coex_fixture(101);

    /* Repeating an equal effective table must not continually stop capture. */
    power.tpe[0] = 40;
    a = wma_injection_tpc_begin(&power_sta, &power);
    CHECK(control.snapshot.generation == 101 && !stop_notifications);
    CHECK(!wma_injection_native_power_valid(&helper));
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_E_NOSUPPORT);
    power.chan_power_info[0].tx_power = 12; /* sender's later mutation is isolated */
    CHECK(entry->power.chan_power_info[0].tx_power == 23);
    wma_injection_tpc_end(&power_sta, a, QDF_STATUS_SUCCESS);
    CHECK(wma_injection_native_power_valid(&helper) && entry->revision == revision);
    CHECK(wlan_mlme_sta_mon_token_valid(&psoc, 3, 101));
    a = wma_injection_tpc_begin(&power_sta, &power);
    CHECK(!wlan_mlme_sta_mon_token_valid(&psoc, 3, 101) && stop_notifications == 1);
    CHECK(!wma_injection_native_power_valid(&helper));
    wma_injection_tpc_end(&power_sta, a, QDF_STATUS_E_FAILURE);
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_E_NOSUPPORT);
    power_send(&power, QDF_STATUS_SUCCESS);
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_SUCCESS && limit == 12);

    changed = power;
    changed.chan_power_info[0].tx_power = 5;
    for (int reverse = 0; reverse < 2; reverse++) {
        a = wma_injection_tpc_begin(&power_sta, &power);
        b = wma_injection_tpc_begin(&power_sta, &changed);
        CHECK(a == b && entry->pending == 2 && !entry->valid);
        wma_injection_tpc_end(&power_sta, reverse ? a : b, QDF_STATUS_SUCCESS);
        CHECK(entry->pending == 1 && power_acquire(&helper, &limit) == QDF_STATUS_E_NOSUPPORT);
        c = wma_injection_tpc_begin(&power_sta, &changed);
        CHECK(c == a && entry->pending == 2);
        wma_injection_tpc_end(&power_sta, c, QDF_STATUS_SUCCESS);
        wma_injection_tpc_end(&power_sta, reverse ? b : a, QDF_STATUS_SUCCESS);
        CHECK(!entry->pending && !entry->valid);
        power_send(&power, QDF_STATUS_SUCCESS);
        CHECK(power_acquire(&helper, &limit) == QDF_STATUS_SUCCESS && limit == 12);
    }

    a = wma_injection_tpc_begin(&power_sta, &changed);
    wma_injection_power_reset(&power_sta);
    wma_injection_tpc_end(&power_sta, a, QDF_STATUS_SUCCESS);
    CHECK(!entry->valid);
    power_send(&power, QDF_STATUS_SUCCESS);
    power_sta.channel.ch_freq += 20;
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_E_NOSUPPORT);
    power_sta.channel.ch_freq -= 20;
    CHECK(!wma_injection_tpc_begin(&power_helper, &power));
    wma_injection_power_override(power_helper.id);
    CHECK(entry->valid && !entry->overridden);
    wma_injection_deinit(&fake_wma);
}

static void test_power_regulatory_and_reuse(void)
{
    struct reg_tpc_power_info power = power_fixture();
    struct wma_injection_helper helper = { .vdev = &power_helper };
    struct wma_injection_power_entry *entry = &wma_injection_power.entry[0];
    struct wlan_objmgr_vdev replacement = power_sta;
    uint64_t a, b, reg_a, reg_b;
    int8_t limit;
    power_send(&power, QDF_STATUS_SUCCESS);
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_SUCCESS);
    ready_coex_fixture(201);
    a = wma_injection_tpc_begin(&power_sta, &power);
    reg_a = wma_injection_reg_begin(&pdev);
    reg_b = wma_injection_reg_begin(&pdev);
    CHECK(reg_a && reg_b && control.updates == 2 && !entry->valid);
    CHECK(!wlan_mlme_sta_mon_token_valid(&psoc, 3, 201));
    wma_injection_tpc_end(&power_sta, a, QDF_STATUS_SUCCESS);
    wma_injection_reg_end(&pdev, reg_b);
    CHECK(control.updates == 1 && !entry->valid);
    a = wma_injection_tpc_begin(&power_sta, &power);
    wma_injection_reg_end(&pdev, reg_a);
    wma_injection_tpc_end(&power_sta, a, QDF_STATUS_SUCCESS);
    CHECK(!control.updates && !entry->valid);
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_E_NOSUPPORT);
    power_send(&power, QDF_STATUS_SUCCESS);
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_SUCCESS);

    /* A scalar/scale cap cannot vanish through a later START/TPC refresh. */
    wma_injection_power_override(power_sta.id);
    wma_injection_power_reset(&power_sta);
    power_send(&power, QDF_STATUS_SUCCESS);
    CHECK(entry->overridden && !entry->valid && !wma_injection_native_power_valid(&helper));
    wma_injection_power_set_owner(&power_sta, false);
    CHECK(!entry->owner && !entry->overridden && !entry->valid);
    wma_injection_power_set_owner(&power_sta, true);
    power_send(&power, QDF_STATUS_SUCCESS);
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_SUCCESS);

    /* An old lifetime's outstanding send keeps the replacement blocked. */
    a = wma_injection_tpc_begin(&power_sta, &power);
    wma_injection_power_set_owner(&power_sta, false);
    wma_injection_power_set_owner(&replacement, true);
    b = wma_injection_tpc_begin(&replacement, &power);
    wma_injection_tpc_end(&replacement, b, QDF_STATUS_SUCCESS);
    CHECK(entry->pending == 1 && !entry->valid);
    wma_injection_tpc_end(&power_sta, a, QDF_STATUS_SUCCESS);
    CHECK(!entry->pending && !entry->valid && entry->owner == &replacement);
    b = wma_injection_tpc_begin(&replacement, &power);
    wma_injection_tpc_end(&replacement, b, QDF_STATUS_SUCCESS);
    CHECK(entry->valid);
    CHECK(power_acquire(&helper, &limit) == QDF_STATUS_E_NOSUPPORT); /* wrong owner */

    /* WMA reset must not let a stale completion consume a new send ticket. */
    a = wma_injection_tpc_begin(&replacement, &power);
    wma_injection_power_init(&psoc);
    wma_injection_power_set_owner(&power_sta, true);
    b = wma_injection_tpc_begin(&power_sta, &power);
    CHECK(a != b && entry->pending == 1);
    wma_injection_tpc_end(&replacement, a, QDF_STATUS_SUCCESS);
    CHECK(entry->pending == 1 && !entry->valid);
    wma_injection_tpc_end(&power_sta, b, QDF_STATUS_SUCCESS);
    CHECK(entry->valid && !entry->pending);

    /* Regulatory work holds its MLME gate across WMA detach/reinit. */
    reg_a = wma_injection_reg_begin(&pdev);
    CHECK(control.updates == 1);
    wma_injection_power_init(NULL);
    CHECK(control.updates == 1 && !wma_injection_power.psoc);
    wma_injection_reg_end(&pdev, reg_a);
    CHECK(!control.updates);
    wma_injection_power_init(&psoc);
    wma_injection_power_set_owner(&power_sta, true);
    reg_a = wma_injection_reg_begin(&pdev);
    wma_injection_power_init(&psoc);
    wma_injection_power_set_owner(&power_sta, true);
    power_send(&power, QDF_STATUS_SUCCESS);
    CHECK(entry->valid && control.updates == 1);
    wma_injection_reg_end(&pdev, reg_a);
    CHECK(!entry->valid && !control.updates); /* reject mid-update snapshot */

    reg_a = wma_injection_reg_begin(&pdev);
    wma_injection_power_init(&psoc);
    wma_injection_power_set_owner(&power_sta, true);
    reg_b = wma_injection_reg_begin(&pdev);
    a = wma_injection_tpc_begin(&power_sta, &power);
    CHECK(control.updates == 2 && wma_injection_power.reg_updates == 1);
    wma_injection_reg_end(&pdev, reg_a);
    CHECK(control.updates == 1 && wma_injection_power.reg_updates == 1);
    wma_injection_reg_end(&pdev, reg_b);
    CHECK(!control.updates && !wma_injection_power.reg_updates);
    wma_injection_tpc_end(&power_sta, a, QDF_STATUS_SUCCESS);
    CHECK(!entry->valid && !entry->pending);
    power_send(&power, QDF_STATUS_SUCCESS);
    CHECK(entry->valid && power_acquire(&helper, &limit) == QDF_STATUS_SUCCESS);

    replacement.id = WLAN_UMAC_PSOC_MAX_VDEVS;
    wma_injection_power_set_owner(&replacement, true);
    wma_injection_power_reset(&replacement);
    wma_injection_power_override(replacement.id);
    CHECK(!wma_injection_tpc_begin(&replacement, &power));
    wma_injection_tpc_end(&replacement, b, QDF_STATUS_SUCCESS);
    CHECK(entry->valid);
    wma_injection_deinit(&fake_wma);
    CHECK(!wma_injection_power.psoc && !entry->valid);
}

static void test_native_power_start(void)
{
    for (unsigned int fault = 0; fault < 7; fault++) {
        struct reg_tpc_power_info power = power_fixture();
        struct wma_injection_helper *helper = &wma_injection_ctx.helper;
        struct vdev_mlme_obj mlme = { .vdev = &power_helper };
        int8_t limit;
        power.chan_power_info[0].tx_power = 0;
        power_send(&power, QDF_STATUS_SUCCESS);
        ready_coex_fixture(301);
        *helper = (struct wma_injection_helper){
            .native = true, .vdev = &power_helper, .vdev_id = power_helper.id,
            .monitor_vdev_id = 3, .generation = 301,
            .start_status = QDF_STATUS_SUCCESS,
        };
        CHECK(power_acquire(helper, &limit) == QDF_STATUS_SUCCESS && limit == 0);
        tpc_ops_missing = false;
        native_reg_ops.set_tpc_power = send_native_tpc;
        native_tpc_sends = native_up_sends = native_start_events = 0;
        native_tpc_status = native_up_status = QDF_STATUS_SUCCESS;
        invalidate_during_tpc = NULL;
        switch (fault) {
        case 1: tpc_ops_missing = true; break;
        case 2: native_reg_ops.set_tpc_power = NULL; break;
        case 3: native_tpc_status = QDF_STATUS_E_FAILURE; break;
        case 4: invalidate_during_tpc = &power_sta; break;
        case 5: power_helper.fw_uncertain = true; break;
        case 6: native_up_status = QDF_STATUS_E_FAILURE; break;
        }
        QDF_STATUS status = wma_injection_helper_start_continue(&mlme, 0, NULL);
        if (!fault || fault == 6) {
            CHECK(status == QDF_STATUS_SUCCESS && helper->power_programmed);
            CHECK(native_tpc_sends == 1 && native_start_events == 1 && !native_up_sends);
            for (unsigned int i = 0; i < 3; i++) CHECK(native_sent_power.chan_power_info[i].tx_power == 0);
            CHECK(wma_injection_helper_up_send(&mlme, 0, NULL) == native_up_status);
            CHECK(native_up_sends == 1 && helper->wmi_up == !fault);
        } else {
            CHECK(QDF_IS_STATUS_ERROR(status) && !helper->power_programmed);
            CHECK(helper->start_done.done == 1 && !native_up_sends && !native_start_events);
            CHECK(wma_injection_helper_up_send(&mlme, 0, NULL) == QDF_STATUS_E_AGAIN);
            CHECK(!native_up_sends && !helper->wmi_up);
        }
        wma_injection_deinit(&fake_wma);
    }
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
    wma_injection_init(&fake_wma);
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
    CHECK(wma_injection_ctx.in_flight == 1 && injection_completed == 0);
    wma_injection_dp_release(&packets[0], 1);
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
    CHECK(wma_injection_ctx.in_flight == 4 && wma_injection_ctx.pending.len == 1);
    wma_injection_dp_release(&packets[1], 2);
    CHECK(!wma_injection_ctx.pending.len && packets[5].sent == 1);
    CHECK(injection_completion_unknown == 1);
    for (unsigned int i = 1; i <= 5; i++) {
        CHECK(submitted_vdev[i] == i && submitted_params[i].tid == i);
        CHECK(submitted_params[i].mcs_mask == 1U << i);
        CHECK(submitted_params[i].interface_mac[5] == i);
    }
    CHECK(wma_injection_dp_complete(NULL, &packets[2], 1));
    wma_injection_dp_release(&packets[2], 3);
    CHECK(injection_completion_failed == 1);
    CHECK(wma_injection_dp_complete(NULL, &packets[3], 0));
    wma_injection_dp_release(&packets[3], 4);
    CHECK(wma_injection_dp_complete(NULL, &packets[4], 0));
    wma_injection_dp_release(&packets[4], 5);
    CHECK(wma_injection_dp_complete(NULL, &packets[5], 0));
    wma_injection_dp_release(&packets[5], 6);

    CHECK(wma_injection_tx(&packets[6], 7, &p) == 0);
    send_result = QDF_STATUS_E_FAILURE;
    wma_injection_refill(true);
    CHECK(packets[6].freed == 1 && injection_send_failed == 1);
    CHECK(wma_injection_tx(&packets[7], 9, &p) == 0);
    packets[7].reset = false;
    wma_injection_deinit(NULL);
    CHECK(packets[7].freed == 1 && destroyed == 1);
    CHECK(!wma_injection_ctx.pending.len && !wma_injection_ctx.active);
    test_coex_restart(&p);
    test_pending_stop(&p);
    test_coex_admission(&p);
    test_resume_guards();
    test_failed_drain(&p);
    test_deinit_dma_ownership(&p);
    test_ap_admissions();
    test_ap_handoff_guards();
    test_triple_arm();
    test_arm_pause_reset();
    test_triple_admissions_and_csa();
    test_triple_owner_events();
    test_triple_handoff_guards();
    test_ap_invalidation_ownership(&p, false);
    test_ap_invalidation_ownership(&p, true);
    test_ap_firmware_uncertainty(&p, false);
    test_ap_firmware_uncertainty(&p, true);
    test_ap_power_owner();
    test_power_limits();
    test_power_update_order();
    test_power_regulatory_and_reuse();
    test_native_power_start();
    printf("%u\n", cases);
    return 0;
}
