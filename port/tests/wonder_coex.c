/* Production coex/dwell/packet-token host fixture. External services are mocks. */
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef unsigned long long u64;
typedef int32_t s32;
#define scnprintf snprintf
static atomic_uint assertions;
static unsigned cases;
static const char *current_case;
#define CHECK(c) do { assertions++; if (!(c)) { \
    fprintf(stderr, "%s:%d %s: %s\n", __FILE__, __LINE__, current_case, #c); \
    abort(); \
} } while (0)
#define TEST(f) do { current_case = #f; f(); cases++; } while (0)
#define FEATURE_WLAN_WONDER
#define GFP_KERNEL 0
#define GFP_ATOMIC 1
#define NSEC_PER_MSEC 1000000ULL
#define WLAN_SCAN_ID 1
#define WLAN_SCAN_CANCEL_SINGLE 1
#define SCAN_TYPE_DEFAULT 0
#define SCAN_DWELL_MODE_STATIC 0
#define IEEE80211_CHAN_DISABLED 1
#define IEEE80211_CHAN_NO_IR 2
#define IEEE80211_CHAN_RADAR 4
#define REG_CURRENT_PWR_MODE 0
enum { CH_WIDTH_20MHZ, CH_WIDTH_40MHZ, CH_WIDTH_80MHZ, CH_WIDTH_160MHZ };
#define THIS_MODULE ((void *)1)
#define DECLARE_BITMAP(name, count) unsigned long name[((count) + 63) / 64]
#define container_of(p, type, member) ((type *)((char *)(p) - offsetof(type, member)))
#define to_delayed_work(p) container_of(p, struct delayed_work, work)
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define IS_ERR(p) ((intptr_t)(p) < 0 && (intptr_t)(p) >= -4095)
#define READ_ONCE(x) (x)
#define smp_load_acquire(p) (*(p))
#define rcu_dereference(p) (p)

typedef int QDF_STATUS;
#define QDF_STATUS_SUCCESS 0
#define QDF_IS_STATUS_ERROR(s) ((s) != 0)
#define QDF_IS_STATUS_SUCCESS(s) ((s) == 0)
#define qdf_status_to_os_return(s) (s)

struct wlan_objmgr_psoc { unsigned unused; };
struct wlan_objmgr_vdev { u8 id; };
struct wlan_channel { u32 ch_freq, ch_cfreq2; int ch_width; };
struct hdd_context { struct wlan_objmgr_psoc *psoc; void *wiphy, *pdev; };
struct hdd_link { u8 vdev_id; };
struct hdd_adapter {
    struct hdd_context *hdd_ctx; struct hdd_link *deflink;
    bool wonder_owned, sta_mon_coexist;
};
struct ieee80211_channel { u32 flags; };
struct ch_params { int ch_width; };
struct net_device { struct hdd_adapter *adapter; };
#define WLAN_HDD_GET_PRIV_PTR(dev) ((dev)->adapter)
struct wma_wonder_helper_snapshot { u64 cookie; u8 vdev_id; };
struct kref { unsigned count; };
typedef struct { pthread_mutex_t mutex; } spinlock_t;
struct completion { bool done; };
struct work_struct { void (*function)(struct work_struct *); };
struct delayed_work { struct work_struct work; u64 delay; bool pending; };
struct scan_start_request {
    struct wlan_objmgr_vdev *vdev;
    struct {
        u32 scan_id, scan_req_id, vdev_id, scan_type, scan_flags;
        struct { u8 num_chan; struct { u32 freq; } chan[256]; } chan_list;
        bool scan_f_passive, scan_f_offchan_data_tx, scan_f_offchan_mgmt_tx;
        bool scan_f_promisc_mode, scan_ev_started, scan_ev_completed;
        bool scan_ev_bss_chan, scan_ev_foreign_chan, scan_ev_foreign_chn_exit;
        bool scan_ev_dequeued, scan_ev_preempted, scan_ev_start_failed;
        bool scan_ev_restarted, scan_ev_suspended;
        u32 adaptive_dwell_time_mode, dwell_time_passive, dwell_time_active;
        u32 dwell_time_active_2g, dwell_time_active_6g, max_scan_time, burst_duration;
    } scan_req;
};
struct scan_cancel_request {
    struct wlan_objmgr_vdev *vdev;
    struct { u32 scan_id, requester, vdev_id, req_type; } cancel_req;
};

/* INSERT_SCAN_TYPES */
/* INSERT_MLME_TYPES */
/* INSERT_DWELL_API */
/* INSERT_COEX_API */
/* INSERT_RX_LEASE */
/* INSERT_CHANNEL_TYPES */
/* INSERT_PROBE_PARAMETER */

static struct wlan_objmgr_psoc psoc;
static struct wlan_objmgr_vdev vdev = { .id = 7 };
static struct hdd_context hdd_ctx = { .psoc = &psoc };
static struct hdd_link link = { .vdev_id = 7 };
static struct hdd_adapter adapter = { .hdd_ctx = &hdd_ctx, .deflink = &link };
static struct net_device netdev = { .adapter = &adapter };
static struct wma_wonder_helper_snapshot helper = { .cookie = 0x314159, .vdev_id = 8 };
static struct wlan_mlme_sta_mon_snapshot live;
static pthread_mutex_t admission = PTHREAD_MUTEX_INITIALIZER;
static unsigned module_refs, psoc_refs, vdev_refs, cancels, starts, rcu_depth;
static u64 now_ns;
static u32 next_scan_id;
static bool admission_ready, reserved, submitted, fail_alloc;
static struct wlan_mlme_sta_mon_scan_reservation reservation;
static wlan_mlme_sta_mon_scan_cb scan_callback;
static void *scan_arg;
static struct work_struct *pending_free;
static struct scan_start_request last_request;
static struct scan_cancel_request last_cancel;
static enum { WAIT_ENTER, WAIT_SILENT, SUBMIT_FAIL, SUBMIT_TRUSTED_FAIL, SUBMIT_DELAYED } mode;
static void route_event(enum scan_event_type type, u32 frequency);
static void route_notice(enum wlan_mlme_sta_mon_scan_notice notice);

static void spin_lock_init(spinlock_t *lock) { CHECK(!pthread_mutex_init(&lock->mutex, NULL)); }
static void spin_lock(spinlock_t *lock) { CHECK(!pthread_mutex_lock(&lock->mutex)); }
static void spin_unlock(spinlock_t *lock) { CHECK(!pthread_mutex_unlock(&lock->mutex)); }
#define spin_lock_irqsave(lock, flags) do { (flags) = 0; spin_lock(lock); } while (0)
#define spin_unlock_irqrestore(lock, flags) do { (void)(flags); spin_unlock(lock); } while (0)
static void kref_init(struct kref *ref) { ref->count = 1; }
static void kref_get(struct kref *ref) { CHECK(ref->count); ref->count++; }
static bool kref_put(struct kref *ref, void (*release)(struct kref *))
{
    CHECK(ref->count);
    if (--ref->count) return false;
    release(ref);
    return true;
}
static void *kzalloc(size_t length, int flags)
{
    (void)flags;
    if (fail_alloc) return NULL;
    return calloc(1, length);
}
static void kfree(void *p) { free(p); }
static void *qdf_mem_malloc(size_t length) { return kzalloc(length, GFP_KERNEL); }
static void qdf_mem_free(void *p) { kfree(p); }
static bool try_module_get(void *module) { CHECK(module == THIS_MODULE); module_refs++; return true; }
static void module_put(void *module) { CHECK(module == THIS_MODULE && module_refs); module_refs--; }
static QDF_STATUS wlan_objmgr_psoc_try_get_ref(struct wlan_objmgr_psoc *p, int id)
{ CHECK(p == &psoc && id == WLAN_SCAN_ID); psoc_refs++; return 0; }
static void wlan_objmgr_psoc_release_ref(struct wlan_objmgr_psoc *p, int id)
{ CHECK(p == &psoc && id == WLAN_SCAN_ID && psoc_refs); psoc_refs--; }
static struct wlan_objmgr_vdev *wlan_objmgr_get_vdev_by_id_from_psoc(
    struct wlan_objmgr_psoc *p, u32 vdev_id, int id)
{ CHECK(p == &psoc && vdev_id == vdev.id && id == WLAN_SCAN_ID); vdev_refs++; return &vdev; }
static void wlan_objmgr_vdev_release_ref(struct wlan_objmgr_vdev *v, int id)
{ CHECK(v == &vdev && id == WLAN_SCAN_ID && vdev_refs); vdev_refs--; }
static u64 ktime_get_ns(void) { return now_ns; }
static u64 div_u64(u64 n, u32 d) { return n / d; }
static u64 nsecs_to_jiffies(u64 n) { return n / NSEC_PER_MSEC; }
static void init_completion(struct completion *c) { c->done = false; }
static void reinit_completion(struct completion *c) { c->done = false; }
static void complete_all(struct completion *c) { c->done = true; }
#define INIT_WORK(w, f) ((w)->function = (f))
#define INIT_DELAYED_WORK(w, f) INIT_WORK(&(w)->work, f)
static void schedule_work(struct work_struct *work) { CHECK(!pending_free); pending_free = work; }
static void *system_wq;
static void mod_delayed_work(void *queue, struct delayed_work *work, u64 delay)
{ (void)queue; work->delay = delay; work->pending = true; }
static void cancel_delayed_work_sync(struct delayed_work *work) { work->pending = false; }
static bool test_bit(u32 bit, unsigned long *bits) { return !!(bits[bit / 64] & (1UL << (bit % 64))); }
static void set_bit(u32 bit, unsigned long *bits) { bits[bit / 64] |= 1UL << (bit % 64); }
static void rcu_read_lock(void) { rcu_depth++; }
static void rcu_read_unlock(void) { CHECK(rcu_depth); rcu_depth--; }

static bool wlan_mlme_sta_mon_get_snapshot(void *p, u8 monitor, u64 generation,
    struct wlan_mlme_sta_mon_snapshot *out)
{
    CHECK(p == &psoc && out);
    CHECK(!pthread_mutex_lock(&admission));
    bool ok = admission_ready && monitor == live.mon_vdev_id && generation == live.generation;
    if (ok) *out = live;
    CHECK(!pthread_mutex_unlock(&admission));
    return ok;
}
static bool wlan_mlme_sta_mon_tx_begin(void *p, u8 monitor, u64 generation, unsigned long *flags)
{
    CHECK(p == &psoc && flags);
    CHECK(!pthread_mutex_lock(&admission));
    *flags = 0;
    if (admission_ready && monitor == live.mon_vdev_id && generation == live.generation)
        return true;
    CHECK(!pthread_mutex_unlock(&admission));
    return false;
}
static void wlan_mlme_sta_mon_tx_end(unsigned long flags)
{ CHECK(!flags); CHECK(!pthread_mutex_unlock(&admission)); }
static bool wlan_mlme_sta_mon_scan_reserve(struct wlan_objmgr_psoc *p,
    const struct wlan_mlme_sta_mon_scan_reservation *r,
    wlan_mlme_sta_mon_scan_cb callback, void *arg)
{
    CHECK(p == &psoc && callback && arg && !reserved);
    CHECK(r->vdev_id == live.mon_vdev_id && r->generation == live.generation);
    CHECK(r->helper_cookie == helper.cookie && r->frequency != live.channel.ch_freq);
    reservation = *r; scan_callback = callback; scan_arg = arg;
    reserved = true; submitted = false;
    return true;
}
static bool wlan_mlme_sta_mon_scan_release_unsubmitted(struct wlan_objmgr_psoc *p,
    const struct wlan_mlme_sta_mon_scan_reservation *r)
{
    CHECK(p == &psoc && r->scan_id == reservation.scan_id);
    if (!reserved || submitted) return false;
    reserved = false; scan_callback = NULL; scan_arg = NULL;
    return true;
}
static u32 wlan_scan_register_requester(struct wlan_objmgr_psoc *p, u8 *name,
    void (*callback)(struct wlan_objmgr_vdev *, struct scan_event *, void *), void *arg)
{ CHECK(p == &psoc && !strcmp((char *)name, "wonder-dwell") && callback && !arg); return 88; }
static void wlan_scan_unregister_requester(struct wlan_objmgr_psoc *p, u32 requester)
{ CHECK(p == &psoc && requester == 88); }
static u32 wlan_scan_get_scan_id(struct wlan_objmgr_psoc *p)
{ CHECK(p == &psoc); return next_scan_id++; }
static QDF_STATUS wlan_scan_init_default_params(struct wlan_objmgr_vdev *v,
    struct scan_start_request *req)
{ CHECK(v == &vdev); memset(req, 0, sizeof(*req)); req->vdev = v; return 0; }
static QDF_STATUS wlan_scan_start(struct scan_start_request *req)
{
    starts++; last_request = *req;
    CHECK(req->vdev == &vdev && req->scan_req.scan_id == reservation.scan_id);
    CHECK(req->scan_req.chan_list.num_chan == 1 && req->scan_req.scan_f_offchan_data_tx);
    if (mode == SUBMIT_TRUSTED_FAIL) route_notice(WLAN_STA_MON_SCAN_NOT_SUBMITTED);
    else if (mode != SUBMIT_FAIL) submitted = true;
    if (mode == SUBMIT_DELAYED) now_ns += 100 * NSEC_PER_MSEC;
    free(req);
    return mode == SUBMIT_FAIL || mode == SUBMIT_TRUSTED_FAIL ? -EBUSY : 0;
}
static QDF_STATUS wlan_scan_cancel(struct scan_cancel_request *req)
{
    cancels++; last_cancel = *req;
    CHECK(req->cancel_req.req_type == WLAN_SCAN_CANCEL_SINGLE);
    CHECK(req->cancel_req.scan_id == reservation.scan_id);
    CHECK(req->cancel_req.requester == reservation.requester);
    free(req); return 0; /* Sending CANCEL does not retire accepted firmware. */
}
static u64 wait_for_completion_timeout(struct completion *completion, u64 timeout)
{
    CHECK(timeout);
    if (mode == WAIT_ENTER) {
        now_ns += NSEC_PER_MSEC;
        route_event(SCAN_EVENT_TYPE_STARTED, reservation.frequency);
        now_ns += NSEC_PER_MSEC;
        route_event(SCAN_EVENT_TYPE_FOREIGN_CHANNEL, reservation.frequency);
    }
    return completion->done ? 1 : 0;
}

/* INSERT_DWELL_CORE */
/* INSERT_COEX_CORE */

struct hdd_wonder_session {
    struct hdd_adapter *adapter;
    struct hdd_wonder_coex *coex;
    void *peer;
    bool suspended, failed, exclusive_bootstrap;
    struct { u32 freq; } channel;
};
static struct hdd_wonder_session session;
static struct hdd_wonder_session *hdd_wonder_active;
static bool peer_ready;
static bool hdd_wonder_peer_ready(void *peer) { CHECK(peer == &helper); return peer_ready; }
static struct ieee80211_channel channel;
static bool channel_missing, regulatory_reject;
static unsigned regulatory_calls;
static int shared_error;
static struct ieee80211_channel *ieee80211_get_channel(void *wiphy, u32 frequency)
{ CHECK(wiphy == hdd_ctx.wiphy && frequency); return channel_missing ? NULL : &channel; }
static int hdd_sta_mon_get_channel(struct hdd_adapter *a, struct wlan_channel *shared)
{ CHECK(a == &adapter); *shared = live.channel; return shared_error; }
static u64 wlan_mlme_sta_mon_epoch(struct wlan_objmgr_psoc *p)
{ CHECK(p == &psoc); return live.generation; }
static void wlan_reg_set_channel_params_for_pwrmode(void *pdev, u32 frequency,
    u32 secondary, struct ch_params *bonded, int mode)
{
    CHECK(pdev == hdd_ctx.pdev && frequency && !secondary && mode == REG_CURRENT_PWR_MODE);
    regulatory_calls++;
    if (regulatory_reject) bonded->ch_width = -1;
}
static int hdd_validate_channel_and_bandwidth(struct hdd_adapter *a, u32 frequency,
    u32 secondary, int width)
{ CHECK(a == &adapter && frequency && !secondary && width <= CH_WIDTH_80MHZ); return 0; }

/* Bootstrap channel construction is an external policy primitive in this fixture.
 * The actual provider preflight must dispatch to it before reading a live lease.
 */
static int exclusive_channel_status;
static unsigned exclusive_channel_calls;
static int hdd_wonder_build_exclusive_channel(struct hdd_adapter *a, u32 frequency,
    u32 bandwidth, struct wlan_channel *requested)
{
    CHECK(a == &adapter && frequency && requested && bandwidth <= CH_WIDTH_80MHZ);
    exclusive_channel_calls++;
    *requested = (struct wlan_channel){ .ch_freq = frequency, .ch_width = bandwidth };
    return exclusive_channel_status;
}

/* INSERT_PROVIDER_PUBLICATION */
/* INSERT_PROVIDER_PREFLIGHT */

static void route_notice(enum wlan_mlme_sta_mon_scan_notice notice)
{
    struct scan_event event = { .vdev_id = reservation.vdev_id,
        .requester = reservation.requester, .scan_id = reservation.scan_id,
        .type = SCAN_EVENT_TYPE_COMPLETED };
    CHECK(reserved && scan_callback);
    CHECK(!pthread_mutex_lock(&admission));
    scan_callback(scan_arg, &event, notice, reservation.generation, reservation.helper_cookie);
    reserved = false; scan_callback = NULL; scan_arg = NULL; submitted = false;
    CHECK(!pthread_mutex_unlock(&admission));
}
static void route_event(enum scan_event_type type, u32 frequency)
{
    struct scan_event event = { .vdev_id = reservation.vdev_id,
        .requester = reservation.requester, .scan_id = reservation.scan_id,
        .type = type, .chan_freq = frequency, .timestamp = (u32)(now_ns / 1000) };
    CHECK(reserved && scan_callback);
    CHECK(!pthread_mutex_lock(&admission));
    scan_callback(scan_arg, &event, WLAN_STA_MON_SCAN_FIRMWARE,
                  reservation.generation, reservation.helper_cookie);
    if (type == SCAN_EVENT_TYPE_COMPLETED || type == SCAN_EVENT_TYPE_START_FAILED ||
        type == SCAN_EVENT_TYPE_DEQUEUED) {
        reserved = false; scan_callback = NULL; scan_arg = NULL; submitted = false;
    }
    CHECK(!pthread_mutex_unlock(&admission));
}
static void drain_free(void)
{
    CHECK(pending_free);
    struct work_struct *work = pending_free;
    pending_free = NULL;
    work->function(work);
    CHECK(!module_refs && !psoc_refs && !vdev_refs);
}
static struct hdd_wonder_coex *fresh(void)
{
    CHECK(!module_refs && !psoc_refs && !vdev_refs && !pending_free && !rcu_depth);
    memset(&live, 0, sizeof(live));
    live.generation = 0x123456; live.mon_vdev_id = 7; live.sta_vdev_id = 24;
    live.channel.ch_freq = 5180;
    live.channel.ch_width = CH_WIDTH_80MHZ;
    admission_ready = peer_ready = true;
    adapter.wonder_owned = true;
    adapter.sta_mon_coexist = true;
    wonder_sta_offchan_probe = false;
    channel.flags = 0; channel_missing = regulatory_reject = false;
    regulatory_calls = 0; shared_error = 0;
    reserved = submitted = fail_alloc = false;
    scan_callback = NULL; scan_arg = NULL;
    now_ns = 1000000000ULL; next_scan_id = 1;
    cancels = starts = 0; mode = WAIT_ENTER;
    struct hdd_wonder_coex *coex = hdd_wonder_coex_create(&adapter, 5180, live.generation, &helper);
    CHECK(!IS_ERR(coex));
    memset(&session, 0, sizeof(session));
    session.adapter = &adapter; session.peer = &helper; session.coex = coex;
    session.channel.freq = 5180; hdd_wonder_active = &session;
    CHECK(coex->ref.count == 1 && module_refs == 1 && psoc_refs == 1);
    return coex;
}
static void dispose(struct hdd_wonder_coex *coex)
{
    hdd_wonder_active = NULL;
    hdd_wonder_coex_destroy(coex);
    if (reserved) route_event(SCAN_EVENT_TYPE_COMPLETED, 0);
    drain_free();
}
static void acquire(struct hdd_wonder_coex *coex, u32 frequency)
{
    u64 completion = 0;
    CHECK(!hdd_wonder_coex_acquire(coex, frequency, now_ns + 40 * NSEC_PER_MSEC,
                                  20 * NSEC_PER_MSEC, &completion));
    CHECK(completion == coex->entry_ns && completion && coex->scan_ref);
    CHECK(coex->dwell.phase == HDD_WONDER_DWELL_READY && coex->ref.count >= 2);
}

static void create_and_scan_parameters(void)
{
    struct hdd_wonder_coex *coex = fresh();
    CHECK(coex->dwell.home_vdev_id == live.sta_vdev_id);
    acquire(coex, 5745);
    CHECK(coex->dwell.home_freq == 5180 && coex->logical_frequency == 5745);
    CHECK(last_request.scan_req.scan_f_passive && last_request.scan_req.scan_f_promisc_mode);
    CHECK(last_request.scan_req.scan_f_offchan_data_tx && last_request.scan_req.scan_f_offchan_mgmt_tx);
    CHECK(last_request.scan_req.chan_list.chan[0].freq == 5745);
    CHECK(last_request.scan_req.dwell_time_passive == 20 && last_request.scan_req.dwell_time_active == 0);
    CHECK(last_request.scan_req.max_scan_time == 20 && !vdev_refs);
    dispose(coex);
}
static void probe_preflight_preserves_home_and_reservation(void)
{
    struct hdd_wonder_coex *coex = fresh();
    struct wondertap_set_freq_params params = { .freq = 5745, .bandwidth = WONDERTAP_RATE_BW_20 };
    struct hdd_wonder_dwell saved_dwell = coex->dwell;
    CHECK(!wonder_sta_offchan_probe);
    CHECK(hdd_wonder_validate_channel(&session, &params) == -EOPNOTSUPP);
    CHECK(!regulatory_calls && !starts && !reserved);
    CHECK(!memcmp(&coex->dwell, &saved_dwell, sizeof(saved_dwell)));
    CHECK(coex->logical_frequency == 5180 && coex->ref.count == 1);
    params.freq = 5180;
    CHECK(!hdd_wonder_validate_channel(&session, &params));
    CHECK(!regulatory_calls && !starts && !reserved);
    params.freq = 5745; wonder_sta_offchan_probe = true;
    CHECK(!hdd_wonder_validate_channel(&session, &params));
    CHECK(regulatory_calls == 1 && !starts && !reserved);
    CHECK(!memcmp(&coex->dwell, &saved_dwell, sizeof(saved_dwell)));
    params.bandwidth = WONDERTAP_RATE_BW_40;
    CHECK(hdd_wonder_validate_channel(&session, &params) == -EOPNOTSUPP);
    params.bandwidth = WONDERTAP_RATE_BW_80;
    CHECK(hdd_wonder_validate_channel(&session, &params) == -EOPNOTSUPP);
    params.bandwidth = WONDERTAP_RATE_BW_20;
    live.ap_owner = true;
    CHECK(hdd_wonder_validate_channel(&session, &params) == -EOPNOTSUPP);
    live.sta_ap_coexist = true;
    CHECK(hdd_wonder_validate_channel(&session, &params) == -EOPNOTSUPP);
    params.freq = 5180;
    CHECK(!hdd_wonder_validate_channel(&session, &params));
    params.freq = 5745; live.ap_owner = live.sta_ap_coexist = false;
    live.exclusive = true;
    CHECK(hdd_wonder_validate_channel(&session, &params) == -EOPNOTSUPP);
    live.exclusive = false; regulatory_reject = true;
    CHECK(hdd_wonder_validate_channel(&session, &params) == -EOPNOTSUPP);
    regulatory_reject = false;
    static const u32 flags[] = { IEEE80211_CHAN_DISABLED, IEEE80211_CHAN_NO_IR, IEEE80211_CHAN_RADAR };
    for (unsigned i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        channel.flags = flags[i];
        CHECK(hdd_wonder_validate_channel(&session, &params) == -EOPNOTSUPP);
    }
    channel.flags = 0; channel_missing = true;
    CHECK(hdd_wonder_validate_channel(&session, &params) == -EOPNOTSUPP);
    channel_missing = false; shared_error = -EAGAIN;
    CHECK(hdd_wonder_validate_channel(&session, &params) == -EAGAIN);
    shared_error = 0; admission_ready = false;
    CHECK(hdd_wonder_validate_channel(&session, &params) == -EOPNOTSUPP);
    admission_ready = true;
    session.exclusive_bootstrap = true;
    CHECK(!hdd_wonder_validate_channel(&session, &params));
    CHECK(exclusive_channel_calls == 1 && !starts && !reserved);
    exclusive_channel_status = -EAGAIN;
    CHECK(hdd_wonder_validate_channel(&session, &params) == -EAGAIN);
    CHECK(exclusive_channel_calls == 2 && !starts && !reserved);
    exclusive_channel_status = 0; session.exclusive_bootstrap = false;
    CHECK(hdd_wonder_validate_channel(&session, NULL) == -EINVAL);
    params.freq = 0;
    CHECK(hdd_wonder_validate_channel(&session, &params) == -EINVAL);
    CHECK(!memcmp(&coex->dwell, &saved_dwell, sizeof(saved_dwell)));
    CHECK(!starts && !reserved && coex->logical_frequency == 5180 && coex->ref.count == 1);
    dispose(coex);
}
static void old_queued_tuple_same_frequency_denied(void)
{
    struct hdd_wonder_coex *coex = fresh(); acquire(coex, 5745);
    void *old = hdd_wonder_coex_tx_token(coex, 5745);
    CHECK(!IS_ERR(old) && coex->ref.count == 3);
    unsigned long flags;
    CHECK(hdd_wonder_coex_tx_begin(old, &flags)); hdd_wonder_coex_tx_end(old, flags);
    CHECK(hdd_wonder_coex_tx_frequency(old) == 5745);
    struct hdd_wonder_coex_tx_token *old_token = old;
    old_token->owner.helper_cookie++;
    CHECK(!hdd_wonder_coex_tx_begin(old, &flags));
    old_token->owner.helper_cookie--;
    route_event(SCAN_EVENT_TYPE_COMPLETED, 0);
    CHECK(coex->ref.count == 2);
    now_ns += 5 * NSEC_PER_MSEC;
    u64 completion = 0;
    CHECK(!hdd_wonder_coex_acquire(coex, 5745, old_token->deadline_ns,
                                  20 * NSEC_PER_MSEC, &completion));
    CHECK(coex->dwell.deadline_ns == old_token->deadline_ns);
    CHECK(coex->dwell.scan.scan_id != old_token->scan.scan_id);
    CHECK(!hdd_wonder_coex_tx_begin(old, &flags));
    void *current = hdd_wonder_coex_tx_token(coex, 5745);
    CHECK(!IS_ERR(current));
    CHECK(hdd_wonder_coex_tx_begin(current, &flags)); hdd_wonder_coex_tx_end(current, flags);
    hdd_wonder_coex_tx_release(old); hdd_wonder_coex_tx_release(current);
    CHECK(coex->ref.count == 2); dispose(coex);
}
static void home_and_unknown_packets_blocked_until_terminal(void)
{
    struct hdd_wonder_coex *coex = fresh(); unsigned long flags;
    struct cdp_wonder_rx_lease lease = {0};
    CHECK(wlan_injection_wonder_rx_begin(&psoc, 7, live.generation, 0, &lease));
    wlan_injection_wonder_rx_end(&lease); CHECK(!rcu_depth);
    CHECK(!pthread_mutex_trylock(&coex->lock.mutex));
    CHECK(!pthread_mutex_unlock(&coex->lock.mutex));
    mode = WAIT_SILENT; u64 completion = 0;
    CHECK(hdd_wonder_coex_acquire(coex, 5745, now_ns + 40 * NSEC_PER_MSEC,
          20 * NSEC_PER_MSEC, &completion) == -EAGAIN);
    CHECK(coex->dwell.phase == HDD_WONDER_DWELL_CANCEL_PENDING && coex->scan_ref);
    CHECK(!hdd_wonder_coex_publish_begin(coex, 5180, &flags));
    CHECK(!wlan_injection_wonder_rx_begin(&psoc, 7, live.generation, 0, &lease));
    CHECK(!rcu_depth);
    CHECK(wlan_mlme_sta_mon_tx_begin(&psoc, 7, live.generation, &flags));
    CHECK(!wlan_injection_wonder_home_tx_begin_locked(&psoc, 7, live.generation, &lease));
    wlan_mlme_sta_mon_tx_end(flags); CHECK(!rcu_depth);
    route_event(SCAN_EVENT_TYPE_FOREIGN_CHANNEL, 5745);
    CHECK(!wlan_injection_wonder_rx_begin(&psoc, 7, live.generation, 5745, &lease));
    CHECK(hdd_wonder_coex_home(coex) == -EBUSY); /* Wait for real terminal. */
    CHECK(!hdd_wonder_coex_publish_begin(coex, 5180, &flags));
    CHECK(!wlan_injection_wonder_rx_begin(&psoc, 7, live.generation, 0, &lease));
    route_event(SCAN_EVENT_TYPE_COMPLETED, 0);
    CHECK(!hdd_wonder_coex_home(coex));
    CHECK(wlan_injection_wonder_rx_begin(&psoc, 7, live.generation, 5180, &lease));
    wlan_injection_wonder_rx_end(&lease); dispose(coex);
}
static void generic_shared_home_only(void)
{
    struct hdd_wonder_coex *coex = fresh(); struct cdp_wonder_rx_lease lease = {0};
    hdd_wonder_active = NULL;
    CHECK(wlan_injection_wonder_rx_begin(&psoc, 7, live.generation, 5180, &lease));
    wlan_injection_wonder_rx_end(&lease);
    CHECK(wlan_injection_wonder_rx_begin(&psoc, 7, live.generation, 0, &lease));
    wlan_injection_wonder_rx_end(&lease);
    CHECK(!wlan_injection_wonder_rx_begin(&psoc, 7, live.generation, 5745, &lease));
    CHECK(!rcu_depth);
    hdd_wonder_active = &session; session.failed = true;
    CHECK(!wlan_injection_wonder_rx_begin(&psoc, 7, live.generation, 5180, &lease));
    session.failed = false; session.suspended = true;
    CHECK(!wlan_injection_wonder_rx_begin(&psoc, 7, live.generation, 5180, &lease));
    session.suspended = false; peer_ready = false;
    CHECK(!wlan_injection_wonder_rx_begin(&psoc, 7, live.generation, 5180, &lease));
    peer_ready = true; live.generation++;
    CHECK(!wlan_injection_wonder_rx_begin(&psoc, 7, coex->owner.generation, 5180, &lease));
    CHECK(!rcu_depth); live.generation--; dispose(coex);
}
static void expiry_deadline_underflow_and_new_scan(void)
{
    struct hdd_wonder_coex *coex = fresh(); acquire(coex, 5745);
    u64 old_deadline = coex->dwell.deadline_ns;
    route_event(SCAN_EVENT_TYPE_COMPLETED, 0);
    now_ns += 3 * NSEC_PER_MSEC; acquire(coex, 5745);
    CHECK(coex->dwell.deadline_ns > old_deadline);
    now_ns = old_deadline; hdd_wonder_coex_expiry(&coex->expiry.work);
    CHECK(coex->dwell.phase == HDD_WONDER_DWELL_READY && !cancels);
    now_ns = coex->dwell.deadline_ns; hdd_wonder_coex_expiry(&coex->expiry.work);
    CHECK(coex->dwell.phase == HDD_WONDER_DWELL_CANCEL_PENDING && cancels == 1);
    CHECK(last_cancel.cancel_req.scan_id == coex->dwell.scan.scan_id);
    CHECK(coex->scan_ref && !hdd_wonder_coex_ready(coex, 5745));
    dispose(coex);
}
static void delayed_submission_does_not_wrap_expiry(void)
{
    struct hdd_wonder_coex *coex = fresh(); u64 completion = 0;
    CHECK(hdd_wonder_coex_acquire(coex, 5745, now_ns - 1, 20 * NSEC_PER_MSEC,
                                  &completion) == -EINVAL);
    CHECK(!vdev_refs && !coex->scan_ref);
    mode = SUBMIT_DELAYED;
    CHECK(hdd_wonder_coex_acquire(coex, 5745, now_ns + 40 * NSEC_PER_MSEC,
                                  20 * NSEC_PER_MSEC, &completion) == -EAGAIN);
    CHECK(coex->expiry.delay == 1 && coex->scan_ref && !completion);
    CHECK(coex->dwell.phase == HDD_WONDER_DWELL_CANCEL_PENDING && cancels == 1);
    dispose(coex);
}
static void context_retained_through_synthetic_cancel(void)
{
    struct hdd_wonder_coex *coex = fresh(); acquire(coex, 5745);
    struct scan_event synthetic = { .type = SCAN_EVENT_TYPE_COMPLETED };
    hdd_wonder_coex_scm_event(&vdev, &synthetic, NULL);
    CHECK(coex->scan_ref && coex->ref.count == 2 && !pending_free);
    hdd_wonder_active = NULL; hdd_wonder_coex_destroy(coex);
    CHECK(coex->detached && coex->scan_ref && coex->ref.count == 1);
    CHECK(module_refs == 1 && psoc_refs == 1 && !pending_free);
    hdd_wonder_coex_scm_event(&vdev, &synthetic, NULL);
    CHECK(coex->scan_ref && coex->ref.count == 1 && !pending_free);
    route_event(SCAN_EVENT_TYPE_COMPLETED, 0); CHECK(pending_free); drain_free();
}
static void queued_token_retains_detached_context(void)
{
    struct hdd_wonder_coex *coex = fresh(); acquire(coex, 5745);
    void *token = hdd_wonder_coex_tx_token(coex, 5745);
    CHECK(!IS_ERR(token) && coex->ref.count == 3);
    hdd_wonder_active = NULL; hdd_wonder_coex_destroy(coex);
    CHECK(coex->ref.count == 2 && coex->scan_ref && !pending_free);
    unsigned long flags;
    CHECK(!hdd_wonder_coex_tx_begin(token, &flags));
    route_event(SCAN_EVENT_TYPE_COMPLETED, 0);
    CHECK(coex->ref.count == 1 && !coex->scan_ref && !pending_free);
    CHECK(module_refs == 1 && psoc_refs == 1);
    hdd_wonder_coex_tx_release(token); CHECK(pending_free); drain_free();
}
static void contradictory_notice_revokes_packet_lease(void)
{
    struct hdd_wonder_coex *coex = fresh(); acquire(coex, 5745);
    struct scan_event stale = { .vdev_id = reservation.vdev_id,
        .requester = reservation.requester, .scan_id = reservation.scan_id + 1,
        .type = SCAN_EVENT_TYPE_FOREIGN_CHANNEL, .chan_freq = 5746 };
    CHECK(!pthread_mutex_lock(&admission));
    hdd_wonder_coex_notice(coex, &stale, WLAN_STA_MON_SCAN_FIRMWARE,
                           reservation.generation, reservation.helper_cookie);
    CHECK(!pthread_mutex_unlock(&admission));
    CHECK(hdd_wonder_coex_ready(coex, 5745));
    route_event(SCAN_EVENT_TYPE_FOREIGN_CHANNEL, 5746);
    CHECK(coex->dwell.revoked && coex->scan_ref && coex->ref.count == 2);
    struct cdp_wonder_rx_lease lease = {0};
    CHECK(!wlan_injection_wonder_rx_begin(&psoc, 7, live.generation, 5745, &lease));
    CHECK(!rcu_depth); dispose(coex);
}
static void submission_failure_balances_context(void)
{
    struct hdd_wonder_coex *coex = fresh(); u64 completion = 0;
    mode = SUBMIT_FAIL;
    CHECK(hdd_wonder_coex_acquire(coex, 5745, now_ns + 40 * NSEC_PER_MSEC,
          20 * NSEC_PER_MSEC, &completion) == -EBUSY);
    CHECK(!reserved && !coex->scan_ref && coex->ref.count == 1);
    CHECK(coex->dwell.phase == HDD_WONDER_DWELL_IDLE && !vdev_refs);
    mode = SUBMIT_TRUSTED_FAIL;
    CHECK(hdd_wonder_coex_acquire(coex, 5745, now_ns + 40 * NSEC_PER_MSEC,
          20 * NSEC_PER_MSEC, &completion) == -EBUSY);
    CHECK(!reserved && !coex->scan_ref && coex->ref.count == 1);
    CHECK(coex->dwell.phase == HDD_WONDER_DWELL_IDLE && !vdev_refs);
    dispose(coex);
}
static atomic_bool exit_started;
static void *exit_thread(void *arg)
{
    (void)arg; atomic_store(&exit_started, true);
    route_event(SCAN_EVENT_TYPE_FOREIGN_CHANNEL_EXIT, reservation.frequency);
    return NULL;
}
static void publication_serializes_exit(void)
{
    struct hdd_wonder_coex *coex = fresh(); acquire(coex, 5745);
    struct cdp_wonder_rx_lease lease = {0};
    CHECK(wlan_injection_wonder_rx_begin(&psoc, 7, live.generation, 5745, &lease));
    CHECK(lease.coex == coex && rcu_depth == 1);
    CHECK(hdd_wonder_netdev_transport_ready(&netdev));
    CHECK(rcu_depth == 1); /* The RX callback must not reenter admission/dwell. */
    CHECK(pthread_mutex_trylock(&admission) == EBUSY);
    CHECK(pthread_mutex_trylock(&coex->lock.mutex) == EBUSY);
    pthread_t thread; atomic_store(&exit_started, false);
    CHECK(!pthread_create(&thread, NULL, exit_thread, NULL));
    while (!atomic_load(&exit_started)) sched_yield();
    CHECK(coex->dwell.phase == HDD_WONDER_DWELL_READY);
    /* The DP fixture separately proves osif_rx_mon executes inside this lease. */
    wlan_injection_wonder_rx_end(&lease);
    CHECK(!pthread_join(thread, NULL));
    CHECK(!rcu_depth && coex->dwell.revoked);
    CHECK(!wlan_injection_wonder_rx_begin(&psoc, 7, live.generation, 5745, &lease));
    dispose(coex);
}

int main(void)
{
    TEST(create_and_scan_parameters);
    TEST(probe_preflight_preserves_home_and_reservation);
    TEST(old_queued_tuple_same_frequency_denied);
    TEST(home_and_unknown_packets_blocked_until_terminal);
    TEST(generic_shared_home_only);
    TEST(expiry_deadline_underflow_and_new_scan);
    TEST(delayed_submission_does_not_wrap_expiry);
    TEST(context_retained_through_synthetic_cancel);
    TEST(queued_token_retains_detached_context);
    TEST(contradictory_notice_revokes_packet_lease);
    TEST(submission_failure_balances_context);
    TEST(publication_serializes_exit);
    printf("{\"assertions\":%u,\"cases\":%u}\n", atomic_load(&assertions), cases);
    return 0;
}
