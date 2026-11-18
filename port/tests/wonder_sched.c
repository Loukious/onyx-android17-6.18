/* SPDX-License-Identifier: GPL-2.0-only */
/* Production source executes against bounded paired FW captures. These shims
 * do not emulate concurrent workqueue, RTNL or firmware scheduling behavior.
 */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t s32;
typedef int64_t s64;
#define FEATURE_WLAN_WONDER
#define WLAN_FEATURE_TSF_TIMER_SYNC
#define U8_MAX UINT8_MAX
#define NSEC_PER_USEC 1000ULL
#define NSEC_PER_SEC 1000000000ULL
#define HRTIMER_MODE_ABS 0
#define WQ_HIGHPRI 1
#define WQ_MEM_RECLAIM 2
#define GFP_KERNEL 0
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p) > (uintptr_t)-4096)
#define container_of(p, type, member) ((type *)((char *)(p) - offsetof(type, member)))

struct mutex { bool held; };
typedef int spinlock_t;
struct completion { bool done; };
struct kref { unsigned int count; };
struct work_struct { void (*fn)(struct work_struct *); bool queued; };
struct delayed_work { struct work_struct work; bool queued; };
struct workqueue_struct { int unused; };
enum hrtimer_restart { HRTIMER_NORESTART };
struct hrtimer { u64 deadline; bool armed; };
struct osif_vdev_sync { int unused; };
struct hdd_link { u8 vdev_id; };
struct hdd_adapter { struct hdd_link *deflink; void *dev; };

static u64 host_ns, qtimer_us;
static u64 ktime_get_ns(void) { return host_ns; }
static u64 qdf_get_log_timestamp_usecs(void) { return qtimer_us; }
static s64 div_s64(s64 n, s64 d) { return n / d; }
static u64 div64_u64(u64 n, u64 d) { return n / d; }
static u64 ns_to_ktime(u64 ns) { return ns; }
static unsigned long msecs_to_jiffies(unsigned long ms) { return ms; }
#define DEFINE_MUTEX(n) struct mutex n
#define DEFINE_SPINLOCK(n) spinlock_t n
#define DECLARE_COMPLETION(n) struct completion n
static void mutex_init(struct mutex *lock) { lock->held = false; }
static void mutex_lock(struct mutex *lock) { assert(!lock->held); lock->held = true; }
static void mutex_unlock(struct mutex *lock) { assert(lock->held); lock->held = false; }
#define spin_lock_init(p) (*(p) = 0)
#define spin_lock_irqsave(p, flags) do { (void)(p); (flags) = 0; } while (0)
#define spin_unlock_irqrestore(p, flags) do { (void)(p); (void)(flags); } while (0)
static void reinit_completion(struct completion *c) { c->done = false; }
static void complete(struct completion *c) { c->done = true; }
static unsigned long wait_for_completion_timeout(struct completion *, unsigned long);
static void kref_init(struct kref *ref) { ref->count = 1; }
static void kref_get(struct kref *ref) { assert(ref->count); ref->count++; }
static void kref_put(struct kref *ref, void (*release)(struct kref *))
{ assert(ref->count); if (!--ref->count) release(ref); }
static void *kzalloc(size_t bytes, int flags) { (void)flags; return calloc(1, bytes); }
static void kfree(void *p) { free(p); }
#define INIT_WORK(w, callback) do { (w)->fn = (callback); (w)->queued = false; } while (0)
#define INIT_DELAYED_WORK(w, callback) INIT_WORK(&(w)->work, callback)
#define to_delayed_work(w) container_of(w, struct delayed_work, work)
static void hrtimer_setup(struct hrtimer *timer,
                         enum hrtimer_restart (*callback)(struct hrtimer *),
                         int clock_id, int mode)
{ (void)callback; (void)clock_id; (void)mode; memset(timer, 0, sizeof(*timer)); }
static void hrtimer_start(struct hrtimer *timer, u64 at, int mode)
{ (void)mode; timer->deadline = at; timer->armed = true; }
static void hrtimer_cancel(struct hrtimer *timer) { timer->armed = false; }
static struct workqueue_struct *alloc_ordered_workqueue(const char *name, int flags)
{ (void)name; (void)flags; return calloc(1, sizeof(struct workqueue_struct)); }
static void destroy_workqueue(struct workqueue_struct *q) { free(q); }
static void queue_work(struct workqueue_struct *q, struct work_struct *w)
{ (void)q; w->queued = true; }
static void queue_delayed_work(struct workqueue_struct *q, struct delayed_work *w,
                               unsigned long delay)
{ (void)q; (void)delay; w->queued = true; }
static void mod_delayed_work(struct workqueue_struct *q, struct delayed_work *w,
                             unsigned long delay) { queue_delayed_work(q, w, delay); }
static void cancel_delayed_work(struct delayed_work *w) { w->queued = false; }
static void cancel_delayed_work_sync(struct delayed_work *w) { w->queued = false; }
static void cancel_work_sync(struct work_struct *w) { w->queued = false; }
static unsigned int op_starts, op_stops;
static int osif_vdev_sync_op_start(void *dev, struct osif_vdev_sync **sync)
{ static struct osif_vdev_sync operation; (void)dev; *sync = &operation; op_starts++; return 0; }
static void osif_vdev_sync_op_stop(struct osif_vdev_sync *sync)
{ (void)sync; op_stops++; }

/* INSERT_TYPES */

struct mock_wma { unsigned int max_bssid; };
typedef struct mock_wma *tp_wma_handle;
typedef int QDF_STATUS;
#define QDF_MODULE_ID_WMA 1
#define QDF_IS_STATUS_ERROR(status) ((status) != 0)
static int qdf_status_to_os_return(int status) { return status; }
static void *cds_get_context(int module)
{ static struct mock_wma wma = {16}; (void)module; return &wma; }
static u8 live_monitor, live_helper, commanded_helper;
static u64 live_cookie;
static unsigned int capture_count;
static int command_error;
static bool deliver_reply;
static struct stsf reply;
static void (*capture_hook)(void);
static bool wma_wonder_helper_identity_valid(u8 monitor, u8 helper, u64 cookie)
{ return monitor == live_monitor && helper == live_helper && cookie == live_cookie && cookie; }
static QDF_STATUS wma_capture_tsf(tp_wma_handle wma, u32 id)
{ (void)wma; commanded_helper = id; capture_count++; return command_error; }

/* INSERT_WMA */

static unsigned long wait_for_completion_timeout(struct completion *c, unsigned long timeout)
{
    (void)timeout;
    if (capture_hook) capture_hook();
    if (deliver_reply) wma_wonder_tsf_event(&reply);
    return c->done ? 1 : 0;
}

/* INSERT_SCHED */

static unsigned int assertions, failures;
static bool current_failed;
#define EXPECT(expr) do { assertions++; if (!(expr)) { current_failed = true; \
    fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #expr); } } while (0)
static struct hdd_wonder_sched *hook_sched;
static struct hdd_link link = {3};
static struct hdd_adapter adapter = {&link, &adapter};
static int switch_mode;
static bool switch_shared;
static int switch_error;
static u64 switch_latency_us;
static unsigned int switch_calls;
static u64 requested_end_ns, requested_duration_ns;
static struct wondertap_set_freq_params switched_channel;

static void firmware(u64 tsf, u64 qtime, u32 mac, u32 tsf_id)
{
    reply = (struct stsf){.vdev_id = live_helper, .tsf_low = (u32)tsf,
        .tsf_high = tsf >> 32, .soc_timer_low = (u32)qtime,
        .soc_timer_high = qtime >> 32, .mac_id = mac,
        .tsf_id = tsf_id, .tsf_id_valid = 1};
}

static void advance(u64 host_us, u64 timer_us, u64 tsf_us)
{
    u64 old_tsf = ((u64)reply.tsf_high << 32) | reply.tsf_low;
    host_ns += host_us * NSEC_PER_USEC;
    qtimer_us += timer_us;
    firmware(old_tsf + tsf_us, qtimer_us, reply.mac_id, reply.tsf_id);
}

static int validate_channel(void *context, const struct wondertap_set_freq_params *channel)
{ (void)context; return channel->freq == 2412 || channel->freq == 2437 ? 0 : -EINVAL; }
static int set_channel(void *context, const struct wondertap_set_freq_params *channel,
                       u64 generation, u64 slot_end_host_ns, u64 duration_ns,
                       u64 *completed)
{
    struct hdd_wonder_sched *sched = context;
    if (!hdd_wonder_sched_generation_active(sched, generation)) return -ESTALE;
    switched_channel = *channel;
    switch_calls++;
    requested_end_ns = slot_end_host_ns;
    requested_duration_ns = duration_ns;
    advance(switch_latency_us, switch_latency_us,
            switch_shared || switch_error || switch_mode ? switch_latency_us : 1500);
    if (switch_error) return switch_error;
    if (switch_mode) reply.mac_id = 1;
    *completed = host_ns;
    if (switch_shared) return 0;
    hdd_wonder_sched_unbind_tsf(sched);
    return hdd_wonder_sched_bind_tsf(sched, live_helper, live_cookie);
}
static const struct hdd_wonder_sched_ops ops = {set_channel, validate_channel};

static struct hdd_wonder_sched *new_sched(bool bind)
{
    wma_wonder_tsf_reset();
    host_ns = 10 * NSEC_PER_SEC; qtimer_us = 10000000;
    live_monitor = 3; live_helper = 9; live_cookie = 11;
    command_error = 0; deliver_reply = true; capture_hook = NULL;
    capture_count = 0; op_starts = op_stops = 0; switch_mode = 0;
    switch_shared = false; switch_error = 0; switch_latency_us = 100;
    switch_calls = 0; requested_end_ns = requested_duration_ns = 0;
    memset(&switched_channel, 0, sizeof(switched_channel));
    firmware(1000000, qtimer_us, 0, 0);
    struct hdd_wonder_sched *sched = hdd_wonder_sched_create(&adapter, NULL, &ops);
    assert(sched && !IS_ERR(sched)); sched->context = sched;
    if (bind) EXPECT(hdd_wonder_sched_bind_tsf(sched, live_helper, live_cookie) == 0);
    return sched;
}

static void request_plan(struct hdd_wonder_sched *sched)
{
    struct wondertap_channel_list_params channels[] = {{2412, WONDERTAP_RATE_BW_20, WONDERTAP_ROLE_STA}};
    u32 tsf = 0;
    EXPECT(hdd_wonder_sched_get_tsf(sched, &tsf) == 0);
    struct channel_schedule_request request = {.channel_list_len = 1,
        .next_channel_index = 0, .dwell_time_tu = 20,
        .target_switch_time_tsf = tsf, .channel_list = channels};
    EXPECT(hdd_wonder_sched_request(sched, &request) == 0);
}
static void cookie_changed(void) { live_cookie++; }
static void unbound(void) { hdd_wonder_sched_unbind_tsf(hook_sched); }

static void helper_identity(void)
{
    struct hdd_wonder_sched *s = new_sched(false);
    EXPECT(hdd_wonder_sched_bind_tsf(s, 3, live_cookie) == -ESTALE);
    EXPECT(hdd_wonder_sched_bind_tsf(s, live_helper, 99) == -ESTALE);
    EXPECT(capture_count == 0);
    EXPECT(hdd_wonder_sched_bind_tsf(s, live_helper, live_cookie) == 0);
    EXPECT(commanded_helper == 9 && s->clock.vdev_id == 9 && s->clock.helper_cookie == 11);
    EXPECT(op_starts == 0 && op_stops == 0);
    hdd_wonder_sched_destroy(s);
}
static void helper_cookie_changes_during_capture(void)
{
    struct hdd_wonder_sched *s = new_sched(false);
    capture_hook = cookie_changed;
    EXPECT(hdd_wonder_sched_bind_tsf(s, live_helper, 11) == -ESTALE);
    EXPECT(!s->clock.valid);
    hdd_wonder_sched_destroy(s);
}
static void unbind_during_capture(void)
{
    struct hdd_wonder_sched *s = new_sched(false);
    hook_sched = s; capture_hook = unbound;
    EXPECT(hdd_wonder_sched_bind_tsf(s, live_helper, live_cookie) == -ESTALE);
    EXPECT(!s->clock.valid);
    hdd_wonder_sched_destroy(s);
}
static void continuous_helper_replacement(void)
{
    struct hdd_wonder_sched *s = new_sched(true); request_plan(s);
    u64 generation = s->generation;
    hdd_wonder_sched_unbind_tsf(s); live_cookie++; advance(1000, 1000, 1000);
    EXPECT(hdd_wonder_sched_bind_tsf(s, live_helper, live_cookie) == 0);
    EXPECT(hdd_wonder_sched_generation_active(s, generation));
    EXPECT(s->clock.helper_cookie == live_cookie);
    hdd_wonder_sched_destroy(s);
}
static void epoch_change(unsigned int kind, bool suspend)
{
    struct hdd_wonder_sched *s = new_sched(true); request_plan(s);
    u64 generation = s->generation;
    if (suspend) hdd_wonder_sched_suspend(s); else hdd_wonder_sched_unbind_tsf(s);
    advance(1000, 1000, kind == 2 ? 9000 : 1000);
    if (kind == 0) reply.mac_id = 1;
    if (kind == 1) reply.tsf_id = 1;
    if (kind == 3) firmware(100, qtimer_us, 0, 0);
    int ret = suspend ? hdd_wonder_sched_resume(s, live_helper, live_cookie) :
                        hdd_wonder_sched_bind_tsf(s, live_helper, live_cookie);
    EXPECT(ret == -ESTALE);
    EXPECT(!s->clock.valid && !hdd_wonder_sched_generation_active(s, generation));
    if (suspend) EXPECT(!s->running);
    hdd_wonder_sched_destroy(s);
}
static void active_lmac_changes(void) { epoch_change(0, false); }
static void active_tsf_register_changes(void) { epoch_change(1, false); }
static void active_tsf_jump(void) { epoch_change(2, false); }
static void suspend_counter_reset(void) { epoch_change(3, true); }
static void suspend_lmac_changes(void) { epoch_change(0, true); }
static void suspend_tsf_register_changes(void) { epoch_change(1, true); }
static void idle_manual_new_epoch(void)
{
    struct hdd_wonder_sched *s = new_sched(true);
    u64 generation = s->generation;
    hdd_wonder_sched_unbind_tsf(s); live_cookie++;
    firmware(200, qtimer_us, 1, 1);
    EXPECT(hdd_wonder_sched_bind_tsf(s, live_helper, live_cookie) == 0);
    EXPECT(s->clock.valid && s->clock.sample.tsf_us == 200 && s->generation > generation);
    hdd_wonder_sched_destroy(s);
}
static void suspend_qtimer_continuity(void)
{
    struct hdd_wonder_sched *s = new_sched(true); request_plan(s);
    u64 generation = s->generation;
    hdd_wonder_sched_suspend(s);
    advance(1000, 30000000, 30000000);
    EXPECT(hdd_wonder_sched_resume(s, live_helper, live_cookie) == 0);
    u32 tsf = 0;
    EXPECT(hdd_wonder_sched_get_tsf(s, &tsf) == 0 && tsf == 31000000);
    EXPECT(s->clock.sample_host_ns == host_ns);
    EXPECT(!hdd_wonder_sched_generation_active(s, generation));
    request_plan(s);
    EXPECT(hdd_wonder_sched_generation_active(s, s->generation));
    hdd_wonder_sched_destroy(s);
}
static void unavailable_clocks(void)
{
    struct hdd_wonder_sched *s = new_sched(false); u32 tsf = 0;
    EXPECT(hdd_wonder_sched_get_tsf(s, &tsf) == -ENODATA && capture_count == 0);
    EXPECT(hdd_wonder_sched_bind_tsf(s, live_helper, live_cookie) == 0);
    hdd_wonder_sched_unbind_tsf(s);
    EXPECT(hdd_wonder_sched_get_tsf(s, &tsf) == -ENODATA);
    EXPECT(hdd_wonder_sched_bind_tsf(s, live_helper, live_cookie) == 0);
    advance(11000000, 11000000, 11000000); deliver_reply = false;
    EXPECT(hdd_wonder_sched_get_tsf(s, &tsf) == -ETIMEDOUT);
    EXPECT(op_starts == 1 && op_stops == 1);
    hdd_wonder_sched_destroy(s);
}
static void unknown_or_old_capture(void)
{
    struct hdd_wonder_sched *s = new_sched(false);
    reply.tsf_id_valid = 0;
    EXPECT(hdd_wonder_sched_bind_tsf(s, live_helper, live_cookie) == -ENODATA);
    firmware(1000000, qtimer_us + 1, 0, 0);
    EXPECT(hdd_wonder_sched_bind_tsf(s, live_helper, live_cookie) == -ERANGE);
    firmware(1000000, qtimer_us - 1000001, 0, 0);
    EXPECT(hdd_wonder_sched_bind_tsf(s, live_helper, live_cookie) == -ERANGE);
    firmware(1000000, qtimer_us, 2, 0);
    EXPECT(hdd_wonder_sched_bind_tsf(s, live_helper, live_cookie) == -ENODATA);
    hdd_wonder_sched_destroy(s);
}
static void paired_capture_age(void)
{
    struct hdd_wonder_sched *s = new_sched(false);
    firmware(999750, qtimer_us - 250, 0, 0);
    EXPECT(hdd_wonder_sched_bind_tsf(s, live_helper, live_cookie) == 0);
    u32 tsf = 0;
    EXPECT(hdd_wonder_sched_get_tsf(s, &tsf) == 0 && tsf == 1000000);
    EXPECT(s->clock.sample_host_ns == host_ns - 250 * NSEC_PER_USEC);
    hdd_wonder_sched_destroy(s);
}
static void capture_timeout_quarantine(void)
{
    struct hdd_wonder_sched *s = new_sched(false); deliver_reply = false;
    EXPECT(hdd_wonder_sched_bind_tsf(s, live_helper, live_cookie) == -ETIMEDOUT);
    reply.mac_id_valid = 1;
    EXPECT(!wma_wonder_tsf_event(&reply));
    EXPECT(hdd_wonder_sched_bind_tsf(s, live_helper, live_cookie) == -EAGAIN);
    reply.mac_id_valid = 0;
    EXPECT(wma_wonder_tsf_event(&reply));
    deliver_reply = true;
    EXPECT(hdd_wonder_sched_bind_tsf(s, live_helper, live_cookie) == 0);
    hdd_wonder_sched_destroy(s);
}
static void fresh_clock_after_channel_completion(void)
{
    struct hdd_wonder_sched *s = new_sched(true); request_plan(s);
    hdd_wonder_sched_switch_work(&s->switch_work);
    struct hdd_wonder_slot *slot = &s->plan->slots[0];
    EXPECT(slot->start_tsf == 1001500 && slot->status.channel_start_tsf == 1001500);
    EXPECT(s->current_freq == 2412 && s->plan->slot_active);
    EXPECT(s->timer.deadline == host_ns + (20480 - 1500) * NSEC_PER_USEC);
    struct wondertap_channel_status_report *report = calloc(1, sizeof(*report) + sizeof(report->status[0]));
    assert(report); report->channel_status_len = 1;
    EXPECT(hdd_wonder_sched_get_report(s, report) == 0 && report->status[0].channel_start_tsf == 1001500);
    free(report); hdd_wonder_sched_destroy(s);
}
static void delayed_slot_bounds_duration(void)
{
    struct hdd_wonder_sched *s = new_sched(true); request_plan(s);
    advance(5000, 5000, 5000);
    switch_shared = true;
    hdd_wonder_sched_switch_work(&s->switch_work);
    EXPECT(requested_end_ns == 10 * NSEC_PER_SEC + 20480 * NSEC_PER_USEC);
    EXPECT(requested_duration_ns == 15480 * NSEC_PER_USEC);
    EXPECT(s->plan->slots[0].status.channel_switch_tsf == 1000000);
    hdd_wonder_sched_destroy(s);
}
static void slot_deadline_uses_paired_clock(void)
{
    struct hdd_wonder_sched *s = new_sched(true); request_plan(s);
    /* A proven 900us firmware/host offset changes the absolute slot end. */
    advance(100, 100, 1000);
    EXPECT(hdd_wonder_sched_bind_tsf(s, live_helper, live_cookie) == 0);
    switch_shared = true;
    hdd_wonder_sched_switch_work(&s->switch_work);
    EXPECT(requested_end_ns == 10 * NSEC_PER_SEC + 19580 * NSEC_PER_USEC);
    EXPECT(requested_duration_ns == 19480 * NSEC_PER_USEC);
    hdd_wonder_sched_destroy(s);
}
static void retries_keep_slot_bounds(void)
{
    struct hdd_wonder_sched *s = new_sched(true); request_plan(s);
    advance(5000, 5000, 5000); switch_error = -EAGAIN;
    for (unsigned int attempt = 0; attempt < 4; attempt++) {
        hdd_wonder_sched_switch_work(&s->switch_work);
        EXPECT(requested_end_ns == 10 * NSEC_PER_SEC + 20480 * NSEC_PER_USEC);
        EXPECT(requested_duration_ns == 15480 * NSEC_PER_USEC);
        EXPECT(s->plan->next_tsf == 1000000 && s->plan->next_index == 0);
        EXPECT(s->plan->switch_pending && !s->plan->slot_active);
        advance(1000, 1000, 1000);
    }
    EXPECT(switch_calls == 4 && capture_count == 1);
    switch_error = 0; switch_shared = true;
    hdd_wonder_sched_switch_work(&s->switch_work);
    EXPECT(requested_end_ns == 10 * NSEC_PER_SEC + 20480 * NSEC_PER_USEC);
    EXPECT(requested_duration_ns == 15480 * NSEC_PER_USEC);
    EXPECT(s->plan->slot_active && !s->plan->switch_pending);
    hdd_wonder_sched_destroy(s);
}
static void refresh_cannot_extend_pending_slot(void)
{
    struct hdd_wonder_sched *s = new_sched(true); request_plan(s);
    switch_error = -EBUSY;
    hdd_wonder_sched_switch_work(&s->switch_work);
    advance(1000, 1000, 100);
    EXPECT(hdd_wonder_sched_bind_tsf(s, live_helper, live_cookie) == 0);
    hdd_wonder_sched_switch_work(&s->switch_work);
    EXPECT(requested_end_ns == 10 * NSEC_PER_SEC + 20480 * NSEC_PER_USEC);
    EXPECT(requested_duration_ns == 20480 * NSEC_PER_USEC);
    EXPECT(switch_calls == 2 && s->plan->next_tsf == 1000000);
    hdd_wonder_sched_destroy(s);
}
static void expired_retry_does_not_acquire_new_dwell(void)
{
    struct hdd_wonder_sched *s = new_sched(true); request_plan(s);
    advance(19000, 19000, 19000); switch_error = -EAGAIN;
    hdd_wonder_sched_switch_work(&s->switch_work);
    advance(1000, 1000, 1000);
    hdd_wonder_sched_switch_work(&s->switch_work);
    EXPECT(s->timer.deadline == 10 * NSEC_PER_SEC + 20480 * NSEC_PER_USEC);
    advance(5000, 5000, 5000);
    hdd_wonder_sched_switch_work(&s->switch_work);
    EXPECT(switch_calls == 2 && s->plan->next_tsf == 1000000);
    EXPECT(s->last_error == -ETIMEDOUT && s->generation != s->plan->generation);
    EXPECT(!s->plan->slot_active);
    hdd_wonder_sched_destroy(s);
}
static void completion_after_slot_expiry(void)
{
    struct hdd_wonder_sched *s = new_sched(true); request_plan(s);
    switch_shared = true; switch_latency_us = 20480;
    hdd_wonder_sched_switch_work(&s->switch_work);
    EXPECT(s->last_error == -ETIMEDOUT && s->generation != s->plan->generation);
    EXPECT(!s->plan->slot_active && s->plan->slots[0].status.freq == 0);
    hdd_wonder_sched_destroy(s);
}
static void pending_deadline_survives_clock_loss(void)
{
    struct hdd_wonder_sched *s = new_sched(true); request_plan(s);
    switch_error = -EAGAIN;
    hdd_wonder_sched_switch_work(&s->switch_work);
    hdd_wonder_sched_unbind_tsf(s);
    advance(1000, 1000, 1000);
    hdd_wonder_sched_switch_work(&s->switch_work);
    EXPECT(s->timer.deadline == 10 * NSEC_PER_SEC + 20480 * NSEC_PER_USEC);
    advance(25000, 25000, 25000);
    hdd_wonder_sched_switch_work(&s->switch_work);
    EXPECT(switch_calls == 1 && s->last_error == -ETIMEDOUT);
    EXPECT(s->generation != s->plan->generation);
    hdd_wonder_sched_destroy(s);
}
static void shared_dwell_keeps_home_clock(void)
{
    struct hdd_wonder_sched *s = new_sched(true); request_plan(s);
    struct hdd_wonder_clock home = s->clock;
    u64 identity = s->identity_sequence;
    switch_shared = true;
    hdd_wonder_sched_switch_work(&s->switch_work);
    EXPECT(capture_count == 1 && s->identity_sequence == identity);
    EXPECT(s->tsf_bound && s->clock.valid && s->clock.vdev_id == home.vdev_id);
    EXPECT(s->clock.sample_host_ns == home.sample_host_ns &&
           s->clock.sample.tsf_us == home.sample.tsf_us &&
           s->clock.helper_cookie == home.helper_cookie);
    EXPECT(s->plan->slots[0].start_tsf == 1000100);
    EXPECT(s->timer.deadline == 10 * NSEC_PER_SEC + 20480 * NSEC_PER_USEC);
    hdd_wonder_sched_destroy(s);
}
static void nop_keeps_recorded_channel(void)
{
    struct hdd_wonder_sched *s = new_sched(true);
    struct wondertap_channel_list_params channel = {
        .freq = 0, .bandwidth = WONDERTAP_RATE_BW_20, .role = WONDERTAP_ROLE_NOP};
    struct channel_schedule_request request = {.channel_list_len = 1,
        .next_channel_index = 0, .dwell_time_tu = 20, .channel_list = &channel};
    hdd_wonder_sched_note_channel(s, 2412, WONDERTAP_RATE_BW_80, host_ns);
    EXPECT(hdd_wonder_sched_get_tsf(s, &request.target_switch_time_tsf) == 0);
    EXPECT(hdd_wonder_sched_request(s, &request) == 0);
    hdd_wonder_sched_switch_work(&s->switch_work);
    EXPECT(switched_channel.freq == 2412 && switched_channel.bandwidth == WONDERTAP_RATE_BW_80);

    /* Manual control cancels the plan, then publishes its complete channel. */
    struct channel_schedule_request cancel = {0};
    EXPECT(hdd_wonder_sched_request(s, &cancel) == 0);
    hdd_wonder_sched_note_channel(s, 2437, WONDERTAP_RATE_BW_40, host_ns);
    EXPECT(hdd_wonder_sched_get_tsf(s, &request.target_switch_time_tsf) == 0);
    EXPECT(hdd_wonder_sched_request(s, &request) == 0);
    hdd_wonder_sched_switch_work(&s->switch_work);
    EXPECT(switched_channel.freq == 2437 && switched_channel.bandwidth == WONDERTAP_RATE_BW_40);
    hdd_wonder_sched_destroy(s);
}
static void ppdu_lmac_and_generation(void)
{
    struct hdd_wonder_sched *s = new_sched(true); request_plan(s);
    hdd_wonder_sched_switch_work(&s->switch_work);
    u32 tsf = s->plan->slots[0].start_tsf;
    hdd_wonder_sched_note_airtime(s, 1, 2412, tsf, true, 100);
    EXPECT(s->plan->slots[0].tx_us == 0);
    hdd_wonder_sched_note_airtime(s, 0, 2412, tsf, true, 100);
    EXPECT(s->plan->slots[0].tx_us == 100);
    hdd_wonder_sched_unbind_tsf(s);
    hdd_wonder_sched_note_airtime(s, 0, 2412, tsf, true, 100);
    EXPECT(s->plan->slots[0].tx_us == 100);
    EXPECT(hdd_wonder_sched_bind_tsf(s, live_helper, live_cookie) == 0);
    hdd_wonder_sched_suspend(s); advance(1000, 1000, 1000);
    EXPECT(hdd_wonder_sched_resume(s, live_helper, live_cookie) == 0);
    hdd_wonder_sched_note_airtime(s, 0, 2412, tsf + 1000, true, 100);
    EXPECT(s->plan->slots[0].tx_us == 100);
    hdd_wonder_sched_destroy(s);
}
static void channel_counter_discontinuity(void)
{
    struct hdd_wonder_sched *s = new_sched(true); request_plan(s);
    switch_mode = 1;
    hdd_wonder_sched_switch_work(&s->switch_work);
    EXPECT(!s->plan->slot_active && s->plan->slots[0].status.freq == 0);
    EXPECT(s->last_error == -ESTALE && !s->timer.armed);
    hdd_wonder_sched_destroy(s);
}

int main(void)
{
    static const struct { const char *name; void (*run)(void); } cases[] = {
#define CASE(fn) {#fn, fn}
        CASE(helper_identity), CASE(helper_cookie_changes_during_capture), CASE(unbind_during_capture),
        CASE(continuous_helper_replacement), CASE(active_lmac_changes), CASE(active_tsf_register_changes),
        CASE(active_tsf_jump), CASE(suspend_counter_reset), CASE(suspend_lmac_changes),
        CASE(suspend_tsf_register_changes), CASE(idle_manual_new_epoch),
        CASE(suspend_qtimer_continuity), CASE(unavailable_clocks), CASE(unknown_or_old_capture),
        CASE(paired_capture_age), CASE(capture_timeout_quarantine), CASE(fresh_clock_after_channel_completion),
        CASE(delayed_slot_bounds_duration), CASE(slot_deadline_uses_paired_clock),
        CASE(retries_keep_slot_bounds), CASE(refresh_cannot_extend_pending_slot),
        CASE(expired_retry_does_not_acquire_new_dwell), CASE(completion_after_slot_expiry),
        CASE(pending_deadline_survives_clock_loss),
        CASE(shared_dwell_keeps_home_clock),
        CASE(nop_keeps_recorded_channel),
        CASE(ppdu_lmac_and_generation),
        CASE(channel_counter_discontinuity),
    };
    printf("{\"cases\":[");
    for (unsigned int i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        current_failed = false; cases[i].run(); failures += current_failed;
        printf("%s{\"name\":\"%s\",\"passed\":%s}", i ? "," : "", cases[i].name,
               current_failed ? "false" : "true");
    }
    printf("],\"assertions\":%u,\"failed\":%u}\n", assertions, failures);
    return failures ? 1 : 0;
}
