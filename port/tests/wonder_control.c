/* Production control/PM callbacks with host clock and provider witnesses.
 * These mocks exercise software contracts, not RF or firmware behavior.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t s32;
typedef int64_t s64;
typedef int spinlock_t;
#define ETH_ALEN 6
#define NSEC_PER_USEC 1000ULL
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define smp_store_release(p, v) (*(p) = (v))
struct mutex { bool held; };
static void mutex_lock(struct mutex *lock) { assert(!lock->held); lock->held = true; }
static void mutex_unlock(struct mutex *lock) { assert(lock->held); lock->held = false; }
#define lockdep_assert_held(lock) assert((lock)->held)
#define spin_lock_irqsave(lock, flags) do { assert(!*(lock)); *(lock) = 1; (flags) = 0; } while (0)
#define spin_unlock_irqrestore(lock, flags) do { assert(*(lock)); *(lock) = 0; (void)(flags); } while (0)
#define pr_warn(...) ((void)0)
#define pr_err(...) ((void)0)
#define pr_debug(...) ((void)0)
#define GFP_KERNEL 0
#define kfree(ptr) free(ptr)
static bool allocation_fail;
static void *kmemdup(const void *source, size_t size, int flags)
{
    (void)flags;
    if (allocation_fail) return NULL;
    void *copy = malloc(size);
    if (copy) memcpy(copy, source, size);
    return copy;
}
static u64 boot_ns;
static u64 ktime_get_boottime_ns(void) { return boot_ns; }
static u64 div_u64(u64 value, u32 divisor) { return value / divisor; }
/* INSERT_TYPES */
struct wondertap_ops {
    int (*set_freq)(void *, const struct wondertap_set_freq_params *);
    int (*set_fixed_tx_rate)(void *, const struct wondertap_fixed_tx_rate_params *);
    int (*set_tx_rate_mask)(void *, const struct wondertap_tx_rate_mask_params *);
    int (*channel_schedule_request)(void *, const struct channel_schedule_request *);
    int (*get_mac_tsf)(void *, u32 *);
    int (*get_capabilities)(void *, struct wondertap_capability *);
};
struct wondertap_data {
    bool monitor_backend, monitor_pm_suspended, monitor_pm_resume_pending;
    enum wondertap_state state;
    struct mutex lock;
    spinlock_t tx_config_lock;
    void *vendor_handle;
    u32 cache_flags;
    struct wondertap_set_freq_params cached_freq;
    struct wondertap_fixed_tx_rate_params cached_tx_rate;
    struct wondertap_init_params init_params;
    struct channel_schedule_request cached_channel_schedule;
    u64 channel_schedule_accepted_boottime_ns;
    s32 channel_schedule_target_delta_us;
    bool channel_schedule_accepted;
    const struct wondertap_ops *wonder_ops;
    const struct wondertap_monitor_ops *monitor_ops;
};
struct wiphy { bool held; };
struct wireless_dev {
    bool registered;
    struct wiphy *wiphy;
    enum nl80211_iftype iftype;
    struct net_device *netdev;
};
enum { NETREG_REGISTERED = 1 };
struct net_device {
    struct wireless_dev *ieee80211_ptr;
    int reg_state;
    bool running;
    u8 dev_addr[ETH_ALEN];
};
struct ieee80211_vif {
    enum nl80211_iftype type;
    struct wireless_dev *wdev;
    u8 addr[ETH_ALEN];
    struct { u8 addr[ETH_ALEN]; } bss_conf;
};
struct ieee80211_hw { void *priv; struct wiphy *wiphy; };
struct wonder_data {
    struct wondertap_data *wondertap_data;
    struct ieee80211_hw *hw;
    struct net_device *pdev, *vdev;
    struct ieee80211_vif *vif;
    enum nl80211_iftype iftype;
    int tx_work;
};
#define lockdep_assert_wiphy(wiphy) assert((wiphy)->held)
#define VDEV_NAME "wonder0"
static int init_net;
static struct net_device *lookup_vdev;
static unsigned int references, drains, work_cancels;
static struct net_device *dev_get_by_name(void *net, const char *name)
{ assert(net == &init_net && !strcmp(name, VDEV_NAME)); if (lookup_vdev) references++; return lookup_vdev; }
static void dev_put(struct net_device *dev) { assert(dev && references); references--; }
static bool netif_running(struct net_device *dev) { return dev->running; }
static void cancel_delayed_work_sync(int *work) { (void)work; work_cancels++; }
static void synchronize_net(void) { drains++; }
static struct wireless_dev *ieee80211_vif_to_wdev(struct ieee80211_vif *vif) { return vif->wdev; }
static void eth_hw_addr_set(struct net_device *dev, void *address) { memcpy(dev->dev_addr, address, ETH_ALEN); }
#define ether_addr_copy(dest, source) memcpy((dest), (source), ETH_ALEN)
/* INSERT_FUNCTIONS */
static unsigned int calls, assertions, schedule_calls, tsf_calls, resume_calls, suspend_calls;
static int callback_result, schedule_result, tsf_result, resume_result, suspend_result;
static bool provider_suspended;
static u32 firmware_tsf;
static struct wondertap_capability provider_caps;
static struct channel_schedule_request last_schedule;
static struct wondertap_channel_list_params last_channels[255];
#define CHECK(expr) do { assert(expr); assertions++; } while (0)
static int fixed_rate(void *handle, const struct wondertap_fixed_tx_rate_params *params)
{ assert(handle && params); calls++; return callback_result; }
static int frequency(void *handle, const struct wondertap_set_freq_params *params)
{ assert(handle && params); calls++; return callback_result; }
static int capture_tsf(void *handle, u32 *tsf)
{
    assert(handle && tsf); tsf_calls++;
    if (tsf_result) return tsf_result;
    if (provider_suspended) return -EHOSTDOWN;
    *tsf = firmware_tsf; return 0;
}
static int capabilities(void *handle, struct wondertap_capability *caps)
{ assert(handle && caps); *caps = provider_caps; return 0; }
static int schedule(void *handle, const struct channel_schedule_request *request)
{
    assert(handle && request); schedule_calls++;
    if (schedule_result) return schedule_result;
    assert(!provider_suspended);
    last_schedule = *request;
    if (request->channel_list_len)
        memcpy(last_channels, request->channel_list, request->channel_list_len * sizeof(*last_channels));
    last_schedule.channel_list = last_channels;
    return 0;
}
static int suspend_provider(void *handle)
{
    struct wondertap_data *tap = handle;
    assert(tap->lock.held && tap->monitor_pm_suspended); suspend_calls++;
    if (!suspend_result) provider_suspended = true;
    return suspend_result;
}
static int resume_provider(void *handle)
{
    struct wondertap_data *tap = handle;
    assert(tap->lock.held && tap->monitor_pm_suspended); resume_calls++;
    if (!resume_result) provider_suspended = false;
    return resume_result;
}
static const struct wondertap_ops ops = {
    .set_freq = frequency, .set_fixed_tx_rate = fixed_rate,
    .channel_schedule_request = schedule, .get_mac_tsf = capture_tsf,
    .get_capabilities = capabilities,
};
static const struct wondertap_monitor_ops pm_ops = {.suspend = suspend_provider, .resume = resume_provider};
static struct wiphy wiphy = {.held = true};
static struct wireless_dev wdev = {.registered = true, .wiphy = &wiphy, .iftype = NL80211_IFTYPE_ADHOC};
static struct net_device pdev = {.running = true, .reg_state = NETREG_REGISTERED, .dev_addr = {2, 1, 2, 3, 4, 5}};
static struct net_device vdev = {.running = true, .reg_state = NETREG_REGISTERED, .ieee80211_ptr = &wdev};
static struct ieee80211_vif vif = {.type = NL80211_IFTYPE_ADHOC, .wdev = &wdev};
static struct ieee80211_hw hw = {.wiphy = &wiphy};
static struct wondertap_data tap;
static struct wonder_data wonder;
static void reset(void)
{
    free(tap.cached_channel_schedule.channel_list);
    tap = (struct wondertap_data){.monitor_backend = true, .wonder_ops = &ops, .monitor_ops = &pm_ops,
                                 .state = WONDERTAP_STATE_UP, .init_params.channel_hopping_enable = true};
    tap.vendor_handle = &tap;
    wonder = (struct wonder_data){.wondertap_data = &tap, .hw = &hw, .pdev = &pdev,
                                .vdev = &vdev, .vif = &vif, .iftype = NL80211_IFTYPE_ADHOC};
    hw.priv = &wonder; wdev.netdev = &vdev; lookup_vdev = &vdev;
    calls = schedule_calls = tsf_calls = resume_calls = suspend_calls = drains = work_cancels = 0;
    callback_result = schedule_result = tsf_result = resume_result = suspend_result = 0;
    provider_suspended = allocation_fail = false;
    boot_ns = 1000000000ULL; firmware_tsf = 1000000;
    provider_caps = (struct wondertap_capability){.bits.channel_hopping = true,
                                                .maximum_channel_switch_time_us = 2000};
    vdev.reg_state = NETREG_REGISTERED; vdev.running = true; wdev.registered = true;
    last_schedule = (struct channel_schedule_request){0};
}
static struct channel_schedule_request accepted_schedule(void)
{
    struct wondertap_channel_list_params list[] = {
        {.freq = 2437, .bandwidth = WONDERTAP_RATE_BW_20, .role = WONDERTAP_ROLE_STA},
        {.freq = 5745, .bandwidth = WONDERTAP_RATE_BW_80, .role = WONDERTAP_ROLE_STA},
        {.freq = 0, .bandwidth = WONDERTAP_RATE_BW_20, .role = WONDERTAP_ROLE_NOP},
    };
    struct channel_schedule_request request = {.channel_list_len = 3, .channel_list = list,
        .next_channel_index = 2, .dwell_time_tu = 16, .target_switch_time_tsf = firmware_tsf + 9000};
    CHECK(wondertap_channel_schedule_request(&tap, &request) == 0);
    CHECK(tap.channel_schedule_accepted && tap.cached_channel_schedule.channel_list != list);
    CHECK(!memcmp(list, tap.cached_channel_schedule.channel_list, sizeof(list)));
    return tap.cached_channel_schedule;
}
static void settings(void)
{
    reset(); tap.state = WONDERTAP_STATE_DOWN;
    struct wondertap_fixed_tx_rate_params rate = {.preamble = WONDERTAP_RATE_PREAMBLE_HT,
        .bw = WONDERTAP_RATE_BW_20, .nss = 1, .mcs = 7, .gi = WONDERTAP_RATE_GI_DEFAULT};
    struct wondertap_set_freq_params channel = {.freq = 5745, .bandwidth = WONDERTAP_RATE_BW_20};
    CHECK(wondertap_set_fixed_tx_rate(&tap, &rate) == 0 && calls == 0);
    CHECK(!memcmp(&tap.cached_tx_rate, &rate, sizeof(rate)));
    CHECK(wondertap_set_freq(&tap, &channel) == 0 && calls == 0);
    tap.state = WONDERTAP_STATE_UP;
    callback_result = -EBUSY; rate.mcs = 6; channel.freq = 2437;
    CHECK(wondertap_set_fixed_tx_rate(&tap, &rate) == -EBUSY);
    CHECK(tap.cached_tx_rate.mcs == 7 && calls == 1);
    struct channel_schedule_request saved = accepted_schedule();
    CHECK(wondertap_set_freq(&tap, &channel) == -EBUSY);
    CHECK(tap.cached_freq.freq == 5745 && calls == 2);
    CHECK(tap.cached_channel_schedule.channel_list == saved.channel_list && tap.channel_schedule_accepted);
    CHECK(!tap.lock.held && !tap.tx_config_lock);
    callback_result = 0;
    CHECK(wondertap_set_fixed_tx_rate(&tap, &rate) == 0);
    CHECK(tap.cached_tx_rate.mcs == 6 && calls == 3);
    CHECK(wondertap_set_freq(&tap, &channel) == 0);
    CHECK(tap.cached_freq.freq == 2437 && calls == 4);
    CHECK(!tap.cached_channel_schedule.channel_list && !tap.channel_schedule_accepted);
    rate.nss = 2;
    CHECK(wondertap_set_fixed_tx_rate(&tap, &rate) == 0 && calls == 5);
    CHECK(tap.cached_tx_rate.nss == 2);
    rate.nss = 3;
    CHECK(wondertap_set_fixed_tx_rate(&tap, &rate) == -EOPNOTSUPP && calls == 5);
    CHECK(tap.cached_tx_rate.nss == 2);
    tap.state = WONDERTAP_STATE_DOWN;
    struct wondertap_tx_rate_mask_params mask = {0};
    CHECK(wondertap_set_tx_rate_mask(&tap, &mask) == -EOPNOTSUPP);
    CHECK(tap.cached_tx_rate.mcs == 6 && tap.cached_tx_rate.nss == 2);
}
static void pm_preserves_phase(void)
{
    reset(); struct channel_schedule_request saved = accepted_schedule();
    CHECK(wonder_monitor_pm_suspend(&wonder, true) == 0);
    CHECK(provider_suspended && tap.monitor_pm_suspended && suspend_calls == 1);
    boot_ns += 700000000ULL; firmware_tsf += 700000;
    wonder.vif = NULL;
    CHECK(wonder_monitor_pm_resume(&wonder, true) == 0);
    CHECK(!provider_suspended && tap.monitor_pm_suspended && tap.monitor_pm_resume_pending);
    CHECK(last_schedule.target_switch_time_tsf == saved.target_switch_time_tsf);
    CHECK(last_schedule.dwell_time_tu == saved.dwell_time_tu && last_schedule.next_channel_index == 2);
    CHECK(last_schedule.channel_list_len == 3 && !memcmp(last_channels, saved.channel_list, 3 * sizeof(*last_channels)));
    CHECK(tap.cached_channel_schedule.channel_list == saved.channel_list);
    CHECK(wonder_add_interface(&hw, &vif) == 0);
    CHECK(wonder.vif == &vif && !tap.monitor_pm_suspended && !tap.monitor_pm_resume_pending);
    wonder_remove_interface(&hw, &vif);
    CHECK(!wonder.vif && tap.monitor_pm_suspended && tap.monitor_pm_resume_pending);
    CHECK(wonder_monitor_pm_suspend(&wonder, false) == 0 && provider_suspended && suspend_calls == 2);
    CHECK(!tap.monitor_pm_resume_pending && drains >= 3 && work_cancels == 2);
}
static void failure_retains_cache(void)
{
    for (unsigned int mode = 0; mode < 5; mode++) {
        reset(); struct channel_schedule_request saved = accepted_schedule();
        CHECK(wonder_monitor_pm_suspend(&wonder, true) == 0);
        if (mode == 0) resume_result = -ENETDOWN;
        if (mode == 1) schedule_result = -EIO;
        if (mode == 2) tsf_result = -ENODATA;
        if (mode == 3) { boot_ns += ((u64)INT_MAX + 1) * NSEC_PER_USEC; firmware_tsf += 1000; }
        if (mode == 4) firmware_tsf -= 100000; /* Reject a backwards/ambiguous real sample. */
        int expected = mode == 0 ? -ENETDOWN : mode == 1 ? -EIO : mode == 2 ? -ENODATA : -ESTALE;
        CHECK(wonder_monitor_pm_resume(&wonder, false) == expected);
        CHECK(provider_suspended && tap.monitor_pm_suspended && !tap.monitor_pm_resume_pending);
        CHECK(tap.cached_channel_schedule.channel_list == saved.channel_list && tap.channel_schedule_accepted);
        CHECK(tap.cached_channel_schedule.target_switch_time_tsf == saved.target_switch_time_tsf);
        CHECK(suspend_calls == (mode == 0 ? 1U : 2U));
        CHECK(schedule_calls == (mode == 1 ? 2U : 1U));
    }
}
static void cancellation_and_unaccepted(void)
{
    reset(); struct channel_schedule_request saved = accepted_schedule();
    tsf_result = -ENODATA;
    struct channel_schedule_request cancel = {0};
    unsigned int captures = tsf_calls;
    schedule_result = -EBUSY;
    CHECK(wondertap_channel_schedule_request(&tap, &cancel) == -EBUSY);
    CHECK(tap.cached_channel_schedule.channel_list == saved.channel_list && tap.channel_schedule_accepted);
    schedule_result = 0;
    CHECK(wondertap_channel_schedule_request(&tap, &cancel) == 0);
    CHECK(tsf_calls == captures && !tap.cached_channel_schedule.channel_list && !tap.channel_schedule_accepted);
    CHECK(wonder_monitor_pm_suspend(&wonder, true) == 0);
    CHECK(wonder_monitor_pm_resume(&wonder, false) == 0);
    CHECK(!tap.monitor_pm_suspended && tsf_calls == captures && last_schedule.channel_list_len == 0);
    reset();
    struct wondertap_channel_list_params entry = {.freq = 2437, .role = WONDERTAP_ROLE_STA};
    struct channel_schedule_request request = {.channel_list_len = 1, .channel_list = &entry,
        .next_channel_index = 0, .dwell_time_tu = 4, .target_switch_time_tsf = 123};
    tsf_result = -ENODATA;
    CHECK(wondertap_channel_schedule_request(&tap, &request) == -ENODATA && schedule_calls == 0);
    CHECK(!tap.cached_channel_schedule.channel_list);
    tsf_result = 0; allocation_fail = true;
    CHECK(wondertap_channel_schedule_request(&tap, &request) == -ENOMEM && schedule_calls == 0);
    allocation_fail = false; tap.state = WONDERTAP_STATE_DOWN;
    CHECK(wondertap_channel_schedule_request(&tap, &request) == 0 && schedule_calls == 0);
    CHECK(!tap.channel_schedule_accepted);
    tap.state = WONDERTAP_STATE_UP;
    provider_caps.bits.channel_hopping = false;
    mutex_lock(&tap.lock);
    CHECK(wondertap_replay_channel_schedule_locked(&tap, true) == -EOPNOTSUPP);
    mutex_unlock(&tap.lock);
    CHECK(!tap.channel_schedule_accepted && schedule_calls == 0);
    provider_caps.bits.channel_hopping = true;
    mutex_lock(&tap.lock);
    CHECK(wondertap_replay_channel_schedule_locked(&tap, true) == 0);
    mutex_unlock(&tap.lock);
    CHECK(tap.channel_schedule_accepted && last_schedule.target_switch_time_tsf == firmware_tsf + 2000);
}
static void replacement_and_suspend_failure(void)
{
    reset(); struct channel_schedule_request saved = accepted_schedule();
    u64 accepted_time = tap.channel_schedule_accepted_boottime_ns;
    struct wondertap_channel_list_params replacement = {.freq = 5180, .role = WONDERTAP_ROLE_STA};
    struct channel_schedule_request request = {.channel_list_len = 1, .channel_list = &replacement,
        .next_channel_index = 0, .dwell_time_tu = 8, .target_switch_time_tsf = firmware_tsf + 1000};
    schedule_result = -EBUSY; boot_ns += 5000000;
    CHECK(wondertap_channel_schedule_request(&tap, &request) == -EBUSY);
    CHECK(tap.cached_channel_schedule.channel_list == saved.channel_list &&
          tap.cached_channel_schedule.dwell_time_tu == saved.dwell_time_tu);
    CHECK(tap.cached_channel_schedule.target_switch_time_tsf == saved.target_switch_time_tsf &&
          tap.channel_schedule_accepted_boottime_ns == accepted_time);
    suspend_result = -EIO;
    CHECK(wonder_monitor_pm_suspend(&wonder, true) == -EIO);
    CHECK(!provider_suspended && !tap.monitor_pm_suspended && !tap.monitor_pm_resume_pending);
    CHECK(work_cancels == 0 && drains == 0);
    suspend_result = 0; schedule_result = 0;
    CHECK(wonder_monitor_pm_suspend(&wonder, true) == 0);
    /* Invalidated virtual state must fail before making the provider live. */
    wonder.vdev = NULL; vdev.reg_state = 0;
    CHECK(wonder_monitor_pm_resume(&wonder, true) == -ENODEV);
    CHECK(provider_suspended && tap.monitor_pm_suspended && resume_calls == 0);
    CHECK(!references && tap.cached_channel_schedule.channel_list == saved.channel_list);
}
int main(void)
{
    settings(); pm_preserves_phase(); failure_retains_cache(); cancellation_and_unaccepted();
    replacement_and_suspend_failure();
    reset(); free(tap.cached_channel_schedule.channel_list);
    CHECK(!references && !tap.lock.held && !tap.tx_config_lock);
    printf("%u\n", assertions);
    return 0;
}
