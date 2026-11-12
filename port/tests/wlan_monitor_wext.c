#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Kernel and driver control objects are deliberately small, strict stubs. */
typedef uint64_t u64;
typedef int64_t s64;
typedef uint32_t u32;
typedef int32_t s32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef unsigned int qdf_freq_t;
#define U32_MAX UINT32_MAX
#define U64_MAX UINT64_MAX
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define check_mul_overflow(a,b,out) __builtin_mul_overflow(a,b,out)
#define div_u64(a,b) ((a) / (b))
#define READ_ONCE(a) (a)
#define BIT(n) (1UL << (n))
#define IFF_UP 1
#define IW_FREQ_FIXED 1
#define hweight_long(a) __builtin_popcountl(a)
#define WLAN_OSIF_ID 1
#define QDF_IS_STATUS_SUCCESS(status) ((status) == 0)
#define qdf_mem_copy(dst,src,n) memcpy(dst,src,n)
#define DEVICE_IFACE_OPENED 0
#define NL80211_IFTYPE_STATION 2
#define NL80211_IFTYPE_MONITOR 6
#define QDF_STA_MODE 1
#define QDF_MONITOR_MODE 5
#define IEEE80211_CHAN_DISABLED BIT(0)
#define IEEE80211_CHAN_NO_IR BIT(1)
#define IEEE80211_CHAN_RADAR BIT(3)
#define WLAN_REG_IS_6GHZ_CH_FREQ(f) ((f) >= 5925 && (f) <= 7125)
#define WLAN_REG_IS_24GHZ_CH_FREQ(f) ((f) >= 2400 && (f) <= 2500)
#define WLAN_REG_IS_5GHZ_CH_FREQ(f) ((f) >= 4900 && (f) < 5925)
#define hdd_debug(...) ((void)0)
#define hdd_err(...) ((void)0)
#define hdd_err_rl(...) ((void)0)
#define hdd_enter() ((void)0)
#define hdd_exit() ((void)0)
#define hdd_enter_dev(a) ((void)0)
#define hdd_exit_dev(a) ((void)0)
enum nl80211_band { NL80211_BAND_2GHZ, NL80211_BAND_5GHZ, NL80211_BAND_6GHZ };
enum nl80211_chan_width { NL80211_CHAN_WIDTH_20_NOHT, NL80211_CHAN_WIDTH_20,
    NL80211_CHAN_WIDTH_40, NL80211_CHAN_WIDTH_80, NL80211_CHAN_WIDTH_80P80,
    NL80211_CHAN_WIDTH_160, NL80211_CHAN_WIDTH_320, NL80211_CHAN_WIDTH_5, NL80211_CHAN_WIDTH_10 };
enum phy_ch_width { CH_WIDTH_20MHZ, CH_WIDTH_40MHZ, CH_WIDTH_80MHZ,
    CH_WIDTH_160MHZ, CH_WIDTH_80P80MHZ, CH_WIDTH_5MHZ, CH_WIDTH_10MHZ };
enum nl80211_channel_type { NL80211_CHAN_NO_HT, NL80211_CHAN_HT20 };
struct iw_freq { int32_t m; int16_t e; uint8_t i; uint8_t flags; };
union iwreq_data { struct iw_freq freq; };
struct iw_request_info { int unused; };
struct ieee80211_channel { int center_freq; unsigned flags; enum nl80211_band band; };
struct cfg80211_chan_def { struct ieee80211_channel *chan; enum nl80211_chan_width width;
    int center_freq1, center_freq2; unsigned punctured; };
struct wiphy { unsigned held; };
struct wireless_dev { struct wiphy *wiphy; int iftype; unsigned valid_links; };
struct hdd_context { struct wiphy *wiphy; void *psoc; void *pdev; };
struct wlan_hdd_link_info { int unused; };
struct hdd_adapter { struct hdd_context *hdd_ctx; struct wlan_hdd_link_info *deflink;
    int device_mode; bool sta_mon_coexist, delete_in_progress, sta_mon_stop_failed;
    bool monitor_mode_vdev_up_in_progress; unsigned long event_flags, active_links; };
struct net_device { struct wireless_dev *ieee80211_ptr; struct hdd_adapter *adapter;
    bool running, present; unsigned flags; char name[16]; };
struct osif_psoc_sync { unsigned held; };
struct wlan_objmgr_vdev { bool active; unsigned refs; };
struct wlan_channel { unsigned ch_freq, ch_cfreq1, ch_cfreq2, ch_width,
    puncture_bitmap; };

static struct ieee80211_channel channels[] = {
    {2412,0,NL80211_BAND_2GHZ}, {2462,0,NL80211_BAND_2GHZ},
    {2472,0,NL80211_BAND_2GHZ}, {2484,0,NL80211_BAND_2GHZ},
    {5180,0,NL80211_BAND_5GHZ}, {5200,0,NL80211_BAND_5GHZ},
    {5260,0,NL80211_BAND_5GHZ}, {5500,0,NL80211_BAND_5GHZ},
    {5825,0,NL80211_BAND_5GHZ}, {5955,0,NL80211_BAND_6GHZ}
};
static struct wiphy phy;
static struct wireless_dev wireless;
static struct hdd_context context;
static struct wlan_hdd_link_info link;
static struct hdd_adapter adapter;
static struct net_device device;
static struct osif_psoc_sync operation;
static struct wlan_objmgr_vdev vdev;
static struct wlan_channel hardware;
static struct cfg80211_chan_def current, submitted;
static unsigned locks, unlocks, starts, stops, sets, reads, cases;
static int adapter_error, context_error, sync_error, setter_error, read_error, read_failure_at;
static bool mismatch_readback, modules_valid, wrong_width, wrong_center, wrong_puncture;

#define WLAN_HDD_GET_PRIV_PTR(d) ((d)->adapter)
#define WLAN_HDD_GET_CTX(a) ((a)->hdd_ctx)
#define test_bit(n,p) (((*(p)) & BIT(n)) != 0)
static bool netif_running(struct net_device *dev) { return dev->running; }
static bool netif_device_present(struct net_device *dev) { return dev->present; }
static int hdd_validate_adapter(struct hdd_adapter *a) { return a ? adapter_error : -EINVAL; }
static int wlan_hdd_validate_context(struct hdd_context *ctx) { return ctx ? context_error : -EINVAL; }
static bool wlan_hdd_validate_modules_state(struct hdd_context *ctx) { return modules_valid; }
static void *wiphy_dev(struct wiphy *w) { return w; }
static void wiphy_lock(struct wiphy *w)
{
    assert(w == &phy && !w->held && !operation.held);
    w->held = 1; locks++;
}
static void wiphy_unlock(struct wiphy *w)
{
    assert(w == &phy && w->held && !operation.held);
    w->held = 0; unlocks++;
}
static void hdd_wiphy_lock(struct wiphy *w, struct wireless_dev *wd)
{ wiphy_lock(w ? w : wd->wiphy); }
static void hdd_wiphy_unlock(struct wiphy *w, struct wireless_dev *wd)
{ wiphy_unlock(w ? w : wd->wiphy); }
static int osif_psoc_sync_op_start(void *dev, struct osif_psoc_sync **out)
{
    assert(dev == &phy && phy.held && !operation.held);
    starts++;
    if (sync_error) return sync_error;
    operation.held = 1; *out = &operation; return 0;
}
static void osif_psoc_sync_op_stop(struct osif_psoc_sync *sync)
{
    assert(sync == &operation && phy.held && sync->held);
    sync->held = 0; stops++;
}
static int ieee80211_channel_to_frequency(int channel, enum nl80211_band band)
{
    if (channel <= 0) return 0;
    if (band == NL80211_BAND_2GHZ)
        return channel == 14 ? 2484 : channel < 14 ? 2407 + channel * 5 : 0;
    if (band == NL80211_BAND_5GHZ)
        return channel >= 182 && channel <= 196 ? 4000 + channel * 5 :
               channel <= 177 ? 5000 + channel * 5 : 0;
    return 5950 + channel * 5;
}
static struct ieee80211_channel *ieee80211_get_channel(struct wiphy *w, int frequency)
{
    assert(w == &phy);
    for (unsigned i=0; i<ARRAY_SIZE(channels); i++)
        if (channels[i].center_freq == frequency) return &channels[i];
    return NULL;
}
static bool cfg80211_chandef_valid(const struct cfg80211_chan_def *def)
{ return def && def->chan && def->center_freq1 > 0; }
static bool cfg80211_chandef_identical(const struct cfg80211_chan_def *a,
                                      const struct cfg80211_chan_def *b)
{ return a->chan == b->chan && a->width == b->width &&
         a->center_freq1 == b->center_freq1 && a->center_freq2 == b->center_freq2 &&
         a->punctured == b->punctured; }
static void cfg80211_chandef_create(struct cfg80211_chan_def *def,
                                  struct ieee80211_channel *channel,
                                  enum nl80211_channel_type type)
{
    memset(def,0,sizeof(*def)); def->chan=channel;
    def->width=type == NL80211_CHAN_NO_HT ? NL80211_CHAN_WIDTH_20_NOHT : NL80211_CHAN_WIDTH_20;
    def->center_freq1=channel->center_freq;
}
static int wlan_hdd_cfg80211_get_channel_mon(struct wiphy *w,
                                            struct cfg80211_chan_def *def,
                                            struct hdd_adapter *a)
{
    assert(w == &phy && a == &adapter && phy.held && operation.held);
    reads++;
    if (read_error && (!read_failure_at || reads == (unsigned)read_failure_at)) return read_error;
    *def = current;
    return 0;
}
static int phy_width(enum nl80211_chan_width width)
{
    switch(width) {
    case NL80211_CHAN_WIDTH_20_NOHT: case NL80211_CHAN_WIDTH_20: return CH_WIDTH_20MHZ;
    case NL80211_CHAN_WIDTH_40: return CH_WIDTH_40MHZ;
    case NL80211_CHAN_WIDTH_80: return CH_WIDTH_80MHZ;
    case NL80211_CHAN_WIDTH_80P80: return CH_WIDTH_80P80MHZ;
    case NL80211_CHAN_WIDTH_160: return CH_WIDTH_160MHZ;
    default: assert(0); return 0;
    }
}
static bool failed_read(void)
{
    reads++;
    return read_error && (!read_failure_at || reads == (unsigned)read_failure_at);
}
static void fill_hardware(void)
{
    memset(&hardware,0,sizeof(hardware));
    if (!current.chan) return;
    hardware=(struct wlan_channel){.ch_freq=current.chan->center_freq,
        .ch_width=phy_width(current.width),.ch_cfreq1=current.center_freq1,
        .ch_cfreq2=current.center_freq2,.puncture_bitmap=current.punctured};
    if (current.width==NL80211_CHAN_WIDTH_160) {
        hardware.ch_cfreq1=current.center_freq1-40;
        hardware.ch_cfreq2=current.center_freq1;
    }
    if (reads>1 && wrong_width) hardware.ch_width=CH_WIDTH_40MHZ;
    if (reads>1 && wrong_center) hardware.ch_cfreq1+=10;
    if (reads>1 && wrong_puncture) hardware.puncture_bitmap^=1;
}
static int hdd_sta_mon_get_channel(struct hdd_adapter *a, struct wlan_channel *channel)
{
    assert(a==&adapter && phy.held && operation.held);
    if (failed_read()) return read_error;
    fill_hardware();
    if (!hardware.ch_freq) return -ENODATA;
    *channel=hardware;
    return 0;
}
static struct wlan_objmgr_vdev *hdd_objmgr_get_vdev_by_user(
        struct wlan_hdd_link_info *l, unsigned user)
{
    assert(l==&link && user==WLAN_OSIF_ID && phy.held && operation.held);
    if (failed_read()) return NULL;
    vdev.refs++;
    return &vdev;
}
static struct wlan_channel *wlan_vdev_get_active_channel(struct wlan_objmgr_vdev *v)
{ assert(v==&vdev && v->refs==1); fill_hardware(); return &hardware; }
static int wlan_vdev_is_up_active_state(struct wlan_objmgr_vdev *v)
{ assert(v==&vdev && v->refs==1); return v->active ? 0 : 1; }
static void hdd_objmgr_put_vdev_by_user(struct wlan_objmgr_vdev *v, unsigned user)
{ assert(v==&vdev && user==WLAN_OSIF_ID && v->refs==1); v->refs--; }
static void wlan_hdd_set_chandef_for_11be(struct cfg80211_chan_def *def,
                                        const struct wlan_channel *channel)
{ def->punctured=channel->puncture_bitmap; }
static int __wlan_hdd_cfg80211_set_mon_ch(struct wiphy *w, struct net_device *dev,
                                        struct cfg80211_chan_def *def)
{
    assert(w == &phy && dev == &device && phy.held && operation.held);
    assert(cfg80211_chandef_valid(def) && vdev.refs==0);
    submitted=*def; sets++;
    if (setter_error) return setter_error;
    if (!mismatch_readback) current=*def;
    return 0;
}

/* INSERT_UPDATE */
/* INSERT_PARSER */
/* INSERT_GETTER */
/* INSERT_BRIDGE */
/* INSERT_CALLBACK */

static void reset(void)
{
    memset(&phy,0,sizeof(phy)); memset(&operation,0,sizeof(operation));
    vdev=(struct wlan_objmgr_vdev){.active=true};
    wireless=(struct wireless_dev){.wiphy=&phy,.iftype=NL80211_IFTYPE_MONITOR};
    context=(struct hdd_context){.wiphy=&phy,.psoc=&context,.pdev=&context};
    adapter=(struct hdd_adapter){.hdd_ctx=&context,.deflink=&link,
        .device_mode=QDF_MONITOR_MODE,.event_flags=BIT(DEVICE_IFACE_OPENED),.active_links=BIT(0)};
    device=(struct net_device){.ieee80211_ptr=&wireless,.adapter=&adapter,
        .running=true,.present=true,.flags=IFF_UP};
    strcpy(device.name,"wlan0mon");
    for (unsigned i=0;i<ARRAY_SIZE(channels);i++) channels[i].flags=0;
    current=(struct cfg80211_chan_def){.chan=&channels[0],
        .width=NL80211_CHAN_WIDTH_20_NOHT,.center_freq1=2412};
    submitted=(struct cfg80211_chan_def){0};
    locks=unlocks=starts=stops=sets=reads=0;
    adapter_error=context_error=sync_error=setter_error=read_error=read_failure_at=0;
    mismatch_readback=wrong_width=wrong_center=wrong_puncture=false; modules_valid=true;
}
static int set_frequency(int m, int e)
{
    union iwreq_data request={.freq={.m=m,.e=e}};
    int ret=hdd_monitor_wext_siwfreq(&device,NULL,&request,NULL);
    assert(!phy.held && !operation.held && !vdev.refs && locks==unlocks);
    assert(stops <= starts && (sync_error ? stops==0 : stops==starts));
    cases++;
    return ret;
}
static void parser_test(int m,int e,int expected)
{
    struct iw_freq request={.m=m,.e=e};
    assert(hdd_monitor_wext_freq_mhz(&request)==expected); cases++;
}
static void parser_request_test(const struct iw_freq *request,int expected)
{
    assert(hdd_monitor_wext_freq_mhz(request)==expected); cases++;
}

int main(void)
{
    parser_test(1,0,2412); parser_test(11,0,2462); parser_test(13,0,2472);
    parser_test(14,0,2484); parser_test(36,0,5180); parser_test(165,0,5825);
    parser_test(2412,6,2412); parser_test(241200000,1,2412);
    parser_test(2412000,3,2412); parser_test(24120,5,2412);
    parser_test(0,0,-EINVAL); parser_test(-1,0,-EINVAL);
    parser_test(2412,-1,-EINVAL); parser_test(241234,4,-EINVAL);
    parser_test(INT_MAX,9,-EINVAL);
    parser_test(2412,10,-EINVAL); parser_test(197,0,-EINVAL);
    parser_test(182,0,4910); parser_test(196,0,4980);
    parser_request_test(NULL,-EINVAL);
    parser_request_test(&(struct iw_freq){.m=11,.i=1},-EINVAL);
    parser_request_test(&(struct iw_freq){.m=11,.flags=IW_FREQ_FIXED},2462);
    parser_request_test(&(struct iw_freq){.m=11,.flags=2},-EINVAL);

    reset(); assert(set_frequency(11,0)==0);
    assert(sets==1 && submitted.chan==&channels[1]);
    assert(submitted.width==NL80211_CHAN_WIDTH_20_NOHT);
    assert(submitted.center_freq1==2462 && submitted.center_freq2==0);
    assert(reads>=1 && starts==1 && stops==1);

    reset(); assert(set_frequency(2412,6)==0);
    assert(current.chan==&channels[0]);

    reset(); assert(set_frequency(5180,6)==0);
    assert(sets==1 && submitted.chan==&channels[4]);
    reset(); assert(set_frequency(14,0)==0);
    assert(sets==1 && submitted.chan==&channels[3]);
    assert(submitted.width==NL80211_CHAN_WIDTH_20_NOHT);

    reset(); adapter.sta_mon_coexist=true; read_error=-ENODATA; read_failure_at=2;
    assert(set_frequency(1,0)==-ENODATA && sets==0 && reads==2);
    reset(); adapter.sta_mon_coexist=true; wrong_width=true;
    assert(set_frequency(1,0)==-EIO && sets==0 && reads==2);

    for (unsigned width=NL80211_CHAN_WIDTH_40;width<=NL80211_CHAN_WIDTH_160;width++) {
        reset(); adapter.sta_mon_coexist=true;
        current=(struct cfg80211_chan_def){.chan=&channels[4],.width=width,
            .center_freq1=width==NL80211_CHAN_WIDTH_160 ? 5250 : 5210,
            .center_freq2=width==NL80211_CHAN_WIDTH_80P80 ? 5775 : 0};
        struct cfg80211_chan_def original=current;
        assert(set_frequency(36,0)==0);
        assert(memcmp(&current,&original,sizeof(current))==0);
        assert(sets==0 && reads==2);
    }

    reset(); adapter.sta_mon_coexist=true;
    current=(struct cfg80211_chan_def){.chan=&channels[4],
        .width=NL80211_CHAN_WIDTH_80,.center_freq1=5210};
    assert(set_frequency(11,0)==0);
    assert(sets==1 && submitted.width==NL80211_CHAN_WIDTH_20_NOHT);
    assert(submitted.center_freq1==2462 && !submitted.center_freq2 && !submitted.punctured);

    reset(); device.running=false; device.flags=0;
    assert(set_frequency(11,0)<0 && sets==0);
    reset(); adapter.event_flags=0;
    assert(set_frequency(11,0)==-ENETDOWN && sets==0);
    reset(); device.ieee80211_ptr=NULL;
    assert(set_frequency(11,0)==-ENODEV && sets==0 && locks==0);
    reset(); wireless.wiphy=NULL;
    assert(set_frequency(11,0)==-ENODEV && sets==0 && locks==0);
    reset(); device.adapter=NULL;
    assert(set_frequency(11,0)==-EINVAL && sets==0);
    reset(); wireless.iftype=NL80211_IFTYPE_STATION;
    assert(set_frequency(11,0)<0 && sets==0);
    reset(); adapter.device_mode=QDF_STA_MODE;
    assert(set_frequency(11,0)<0 && sets==0);
    reset(); adapter.deflink=NULL;
    assert(set_frequency(11,0)<0 && sets==0);
    reset(); adapter.delete_in_progress=true;
    assert(set_frequency(11,0)==-EBUSY && sets==0);
    reset(); adapter.sta_mon_stop_failed=true;
    assert(set_frequency(11,0)==-EBUSY && sets==0);
    reset(); adapter.monitor_mode_vdev_up_in_progress=true;
    assert(set_frequency(11,0)==-EBUSY && sets==0);
    reset(); context_error=-EBUSY;
    assert(set_frequency(11,0)==-EBUSY && sets==0);
    reset(); sync_error=-EBUSY;
    assert(set_frequency(11,0)==-EBUSY && sets==0);
    reset(); setter_error=-EBUSY;
    assert(set_frequency(11,0)==-EBUSY && sets==1 && current.chan==&channels[0]);
    reset(); setter_error=-EOPNOTSUPP;
    assert(set_frequency(11,0)==-EOPNOTSUPP && sets==1);
    reset(); adapter.sta_mon_coexist=true; read_error=-ENODATA;
    assert(set_frequency(11,0)<0 && sets==0);
    reset(); read_error=-ENODATA; read_failure_at=1; current.chan=NULL;
    assert(set_frequency(11,0)==0 && sets==1);
    reset(); vdev.active=false; setter_error=-EBUSY;
    assert(set_frequency(11,0)==-EBUSY && sets==1);
    reset(); read_error=-ENODATA; read_failure_at=2;
    assert(set_frequency(11,0)<0 && sets==1);
    reset(); mismatch_readback=true;
    assert(set_frequency(11,0)<0 && sets==1 && current.chan==&channels[0]);
    reset(); wrong_width=true;
    assert(set_frequency(11,0)<0 && sets==1);
    reset(); wrong_center=true;
    assert(set_frequency(11,0)<0 && sets==1);
    reset(); wrong_puncture=true;
    assert(set_frequency(11,0)<0 && sets==1);
    reset(); adapter.active_links=BIT(0)|BIT(1);
    assert(set_frequency(11,0)<0 && sets==0);
    reset(); adapter.active_links=0;
    assert(set_frequency(11,0)==-EOPNOTSUPP && sets==0);
    reset(); assert(set_frequency(5955,6)<0 && sets==0);
    reset(); assert(set_frequency(15,0)<0 && sets==0);
    reset(); assert(set_frequency(241234,4)<0 && sets==0);
    reset(); channels[1].flags=IEEE80211_CHAN_DISABLED;
    assert(set_frequency(11,0)<0 && sets==0);
    printf("%u\n",cases);
    return 0;
}
