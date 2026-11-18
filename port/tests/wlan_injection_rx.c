/* Host fixture for production monitor frequency provenance and publication. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned assertions;
#define CHECK(c) do { assertions++; if (!(c)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); abort(); \
} } while (0)
#define QDF_MAC_ADDR_SIZE 6
#define QDF_STATUS_SUCCESS 0
#define QDF_STATUS_E_FAILURE 1
#define NET_RX_SUCCESS 0
#define READ_ONCE(value) (value)
#define qdf_likely(value) (value)
typedef int QDF_STATUS;
typedef void *qdf_nbuf_t;
typedef void *ol_osif_vdev_handle;
/* INSERT_RX_PUSH_ENUM */
struct hdd_adapter { bool wonder_owned; };
struct net_device { struct hdd_adapter *adapter; };
#ifdef FEATURE_WLAN_WONDER
static void *netdev_priv(struct net_device *dev) { return dev->adapter; }
/* INSERT_RX_PRIV_MACRO */
#endif
struct list_head { unsigned unused; };
struct mon_rx_status { uint32_t chan_freq; };
struct dp_soc { bool coex, paused; };
struct dp_mon_pdev { bool monitor_configured; };
struct dp_pdev { struct dp_soc *soc; struct dp_mon_pdev *monitor_pdev; };
struct dp_mon_vdev {
    void (*osif_rx_mon)(void *, qdf_nbuf_t, struct mon_rx_status *);
};
struct dp_vdev {
    struct dp_pdev *pdev;
    struct dp_mon_vdev *monitor_vdev;
    void *osif_vdev;
    QDF_STATUS (*osif_rx)(void *, qdf_nbuf_t);
    uint8_t vdev_id, lmac_id;
};
struct dp_mon_mac {
    struct dp_vdev *mvdev;
    uint32_t mon_chan_freq, wonder_rx_frequency, wonder_rx_frequency_ppdu_id;
    struct {
        struct mon_rx_status rx_status;
        struct { uint32_t ppdu_id; } com_info;
    } ppdu_info;
};

/* INSERT_RX_BINDING */
/* INSERT_RX_LEASE */

static struct list_head dp_sta_mon_bindings;
static struct dp_sta_mon_helper_binding *bindings[3];
static unsigned binding_count, rcu_depth, lease_depth, published, begun, ended;
static bool mon_lock_held, token_allowed, lease_allowed;
static uint64_t owner_generation;
static uint8_t owner_monitor;
static uint32_t expected_frequency;
static struct dp_soc soc;
static struct dp_mon_pdev mon_pdev;
static struct dp_pdev pdev;
static struct dp_mon_mac mon_mac;
static struct dp_mon_vdev mon_vdev;
static struct dp_vdev monitor, helper;
static struct dp_sta_mon_helper_binding binding;
static int owner, packet;
static struct hdd_adapter network_adapter;
static struct net_device network_device = { .adapter = &network_adapter };
static bool network_delivery, atomic_context;
static unsigned queued, consumed, immediate, bh_depth, bh_entries;
static qdf_nbuf_t backlog_packet;

#define list_for_each_entry_rcu(pos, head, member) \
    for (unsigned fixture_index = 0; (void)(head), \
         fixture_index < binding_count && ((pos) = bindings[fixture_index]); \
         fixture_index++)
#define smp_load_acquire(p) (*(p))
#define rcu_dereference(p) (p)
#define dp_mon_warn_rl(...) ((void)0)
static void qdf_nbuf_list_free(qdf_nbuf_t nbuf) { (void)nbuf; }
static bool dp_mon_is_sta_coex(struct dp_soc *s) { return s->coex; }
static bool dp_mon_sta_coex_is_paused(struct dp_soc *s) { return s->paused; }
static void rcu_read_lock(void) { rcu_depth++; }
static void rcu_read_unlock(void) { CHECK(rcu_depth > 0); rcu_depth--; }

static bool token(void *arg, uint8_t monitor_id, uint64_t generation)
{
    CHECK(arg == &owner);
    CHECK(mon_lock_held && rcu_depth);
    return token_allowed && monitor_id == owner_monitor &&
           generation == owner_generation;
}

#ifdef FEATURE_WLAN_WONDER
/* The owner implementation is mocked; the fixture tests its actual DP caller. */
static bool wlan_injection_wonder_rx_begin(void *arg, uint8_t monitor_id,
    uint64_t generation, uint32_t frequency, struct cdp_wonder_rx_lease *lease)
{
    begun++;
    CHECK(arg == &owner && monitor_id == owner_monitor);
    CHECK(generation == owner_generation);
    CHECK(frequency == expected_frequency);
    CHECK(mon_lock_held && rcu_depth && !lease_depth);
    CHECK(!lease->coex && !lease->flags);
    if (!lease_allowed)
        return false;
    lease->coex = &owner;
    lease->flags = 0xabc;
    lease_depth++;
    return true;
}

static void wlan_injection_wonder_rx_end(struct cdp_wonder_rx_lease *lease)
{
    CHECK(lease_depth == 1 && lease->coex == &owner && lease->flags == 0xabc);
    CHECK(mon_lock_held && rcu_depth);
    lease_depth--;
    lease->coex = NULL;
    lease->flags = 0;
    ended++;
}
#endif

static bool qdf_in_atomic(void) { return atomic_context; }
static void local_bh_disable(void) { CHECK(!bh_depth); bh_depth++; bh_entries++; }
static void local_bh_enable(void) { CHECK(bh_depth == 1); bh_depth--; }

/* Model the stack RX handler generating TX, which reenters radio admission. */
static void network_consume(qdf_nbuf_t nbuf)
{
    CHECK(nbuf == &packet);
    consumed++;
#ifdef FEATURE_WLAN_WONDER
    if (network_adapter.wonder_owned) {
        CHECK(!lease_depth && "recursive Wonder consumption while lease is held");
        CHECK(!rcu_depth && !mon_lock_held);
    }
#endif
}

static int netif_receive_skb(qdf_nbuf_t nbuf)
{
    immediate++;
    network_consume(nbuf);
    return NET_RX_SUCCESS;
}

static int netif_rx(qdf_nbuf_t nbuf)
{
    CHECK(!backlog_packet);
    backlog_packet = nbuf;
    queued++;
    return NET_RX_SUCCESS;
}

static int netif_rx_ni(qdf_nbuf_t nbuf)
{
    return netif_rx(nbuf);
}

/* INSERT_RX_NETWORK_FUNCTIONS */

#ifdef FEATURE_WLAN_WONDER
static void drain_backlog(void)
{
    qdf_nbuf_t nbuf = backlog_packet;

    CHECK(nbuf && !lease_depth && !rcu_depth && !mon_lock_held);
    backlog_packet = NULL;
    network_consume(nbuf);
}
#endif

static void receive(void *context, qdf_nbuf_t nbuf, struct mon_rx_status *status)
{
    CHECK(context == &monitor && nbuf == &packet);
    CHECK(!status || status == &mon_mac.ppdu_info.rx_status);
    CHECK(mon_lock_held);
    CHECK(mon_mac.mon_chan_freq == 5180 && binding.frequency == 5180);
    if (soc.coex) {
        CHECK(rcu_depth);
#ifdef FEATURE_WLAN_WONDER
        CHECK(lease_depth == 1);
#else
        CHECK(!lease_depth);
#endif
    }
    published++;
    if (network_delivery)
        CHECK(osif_dp_rx_pkt_to_nw(nbuf, dp_mon_rx_push_type(&network_device)) ==
              QDF_STATUS_SUCCESS);
}

/* INSERT_RX_FREQUENCY_FUNCTIONS */
/* INSERT_RX_FUNCTIONS */

static void reset(void)
{
    CHECK(!backlog_packet && !bh_depth);
    memset(&soc, 0, sizeof(soc));
    memset(&mon_mac, 0, sizeof(mon_mac));
    memset(&binding, 0, sizeof(binding));
    memset(&monitor, 0, sizeof(monitor));
    memset(&helper, 0, sizeof(helper));
    soc.coex = true;
    mon_pdev.monitor_configured = true;
    pdev.soc = &soc;
    pdev.monitor_pdev = &mon_pdev;
    mon_mac.mvdev = &monitor;
    mon_mac.mon_chan_freq = 5180;
    mon_mac.ppdu_info.rx_status.chan_freq = 5180;
    mon_mac.ppdu_info.com_info.ppdu_id = 41;
    mon_vdev.osif_rx_mon = receive;
    monitor.pdev = helper.pdev = &pdev;
    monitor.monitor_vdev = &mon_vdev;
    monitor.osif_vdev = &monitor;
    monitor.vdev_id = owner_monitor = 7;
    helper.vdev_id = 8;
    monitor.lmac_id = helper.lmac_id = 1;
    helper.osif_rx = dp_sta_mon_helper_rx_marker;
    helper.osif_vdev = &binding;
    binding.helper = &helper;
    binding.monitor = &monitor;
    binding.soc = &soc;
    binding.mon_mac = &mon_mac;
    binding.generation = owner_generation = 0xabcdef;
    binding.frequency = 5180;
    binding.token_valid = token;
    binding.arg = &owner;
    bindings[0] = &binding;
    binding_count = 1;
    rcu_depth = lease_depth = published = begun = ended = 0;
    mon_lock_held = token_allowed = lease_allowed = true;
    expected_frequency = 0;
    network_adapter.wonder_owned = network_delivery = atomic_context = false;
    queued = consumed = immediate = bh_entries = 0;
}

static bool publish(uint32_t frequency)
{
    bool ok;
    expected_frequency = frequency;
    rcu_read_lock();
    ok = dp_sta_mon_publish(&soc, &mon_mac, &binding, &packet, NULL, frequency);
    rcu_read_unlock();
    CHECK(!rcu_depth && !lease_depth);
    return ok;
}

static void test_binding_and_publication(void)
{
    reset();
    CHECK(publish(0));
    CHECK(published == 1);
#ifdef FEATURE_WLAN_WONDER
    CHECK(begun == 1 && ended == 1);
    CHECK(publish(5745)); /* Measured away channel, HOME remains 5180. */
    CHECK(published == 2 && begun == 2 && ended == 2);
    lease_allowed = false;
    CHECK(!publish(5745));
    CHECK(published == 2 && begun == 3 && ended == 2);
    CHECK(!publish(0)); /* Unknown provenance uses the same final owner gate. */
    CHECK(published == 2 && begun == 4 && ended == 2);
#else
    CHECK(!publish(5745));
    CHECK(published == 1);
    CHECK(publish(5180));
#endif

    reset(); token_allowed = false;
    CHECK(!publish(0)); CHECK(!published && !begun && !ended);
    reset(); owner_generation++;
    CHECK(!publish(0)); CHECK(!published && !begun);
    reset(); owner_monitor++;
    CHECK(!publish(0)); CHECK(!published && !begun);
    reset(); soc.paused = true;
    CHECK(!publish(0)); CHECK(!published && !begun);
    reset(); mon_pdev.monitor_configured = false;
    CHECK(!publish(0)); CHECK(!published && !begun);
    reset(); mon_mac.mon_chan_freq = 5745;
    CHECK(!publish(0)); CHECK(!published && !begun);
    reset(); binding.frequency = 5745;
    CHECK(!publish(0)); CHECK(!published && !begun);
    reset(); helper.osif_vdev = &owner;
    CHECK(!publish(0)); CHECK(!published && !begun);
    reset(); helper.osif_rx = NULL;
    CHECK(!publish(0)); CHECK(!published && !begun);
    reset(); helper.lmac_id++;
    CHECK(!publish(0)); CHECK(!published && !begun);
    reset(); binding.monitor = NULL;
    CHECK(!publish(0)); CHECK(!published && !begun);
}

static void test_full_destination(void)
{
    reset();
    expected_frequency = 0;
    CHECK(dp_sta_mon_publish_full(&soc, &mon_mac, &packet,
                                  &mon_mac.ppdu_info.rx_status));
    CHECK(published == 1 && !lease_depth && !rcu_depth);
    reset(); binding_count = 0;
    CHECK(!dp_sta_mon_publish_full(&soc, &mon_mac, &packet, NULL));
    CHECK(!published && !begun && !lease_depth && !rcu_depth);
    reset(); struct dp_mon_mac other_mac = {0}; binding.mon_mac = &other_mac;
    CHECK(!dp_sta_mon_publish_full(&soc, &mon_mac, &packet, NULL));
    CHECK(!published && !begun && !lease_depth && !rcu_depth);
    reset(); struct dp_soc other_soc = {0}; binding.soc = &other_soc;
    CHECK(!dp_sta_mon_publish_full(&soc, &mon_mac, &packet, NULL));
    CHECK(!published && !begun && !lease_depth && !rcu_depth);
    reset(); soc.coex = false;
    CHECK(dp_sta_mon_publish_full(&soc, &mon_mac, &packet, NULL));
    CHECK(published == 1 && !begun && !ended && !lease_depth && !rcu_depth);
}

#ifdef FEATURE_WLAN_WONDER
static void test_measured_frequency(void)
{
    static const uint32_t frequencies[] = {2412, 5180, 5745, 5975, 65535};
    reset();
    CHECK(!dp_sta_mon_measured_frequency(&mon_mac));
    for (unsigned i = 0; i < sizeof(frequencies) / sizeof(frequencies[0]); i++) {
        mon_mac.ppdu_info.rx_status.chan_freq = frequencies[i];
        mon_mac.ppdu_info.com_info.ppdu_id = i;
        dp_mon_wonder_rx_frequency_start(&mon_mac);
        CHECK(dp_sta_mon_measured_frequency(&mon_mac) == frequencies[i]);
        CHECK(mon_mac.wonder_rx_frequency_ppdu_id == i);
        expected_frequency = frequencies[i];
        CHECK(dp_sta_mon_publish_full(&soc, &mon_mac, &packet,
                                      &mon_mac.ppdu_info.rx_status));
        CHECK(!lease_depth && !rcu_depth);
        CHECK(mon_mac.mon_chan_freq == 5180 && binding.frequency == 5180);
        mon_mac.ppdu_info.com_info.ppdu_id++;
        CHECK(!dp_sta_mon_measured_frequency(&mon_mac));
        mon_mac.ppdu_info.com_info.ppdu_id--;
        mon_mac.ppdu_info.rx_status.chan_freq = 5260;
        CHECK(!dp_sta_mon_measured_frequency(&mon_mac));
        dp_mon_wonder_rx_frequency_reset(&mon_mac);
        CHECK(!mon_mac.wonder_rx_frequency && !mon_mac.wonder_rx_frequency_ppdu_id);
    }
    mon_mac.ppdu_info.rx_status.chan_freq = 0;
    dp_mon_wonder_rx_frequency_start(&mon_mac);
    mon_mac.ppdu_info.rx_status.chan_freq = mon_mac.mon_chan_freq; /* Fallback. */
    CHECK(!dp_sta_mon_measured_frequency(&mon_mac));
    mon_mac.ppdu_info.rx_status.chan_freq = 65536;
    dp_mon_wonder_rx_frequency_start(&mon_mac);
    CHECK(!mon_mac.wonder_rx_frequency);
    CHECK(!dp_sta_mon_measured_frequency(&mon_mac));
    mon_mac.wonder_rx_frequency = 65536;
    CHECK(!dp_sta_mon_measured_frequency(&mon_mac));
}
#endif

static void test_network_delivery(void)
{
#ifdef FEATURE_WLAN_WONDER
    reset();
    CHECK(!hdd_wonder_netdev_is_owned(NULL));
    CHECK(!hdd_wonder_netdev_is_owned(&network_device));
    network_adapter.wonder_owned = true;
    CHECK(hdd_wonder_netdev_is_owned(&network_device));
    CHECK(!rcu_depth && !lease_depth); /* The actual predicate is pure. */

    for (unsigned context = 0; context < 2; context++) {
        reset();
        network_delivery = network_adapter.wonder_owned = true;
        atomic_context = context;
        CHECK(publish(5745));
        CHECK(published == 1 && begun == 1 && ended == 1);
        CHECK(backlog_packet == &packet && queued == 1);
        CHECK(!consumed && !immediate && !bh_entries && !bh_depth);
        CHECK(!lease_depth && !rcu_depth);
        mon_lock_held = false;
        drain_backlog();
        CHECK(consumed == 1 && !backlog_packet);
    }
#endif

    /* An ordinary monitor retains immediate NAPI/BH delivery in both builds. */
    for (unsigned context = 0; context < 2; context++) {
        reset();
        soc.coex = false;
        network_delivery = true;
        atomic_context = context;
        CHECK(dp_mon_rx_push_type(&network_device) ==
              (context ? DP_NBUF_PUSH_NAPI : DP_NBUF_PUSH_BH_DISABLE));
        CHECK(dp_sta_mon_publish_full(&soc, &mon_mac, &packet, NULL));
        CHECK(published == 1 && consumed == 1 && immediate == 1);
        CHECK(!queued && !backlog_packet && !begun && !ended);
        CHECK(bh_entries == !context && !bh_depth);
    }
}

int main(void)
{
    test_binding_and_publication();
    test_full_destination();
#ifdef FEATURE_WLAN_WONDER
    test_measured_frequency();
#endif
    test_network_delivery();
    printf("%u\n", assertions);
    return 0;
}
