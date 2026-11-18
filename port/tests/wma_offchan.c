/* Production queue/publication/completion code with deterministic work/DMA mocks. */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static atomic_uint assertions;
#define CHECK(x) do { atomic_fetch_add(&assertions, 1); assert(x); } while (0)
typedef int QDF_STATUS;
enum { QDF_STATUS_SUCCESS, QDF_STATUS_E_CANCELED, QDF_STATUS_E_BUSY,
	QDF_STATUS_E_INVAL, QDF_STATUS_E_NOSUPPORT, QDF_STATUS_E_NOMEM,
	QDF_STATUS_E_FAILURE, WMI_MGMT_TX_COMP_TYPE_COMPLETE_OK = 0,
	CH_WIDTH_20MHZ, REG_CURRENT_PWR_MODE, CHANNEL_STATE_ENABLE,
	REG_INVALID_TXPOWER = 255, WMI_RX_WORK_CTX = 1 };
#define QDF_IS_STATUS_ERROR(s) ((s) != QDF_STATUS_SUCCESS)
#define U16_MAX UINT16_MAX
#define U32_MAX UINT32_MAX
#define BIT(n) (1u << (n))
#define GENMASK(h, l) (((~0u) << (l)) & ((~0u) >> (31 - (h))))
#define QDF_MIN(a, b) ((a) < (b) ? (a) : (b))
#define QDF_DMA_TO_DEVICE 1
#define QDF_MAC_ADDR_SIZE 6
#define READ_ONCE(x) (x)
#define qdf_mem_zero(p, n) memset(p, 0, n)
#define wma_err(...) do { } while (0)
#define PAGE_SIZE 4096
#define scnprintf snprintf
struct kernel_param { int unused; };
struct kernel_param_ops { int (*get)(char *, const struct kernel_param *); };
#define module_param_cb(name, ops, arg, mode) \
	static const void *const parameter_##name __attribute__((unused)) = ops
#define MODULE_PARM_DESC(...) /* test metadata */
typedef uint16_t __le16;
#define cpu_to_le16(v) (v)
static uint16_t get_unaligned_le16(void *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static bool ieee80211_is_mgmt(uint16_t v) { return (v & 0xc) == 0; }
static bool ieee80211_is_data(uint16_t v) { return (v & 0xc) == 8; }

static _Thread_local bool softirq;
static _Thread_local unsigned int mutexes, spinlocks;
typedef pthread_mutex_t spinlock_t;
struct mutex { pthread_mutex_t lock; };
#define DEFINE_SPINLOCK(name) spinlock_t name = PTHREAD_MUTEX_INITIALIZER
#define spin_lock_irqsave(lock, flags) do { (flags) = 0; pthread_mutex_lock(lock); spinlocks++; } while (0)
#define spin_unlock_irqrestore(lock, flags) do { (void)(flags); spinlocks--; pthread_mutex_unlock(lock); } while (0)
static void mutex_lock(struct mutex *lock)
{
	CHECK(!softirq);
	pthread_mutex_lock(&lock->lock);
	mutexes++;
}
static void mutex_unlock(struct mutex *lock)
{
	mutexes--;
	pthread_mutex_unlock(&lock->lock);
}
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(name) struct list_head name = { &name, &name }
static bool list_empty(struct list_head *h) { return h->next == h; }
static void list_add_tail(struct list_head *n, struct list_head *h)
{
	n->next = h; n->prev = h->prev; h->prev->next = n; h->prev = n;
}
static void list_del(struct list_head *n) { n->next->prev = n->prev; n->prev->next = n->next; }
#define list_first_entry(h, type, field) ((type *)((char *)(h)->next - offsetof(type, field)))
struct work_struct { void (*fn)(struct work_struct *); bool scheduled; };
#define DECLARE_WORK(name, function) struct work_struct name = { .fn = function }
static void schedule_work(struct work_struct *work)
{
	CHECK(spinlocks > 0);
	work->scheduled = true;
}
static void cancel_work_sync(struct work_struct *work)
{
	CHECK(!mutexes);
	work->scheduled = false;
}
static void wake_up_all(int *wait) { (void)wait; }
static void wma_injection_queue_work(void) { }
static atomic_uint pins;
static bool pin_fail, alloc_fail, owner_valid = true, channel_enabled = true;
static bool owner_exclusive = true, deny_home_guard;
static atomic_uint home_guard_begins, home_guard_ends;
static _Thread_local bool home_guard_held;
#define THIS_MODULE NULL
static bool try_module_get(void *module)
{
	(void)module;
	if (pin_fail) return false;
	atomic_fetch_add(&pins, 1);
	return true;
}
static void module_put(void *module) { (void)module; CHECK(atomic_fetch_sub(&pins, 1) > 0); }
static void *qdf_mem_malloc_atomic(size_t n) { return alloc_fail ? NULL : malloc(n); }
static void qdf_mem_free(void *p) { free(p); }
struct device { atomic_uint refs; };
struct __qdf_device { struct device *dev; };
static struct device *get_device(struct device *d) { atomic_fetch_add(&d->refs, 1); return d; }
static void put_device(struct device *d) { CHECK(atomic_fetch_sub(&d->refs, 1) > 1); }
static atomic_uint frame_frees, unmaps;
struct frame { uint8_t data[40]; unsigned int len, fragments; bool nonlinear, mapped; };
typedef struct frame *qdf_nbuf_t;
static unsigned int qdf_nbuf_len(qdf_nbuf_t f) { return f->len; }
static void *qdf_nbuf_data(qdf_nbuf_t f) { return f->data; }
static bool qdf_nbuf_is_nonlinear(qdf_nbuf_t f) { return f->nonlinear; }
static unsigned int qdf_nbuf_get_num_frags(qdf_nbuf_t f) { return f->fragments; }
static void qdf_nbuf_reset_ctxt(qdf_nbuf_t f) { (void)f; }
static void qdf_nbuf_free(qdf_nbuf_t f)
{
	CHECK(!f->mapped);
	atomic_fetch_add(&frame_frees, 1);
	free(f);
}
static void qdf_nbuf_unmap_single(struct __qdf_device *device, qdf_nbuf_t f, int dir)
{
	CHECK(device->dev && atomic_load(&device->dev->refs) > 1);
	CHECK(f->mapped && dir == QDF_DMA_TO_DEVICE);
	f->mapped = false;
	atomic_fetch_add(&unmaps, 1);
}
static atomic_uint injection_completed, injection_completion_failed,
	injection_send_failed, injection_submitted, injection_data_submitted,
	injection_accepted;
#define atomic64_inc(p) atomic_fetch_add(p, 1)

/* INSERT_TYPES */

struct wlan_objmgr_psoc { int unused; };
struct vdev_mlme_obj { struct { struct { uint8_t maxpower; } generic; } mgmt; };
struct wlan_objmgr_vdev { struct vdev_mlme_obj mlme; };
struct wlan_objmgr_pdev { uint8_t id; };
static struct vdev_mlme_obj *wlan_vdev_mlme_get_cmpt_obj(struct wlan_objmgr_vdev *v) { return &v->mlme; }
struct wma_injection_helper_snapshot { bool direct_dp; };
struct wma_injection_helper {
	bool wonder_owned, wonder_delete_sent, native, ht_supported, vht_supported;
	uint64_t wonder_cookie;
	uint8_t vdev_id, max_nss, channel_bw_mask, expected_mac_id;
	struct { struct { uint8_t maxpower; } channel; } start;
};
struct mock_wmi { int unused; };
typedef struct mock_wmi *wmi_unified_t;
struct wma_handle {
	wmi_unified_t wmi_handle;
	struct __qdf_device *qdf_dev;
	struct wlan_objmgr_psoc *psoc;
	struct wlan_objmgr_pdev *pdev;
	uint8_t max_bssid;
	struct { struct wlan_objmgr_vdev *vdev; uint32_t ch_freq; } interfaces[4];
};
typedef struct wma_handle *tp_wma_handle;
static struct {
	struct mutex lifecycle_lock, helper_lock;
	spinlock_t lock;
	struct wma_injection_helper helper;
	tp_wma_handle wma;
	bool active, paused, channel_change_paused;
	unsigned int in_flight;
	int idle_wait;
} wma_injection_ctx = {
	.lifecycle_lock = { PTHREAD_MUTEX_INITIALIZER },
	.helper_lock = { PTHREAD_MUTEX_INITIALIZER }, .lock = PTHREAD_MUTEX_INITIALIZER,
};
static bool wlan_mlme_sta_mon_token_valid(struct wlan_objmgr_psoc *p, uint8_t id, uint64_t gen)
{
	return p && id == 1 && gen == 5 && owner_valid;
}
static bool wlan_mlme_sta_mon_is_owner(struct wlan_objmgr_psoc *p, uint8_t id) { return p && id == 1; }
struct wlan_mlme_sta_mon_snapshot { bool exclusive; };
static bool wlan_mlme_sta_mon_get_snapshot(struct wlan_objmgr_psoc *p,
		uint8_t id, uint64_t gen, struct wlan_mlme_sta_mon_snapshot *snapshot)
{
	CHECK(!spinlocks);
	snapshot->exclusive = owner_exclusive;
	return wlan_mlme_sta_mon_token_valid(p, id, gen);
}
static bool wlan_mlme_sta_mon_tx_begin(struct wlan_objmgr_psoc *p,
		uint8_t id, uint64_t gen, unsigned long *flags)
{
	CHECK(!home_guard_held && !spinlocks && mutexes == 2);
	atomic_fetch_add(&home_guard_begins, 1);
	if (deny_home_guard || !wlan_mlme_sta_mon_token_valid(p, id, gen))
		return false;
	*flags = 19;
	home_guard_held = true;
	spinlocks++;
	return true;
}
static void wlan_mlme_sta_mon_tx_end(unsigned long flags)
{
	CHECK(home_guard_held && flags == 19 && spinlocks == 1 && mutexes == 2);
	home_guard_held = false;
	spinlocks--;
	atomic_fetch_add(&home_guard_ends, 1);
}
static bool wma_injection_get_helper_snapshot(uint8_t id, uint32_t freq,
		const uint8_t *mac, uint64_t gen, struct wma_injection_helper_snapshot *snap)
{
	snap->direct_dp = true;
	return id == 1 && freq == 2412 && mac[0] == 2 && gen == 5;
}
static bool wlan_reg_is_24ghz_ch_freq(uint32_t f) { return f >= 2400 && f < 2500; }
static bool wlan_reg_is_5ghz_ch_freq(uint32_t f) { return f >= 5000 && f < 5925; }
static int wlan_reg_get_bonded_channel_state_for_pwrmode(struct wlan_objmgr_pdev *p,
		uint32_t freq, int width, int secondary, int mode)
{
	CHECK(p && (freq == 2437 || freq == 2412) && width == CH_WIDTH_20MHZ && !secondary && mode == REG_CURRENT_PWR_MODE);
	return channel_enabled ? CHANNEL_STATE_ENABLE : 0;
}
static uint8_t wlan_reg_get_channel_reg_power_for_freq(struct wlan_objmgr_pdev *p, uint32_t f)
{
	CHECK(p && (f == 2437 || f == 2412)); return 18;
}
static bool swap_pdev_map;
static QDF_STATUS wmi_offchan_data_tx_pdev_id(wmi_unified_t wmi,
		uint32_t target, uint32_t *host)
{
	CHECK(wmi && target >= 1 && target <= 3 && host);
	*host = swap_pdev_map ? (target == 1 ? 1 : 0) : target - 1;
	return QDF_STATUS_SUCCESS;
}
static int (*event_handler)(void *, uint8_t *, uint32_t);
static void *event_context;
static QDF_STATUS send_status, registration_status, unregistration_status;
static unsigned int sends;
static uint32_t last_desc;
static bool immediate_completion, deny_guard;
static atomic_uint arg_releases, guard_begins, guard_ends;
static pthread_mutex_t send_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t send_cond = PTHREAD_COND_INITIALIZER;
static bool pause_send, send_entered, allow_send_return;
static QDF_STATUS wmi_offchan_data_tx_completion_register(wmi_unified_t wmi,
		int (*handler)(void *, uint8_t *, uint32_t), uint8_t context)
{
	CHECK(wmi && context == WMI_RX_WORK_CTX);
	if (registration_status) return registration_status;
	CHECK(!event_handler);
	event_handler = handler; event_context = wma_injection_ctx.wma;
	return QDF_STATUS_SUCCESS;
}
static QDF_STATUS wmi_offchan_data_tx_completion_unregister(wmi_unified_t wmi)
{
	CHECK(wmi);
	if (unregistration_status) return unregistration_status;
	event_handler = NULL;
	return QDF_STATUS_SUCCESS;
}
static QDF_STATUS wmi_extract_offchan_data_tx_compl_param(wmi_unified_t wmi, void *buf,
		struct wmi_host_offchan_data_tx_compl_event *event)
{
	CHECK(wmi && buf);
	memcpy(event, buf, sizeof(*event));
	return QDF_STATUS_SUCCESS;
}
static QDF_STATUS wmi_offchan_data_tx_cmd_send(wmi_unified_t wmi,
		struct wmi_offchan_data_tx_params *param)
{
	CHECK(wmi && mutexes == 2 && (param->chanfreq == 2437 || param->chanfreq == 0));
	if (!param->chanfreq) CHECK(home_guard_held && spinlocks == 1);
	else CHECK(!home_guard_held);
	CHECK(param->vdev_id == 3 && param->tx_params_valid);
	CHECK(param->tx_param.mcs_mask == BIT(4) && param->tx_param.nss_mask == 1);
	CHECK(param->tx_param.preamble_type == BIT(CDP_INJECTION_OFDM));
	CHECK(param->tx_param.pwr == 36 && param->tx_param.retry_limit == 1);
	qdf_nbuf_t f = param->tx_frame;
	CHECK(!f->mapped);
	f->mapped = true;
	sends++; last_desc = param->desc_id;
	if (immediate_completion) {
		struct wmi_host_offchan_data_tx_compl_event event = {
			.desc_id = last_desc, .pdev_id = 0, .status = WMI_MGMT_TX_COMP_TYPE_COMPLETE_OK };
		CHECK(event_handler(event_context, (void *)&event, sizeof(event)) == 0);
		CHECK(f->mapped); /* Completion cannot retire a publishing frame. */
	}
	pthread_mutex_lock(&send_mutex);
	if (pause_send) {
		send_entered = true;
		pthread_cond_broadcast(&send_cond);
		while (!allow_send_return) pthread_cond_wait(&send_cond, &send_mutex);
		CHECK(f->mapped);
	}
	pthread_mutex_unlock(&send_mutex);
	if (send_status) f->mapped = false; /* Production WMI rolls failed maps back. */
	return send_status;
}

/* INSERT_OWNER */

static struct device device = { ATOMIC_VAR_INIT(1) };
static struct __qdf_device dma_device = { &device };
static struct mock_wmi wmi;
static struct wlan_objmgr_psoc psoc;
static struct wlan_objmgr_pdev pdev;
static struct wlan_objmgr_vdev vdev = { .mlme.mgmt.generic.maxpower = 20 };
static struct wma_handle wma = { .wmi_handle = &wmi, .qdf_dev = &dma_device,
	.psoc = &psoc, .pdev = &pdev, .max_bssid = 4,
	.interfaces[1] = { &vdev, 2412 } };
static const struct wma_wonder_helper_snapshot snapshot = { .vdev_id = 3, .cookie = 42 };
static struct cdp_tx_injection_params params = { .rate_valid = true, .bandwidth_valid = true,
	.mcs_mask = BIT(4), .nss_mask = 1, .preamble = CDP_INJECTION_OFDM,
	.bw_mask = BIT(2), .chanfreq = 2437, .interface_mac = { 2 } };
static bool begin(void *arg, unsigned long *flags)
{
	CHECK(arg && mutexes == 2);
	atomic_fetch_add(&guard_begins, 1);
	*flags = 7;
	return !deny_guard;
}
static void end(void *arg, unsigned long flags)
{
	CHECK(arg && flags == 7 && mutexes == 2);
	atomic_fetch_add(&guard_ends, 1);
}
static void release(void *arg)
{
	CHECK(arg && !mutexes);
	atomic_fetch_add(&arg_releases, 1);
}
static qdf_nbuf_t frame(void)
{
	qdf_nbuf_t f = calloc(1, sizeof(*f));
	CHECK(f); f->len = 30; f->fragments = 1; return f;
}
static QDF_STATUS enqueue(qdf_nbuf_t f)
{
	softirq = true;
	QDF_STATUS status = wma_wonder_offchan_tx(f, 1, 2412, 5, &snapshot,
		2437, &params, begin, end, release, &wma);
	softirq = false;
	return status;
}
static QDF_STATUS enqueue_home(qdf_nbuf_t f)
{
	struct cdp_tx_injection_params home = params;
	home.chanfreq = 2412;
	softirq = true;
	QDF_STATUS status = wma_wonder_offchan_tx(f, 1, 2412, 5, &snapshot,
		2412, &home, NULL, NULL, NULL, NULL);
	softirq = false;
	return status;
}
static void run_worker(void) { wma_wonder_offchan_worker(&wma_wonder_offchan_work); }
static void completion(uint32_t desc, uint32_t id, uint32_t status)
{
	struct wmi_host_offchan_data_tx_compl_event e = { desc, status, id };
	CHECK(event_handler && event_handler(event_context, (void *)&e, sizeof(e)) == 0);
}
static void idle(void)
{
	CHECK(!wma_wonder_offchan.in_flight && !wma_wonder_offchan.queued);
	CHECK(!wma_injection_ctx.in_flight && atomic_load(&device.refs) == 1);
	CHECK(atomic_load(&pins) == 0);
}
static void *worker_thread(void *arg) { (void)arg; run_worker(); return NULL; }
int main(void)
{
	wma_injection_ctx.wma = &wma;
	wma_injection_ctx.active = true;
	wma_injection_ctx.helper = (struct wma_injection_helper){ .wonder_owned = true,
		.wonder_cookie = 42, .vdev_id = 3, .max_nss = 2, .channel_bw_mask = BIT(2),
		.ht_supported = true, .vht_supported = true };
	uint8_t mac[6] = { 2 };
	registration_status = QDF_STATUS_E_NOSUPPORT;
	CHECK(wma_wonder_offchan_prepare(1, 2412, mac, 5, &snapshot) == QDF_STATUS_E_NOSUPPORT);
	CHECK(!atomic_load(&pins));
	registration_status = 0;
	CHECK(wma_wonder_offchan_prepare(1, 2412, mac, 5, &snapshot) == 0);
	CHECK(wma_wonder_offchan_prepare(1, 2412, mac, 5, &snapshot) == 0);
	idle();

	qdf_nbuf_t f = frame();
	alloc_fail = true;
	CHECK(enqueue(f) == QDF_STATUS_E_NOMEM && !f->mapped);
	alloc_fail = false; qdf_nbuf_free(f);
	f = frame(); params.gi_valid = true;
	CHECK(enqueue(f) == QDF_STATUS_E_NOSUPPORT && !f->mapped);
	params.gi_valid = false; qdf_nbuf_free(f);

	for (unsigned int i = 0; i < WMA_WONDER_OFFCHAN_SLOTS; i++)
		CHECK(enqueue(frame()) == 0);
	f = frame(); CHECK(enqueue(f) == QDF_STATUS_E_BUSY); qdf_nbuf_free(f);
	CHECK(!sends && !atomic_load(&unmaps));
	/* A generation invalidated while queued never reaches publication. */
	owner_valid = false; run_worker(); owner_valid = true;
	CHECK(!sends && atomic_load(&arg_releases) == WMA_WONDER_OFFCHAN_SLOTS);
	idle();

	deny_guard = true; CHECK(enqueue(frame()) == 0); run_worker(); deny_guard = false;
	CHECK(!sends && !atomic_load(&unmaps) && !atomic_load(&guard_ends));
	idle();
	send_status = QDF_STATUS_E_FAILURE;
	CHECK(enqueue(frame()) == 0); run_worker(); send_status = 0;
	CHECK(sends == 1 && !atomic_load(&unmaps));
	idle();

	immediate_completion = true;
	CHECK(enqueue(frame()) == 0); run_worker(); immediate_completion = false;
	CHECK(atomic_load(&unmaps) == 1);
	idle();
	CHECK(enqueue(frame()) == 0); run_worker();
	CHECK(wma_wonder_offchan.in_flight == 1);
	uint32_t pending_desc = last_desc;
	completion(pending_desc + 1, 0, 0); completion(pending_desc, 1, 0);
	CHECK(wma_wonder_offchan.in_flight == 1 && atomic_load(&unmaps) == 1);
	/* WMA/device context teardown cannot remove the retained DMA device ref. */
	wma.qdf_dev = NULL;
	completion(pending_desc, 0, WMI_MGMT_TX_COMP_TYPE_COMPLETE_OK);
	wma.qdf_dev = &dma_device;
	completion(pending_desc, 0, 0);
	CHECK(atomic_load(&unmaps) == 2);
	idle();

	/* Real concurrent completion before send return remains pending. */
	pause_send = true; send_entered = false; allow_send_return = false;
	CHECK(enqueue(frame()) == 0);
	pthread_t worker;
	CHECK(!pthread_create(&worker, NULL, worker_thread, NULL));
	pthread_mutex_lock(&send_mutex);
	while (!send_entered) pthread_cond_wait(&send_cond, &send_mutex);
	uint32_t racing_desc = last_desc;
	pthread_mutex_unlock(&send_mutex);
	completion(racing_desc, 0, WMI_MGMT_TX_COMP_TYPE_COMPLETE_OK);
	completion(racing_desc, 0, 0);
	CHECK(atomic_load(&unmaps) == 2);
	pthread_mutex_lock(&send_mutex); allow_send_return = true;
	pthread_cond_broadcast(&send_cond); pthread_mutex_unlock(&send_mutex);
	CHECK(!pthread_join(worker, NULL)); pause_send = false;
	CHECK(atomic_load(&unmaps) == 3); idle();
	swap_pdev_map = true;
	wma_injection_ctx.helper.native = true;
	wma_injection_ctx.helper.expected_mac_id = 1;
	wma_injection_ctx.helper.start.channel.maxpower = 20;
	CHECK(enqueue(frame()) == 0); run_worker();
	completion(last_desc, 1, 0);
	CHECK(wma_wonder_offchan.in_flight == 1);
	completion(last_desc, 0, 0); idle();
	swap_pdev_map = false;
	wma_injection_ctx.helper.native = false;
	/* The last ID is reserved synchronously; later admission cannot consume skb.
	 * This synthetic counter boundary does not loop through 65,535 real sends.
	 */
	uint32_t saved_desc = wma_wonder_offchan.next_desc;
	wma_wonder_offchan.next_desc = U16_MAX - 1;
	CHECK(enqueue(frame()) == 0);
	CHECK(wma_wonder_offchan.next_desc == U16_MAX && wma_wonder_offchan.queued == 1);
	struct wma_wonder_offchan_packet *last_packet = list_first_entry(
		&wma_wonder_offchan_queue, struct wma_wonder_offchan_packet, node);
	CHECK(last_packet->desc_id == U16_MAX);
	f = frame();
	unsigned int before_rejection_frees = atomic_load(&frame_frees);
	CHECK(enqueue(f) == QDF_STATUS_E_NOSUPPORT && !f->mapped);
	CHECK(atomic_load(&frame_frees) == before_rejection_frees);
	qdf_nbuf_free(f);
	CHECK(wma_wonder_offchan_prepare(1, 2412, mac, 5, &snapshot) == QDF_STATUS_E_NOSUPPORT);
	unsigned int saved_sends = sends;
	run_worker();
	CHECK(sends == saved_sends + 1 && last_desc == U16_MAX);
	completion(last_desc, 0, 0); idle();
	wma_wonder_offchan.next_desc = saved_desc;

	/* Static worker submission rejects an invalid reserved ID before ownership. */
	f = frame();
	CHECK(wma_wonder_offchan_send(f, 1, 2412, 5, &snapshot, 2437, 0,
		&params, begin, end, &wma) == QDF_STATUS_E_INVAL);
	CHECK(wma_wonder_offchan_send(f, 1, 2412, 5, &snapshot, 2437, U16_MAX + 1u,
		&params, begin, end, &wma) == QDF_STATUS_E_INVAL);
	CHECK(!f->mapped); qdf_nbuf_free(f); idle();

	/* Cancellation consumes the reserved ID permanently, before any DMA map. */
	saved_desc = wma_wonder_offchan.next_desc;
	CHECK(enqueue(frame()) == 0);
	owner_valid = false; run_worker(); owner_valid = true;
	CHECK(wma_wonder_offchan.next_desc == saved_desc + 1);
	CHECK(enqueue(frame()) == 0);
	last_packet = list_first_entry(&wma_wonder_offchan_queue,
		struct wma_wonder_offchan_packet, node);
	CHECK(last_packet->desc_id == saved_desc + 2);
	run_worker(); completion(last_desc, 0, 0); idle();

	/* Exclusive HOME publication rechecks ownership at the final WMI boundary. */
	saved_sends = sends;
	owner_exclusive = false;
	CHECK(enqueue_home(frame()) == 0); run_worker(); owner_exclusive = true;
	CHECK(sends == saved_sends && !atomic_load(&home_guard_begins)); idle();
	deny_home_guard = true;
	CHECK(enqueue_home(frame()) == 0); run_worker(); deny_home_guard = false;
	CHECK(sends == saved_sends && atomic_load(&home_guard_begins) == 1);
	CHECK(!atomic_load(&home_guard_ends) && !home_guard_held); idle();
	immediate_completion = true;
	CHECK(enqueue_home(frame()) == 0); run_worker(); immediate_completion = false;
	CHECK(sends == saved_sends + 1 && atomic_load(&home_guard_begins) == 2);
	CHECK(atomic_load(&home_guard_ends) == 1 && !home_guard_held); idle();
	unsigned int before_stop_unmaps = atomic_load(&unmaps);

	/* Stop drops unsent frames; idle registration does not prevent module exit. */
	CHECK(enqueue(frame()) == 0);
	wma_wonder_offchan_event_stop(&wma);
	CHECK(!event_handler && !wma_wonder_offchan.queued && atomic_load(&unmaps) == before_stop_unmaps);
	CHECK(atomic_load(&pins) == 0);
	wma_wonder_offchan_events_drained(&wma);
	CHECK(!atomic_load(&pins));
	CHECK(wma_wonder_offchan_prepare(1, 2412, mac, 5, &snapshot) == 0);
	CHECK(enqueue(frame()) == 0); run_worker();
	CHECK(wma_wonder_offchan.in_flight == 1);
	wma_wonder_offchan_event_stop(&wma);
	wma_wonder_offchan_events_drained(&wma);
	CHECK(wma_wonder_offchan.in_flight == 1 && atomic_load(&unmaps) == before_stop_unmaps);
	CHECK(atomic_load(&pins) == 1 && atomic_load(&device.refs) == 2);
	CHECK(wma_wonder_offchan_prepare(1, 2412, mac, 5, &snapshot) == QDF_STATUS_E_BUSY);
	char stats[PAGE_SIZE];
	CHECK(wma_wonder_offchan_stats_get(stats, NULL) > 0);
	CHECK(strstr(stats, "registered=0 quiesced=1") && strstr(stats, "pending_mapped=1"));
	CHECK(strstr(stats, "quarantined=1") && wma_wonder_offchan.pdev_mismatch == 2);
	CHECK(wma_wonder_offchan.descriptor_exhausted == 2);
	/* Test fixture reclaims only after this simulated target has fully stopped. */
	for (unsigned int i = 0; i < WMA_WONDER_OFFCHAN_SLOTS; i++)
		if (wma_wonder_offchan.slots[i].nbuf) {
			wma_wonder_offchan.slots[i].releasing = true;
			wma_wonder_offchan_release(&wma_wonder_offchan.slots[i], true);
		}
	CHECK(!atomic_load(&pins) && atomic_load(&device.refs) == 1);
	printf("%u\n", atomic_load(&assertions));
	return 0;
}
