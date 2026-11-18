/* Actual MLME/dispatcher/SCM/target functions, with framework-only mocks. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned int assertions;
#define CHECK(x) do { assertions++; assert(x); } while (0)
typedef int QDF_STATUS;
enum { QDF_STATUS_SUCCESS, QDF_STATUS_E_BUSY, QDF_STATUS_E_NULL_VALUE,
 QDF_STATUS_E_AGAIN, QDF_STATUS_E_FAILURE, QDF_STATUS_E_INVAL,
 WLAN_SCAN_ID, QDF_MODULE_ID_OS_IF, QDF_MODULE_ID_SCAN,
 QDF_MODULE_ID_SERIALIZATION, WLAN_UMAC_COMP_SCAN, WLAN_SER_CMD_SCAN,
 WLAN_SER_CANCEL_SINGLE_SCAN, WLAN_SERIALIZATION_ACTIVE_QUEUE };
#define QDF_IS_STATUS_ERROR(s) ((s) != QDF_STATUS_SUCCESS)
#define QDF_ASSERT(x) CHECK(x)
#define U32_MAX UINT32_MAX
#define WLAN_INVALID_VDEV_ID UINT8_MAX
#define SCAN_TIMEOUT_GRACE_PERIOD 100
#define scm_err(...) do { } while (0)
#define scm_err_rl(...) do { } while (0)
#define scm_info(...) do { } while (0)
#define scm_debug(...) do { } while (0)
#define target_if_err(...) do { } while (0)
#define qdf_mtrace(...) do { } while (0)
#define fallthrough __attribute__((fallthrough))
#define qdf_mem_copy memcpy
static unsigned int lock_depth;
#define DEFINE_SPINLOCK(name) unsigned int name __attribute__((unused))
#define spin_lock_irqsave(lock, flags) do { (void)(lock); (flags) = 0; CHECK(!lock_depth); lock_depth++; } while (0)
#define spin_unlock_irqrestore(lock, flags) do { (void)(lock); (void)(flags); CHECK(lock_depth == 1); lock_depth--; } while (0)
static DEFINE_SPINLOCK(sta_mon_lock);
struct wlan_objmgr_psoc;
struct wlan_objmgr_vdev;
struct wlan_channel { uint32_t ch_freq; };
struct element_info { void *ptr; unsigned int len; };
struct scan_req_params {
 uint32_t vdev_id, scan_id, scan_req_id, max_scan_time;
 struct { uint32_t num_chan; struct { uint32_t freq; } chan[4]; } chan_list;
 bool scan_f_offchan_data_tx;
 struct element_info extraie, htcap, vhtcap;
};
/* INSERT_DEFINITIONS */

struct wlan_mlme_psoc_ext_obj { struct wlan_mlme_sta_mon_control sta_mon; };
struct wlan_objmgr_psoc { unsigned int refs; struct wlan_mlme_psoc_ext_obj ext; };
struct wlan_objmgr_vdev {
 unsigned int refs;
 struct wlan_objmgr_psoc *psoc;
 struct { uint8_t vdev_id; } vdev_objmgr;
};
struct wlan_scan_obj { bool disable_timeout; struct scan_start_request scan_start_request_buff; };
struct scheduler_msg {
 void *bodyptr;
 QDF_STATUS (*callback)(struct scheduler_msg *);
 QDF_STATUS (*flush_callback)(struct scheduler_msg *);
};
enum wlan_serialization_status { WLAN_SER_CMD_PENDING, WLAN_SER_CMD_ACTIVE, WLAN_SER_CMD_DENIED };
enum wlan_serialization_cb_reason {
 WLAN_SER_CB_ACTIVATE_CMD, WLAN_SER_CB_CANCEL_CMD,
 WLAN_SER_CB_ACTIVE_CMD_TIMEOUT, WLAN_SER_CB_RELEASE_MEM_CMD
};
struct wlan_serialization_command {
 uint32_t cmd_type, cmd_id, source, cmd_timeout_duration;
 bool is_high_priority;
 struct wlan_objmgr_vdev *vdev;
 void *umac_cmd;
 QDF_STATUS (*cmd_cb)(struct wlan_serialization_command *, enum wlan_serialization_cb_reason);
};
struct wlan_serialization_queued_cmd_info {
 uint32_t requestor, cmd_type, cmd_id, req_type, queue_type;
 struct wlan_objmgr_vdev *vdev;
};
struct wmi_unified { unsigned int unused; };
typedef void *ol_scn_t;
struct wlan_lmac_if_scan_rx_ops {
 QDF_STATUS (*scan_ev_handler)(struct wlan_objmgr_psoc *, struct scan_event_info *);
};
struct wlan_lmac_if_rx_ops { struct wlan_lmac_if_scan_rx_ops scan; };

static struct wlan_objmgr_psoc psoc;
static struct wlan_objmgr_vdev vdev;
static struct wlan_scan_obj scan_obj;
static struct wmi_unified wmi;
static struct wlan_lmac_if_rx_ops rx_ops;
static struct scheduler_msg scheduled;
static struct wlan_serialization_command serialized;
static bool queued, serialized_live, serialized_active;
static bool scan_allowed, scan_object_present, psoc_ref_fail, vdev_ref_fail;
static bool scheduler_fail, alloc_fail, decode_fail, rx_ops_missing, wmi_missing;
static bool driver_recovering, driver_unloading, fw_down;
static bool synchronous_started, parameter_rewrite, enforce_observer_order;
static enum wlan_serialization_status serialization_status;
static QDF_STATUS target_status, cancel_status, utility_status, activation_status;
static unsigned int requests_allocated, requests_freed, event_allocations, event_frees;
static unsigned int target_attempts, target_accepted, cancels, param_updates, stop_calls;
static unsigned int fw_notices, not_submitted_notices, listener_posts, queue_queries;
static unsigned int before_emit_notices;
static struct scan_event last_notice, last_listener;
static struct wlan_mlme_sta_mon_scan_reservation reservation;

static struct wlan_mlme_psoc_ext_obj *mlme_get_psoc_ext_obj(struct wlan_objmgr_psoc *p) { return &p->ext; }
static bool cds_is_driver_recovering(void) { return driver_recovering; }
static bool cds_is_driver_unloading(void) { return driver_unloading; }
static bool cds_is_fw_down(void) { return fw_down; }
static struct wlan_objmgr_psoc *wlan_vdev_get_psoc(struct wlan_objmgr_vdev *v) { return v->psoc; }
static uint8_t wlan_vdev_get_id(struct wlan_objmgr_vdev *v) { return v->vdev_objmgr.vdev_id; }
static struct wlan_scan_obj *wlan_vdev_get_scan_obj(struct wlan_objmgr_vdev *v) { CHECK(v == &vdev); return scan_object_present ? &scan_obj : NULL; }
static QDF_STATUS wlan_objmgr_psoc_try_get_ref(struct wlan_objmgr_psoc *p, int id)
{ CHECK(p == &psoc && id == WLAN_SCAN_ID); if (psoc_ref_fail) return QDF_STATUS_E_FAILURE; p->refs++; return 0; }
static void wlan_objmgr_psoc_release_ref(struct wlan_objmgr_psoc *p, int id)
{ CHECK(p == &psoc && id == WLAN_SCAN_ID && p->refs > 1); p->refs--; }
static QDF_STATUS wlan_objmgr_vdev_try_get_ref(struct wlan_objmgr_vdev *v, int id)
{ CHECK(v == &vdev && id == WLAN_SCAN_ID); if (vdev_ref_fail) return QDF_STATUS_E_FAILURE; v->refs++; return 0; }
static void wlan_objmgr_vdev_release_ref(struct wlan_objmgr_vdev *v, int id)
{ CHECK(v == &vdev && id == WLAN_SCAN_ID && v->refs > 1); v->refs--; }
static void *qdf_mem_malloc(size_t size)
{ if (alloc_fail) return NULL; event_allocations++; return calloc(1, size); }
static void qdf_mem_free(void *ptr) { if (ptr) event_frees++; free(ptr); }
static QDF_STATUS scm_scan_free_scan_request_mem(struct scan_start_request *req)
{ if (req) requests_freed++; free(req); return 0; }
static bool scm_is_scan_allowed(struct wlan_objmgr_vdev *v) { return v && scan_allowed; }
static QDF_STATUS scheduler_post_message(int a, int b, int c, struct scheduler_msg *msg)
{ CHECK(a == QDF_MODULE_ID_OS_IF && b == QDF_MODULE_ID_SCAN && c == a); CHECK(!queued); if (scheduler_fail) return QDF_STATUS_E_FAILURE; scheduled = *msg; queued = true; return 0; }
static void scm_scan_req_update_params(struct wlan_objmgr_vdev *v, struct scan_start_request *req, struct wlan_scan_obj *obj)
{ CHECK(v == &vdev && obj == &scan_obj); param_updates++; if (parameter_rewrite) { req->scan_req.chan_list.chan[0].freq = 2462; req->scan_req.scan_f_offchan_data_tx = false; } }
static void scm_print_scan_req_info(struct scan_req_params *req) { CHECK(req); }
static QDF_STATUS scm_update_last_scan_time(struct scan_start_request *req) { CHECK(req); return utility_status; }
static QDF_STATUS scm_scan_post_event(struct wlan_objmgr_vdev *v, struct scan_event *event)
{ CHECK(v == &vdev && !lock_depth); listener_posts++; last_listener = *event; return 0; }
static void scm_duration_init(struct wlan_scan_obj *s) { (void)s; }
static void scm_event_duration_start(struct wlan_scan_obj *s) { (void)s; }
static void scm_event_duration_end(struct wlan_scan_obj *s) { (void)s; }
static void scm_to_post_scan_duration_set(struct wlan_scan_obj *s) { (void)s; }
static void scm_update_last_scan_time_per_channel(struct wlan_objmgr_vdev *v, uint32_t f, uint32_t t) { (void)v; (void)f; (void)t; }
static uint32_t qdf_get_time_of_the_day_ms(void) { return 1; }
static void scm_pno_event_handler(struct wlan_objmgr_vdev *v, struct scan_event *e) { (void)v; (void)e; }
static void scm_11d_decide_country_code(struct wlan_objmgr_vdev *v) { CHECK(v == &vdev); }
static enum wlan_serialization_status wlan_serialization_request(struct wlan_serialization_command *cmd)
{
 CHECK(!serialized_live && cmd->vdev == &vdev);
 if (serialization_status == WLAN_SER_CMD_DENIED) return serialization_status;
 serialized = *cmd; serialized_live = true;
 serialized_active = serialization_status == WLAN_SER_CMD_ACTIVE;
 if (serialized_active) activation_status = serialized.cmd_cb(&serialized, WLAN_SER_CB_ACTIVATE_CMD);
 return serialization_status;
}
static bool wlan_serialization_is_cmd_present_in_active_queue(void *unused, struct wlan_serialization_command *cmd)
{
 (void)unused; queue_queries++;
 if (enforce_observer_order) CHECK(fw_notices > before_emit_notices);
 return serialized_live && serialized_active && serialized.cmd_id == cmd->cmd_id;
}
static struct wlan_serialization_command *wlan_serialization_get_scan_cmd_using_scan_id(struct wlan_objmgr_psoc *p, uint8_t id, uint32_t scan_id, bool active)
{ CHECK(p == &psoc && id == 1 && active); return serialized_live && serialized.cmd_id == scan_id ? &serialized : NULL; }
static void release_serialized(void)
{ CHECK(serialized_live); serialized_live = serialized_active = false; CHECK(serialized.cmd_cb(&serialized, WLAN_SER_CB_RELEASE_MEM_CMD) == 0); CHECK(!serialized.umac_cmd); }
static void wlan_serialization_remove_cmd(struct wlan_serialization_queued_cmd_info *cmd)
{ CHECK(cmd->vdev == &vdev && cmd->cmd_id == serialized.cmd_id); release_serialized(); }
static int emit_event(enum scan_event_type type, enum scan_completion_reason reason, unsigned int mismatch);
static QDF_STATUS tgt_scan_start(struct scan_start_request *req)
{
 CHECK(!lock_depth && req); target_attempts++;
 if (synchronous_started) CHECK(emit_event(SCAN_EVENT_TYPE_STARTED, SCAN_REASON_NONE, 0) == 0);
 if (!target_status) target_accepted++;
 return target_status;
}
static QDF_STATUS tgt_scan_cancel(struct scan_cancel_request *req)
{ CHECK(req->vdev == &vdev && !lock_depth); cancels++; return cancel_status; }

/* INSERT_MLME */
/* INSERT_SCM */
/* INSERT_API */

static struct wlan_objmgr_psoc *target_if_get_psoc_from_scn_hdl(ol_scn_t scn) { return scn == &psoc ? &psoc : NULL; }
static struct wmi_unified *get_wmi_unified_hdl_from_psoc(struct wlan_objmgr_psoc *p) { CHECK(p == &psoc); return wmi_missing ? NULL : &wmi; }
static struct wlan_lmac_if_rx_ops *wlan_psoc_get_lmac_if_rxops(struct wlan_objmgr_psoc *p) { CHECK(p == &psoc); return rx_ops_missing ? NULL : &rx_ops; }
static int wmi_extract_vdev_scan_ev_param(struct wmi_unified *handle, uint8_t *data, struct scan_event *event)
{ CHECK(handle == &wmi); if (decode_fail) return -EINVAL; memcpy(event, data, sizeof(*event)); return 0; }
static QDF_STATUS receive_scan_event(struct wlan_objmgr_psoc *p, struct scan_event_info *info)
{
 struct scheduler_msg msg = { .bodyptr = info };
 CHECK(p == &psoc && !lock_depth);
 if (info->event.vdev_id != vdev.vdev_objmgr.vdev_id)
  return QDF_STATUS_E_FAILURE;
 info->vdev = &vdev; vdev.refs++;
 return scm_scan_event_handler(&msg);
}
/* INSERT_TARGET */

static struct wlan_mlme_sta_mon_control *control(void) { return &psoc.ext.sta_mon; }
static void pause_owner(void *arg) { CHECK(arg == &psoc && lock_depth == 1); stop_calls++; }
static void scan_notice(void *arg, const struct scan_event *event,
 enum wlan_mlme_sta_mon_scan_notice notice, uint64_t generation, uint64_t cookie)
{
 CHECK(arg == &reservation && lock_depth == 1);
 CHECK(generation == 100 && cookie == 777);
 CHECK(event->vdev_id == 1 && event->scan_id == 123 && event->requester == 456);
 last_notice = *event;
 if (notice == WLAN_STA_MON_SCAN_FIRMWARE) fw_notices++;
 else { CHECK(notice == WLAN_STA_MON_SCAN_NOT_SUBMITTED); not_submitted_notices++; }
}
static void balanced(void)
{
 CHECK(!queued && !serialized_live && !lock_depth);
 CHECK(psoc.refs == 1 && vdev.refs == 1);
 CHECK(!control()->admissions && !control()->updates);
 CHECK(requests_allocated == requests_freed);
 CHECK(event_allocations == event_frees);
}
static void reset(void)
{
 if (psoc.refs) balanced();
 memset(&psoc, 0, sizeof(psoc)); memset(&vdev, 0, sizeof(vdev)); memset(&scan_obj, 0, sizeof(scan_obj));
 psoc.refs = vdev.refs = 1; vdev.psoc = &psoc; vdev.vdev_objmgr.vdev_id = 1;
 *control() = (struct wlan_mlme_sta_mon_control) { .attached = true, .state = WLAN_STA_MON_READY,
  .snapshot = { .generation = 100, .mon_vdev_id = 1, .sta_vdev_id = 0, .channel = { .ch_freq = 2412 } },
  .stop = pause_owner, .arg = &psoc };
 reservation = (struct wlan_mlme_sta_mon_scan_reservation) { .generation = 100, .helper_cookie = 777,
  .vdev_id = 1, .scan_id = 123, .requester = 456, .frequency = 2437 };
 scan_allowed = scan_object_present = true;
 psoc_ref_fail = vdev_ref_fail = scheduler_fail = alloc_fail = decode_fail = false;
 rx_ops_missing = wmi_missing = synchronous_started = false;
 parameter_rewrite = enforce_observer_order = false;
 driver_recovering = driver_unloading = fw_down = false;
 serialization_status = WLAN_SER_CMD_ACTIVE;
 target_status = cancel_status = utility_status = activation_status = 0;
 requests_allocated = requests_freed = event_allocations = event_frees = 0;
 target_attempts = target_accepted = cancels = param_updates = stop_calls = 0;
 fw_notices = not_submitted_notices = listener_posts = queue_queries = 0;
 rx_ops.scan.scan_ev_handler = receive_scan_event;
}
static void reserve(void) { CHECK(wlan_mlme_sta_mon_scan_reserve(&psoc, &reservation, scan_notice, &reservation)); }
static struct scan_start_request *request(bool ordinary)
{
 struct scan_start_request *req = calloc(1, sizeof(*req)); CHECK(req); requests_allocated++;
 req->vdev = &vdev;
 req->scan_req = (struct scan_req_params) { .vdev_id = 1, .scan_id = ordinary ? 987 : 123,
  .scan_req_id = 456, .max_scan_time = 50, .scan_f_offchan_data_tx = !ordinary,
  .chan_list = { .num_chan = 1, .chan = {{ .freq = 2437 }} } };
 return req;
}
static QDF_STATUS dispatch(bool flush)
{
 struct scheduler_msg msg = scheduled; CHECK(queued); queued = false;
 return flush ? msg.flush_callback(&msg) : msg.callback(&msg);
}
static int emit_event(enum scan_event_type type, enum scan_completion_reason reason, unsigned int mismatch)
{
 struct scan_event event = { .vdev_id = 1, .type = type, .reason = reason,
  .chan_freq = 2437, .scan_id = 123, .requester = 456 };
 if (mismatch == 1) event.vdev_id++;
 if (mismatch == 2) event.scan_id++;
 if (mismatch == 3) event.requester++;
 before_emit_notices = fw_notices;
 return target_if_scan_event_handler(&psoc, (uint8_t *)&event, sizeof(event));
}
static void submit(void)
{
 reserve(); CHECK(wlan_scan_start(request(false)) == 0);
 CHECK(queued && control()->admissions == 1 && control()->scan_submission_started);
 CHECK(control()->snapshot.generation == 100 && control()->state == WLAN_STA_MON_READY && !stop_calls);
 CHECK(dispatch(false) == 0); CHECK(!control()->admissions);
}
static void terminal(void)
{
 enforce_observer_order = true;
 CHECK(emit_event(SCAN_EVENT_TYPE_COMPLETED, SCAN_REASON_COMPLETED, 0) == 0);
 enforce_observer_order = false;
 CHECK(!control()->scan_reserved); balanced();
}
static void test_accepted_cancellation(void)
{
 for (unsigned int mode = 0; mode < 3; mode++) {
  reset(); submit(); CHECK(target_accepted == 1 && control()->scan_fw_pending && !fw_notices);
  CHECK(!wlan_mlme_sta_mon_scan_release_unsubmitted(&psoc, &reservation));
  if (mode == 0) CHECK(serialized.cmd_cb(&serialized, WLAN_SER_CB_CANCEL_CMD) == 0);
  if (mode == 1) CHECK(serialized.cmd_cb(&serialized, WLAN_SER_CB_ACTIVE_CMD_TIMEOUT) == 0);
  if (mode == 2) { cancel_status = QDF_STATUS_E_FAILURE; CHECK(scm_cancel_scan_request(serialized.umac_cmd) == QDF_STATUS_E_FAILURE); }
  CHECK(control()->scan_reserved && !not_submitted_notices && !fw_notices);
  CHECK(listener_posts == 1 && last_listener.type == SCAN_EVENT_TYPE_COMPLETED);
  release_serialized(); CHECK(control()->scan_reserved);
  terminal(); CHECK(fw_notices == 1 && !not_submitted_notices && listener_posts == 1);
  CHECK(queue_queries == 1);
  CHECK(emit_event(SCAN_EVENT_TYPE_COMPLETED, SCAN_REASON_COMPLETED, 0) == 0);
  CHECK(fw_notices == 1 && listener_posts == 1); balanced();
 }
}
static void test_pending_and_send_errors(void)
{
 reset(); serialization_status = WLAN_SER_CMD_PENDING; submit();
 CHECK(!target_attempts && !control()->scan_fw_pending);
 CHECK(serialized.cmd_cb(&serialized, WLAN_SER_CB_CANCEL_CMD) == 0);
 CHECK(!control()->scan_reserved && not_submitted_notices == 1 && !fw_notices);
 release_serialized(); balanced();
 reset(); target_status = QDF_STATUS_E_FAILURE; submit();
 CHECK(activation_status == QDF_STATUS_E_FAILURE && target_attempts == 1 && !target_accepted);
 CHECK(not_submitted_notices == 1 && !control()->scan_reserved && listener_posts == 1);
 release_serialized(); balanced();
 reset(); target_status = QDF_STATUS_E_FAILURE; synchronous_started = true; submit();
 CHECK(activation_status == QDF_STATUS_E_FAILURE && fw_notices == 1 && !not_submitted_notices);
 CHECK(control()->scan_reserved && control()->scan_fw_observed);
 CHECK(serialized.cmd_cb(&serialized, WLAN_SER_CB_CANCEL_CMD) == 0);
 CHECK(control()->scan_reserved && !not_submitted_notices); release_serialized(); terminal(); CHECK(fw_notices == 2);
 reset(); utility_status = QDF_STATUS_E_FAILURE; submit();
 CHECK(activation_status == QDF_STATUS_E_FAILURE && target_accepted == 1);
 CHECK(control()->scan_reserved && !not_submitted_notices && !listener_posts);
 release_serialized(); terminal();
}
static void test_rejections_and_flushes(void)
{
 for (unsigned int mode = 0; mode < 10; mode++) {
  reset(); reserve(); struct scan_start_request *req = request(false);
  if (mode == 0) scan_allowed = false;
  if (mode == 1) vdev_ref_fail = true;
  if (mode == 2) scheduler_fail = true;
  QDF_STATUS status = wlan_scan_start(req);
  if (mode < 3) {
   CHECK(status == (mode == 0 ? QDF_STATUS_E_AGAIN : QDF_STATUS_E_FAILURE));
  } else {
   CHECK(status == 0);
   if (mode == 3) psoc_ref_fail = true;
   if (mode == 5) scan_allowed = false;
   if (mode == 6) scan_object_present = false;
   if (mode == 7) ((struct scan_start_request *)scheduled.bodyptr)->scan_req.chan_list.num_chan = 0;
   if (mode == 8) serialization_status = WLAN_SER_CMD_DENIED;
   if (mode == 9) psoc_ref_fail = true;
   status = dispatch(mode == 4 || mode == 9);
   if (mode == 8) CHECK(status == QDF_STATUS_E_FAILURE);
   if (mode >= 5 && mode <= 7) CHECK(status == QDF_STATUS_E_NULL_VALUE);
  }
  CHECK(!control()->scan_reserved && not_submitted_notices == 1 && !fw_notices && !target_attempts);
  CHECK(!stop_calls && !param_updates && control()->snapshot.generation == 100);
  balanced();
 }
}
static void test_duplicate_and_admission(void)
{
 reset(); reserve(); CHECK(wlan_scan_start(request(false)) == 0);
 CHECK(wlan_scan_start(request(false)) == QDF_STATUS_E_BUSY);
 CHECK(control()->scan_reserved && !not_submitted_notices && control()->admissions == 1);
 CHECK(dispatch(false) == 0); CHECK(target_accepted == 1);
 CHECK(wlan_scan_start(request(false)) == QDF_STATUS_E_BUSY);
 CHECK(control()->scan_reserved && !not_submitted_notices);
 release_serialized(); terminal();
 for (unsigned int mode = 0; mode < 4; mode++) {
  reset(); reserve(); struct scan_start_request *req = request(false);
  if (mode == 0) req->scan_req.chan_list.num_chan = 2;
  if (mode == 1) req->scan_req.chan_list.chan[0].freq = 2462;
  if (mode == 2) req->scan_req.scan_f_offchan_data_tx = false;
  if (mode == 3) control()->snapshot.generation++;
  CHECK(wlan_scan_start(req) == QDF_STATUS_E_BUSY);
  CHECK(control()->scan_reserved && !control()->scan_submission_started && !not_submitted_notices);
  CHECK(wlan_mlme_sta_mon_scan_release_unsubmitted(&psoc, &reservation)); balanced();
 }
}
static void test_activation_and_ordinary(void)
{
 for (unsigned int mode = 0; mode < 9; mode++) {
  reset(); reserve(); CHECK(wlan_scan_start(request(false)) == 0);
  struct scan_start_request *req = scheduled.bodyptr;
  if (mode == 0) req->scan_req.chan_list.num_chan = 2;
  if (mode == 1) req->scan_req.chan_list.chan[0].freq = 2462;
  if (mode == 2) req->scan_req.scan_f_offchan_data_tx = false;
  if (mode == 3) control()->snapshot.generation++;
  if (mode == 4) control()->fw_uncertain = true;
  if (mode == 5) req->scan_req.scan_id++;
  if (mode == 6) req->scan_req.scan_req_id++;
  if (mode == 7) req->scan_req.vdev_id++;
  if (mode == 8) req->sta_mon_reserved = false;
  CHECK(dispatch(false) == 0); CHECK(activation_status == QDF_STATUS_E_BUSY);
  CHECK(!target_attempts);
  if (mode >= 5 && mode <= 7) {
   CHECK(!not_submitted_notices && control()->scan_reserved && !control()->scan_fw_pending);
   /* Only the exact original tuple may retire the proven unsubmitted lease. */
   struct scan_event original = { .vdev_id = 1, .scan_id = 123, .requester = 456,
    .type = SCAN_EVENT_TYPE_COMPLETED };
   wlan_mlme_sta_mon_scan_not_submitted(&psoc, &original);
  }
  CHECK(not_submitted_notices == 1 && !control()->scan_reserved);
  release_serialized(); balanced();
 }
 reset(); parameter_rewrite = true; submit();
 CHECK(!param_updates && ((struct scan_start_request *)serialized.umac_cmd)->scan_req.chan_list.chan[0].freq == 2437);
 release_serialized(); terminal();
 for (unsigned int flush = 0; flush < 2; flush++) {
  reset(); parameter_rewrite = true; CHECK(wlan_scan_start(request(true)) == 0);
  CHECK(control()->updates == 1 && control()->state == WLAN_STA_MON_QUIESCING);
  CHECK(stop_calls == 1 && control()->snapshot.generation == 101);
  CHECK(dispatch(flush) == 0); CHECK(control()->snapshot.generation == 102);
  CHECK(param_updates == !flush && !control()->updates && !control()->admissions);
  if (!flush) { CHECK(target_accepted == 1); release_serialized(); }
  balanced();
 }
 reset(); psoc_ref_fail = true; CHECK(wlan_scan_start(request(true)) == 0);
 CHECK(dispatch(false) == 0); CHECK(control()->snapshot.generation == 102); balanced();
 reset(); scheduler_fail = true; CHECK(wlan_scan_start(request(true)) == QDF_STATUS_E_FAILURE);
 CHECK(control()->snapshot.generation == 102 && stop_calls == 1); balanced();
 CHECK(!wlan_mlme_sta_mon_scan_activate(NULL, 1, 123, 456, 2437, 1, true, true));
 CHECK(wlan_mlme_sta_mon_scan_activate(NULL, 1, 123, 456, 2437, 1, true, false));
}
static void test_target_observation(void)
{
 reset(); submit(); decode_fail = true;
 CHECK(emit_event(SCAN_EVENT_TYPE_COMPLETED, SCAN_REASON_COMPLETED, 0) == -EINVAL);
 CHECK(control()->scan_reserved && !fw_notices && !queue_queries);
 decode_fail = false; alloc_fail = true;
 CHECK(emit_event(SCAN_EVENT_TYPE_COMPLETED, SCAN_REASON_COMPLETED, 0) == -ENOMEM);
 CHECK(!fw_notices); alloc_fail = false;
 for (unsigned int mismatch = 1; mismatch <= 3; mismatch++) {
  CHECK(emit_event(SCAN_EVENT_TYPE_COMPLETED, SCAN_REASON_COMPLETED, mismatch) == (mismatch == 1 ? -EINVAL : 0));
  CHECK(control()->scan_reserved && !fw_notices);
 }
 release_serialized(); terminal();
 for (unsigned int mode = 0; mode < 3; mode++) {
  reset(); submit(); release_serialized();
  if (mode == 0) rx_ops_missing = true;
  if (mode == 1) rx_ops.scan.scan_ev_handler = NULL;
  if (mode == 2) wmi_missing = true;
  CHECK(emit_event(SCAN_EVENT_TYPE_COMPLETED, SCAN_REASON_COMPLETED, 0) == -EINVAL);
  if (mode == 2) { CHECK(control()->scan_reserved && !fw_notices); wmi_missing = false; terminal(); }
  else CHECK(!control()->scan_reserved && fw_notices == 1 && !queue_queries);
  balanced();
 }
 for (unsigned int type = 0; type < 3; type++) {
  reset(); submit();
  enum scan_event_type event_type = type == 0 ? SCAN_EVENT_TYPE_COMPLETED :
   type == 1 ? SCAN_EVENT_TYPE_START_FAILED : SCAN_EVENT_TYPE_DEQUEUED;
  enforce_observer_order = true;
  CHECK(emit_event(event_type, SCAN_REASON_CANCELLED, 0) == 0);
  enforce_observer_order = false;
  CHECK(!control()->scan_reserved && !serialized_live && fw_notices == 1 && listener_posts == 1);
  balanced();
 }
 reset(); reserve(); CHECK(emit_event(SCAN_EVENT_TYPE_COMPLETED, SCAN_REASON_COMPLETED, 0) == 0);
 CHECK(control()->scan_reserved && !fw_notices);
 CHECK(wlan_mlme_sta_mon_scan_release_unsubmitted(&psoc, &reservation)); balanced();
}
static void test_reservation_guards(void)
{
 for (unsigned int mode = 0; mode < 14; mode++) {
  reset(); struct wlan_mlme_sta_mon_scan_reservation bad = reservation;
  if (mode == 0) bad.generation = 0;
  if (mode == 1) bad.helper_cookie = 0;
  if (mode == 2) bad.frequency = 0;
  if (mode == 3) bad.frequency = 65536;
  if (mode == 4) bad.vdev_id = WLAN_INVALID_VDEV_ID;
  if (mode == 5) bad.frequency = 2412;
  if (mode == 6) driver_recovering = true;
  if (mode == 7) driver_unloading = true;
  if (mode == 8) fw_down = true;
  if (mode == 9) control()->updates = 1;
  if (mode == 10) control()->admissions = 1;
  if (mode == 11) control()->snapshot.ap_owner = true;
  if (mode == 12) control()->exclusive_lease = true;
  if (mode == 13) control()->handoff_generation = 100;
  CHECK(!wlan_mlme_sta_mon_scan_reserve(&psoc, &bad, scan_notice, &reservation));
  CHECK(!control()->scan_reserved); control()->updates = control()->admissions = 0; balanced();
 }
 reset(); reserve(); CHECK(!wlan_mlme_sta_mon_scan_reserve(&psoc, &reservation, scan_notice, &reservation));
 for (unsigned int mode = 0; mode < 5; mode++) {
  struct wlan_mlme_sta_mon_scan_reservation bad = reservation;
  if (mode == 0) bad.vdev_id++;
  if (mode == 1) bad.scan_id++;
  if (mode == 2) bad.requester++;
  if (mode == 3) bad.generation++;
  if (mode == 4) bad.helper_cookie++;
  CHECK(!wlan_mlme_sta_mon_scan_release_unsubmitted(&psoc, &bad)); CHECK(control()->scan_reserved);
 }
 CHECK(wlan_mlme_sta_mon_scan_release_unsubmitted(&psoc, &reservation));
 CHECK(!wlan_mlme_sta_mon_scan_release_unsubmitted(&psoc, &reservation)); balanced();
 reset(); CHECK(wlan_scan_start(NULL) == QDF_STATUS_E_NULL_VALUE);
 struct scan_start_request *req = request(false); req->vdev = NULL;
 CHECK(wlan_scan_start(req) == QDF_STATUS_E_NULL_VALUE); balanced();
}
int main(void)
{
 test_accepted_cancellation(); test_pending_and_send_errors(); test_rejections_and_flushes();
 test_duplicate_and_admission(); test_activation_and_ordinary();
 test_target_observation(); test_reservation_guards(); balanced();
 printf("%u\n", assertions); return 0;
}
