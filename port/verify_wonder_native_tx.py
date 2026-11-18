#!/usr/bin/env python3
"""Exercise extracted production WMI admission/send and HDD fallback bodies."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_function(source: str, name: str) -> str:
    match = re.search(r'(?m)^(?:static )?(?:QDF_STATUS|int) ' + name + r'\(', source)
    if match is None:
        raise AssertionError(f'Missing production definition: {name}')
    start = source.index('{', match.start())
    depth = 0
    for end in range(start, len(source)):
        if source[end] == '{':
            depth += 1
        elif source[end] == '}':
            depth -= 1
            if depth == 0:
                return source[match.start():end + 1]
    raise AssertionError(f'Unclosed production definition: {name}')


PREFIX = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>

typedef int QDF_STATUS;
typedef uint16_t __le16;
enum { QDF_STATUS_SUCCESS=0, QDF_STATUS_E_INVAL=1, QDF_STATUS_E_NOSUPPORT=2,
       QDF_STATUS_E_NOMEM=3, QDF_STATUS_E_CANCELED=4, QDF_STATUS_E_BUSY=5,
       QDF_STATUS_E_AGAIN=6 };
#define QDF_IS_STATUS_ERROR(s) ((s) != QDF_STATUS_SUCCESS)
#define U16_MAX UINT16_MAX
#define BIT(n) (1u << (n))
#define CDP_INJECTION_VHT 3
#define THIS_MODULE ((void *)1)
#define WMA_WONDER_OFFCHAN_SLOTS 64
#define READ_ONCE(v) (v)
#define WRITE_ONCE(v, x) ((v)=(x))
#define smp_load_acquire(v) (*(v))
#define rcu_dereference(v) (v)
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define qdf_mem_zero(p,n) memset((p),0,(n))
#define atomic64_inc(p) atomic_fetch_add((p),1)
#define QDF_MIN(a,b) ((a)<(b)?(a):(b))
#define cpu_to_le16(v) (v)
#define CHANNEL_STATE_ENABLE 1
#define CH_WIDTH_20MHZ 20
#define REG_CURRENT_PWR_MODE 0
#define REG_INVALID_TXPOWER 255

struct sk_buff { unsigned int len; unsigned char data[32]; unsigned int consumed; };
typedef struct sk_buff *qdf_nbuf_t;
struct cdp_tx_injection_params {
    bool rate_valid, bandwidth_valid, gi_valid, no_ack, is_data;
    unsigned int he_ltf, tx_flags, bw_mask, preamble;
    unsigned char interface_mac[6];
};
struct wma_wonder_helper_snapshot { uint64_t cookie; uint8_t vdev_id; };
struct device { unsigned int refs; };
struct qdf_device { struct device *dev; };
struct wma_injection_helper {
    bool native; uint8_t expected_mac_id;
    struct { struct { uint8_t maxpower; } channel; } start;
};
struct tx_send_params { int unused; };
struct vdev_mlme_obj { struct { struct { uint8_t maxpower; } generic; } mgmt; };
struct wlan_mlme_sta_mon_snapshot { bool exclusive; };
struct wma {
    void *psoc, *pdev, *wmi_handle; struct qdf_device *qdf_dev;
    struct { void *vdev; } interfaces[4];
};
typedef struct wma *tp_wma_handle;
struct wma_wonder_offchan_slot {
    qdf_nbuf_t nbuf; struct qdf_device dma_device;
    uint32_t desc_id, pdev_id; bool publishing, completion_seen, releasing;
};
struct wmi_offchan_data_tx_params {
    struct tx_send_params tx_param;
    qdf_nbuf_t tx_frame; unsigned int frm_len, vdev_id, desc_id, chanfreq;
    void *pdata; struct qdf_device *qdf_ctx; bool tx_params_valid;
};
struct list_head { struct list_head *next, *prev; };
static struct list_head wma_wonder_offchan_queue;
static void list_add_tail(struct list_head *node, struct list_head *head) {
    node->prev=head->prev; node->next=head; head->prev->next=node; head->prev=node;
}
static void list_del(struct list_head *node) {
    node->prev->next=node->next; node->next->prev=node->prev;
}
static pthread_mutex_t wma_wonder_offchan_lock=PTHREAD_MUTEX_INITIALIZER;
static struct {
    struct wma_wonder_offchan_slot slots[WMA_WONDER_OFFCHAN_SLOTS];
    void *wmi_handle, *wma_context;
    uint32_t next_desc; unsigned int queued, in_flight;
    uint64_t descriptor_exhausted; bool registered, accepting;
} wma_wonder_offchan;
static struct {
    bool active; tp_wma_handle wma; struct wma_injection_helper helper;
    pthread_mutex_t lifecycle_lock, helper_lock, lock;
    unsigned int in_flight;
} wma_injection_ctx = {
    .lifecycle_lock=PTHREAD_MUTEX_INITIALIZER,
    .helper_lock=PTHREAD_MUTEX_INITIALIZER,
    .lock=PTHREAD_MUTEX_INITIALIZER,
};
static _Atomic uint64_t injection_accepted;
static _Atomic unsigned int allocations, frees, pins, work_scheduled;
static bool allocation_allowed, pin_allowed;
static unsigned int wma_wonder_offchan_work;
#define spin_lock_irqsave(lock,flags) do { (flags)=0; assert(!pthread_mutex_lock(lock)); } while(0)
#define spin_unlock_irqrestore(lock,flags) do { (void)(flags); assert(!pthread_mutex_unlock(lock)); } while(0)
#define mutex_lock(lock) assert(!pthread_mutex_lock(lock))
#define mutex_unlock(lock) assert(!pthread_mutex_unlock(lock))
static void *qdf_mem_malloc_atomic(size_t size) {
    if (!allocation_allowed) return NULL;
    void *p=calloc(1,size); assert(p); atomic_fetch_add(&allocations,1); return p;
}
static void qdf_mem_free(void *p) { assert(p); atomic_fetch_add(&frees,1); free(p); }
static bool try_module_get(void *module) {
    (void)module; if (!pin_allowed) return false; atomic_fetch_add(&pins,1); return true;
}
static void module_put(void *module) { (void)module; assert(atomic_fetch_sub(&pins,1)>0); }
static void schedule_work(unsigned int *work) { (void)work; atomic_fetch_add(&work_scheduled,1); }
static unsigned int qdf_nbuf_len(qdf_nbuf_t n) { return n->len; }
static bool qdf_nbuf_is_nonlinear(qdf_nbuf_t n) { (void)n; return false; }
static unsigned int qdf_nbuf_get_num_frags(qdf_nbuf_t n) { (void)n; return 1; }
static void *qdf_nbuf_data(qdf_nbuf_t n) { return n->data; }
static uint16_t get_unaligned_le16(void *p) {
    const unsigned char *b=p; return b[0] | (uint16_t)b[1]<<8;
}
static bool ieee80211_is_mgmt(__le16 fc) { return (fc & 12)==0; }
static bool ieee80211_is_data(__le16 fc) { return (fc & 12)==8; }
static bool wma_wonder_offchan_helper_valid(tp_wma_handle w, uint8_t m, uint32_t f,
    const uint8_t *mac, uint64_t g, const struct wma_wonder_helper_snapshot *s) {
    (void)w;(void)m;(void)f;(void)mac;(void)g;(void)s; return true;
}
static bool wlan_mlme_sta_mon_get_snapshot(void *p, uint8_t m, uint64_t g,
    struct wlan_mlme_sta_mon_snapshot *s) {
    (void)p;(void)m;(void)g; s->exclusive=true; return true;
}
static bool wlan_reg_is_24ghz_ch_freq(uint32_t f) { return f>=2400 && f<2500; }
static bool wlan_reg_is_5ghz_ch_freq(uint32_t f) { return f>=5000 && f<6000; }
static int wlan_reg_get_bonded_channel_state_for_pwrmode(void *p, uint32_t f,
    int w, int c, int mode) { (void)p;(void)f;(void)w;(void)c;(void)mode; return CHANNEL_STATE_ENABLE; }
static uint8_t wlan_reg_get_channel_reg_power_for_freq(void *p, uint32_t f) {
    (void)p;(void)f; return 20;
}
static struct vdev_mlme_obj *wlan_vdev_mlme_get_cmpt_obj(void *v) {
    static struct vdev_mlme_obj obj={.mgmt.generic.maxpower=20}; (void)v; return &obj;
}
static QDF_STATUS wma_wonder_offchan_encode(const struct cdp_tx_injection_params *p,
    const struct wma_injection_helper *h, uint32_t f, int16_t power, struct tx_send_params *out) {
    (void)p;(void)h;(void)f;(void)power;(void)out; return QDF_STATUS_SUCCESS;
}
static QDF_STATUS wmi_offchan_data_tx_pdev_id(void *w, uint32_t id, uint32_t *out) {
    (void)w;*out=id;return QDF_STATUS_SUCCESS;
}
static struct device *get_device(struct device *d) { d->refs++;return d; }
static bool guard_allowed;
static bool wlan_mlme_sta_mon_tx_begin(void *p,uint8_t m,uint64_t g,unsigned long *f) {
    (void)p;(void)m;(void)g;*f=0;return guard_allowed;
}
static void wlan_mlme_sta_mon_tx_end(unsigned long f) { (void)f; }
static unsigned int sent_id, send_calls, slot_releases;
static QDF_STATUS send_result;
static QDF_STATUS wmi_offchan_data_tx_cmd_send(void *w, struct wmi_offchan_data_tx_params *c) {
    (void)w;send_calls++;sent_id=c->desc_id;return send_result;
}
static void wma_wonder_offchan_release(struct wma_wonder_offchan_slot *s,bool mapped) {
    (void)mapped;slot_releases++;s->dma_device.dev->refs--;memset(s,0,sizeof(*s));
    wma_wonder_offchan.in_flight--;wma_injection_ctx.in_flight--;module_put(THIS_MODULE);
}
struct hdd_adapter { unsigned int id; };
struct hdd_wonder_session { struct hdd_adapter *adapter; bool suspended,failed,native_group_ready; };
static struct hdd_wonder_session *hdd_wonder_active;
static bool wonder_native_group_tx;
static QDF_STATUS queue_result;
static bool mdns_result;
static unsigned int queue_calls,mdns_calls;
static struct sk_buff *queued_original,*mdns_original;
static QDF_STATUS hdd_wonder_queue_tx(struct hdd_wonder_session *s,struct sk_buff *b,
    const struct cdp_tx_injection_params *p) {
    (void)s;(void)p;queue_calls++;queued_original=b;
    if (!QDF_IS_STATUS_ERROR(queue_result)) b->consumed++;
    return queue_result;
}
static bool hdd_wonder_tx_mdns(struct hdd_wonder_session *s,struct sk_buff *b,
    const struct cdp_tx_injection_params *p) {
    (void)s;(void)p;mdns_calls++;mdns_original=b;
    if (mdns_result) b->consumed++;
    return mdns_result;
}
static int qdf_status_to_os_return(QDF_STATUS s) { return -s; }
'''

TESTS = r'''
static struct cdp_tx_injection_params valid_params(void) {
    return (struct cdp_tx_injection_params){.rate_valid=true,.bandwidth_valid=true,
        .bw_mask=BIT(2),.preamble=0,.is_data=true};
}
static struct sk_buff valid_frame(void) {
    struct sk_buff b={.len=24};b.data[0]=8;return b;
}
static struct wma_wonder_helper_snapshot snapshot={.cookie=1,.vdev_id=2};
static QDF_STATUS admit(struct sk_buff *b, const struct cdp_tx_injection_params *p) {
    return wma_wonder_offchan_tx(b,2,2437,1,&snapshot,2437,p,NULL,NULL,NULL,NULL);
}
static void reset(void) {
    assert(!atomic_load(&pins));
    memset(&wma_wonder_offchan,0,sizeof(wma_wonder_offchan));
    wma_wonder_offchan.registered=wma_wonder_offchan.accepting=true;
    wma_wonder_offchan_queue.next=wma_wonder_offchan_queue.prev=&wma_wonder_offchan_queue;
    wma_injection_ctx.active=true;wma_injection_ctx.in_flight=0;
    allocation_allowed=pin_allowed=guard_allowed=true;
    allocations=frees=pins=work_scheduled=injection_accepted=0;
    sent_id=send_calls=slot_releases=0;send_result=QDF_STATUS_SUCCESS;
}
static struct wma_wonder_offchan_packet *pop(void) {
    assert(wma_wonder_offchan_queue.next!=&wma_wonder_offchan_queue);
    struct list_head *node=wma_wonder_offchan_queue.next;
    struct wma_wonder_offchan_packet *p=(void *)((char *)node-
        offsetof(struct wma_wonder_offchan_packet,node));
    list_del(node);wma_wonder_offchan.queued--;return p;
}
static void discard(struct wma_wonder_offchan_packet *p) { qdf_mem_free(p);module_put(THIS_MODULE); }
static void test_last_id(void) {
    reset();struct sk_buff a=valid_frame(),b=valid_frame();
    struct cdp_tx_injection_params p=valid_params();
    wma_wonder_offchan.next_desc=65534;
    assert(admit(&a,&p)==QDF_STATUS_SUCCESS);
    assert(wma_wonder_offchan.next_desc==65535);
    assert(admit(&b,&p)==QDF_STATUS_E_NOSUPPORT);
    assert(!b.consumed && wma_wonder_offchan.next_desc==65535);
    assert(wma_wonder_offchan.descriptor_exhausted==1);
    assert(wma_wonder_offchan.queued==1 && injection_accepted==1 && pins==1);
    struct wma_wonder_offchan_packet *packet=pop();
    assert(packet->desc_id==65535 && packet->nbuf==&a);
    static struct device dev;static struct qdf_device qdev;static struct wma wma;
    qdev.dev=&dev;wma.qdf_dev=&qdev;wma.wmi_handle=&wma;wma_injection_ctx.wma=&wma;
    wma_injection_ctx.helper.native=true;wma_injection_ctx.helper.start.channel.maxpower=20;
    wma_wonder_offchan.wmi_handle=wma.wmi_handle;wma_wonder_offchan.wma_context=&wma;
    assert(wma_wonder_offchan_send(packet->nbuf,packet->monitor_id,packet->home_frequency,
        packet->generation,&packet->snapshot,packet->frequency,packet->desc_id,
        &packet->params,packet->begin,packet->end,packet->arg)==QDF_STATUS_SUCCESS);
    assert(send_calls==1 && sent_id==65535 && wma_wonder_offchan.next_desc==65535);
    assert(wma_wonder_offchan.slots[0].nbuf==&a && dev.refs==1);
    wma_wonder_offchan_release(&wma_wonder_offchan.slots[0],true);
    discard(packet);assert(pins==0 && allocations==frees && dev.refs==0);
    puts("last wire ID remains sendable after synchronous exhaustion: PASS");
}
static void reject_unchanged(QDF_STATUS expected,struct cdp_tx_injection_params *p) {
    struct sk_buff b=valid_frame();
    uint32_t before=wma_wonder_offchan.next_desc;
    unsigned int queued=wma_wonder_offchan.queued;
    assert(admit(&b,p)==expected);
    assert(wma_wonder_offchan.next_desc==before && wma_wonder_offchan.queued==queued);
    assert(!b.consumed && pins==0 && work_scheduled==0 && injection_accepted==0);
    assert(allocations==frees);
}
static void test_rejections(void) {
    struct cdp_tx_injection_params p;
    reset();wma_wonder_offchan.next_desc=123;p=valid_params();p.tx_flags=8;
    reject_unchanged(QDF_STATUS_E_NOSUPPORT,&p);
    reset();wma_wonder_offchan.next_desc=123;p=valid_params();p.no_ack=true;
    reject_unchanged(QDF_STATUS_E_NOSUPPORT,&p);
    reset();wma_wonder_offchan.next_desc=123;p=valid_params();p.gi_valid=true;
    reject_unchanged(QDF_STATUS_E_NOSUPPORT,&p);
    reset();wma_wonder_offchan.next_desc=123;p=valid_params();
    wma_wonder_offchan.queued=WMA_WONDER_OFFCHAN_SLOTS;
    reject_unchanged(QDF_STATUS_E_BUSY,&p);
    reset();wma_wonder_offchan.next_desc=123;p=valid_params();pin_allowed=false;
    reject_unchanged(QDF_STATUS_E_CANCELED,&p);
    reset();wma_wonder_offchan.next_desc=123;p=valid_params();allocation_allowed=false;
    reject_unchanged(QDF_STATUS_E_NOMEM,&p);
    reset();wma_wonder_offchan.next_desc=123;p=valid_params();wma_wonder_offchan.accepting=false;
    reject_unchanged(QDF_STATUS_E_CANCELED,&p);
    reset();wma_wonder_offchan.next_desc=123;p=valid_params();wma_injection_ctx.active=false;
    reject_unchanged(QDF_STATUS_E_INVAL,&p);
    puts("metadata, queue, pin, allocation and lifecycle rejection retain caller ownership and ID: PASS");
}
struct thread_state { struct sk_buff frames[8]; };
static void *reserve_thread(void *arg) {
    struct thread_state *s=arg;struct cdp_tx_injection_params p=valid_params();
    for (unsigned int i=0;i<8;i++) { s->frames[i]=valid_frame();assert(admit(&s->frames[i],&p)==0); }
    return NULL;
}
static void test_concurrent_ids(void) {
    reset();pthread_t threads[8];struct thread_state states[8];
    for (unsigned int i=0;i<8;i++) assert(!pthread_create(&threads[i],NULL,reserve_thread,&states[i]));
    for (unsigned int i=0;i<8;i++) assert(!pthread_join(threads[i],NULL));
    assert(wma_wonder_offchan.next_desc==64 && wma_wonder_offchan.queued==64);
    assert(injection_accepted==64 && pins==64 && work_scheduled==64);
    bool seen[65]={false};
    while(wma_wonder_offchan.queued) {
        struct wma_wonder_offchan_packet *p=pop();
        assert(p->desc_id>=1 && p->desc_id<=64 && !seen[p->desc_id]);seen[p->desc_id]=true;
        discard(p);
    }
    assert(pins==0 && allocations==frees);
    // Dropping accepted packets does not recycle their IDs.
    struct sk_buff b=valid_frame();struct cdp_tx_injection_params p=valid_params();
    assert(admit(&b,&p)==0);struct wma_wonder_offchan_packet *n=pop();
    assert(n->desc_id==65);discard(n);
    puts("parallel queue admission reserves unique IDs and canceled packets never recycle them: PASS");
}
static void reset_hdd(struct sk_buff *b) {
    queue_calls=mdns_calls=0;queued_original=mdns_original=NULL;b->consumed=0;
}
static void test_hdd_fallback(void) {
    struct hdd_adapter adapter={.id=1},other={.id=2};
    struct hdd_wonder_session s={.adapter=&adapter,.native_group_ready=true};
    struct sk_buff b=valid_frame();struct cdp_tx_injection_params p=valid_params();
    hdd_wonder_active=&s;wonder_native_group_tx=true;
    reset_hdd(&b);queue_result=0;mdns_result=true;
    assert(hdd_wonder_injection_tx(&adapter,&b,&p)==0);
    assert(queue_calls==1 && mdns_calls==0 && queued_original==&b && b.consumed==1);
    reset_hdd(&b);queue_result=QDF_STATUS_E_NOSUPPORT;mdns_result=true;
    assert(hdd_wonder_injection_tx(&adapter,&b,&p)==0);
    assert(queue_calls==1 && mdns_calls==1 && mdns_original==&b && queued_original==&b && b.consumed==1);
    reset_hdd(&b);queue_result=QDF_STATUS_E_BUSY;mdns_result=false;
    assert(hdd_wonder_injection_tx(&adapter,&b,&p)==-QDF_STATUS_E_BUSY);
    assert(queue_calls==1 && mdns_calls==1 && !b.consumed);
    reset_hdd(&b);s.native_group_ready=false;mdns_result=true;
    assert(hdd_wonder_injection_tx(&adapter,&b,&p)==0);
    assert(queue_calls==0 && mdns_calls==1 && b.consumed==1);
    reset_hdd(&b);mdns_result=false;queue_result=0;
    assert(hdd_wonder_injection_tx(&adapter,&b,&p)==0);
    assert(queue_calls==1 && mdns_calls==1 && b.consumed==1);
    reset_hdd(&b);s.native_group_ready=true;s.failed=true;
    assert(hdd_wonder_injection_tx(&adapter,&b,&p)==-QDF_STATUS_E_AGAIN);
    assert(!queue_calls && !mdns_calls && !b.consumed);
    reset_hdd(&b);s.failed=false;s.suspended=true;
    assert(hdd_wonder_injection_tx(&adapter,&b,&p)==-QDF_STATUS_E_AGAIN);
    assert(!queue_calls && !mdns_calls && !b.consumed);
    reset_hdd(&b);s.suspended=false;
    assert(hdd_wonder_injection_tx(&other,&b,&p)==-QDF_STATUS_E_AGAIN);
    assert(!queue_calls && !mdns_calls && !b.consumed);
    hdd_wonder_active=NULL;
    puts("HDD native success, fallback success/failure and inactive ownership: PASS");
}
int main(void) {
    test_last_id();test_rejections();test_concurrent_ids();test_hdd_fallback();
    assert(pins==0);puts("all extracted production function tests: PASS");return 0;
}
'''


def verify(root: Path, compiler: str = 'cc') -> dict:
    ONYX = root.resolve()
    WMA = ONYX / 'qcacld-3.0/core/wma/src/wma_data.c'
    HDD = ONYX / 'qcacld-3.0/core/hdd/src/wlan_hdd_wonder.c'
    started = time.time()
    wma_bytes, hdd_bytes = WMA.read_bytes(), HDD.read_bytes()
    wma, hdd = wma_bytes.decode(), hdd_bytes.decode()
    names = ('wma_wonder_offchan_tx', 'wma_wonder_offchan_send')
    functions = {name: extract_function(wma, name) for name in names}
    functions['hdd_wonder_injection_tx'] = extract_function(hdd, 'hdd_wonder_injection_tx')
    packet = re.search(r'struct wma_wonder_offchan_packet \{.*?\n\};', wma, re.S)
    assert packet is not None
    fixture = PREFIX + '\n' + packet.group() + '\n' + '\n\n'.join(functions.values()) + '\n' + TESTS
    report = {
        'status': 'RUNNING', 'passed': False, 'started_epoch': started,
        'source_sha256': {str(WMA.relative_to(ONYX)): digest(wma_bytes),
                          str(HDD.relative_to(ONYX)): digest(hdd_bytes)},
        'extracted_function_sha256': {name: digest(body.encode()) for name, body in functions.items()},
        'fixture_sha256': digest(fixture.encode()), 'device_changes': False,
        'limitations': ['Dependency behavior is mocked; this does not establish RF, firmware completion or full kernel concurrency correctness.'],
    }
    try:
        with tempfile.TemporaryDirectory(prefix='onyx-native-tx-tests-') as temp:
            source, binary = Path(temp) / 'fixture.c', Path(temp) / 'fixture'
            source.write_text(fixture)
            flags = ['-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-pthread',
                     '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                     '-fno-pie', '-no-pie', '-fno-omit-frame-pointer']
            build = subprocess.run([compiler, *flags, str(source), '-o', str(binary)],
                                   capture_output=True, text=True, timeout=60)
            report.update(compiler_flags=flags, compile_returncode=build.returncode,
                          compile_output=build.stdout + build.stderr)
            assert build.returncode == 0, report['compile_output']
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
            report.update(run_returncode=run.returncode, run_output=run.stdout + run.stderr)
            assert run.returncode == 0, report['run_output']
            assert digest(WMA.read_bytes()) == digest(wma_bytes), 'WMA changed during test'
            assert digest(HDD.read_bytes()) == digest(hdd_bytes), 'HDD changed during test'
            report.update(status='PASS', passed=True)
            report['sanitizers'] = ['address', 'undefined']
    except BaseException as error:
        report.update(status='FAIL', error=str(error))
        raise
    finally:
        report['finished_epoch'] = time.time()
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', nargs='?', type=Path, default=HERE.parent / 'modules')
    parser.add_argument('--cc', default='cc')
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args()
    result = verify(args.root, args.cc)
    rendered = json.dumps(result, indent=2) + '\n'
    if args.receipt:
        args.receipt.write_text(rendered)
    print(rendered, end='')
