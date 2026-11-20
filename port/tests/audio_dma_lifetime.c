/* Shared host model; the runner inserts the actual production source below. */
/* BASE_HOST */
#include <poll.h>
#include <fcntl.h>
#define __packed __attribute__((packed))
#define GFP_ATOMIC 1
#define ERESTARTSYS 512
#define DECLARE_FLEX_ARRAY(t,n) t n[]
#define READ_ONCE(x) __atomic_load_n(&(x),__ATOMIC_ACQUIRE)
#define WRITE_ONCE(x,v) __atomic_store_n(&(x),v,__ATOMIC_RELEASE)
#define smp_load_acquire(p) __atomic_load_n(p,__ATOMIC_ACQUIRE)
#define smp_store_release(p,v) __atomic_store_n(p,v,__ATOMIC_RELEASE)
#define check_mul_overflow(a,b,out) __builtin_mul_overflow((a),(b),(out))
#define lower_32_bits(a) ((uint32_t)(a))
#define upper_32_bits(a) ((uint32_t)((uint64_t)(a)>>32))
#define dev_err_ratelimited(...) ((void)0)
#define dev_info_ratelimited(...) ((void)0)
#define pr_err_ratelimited(...) ((void)0)
#define pr_warn_ratelimited(...) ((void)0)
#define module_param_named(...)
#define EXPORT_SYMBOL(...)
#define EXPORT_SYMBOL_GPL(...)
#define MODULE_IMPORT_NS(...)
#define EPOLLIN POLLIN
#define EPOLLRDNORM POLLRDNORM
#define EPOLLERR POLLERR
#define EPOLLHUP POLLHUP
typedef uint16_t u16;
typedef int32_t s32;
typedef unsigned long kernel_ulong_t;
typedef unsigned __poll_t;
typedef void poll_table;
struct module;
struct bus_type;
struct device_driver {const char *name;const void *of_match_table;void *bus,*owner;};
typedef struct {atomic_uint value;} atomic_t;
#define ATOMIC_INIT(v) {ATOMIC_VAR_INIT(v)}
static int atomic_inc_return(atomic_t *v) {return (int)(atomic_fetch_add(&v->value,1)+1);}
typedef struct {pthread_mutex_t lock;} spinlock_t;
static void spin_lock_init(spinlock_t *s) {assert(!pthread_mutex_init(&s->lock,NULL));}
#define spin_lock_irqsave(s,f) ((f)=0,assert(!pthread_mutex_lock(&(s)->lock)))
#define spin_unlock_irqrestore(s,f) ((void)(f),assert(!pthread_mutex_unlock(&(s)->lock)))
static int mutex_lock_interruptible(struct mutex *m) {mutex_lock(m);return 0;}
static _Thread_local struct mutex *held_mutexes[8];
static _Thread_local unsigned held_count;
static _Thread_local bool observe_packet_translation;
static struct mutex *translation_gate;
static void model_mutex_acquired(struct mutex *m) {
    assert(held_count<ARRAY_SIZE(held_mutexes));held_mutexes[held_count++]=m;
}
static void model_mutex_released(struct mutex *m) {
    assert(held_count&&held_mutexes[held_count-1]==m);held_count--;
}
static void assert_packet_translation_guarded(void) {
    if(!observe_packet_translation||TEST_PRE_FIX||TEST_GATE_MUTANT)return;
    for(unsigned i=0;i<held_count;i++)if(held_mutexes[i]==translation_gate)return;
    fputs("Packet DMA translation ran outside the remote cleanup gate\n",stderr);abort();
}
struct kref {atomic_uint refs;};
static void kref_init(struct kref *r) {atomic_init(&r->refs,1);}
static void kref_get(struct kref *r) {assert(atomic_fetch_add(&r->refs,1));}
static void kref_put(struct kref *r,void (*release)(struct kref *)) {
    unsigned before=atomic_fetch_sub(&r->refs,1);assert(before);if(before==1)release(r);
}
struct work_struct {void (*fn)(struct work_struct *);};
typedef struct {pthread_mutex_t lock;pthread_cond_t changed;} wait_queue_head_t;
static void init_waitqueue_head(wait_queue_head_t *w) {
    assert(!pthread_mutex_init(&w->lock,NULL));assert(!pthread_cond_init(&w->changed,NULL));
}
static void wake_up(wait_queue_head_t *w) {
    pthread_mutex_lock(&w->lock);pthread_cond_broadcast(&w->changed);pthread_mutex_unlock(&w->lock);
}
static void wake_up_interruptible(wait_queue_head_t *w) {wake_up(w);}
static long model_wait(wait_queue_head_t *w,long ticks);
#define wait_event_timeout(w,c,t) ({long z=model_wait(&(w),(t));(c)?(z?z:1):0;})
#define wait_event_interruptible(w,c) ((c)?0:-ERESTARTSYS)
static unsigned long jiffies;
static unsigned long msecs_to_jiffies(int n) {return n;}
#define time_after_eq(a,b) ((long)((a)-(b))>=0)
static void usleep_range(int a,int b) {(void)b;jiffies+=a/1000;}
static void model_publish_open(struct cdev *c) {(void)c;}
static void *memdup_user(const void *p,size_t n) {
    void *r=kzalloc(n,0);if(!r)return ERR_PTR(-ENOMEM);memcpy(r,p,n);return r;
}
static unsigned copy_to_user(void *to,const void *from,size_t n) {memcpy(to,from,n);return 0;}
struct sk_buff {struct sk_buff *next;size_t len;u8 *data;};
struct sk_buff_head {struct sk_buff *head;spinlock_t lock;};
static struct sk_buff *skb_peek(struct sk_buff_head *q) {return q->head;}
static struct sk_buff *__skb_dequeue(struct sk_buff_head *q) {
    struct sk_buff *b=q->head;if(b)q->head=b->next;return b;
}
static bool skb_queue_empty(struct sk_buff_head *q) {return !q->head;}
static void kfree_skb(struct sk_buff *b) {if(b){kfree(b->data);kfree(b);}}
static void skb_queue_purge(struct sk_buff_head *q) {
    struct sk_buff *b;while((b=__skb_dequeue(q)))kfree_skb(b);
}
static void poll_wait(struct file *f,wait_queue_head_t *w,poll_table *p) {(void)f;(void)w;(void)p;}
static void ipc_log_string(void *log,const char *format,...) {(void)log;(void)format;}
/* HEADERS */
void msm_audio_ion_remote_lock(void);
void msm_audio_ion_remote_unlock(void);
int spf_core_apm_close_all_checked(void);

static struct device spf_parent,ion_parent;
static struct gpr_device spf_service,packet_service;
static struct gpr_pkt last_close_request;
static unsigned close_commands,packet_commands;
static int send_failure;
enum reply_mode {REPLY_OK,REPLY_ERROR,REPLY_MISSING,REPLY_WRONG_TOKEN,
                 REPLY_WRONG_OPCODE,REPLY_TRUNCATED};
static enum reply_mode reply=REPLY_OK;
static pthread_mutex_t response_gate=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t response_changed=PTHREAD_COND_INITIALIZER;
static bool block_response,response_entered,response_released;
static pthread_mutex_t packet_send_gate=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t packet_send_changed=PTHREAD_COND_INITIALIZER;
static bool block_packet_send,packet_send_entered,packet_send_released;

int gpr_send_pkt(struct gpr_device *service,struct gpr_pkt *packet) {
    assert(packet);
    unsigned bytes=GPR_PKT_GET_PACKET_BYTE_SIZE(packet->hdr.header);
    if(service==&spf_service) {
        if(send_failure)return send_failure;
        assert(bytes==24&&packet->hdr.opcode==0x01001013&&packet->hdr.token);
        memcpy(&last_close_request,packet,sizeof(last_close_request));close_commands++;
        return bytes;
    }
    assert(service==&packet_service);
    pthread_mutex_lock(&packet_send_gate);
    if(block_packet_send) {
        packet_send_entered=true;pthread_cond_broadcast(&packet_send_changed);
        struct timespec until;timespec_get(&until,TIME_UTC);until.tv_sec+=5;
        while(!packet_send_released)
            assert(!pthread_cond_timedwait(&packet_send_changed,&packet_send_gate,&until));
    }
    pthread_mutex_unlock(&packet_send_gate);
    if(packet->hdr.opcode==0x0100100C) {
        u32 address;memcpy(&address,((u8 *)packet)+32,sizeof(address));bool found=false;
        for(unsigned i=0;i<2;i++)if((u32)buffers[i].sg[0].dma_address==address) {
            if(!atomic_load(&buffers[i].mapping_refs)) {
                fputs("DSP packet referenced unmapped DMA\n",stderr);abort();
            }
            found=true;
        }
        assert(found);
    }
    packet_commands++;
    for(unsigned i=0;i<2;i++)
        if(atomic_load(&buffers[i].mapping_refs))atomic_store(&buffers[i].dsp_writes,true);
    return bytes;
}
/* SPF_SOURCE */
/* PRE_FIX_ADAPTER */
/* ION_SOURCE */
/* PKT_SOURCE */

_Static_assert(__builtin_types_compatible_p(__typeof__(&spf_core_apm_close_all),void (*)(void)),
               "legacy SPF exported signature");
_Static_assert(__builtin_types_compatible_p(__typeof__(&msm_audio_ion_crash_handler),void (*)(void)),
               "legacy ion cleanup exported signature");
_Static_assert(__builtin_types_compatible_p(__typeof__(&msm_audio_get_phy_addr),int (*)(int,dma_addr_t *,size_t *)),
               "legacy DMA-address exported signature");

/* The host only initializes providers; all exercised data/lifetime paths above
 * are production functions, including SPF request and response validation. */
static struct spf_core_private *test_spf;
static struct spf_core *test_core;
static struct msm_audio_ion_private ion;
static struct audio_pkt_priv packets[2];
static struct inode ion_inodes[2],packet_inodes[3];
static struct file ion_files[2],packet_files[3];

static void clear_dsp_writes(void) {
    for(unsigned i=0;i<2;i++)atomic_store(&buffers[i].dsp_writes,false);
}

static long model_wait(wait_queue_head_t *w,long ticks) {
    (void)w;
    pthread_mutex_lock(&response_gate);
    if(block_response) {
        response_entered=true;pthread_cond_broadcast(&response_changed);
        struct timespec until;timespec_get(&until,TIME_UTC);until.tv_sec+=5;
        while(!response_released)
            assert(!pthread_cond_timedwait(&response_changed,&response_gate,&until));
    }
    pthread_mutex_unlock(&response_gate);
    if(reply==REPLY_MISSING) {jiffies+=ticks;return 0;}
    unsigned payload=reply==REPLY_TRUNCATED?0:8;
    struct gpr_pkt *response=calloc(1,24+payload);assert(response);
    response->hdr=last_close_request.hdr;
    response->hdr.header=GPR_SET_FIELD(GPR_PKT_HEADER_SIZE,6)|GPR_SET_FIELD(GPR_PKT_PACKET_SIZE,24+payload);
    response->hdr.opcode=GPR_IBASIC_RSP_RESULT;
    if(reply==REPLY_WRONG_TOKEN)response->hdr.token--;
    if(payload) {
        u32 data[2]={reply==REPLY_WRONG_OPCODE?APM_CMD_GET_SPF_STATE:APM_CMD_CLOSE_ALL,
                     reply==REPLY_ERROR?1:0};
        memcpy(response->payload,data,sizeof(data));
    }
    if(reply==REPLY_OK)clear_dsp_writes();
    int result=spf_core_callback(&spf_service,response);
    assert(result==(reply==REPLY_TRUNCATED?-EINVAL:0));
    free(response);jiffies+=ticks;
    return reply==REPLY_OK||reply==REPLY_ERROR?1:0;
}

static void init_model(void) {
    device_initialize(&spf_parent);device_initialize(&ion_parent);
    device_initialize(&spf_service.dev);device_initialize(&packet_service.dev);
    test_spf=kzalloc(sizeof(*test_spf),0);assert(test_spf);
    test_core=kzalloc(sizeof(*test_core),0);assert(test_core);
    test_spf->dev=get_device(&spf_parent);kref_init(&test_spf->ref);mutex_init(&test_spf->lock);
    test_spf->spf_core_drv=test_core;test_core->adev=&spf_service;test_core->priv=test_spf;
    spin_lock_init(&test_core->response_lock);init_waitqueue_head(&test_core->wait);
    dev_set_drvdata(&spf_service.dev,test_core);spf_core_priv=test_spf;
#if !TEST_PRE_FIX
    translation_gate=&msm_audio_remote_lock;
#endif
    device_initialize(&ion.chardev);ion.cb_dev=&ion_parent;
    for(unsigned i=0;i<2;i++) {
        buffers[i].size=8192;atomic_init(&buffers[i].refs,1);
        atomic_init(&buffers[i].mapping_refs,0);atomic_init(&buffers[i].dsp_writes,false);
        buffers[i].sg[0]=(struct scatterlist){.dma_address=0x100000+i*0x10000,
            .physical=0x100000+i*0x10000,.dma_length=8192,.length=8192};
        buffers[i].table=(struct sg_table){.sgl=buffers[i].sg,.nents=1,.orig_nents=1};
        fd_table[i]=&buffers[i];
        packets[i].adev=&packet_service;packets[i].bound=packets[i].ever_bound=true;
        device_initialize(&packets[i].chardev);mutex_init(&packets[i].lock);
        init_waitqueue_head(&packets[i].readq);spin_lock_init(&packets[i].queue.lock);
    }
}

static void open_ion(unsigned file) {
    ion_inodes[file].i_cdev=&ion.cdev;ion_files[file].f_inode=&ion_inodes[file];
    assert(!msm_audio_ion_open(&ion_inodes[file],&ion_files[file]));
}
static void map_buffer(unsigned file,unsigned buffer) {
    assert(!msm_audio_ion_ioctl(&ion_files[file],IOCTL_MAP_PHYS_ADDR,buffer));
}
static void close_ion(unsigned file) {
    assert(!msm_audio_ion_release(&ion_inodes[file],&ion_files[file]));
}
static void open_packet(unsigned file,unsigned provider) {
    packet_inodes[file].i_cdev=&packets[provider].cdev;
    assert(!audio_pkt_open(&packet_inodes[file],&packet_files[file]));
}
static void close_packet(unsigned file) {
    assert(!audio_pkt_release(&packet_inodes[file],&packet_files[file]));
}
static void write_map(unsigned file,unsigned buffer) {
    u8 data[44]={0};struct gpr_hdr *header=(void *)data;
    header->header=GPR_SET_FIELD(GPR_PKT_HEADER_SIZE,6)|GPR_SET_FIELD(GPR_PKT_PACKET_SIZE,sizeof(data));
    header->opcode=APM_CMD_SHARED_MEM_MAP_REGIONS;
    struct audio_pkt_apm_cmd_shared_mem_map_regions_t *map=(void *)(data+24);
    map->num_regions=1;map->property_flag=APM_MEMORY_MAP_BIT_MASK_IS_OFFSET_MODE;
    struct audio_pkt_apm_shared_map_region_payload_t *region=(void *)(data+32);
    region->shm_addr_lsw=buffer;region->mem_size_bytes=4096;
    observe_packet_translation=true;
    assert(audio_pkt_write(&packet_files[file],(const char *)data,sizeof(data),NULL)==sizeof(data));
    observe_packet_translation=false;
}
static void initial_graph(void) {
    init_model();open_ion(0);map_buffer(0,0);open_packet(0,0);write_map(0,0);
}
static void retained(unsigned buffer) {
    assert(atomic_load(&buffers[buffer].mapping_refs)==1);
    assert(atomic_load(&buffers[buffer].refs)==2&&module_pins);
}
static void cleaned(unsigned buffer) {
    assert(!atomic_load(&buffers[buffer].mapping_refs));
    assert(atomic_load(&buffers[buffer].refs)==1&&!atomic_load(&buffers[buffer].dsp_writes));
}
static void finish(void) {
    reply=REPLY_OK;send_failure=0;fail_unassign=false;
    spf_core_priv=test_spf;test_spf->spf_core_drv=test_core;
    block_response=false;
    for(unsigned i=0;i<2;i++)if(ion_files[i].private_data)close_ion(i);
    for(unsigned i=0;i<3;i++)if(packet_files[i].private_data)close_packet(i);
    msm_audio_ion_crash_handler();
    for(unsigned i=0;i<2;i++)cleaned(i);
    assert(list_empty(&msm_audio_allocations)&&!attachments&&maps==unmaps&&!module_pins);
    assert(ion.chardev.refs==1&&ion_parent.refs==1);
    for(unsigned i=0;i<2;i++)assert(packets[i].chardev.refs==1&&!packets[i].opens);
    spf_core_priv=NULL;dev_set_drvdata(&spf_service.dev,NULL);kfree(test_core);
    assert(test_spf->ref.refs==1);spf_private_put(test_spf);
    assert(spf_parent.refs==1&&!live);
}

static unsigned ion_first(void) {
    initial_graph();close_ion(0);retained(0);assert(atomic_load(&buffers[0].dsp_writes));
    close_packet(0);cleaned(0);finish();return 3;
}
static unsigned packet_first(void) {
    initial_graph();close_packet(0);retained(0);assert(!atomic_load(&buffers[0].dsp_writes));
    close_ion(0);retained(0);msm_audio_ion_crash_handler();cleaned(0);finish();return 3;
}
static unsigned multiple_owners(void) {
    initial_graph();open_ion(1);map_buffer(1,0);close_ion(0);retained(0);
    close_packet(0);retained(0);assert(!atomic_load(&buffers[0].dsp_writes));
    dma_addr_t address;size_t bytes;
    assert(!msm_audio_get_phy_addr(0,&address,&bytes)&&address==0x100000&&bytes==8192);
    close_ion(1);retained(0);msm_audio_ion_crash_handler();cleaned(0);finish();return 4;
}
static unsigned failed_close(enum reply_mode mode,int failed_send,bool missing_provider,bool missing_service) {
    initial_graph();close_ion(0);reply=mode;send_failure=failed_send;
    if(missing_provider)spf_core_priv=NULL;
    if(missing_service)test_spf->spf_core_drv=NULL;
    close_packet(0);retained(0);assert(atomic_load(&buffers[0].dsp_writes)&&!unmaps);
    reply=REPLY_OK;send_failure=0;spf_core_priv=test_spf;test_spf->spf_core_drv=test_core;
    /* Existing session behavior remains usable; explicit checked cleanup retries. */
    open_packet(0,0);close_packet(0);cleaned(0);finish();return 3;
}
static unsigned legacy_close(void) {
    initial_graph();close_ion(0);reply=REPLY_ERROR;spf_core_apm_close_all();
    retained(0);assert(atomic_load(&buffers[0].dsp_writes));
    reply=REPLY_OK;spf_core_apm_close_all();retained(0);
    assert(!atomic_load(&buffers[0].dsp_writes));msm_audio_ion_crash_handler();cleaned(0);
    finish();return 3;
}
static unsigned secure_retention(void) {
    initial_graph();assert(!msm_audio_ion_ioctl(&ion_files[0],IOCTL_MAP_HYP_ASSIGN,0));
    close_ion(0);fail_unassign=true;close_packet(0);retained(0);assert(buffers[0].secure);
    fail_unassign=false;msm_audio_ion_crash_handler();cleaned(0);assert(!buffers[0].secure);
    finish();return 3;
}

static atomic_bool operation_started,operation_done;
static void *close_thread(void *file) {close_packet((unsigned)(uintptr_t)file);return NULL;}
static void *writer_thread(void *file) {
    atomic_store(&operation_started,true);write_map((unsigned)(uintptr_t)file,1);
    atomic_store(&operation_done,true);return NULL;
}
static void *first_writer_thread(void *unused) {(void)unused;write_map(0,0);return NULL;}
static void *cleanup_thread(void *unused) {
    (void)unused;atomic_store(&operation_started,true);msm_audio_ion_crash_handler();
    atomic_store(&operation_done,true);return NULL;
}
static void wait_for_response(void) {
    pthread_mutex_lock(&response_gate);struct timespec until;timespec_get(&until,TIME_UTC);until.tv_sec+=5;
    while(!response_entered)assert(!pthread_cond_timedwait(&response_changed,&response_gate,&until));
    pthread_mutex_unlock(&response_gate);
}
static void release_response(void) {
    pthread_mutex_lock(&response_gate);response_released=true;
    pthread_cond_broadcast(&response_changed);pthread_mutex_unlock(&response_gate);
}
static unsigned pending_close(void) {
    initial_graph();block_response=true;pthread_t closer;
    assert(!pthread_create(&closer,NULL,close_thread,(void *)(uintptr_t)0));wait_for_response();
    close_ion(0);retained(0);assert(atomic_load(&buffers[0].dsp_writes)&&!unmaps);
    release_response();assert(!pthread_join(closer,NULL));cleaned(0);finish();return 3;
}
static unsigned new_writer(void) {
    initial_graph();open_ion(1);map_buffer(1,1);open_packet(1,1);close_ion(0);
    block_response=true;pthread_t closer,writer;
    assert(!pthread_create(&closer,NULL,close_thread,(void *)(uintptr_t)0));wait_for_response();
    assert(!pthread_create(&writer,NULL,writer_thread,(void *)(uintptr_t)1));
    struct timespec pause={.tv_nsec=20000000};nanosleep(&pause,NULL);
    assert(atomic_load(&operation_started)&&!atomic_load(&operation_done));
    assert(packet_commands==1);retained(0);retained(1);
    release_response();assert(!pthread_join(closer,NULL)&&!pthread_join(writer,NULL));
    cleaned(0);retained(1);assert(packet_commands==2&&atomic_load(&buffers[1].dsp_writes));
    block_response=false;close_ion(1);close_packet(1);cleaned(1);finish();return 4;
}
static unsigned send_cleanup_race(void) {
    init_model();open_ion(0);map_buffer(0,0);open_packet(0,0);block_packet_send=true;
    pthread_t writer,cleanup;assert(!pthread_create(&writer,NULL,first_writer_thread,NULL));
    pthread_mutex_lock(&packet_send_gate);struct timespec until;timespec_get(&until,TIME_UTC);until.tv_sec+=5;
    while(!packet_send_entered)
        assert(!pthread_cond_timedwait(&packet_send_changed,&packet_send_gate,&until));
    pthread_mutex_unlock(&packet_send_gate);
    close_ion(0);retained(0);
    assert(!pthread_create(&cleanup,NULL,cleanup_thread,NULL));
    struct timespec pause={.tv_nsec=20000000};nanosleep(&pause,NULL);
    assert(atomic_load(&operation_started));
    pthread_mutex_lock(&packet_send_gate);packet_send_released=true;
    pthread_cond_broadcast(&packet_send_changed);pthread_mutex_unlock(&packet_send_gate);
    assert(!pthread_join(writer,NULL)&&!pthread_join(cleanup,NULL));cleaned(0);
    block_packet_send=false;finish();return 4;
}

int main(int argc,char **argv) {
    assert(argc==2);unsigned checks=0;
    if(!strcmp(argv[1],"ion_first"))checks=ion_first();
    else if(!strcmp(argv[1],"packet_first"))checks=packet_first();
    else if(!strcmp(argv[1],"pending_close"))checks=pending_close();
    else if(!strcmp(argv[1],"multiple_owners"))checks=multiple_owners();
    else if(!strcmp(argv[1],"legacy_close"))checks=legacy_close();
    else if(!strcmp(argv[1],"secure_retention"))checks=secure_retention();
    else if(!strcmp(argv[1],"new_writer"))checks=new_writer();
    else if(!strcmp(argv[1],"send_cleanup_race"))checks=send_cleanup_race();
    else if(!strcmp(argv[1],"error_reply"))checks=failed_close(REPLY_ERROR,0,false,false);
    else if(!strcmp(argv[1],"missing_reply"))checks=failed_close(REPLY_MISSING,0,false,false);
    else if(!strcmp(argv[1],"wrong_token"))checks=failed_close(REPLY_WRONG_TOKEN,0,false,false);
    else if(!strcmp(argv[1],"wrong_opcode"))checks=failed_close(REPLY_WRONG_OPCODE,0,false,false);
    else if(!strcmp(argv[1],"truncated_reply"))checks=failed_close(REPLY_TRUNCATED,0,false,false);
    else if(!strcmp(argv[1],"send_failure"))checks=failed_close(REPLY_OK,-EIO,false,false);
    else if(!strcmp(argv[1],"missing_provider"))checks=failed_close(REPLY_OK,0,true,false);
    else if(!strcmp(argv[1],"missing_service"))checks=failed_close(REPLY_OK,0,false,true);
    else abort();
    printf("{\"checks\":%u,\"close_commands\":%u,\"packet_commands\":%u,\"unmaps\":%u}\n",
           checks,close_commands,packet_commands,unmaps);
    return 0;
}
