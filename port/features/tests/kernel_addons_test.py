#!/usr/bin/env python3
"""Exercise actual addon C bodies with deterministic host-side boundaries.

These complement ARM64 object/KMI checks; they do not emulate Android boot.
Set TMPDIR to a scratch filesystem with sufficient space.
"""
import ctypes
import math
from pathlib import Path
import random
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
COMMON = ROOT / "common"


def function(source, name):
    match = re.search(r"(?m)^[^\n;{}]*\b" + name + r"\([^;{}]*\)\s*\{", source)
    if match is None:
        raise AssertionError("Function missing: " + name)
    start = match.start()
    if re.match(r"\s*" + name + r"\(", source[start:]):
        previous = source.rfind("\n", 0, start - 1) + 1
        if source[previous:start].strip().startswith("static inline"):
            start = previous
    begin = source.index("{", match.start())
    depth = 1
    end = begin + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end] + "\n"


class KernelAddonTest(unittest.TestCase):
    def run_c(self, text, flags=()):
        with tempfile.TemporaryDirectory(prefix="onyx-addons-test-") as tmp:
            src = Path(tmp) / "test.c"
            binary = Path(tmp) / "test"
            src.write_text(text)
            subprocess.run(["gcc", "-std=gnu11", "-O2", "-Wall", "-Werror", *flags,
                            str(src), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)

    def test_bbr_allocation_failure_release_and_private_stamp_boundaries(self):
        source = (COMMON / "net/ipv4/tcp_bbr3.c").read_text()
        header = (COMMON / "include/net/tcp_bbr3.h").read_text()
        header = re.sub(r"(?m)^#include[^\n]*\n", "", header)
        tcp = (COMMON / "include/net/tcp.h").read_text()
        plb = re.search(r"struct tcp_plb_state\s*\{[^}]*\};", tcp).group()
        bodies = "\n".join(function(source, name) for name in (
            "bbr3_get_priv", "bbr3_alloc_priv", "bbr3_release",
            "tcp_bbr3_stamp_skb", "bbr3_tx_stamp_lookup"))
        text = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint32_t __u32;
struct hlist_node { void *next; };
struct rcu_head { void *next; };
struct sock;
struct sk_buff;
struct tcp_congestion_ops { int dummy; };
struct inet_connection_sock {
    const struct tcp_congestion_ops *icsk_ca_ops;
    u64 icsk_ca_priv[104 / sizeof(u64)];
};
struct tcp_sock { u32 lost; u32 in_flight; };
struct sock { struct inet_connection_sock icsk; struct tcp_sock tcp; };
struct sk_buff { struct { u32 end_seq; } cb; u32 pcount; };
static struct tcp_congestion_ops tcp_bbr_cong_ops, tcp_reno;
static int allocations, frees;
static bool fail_alloc;
static int bbr3_diag_lock;
static inline struct inet_connection_sock *inet_csk(const struct sock *sk) {
    return (struct inet_connection_sock *)&sk->icsk;
}
static inline void *inet_csk_ca(const struct sock *sk) { return (void *)sk->icsk.icsk_ca_priv; }
static inline struct tcp_sock *tcp_sk(const struct sock *sk) { return (struct tcp_sock *)&sk->tcp; }
static inline u32 tcp_packets_in_flight(const struct tcp_sock *tp) { return tp->in_flight; }
static inline u32 tcp_skb_pcount(const struct sk_buff *skb) { return skb->pcount; }
static void *test_zalloc(size_t size) {
    if (fail_alloc) return NULL;
    allocations++;
    return calloc(1, size);
}
static void test_free(void *p) { if (p) { frees++; free(p); } }
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, value) ((x) = (value))
#define BUILD_BUG_ON(x) _Static_assert(!(x), "private state slot fits")
#define ICSK_CA_PRIV_SIZE (sizeof(((struct inet_connection_sock *)0)->icsk_ca_priv))
#define likely(x) (x)
#define unlikely(x) (x)
#define GFP_ATOMIC 0
#define kzalloc(size, flags) test_zalloc(size)
#define kfree_rcu(p, member) test_free(p)
#define pr_warn_ratelimited(...) ((void)0)
#define spin_lock_irqsave(lock, flags) ((void)(lock), (flags) = 0)
#define spin_unlock_irqrestore(lock, flags) ((void)(lock), (void)(flags))
#define hash_del_rcu(node) ((void)(node))
#define TCP_SKB_CB(skb) (&(skb)->cb)
#define min_t(type, a, b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))
#define __maybe_unused __attribute__((unused))
#define __used __attribute__((used))
#define noinline __attribute__((noinline))
''' + plb + "\n" + header + bodies + r'''
int main(void) {
    struct sock sk = {0};
    struct sk_buff skb = {0};
    u32 in_flight, lost;
    struct bbr3 *state;
    sk.icsk.icsk_ca_ops = &tcp_bbr_cong_ops;
    memset(sk.icsk.icsk_ca_priv, 0x5a, ICSK_CA_PRIV_SIZE);
    fail_alloc = true;
    assert(!bbr3_alloc_priv(&sk));
    assert(sk.icsk.icsk_ca_ops == &tcp_reno);
    for (size_t i = 0; i < ICSK_CA_PRIV_SIZE; i++)
        assert(((unsigned char *)inet_csk_ca(&sk))[i] == 0);
    assert(bbr3_get_priv(&sk) == NULL);
    bbr3_release(&sk);
    assert(allocations == 0 && frees == 0);

    fail_alloc = false;
    sk.icsk.icsk_ca_ops = &tcp_bbr_cong_ops;
    assert(bbr3_alloc_priv(&sk));
    state = bbr3_get_priv(&sk);
    assert(state && state->tx_stamp_head == 0);
    assert(!bbr3_tx_stamp_lookup(&sk, 0, &in_flight, &lost));
    skb.pcount = 2;
    sk.tcp.in_flight = 5;
    sk.tcp.lost = 7;
    tcp_bbr3_stamp_skb(&sk, &skb);
    assert(bbr3_tx_stamp_lookup(&sk, 0, &in_flight, &lost));
    assert(in_flight == 7 && lost == 7);
    sk.tcp.lost = 11;
    tcp_bbr3_stamp_skb(&sk, &skb);
    assert(bbr3_tx_stamp_lookup(&sk, 0, &in_flight, &lost));
    assert(lost == 11); /* newest retransmission wins */
    for (u32 i = 1; i <= BBR3_TX_STAMP_RING + 5; i++) {
        skb.cb.end_seq = i;
        sk.tcp.lost = i;
        tcp_bbr3_stamp_skb(&sk, &skb);
    }
    assert(!bbr3_tx_stamp_lookup(&sk, 0, &in_flight, &lost));
    assert(bbr3_tx_stamp_lookup(&sk, BBR3_TX_STAMP_RING + 5, &in_flight, &lost));
    state->tx_stamp_head = (1ULL << 32) + BBR3_TX_STAMP_RING;
    skb.cb.end_seq = 1000;
    tcp_bbr3_stamp_skb(&sk, &skb);
    assert(bbr3_tx_stamp_lookup(&sk, 1000, &in_flight, &lost));
    bbr3_release(&sk);
    assert(bbr3_get_priv(&sk) == NULL);
    bbr3_release(&sk);
    assert(allocations == frees && allocations == 1);
    sk.icsk.icsk_ca_ops = &tcp_reno;
    sk.icsk.icsk_ca_priv[0] = 1; /* foreign CC bytes are not a pointer */
    assert(bbr3_get_priv(&sk) == NULL);
    tcp_bbr3_stamp_skb(&sk, &skb);
    return 0;
}
'''
        self.run_c(text)

    def test_bbg_exact_partition_matching_both_slots_and_protection_options(self):
        source = (COMMON / "security/baseband-guard/blkdev_helper.c").read_text()
        header = (COMMON / "security/baseband-guard/baseband_guard.h").read_text()
        text = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
''' + header + function(source, "partition_name_matches") + function(source, "partition_name_in_allowlist") + r'''
int main(void) {
    assert(partition_name_in_allowlist("userdata", 32));
    assert(partition_name_in_allowlist("metadata", 32));
    assert(!partition_name_in_allowlist("modem_a", 32));
    assert(!partition_name_in_allowlist("fsg", 32));
    assert(!partition_name_in_allowlist("boot_ab", 32));
    assert(!partition_name_in_allowlist("boot_a_extra", 32));
    assert(!partition_name_in_allowlist("bootloader", 32));
    assert(!partition_name_in_allowlist("userdata", 4));
    assert(!partition_name_in_allowlist(NULL, 32));
#ifdef CONFIG_BBG_BLOCK_BOOT
    assert(!partition_name_in_allowlist("boot_a", 32));
    assert(!partition_name_in_allowlist("boot_b", 32));
#else
    assert(partition_name_in_allowlist("boot_a", 32));
    assert(partition_name_in_allowlist("boot_b", 32));
    assert(partition_name_in_allowlist("init_boot_b", 32));
#endif
#ifdef CONFIG_BBG_BLOCK_RECOVERY
    assert(!partition_name_in_allowlist("recovery_b", 32));
#else
    assert(partition_name_in_allowlist("recovery_b", 32));
#endif
    return 0;
}
'''
        self.run_c(text)
        self.run_c(text, ["-DCONFIG_BBG_BLOCK_BOOT", "-DCONFIG_BBG_BLOCK_RECOVERY"])

    def test_bbg_direct_elevation_and_late_policy_without_exec(self):
        source = (COMMON / "security/baseband-guard/tracing/tracing.c").read_text()
        header = (COMMON / "security/baseband-guard/tracing/tracing.h").read_text()
        cache = re.search(r"struct bbg_domain_cache\s*\{[^}]*\};", source).group()
        text = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;
struct cred_security_struct { u32 sid, osid; };
struct bbg_cred_security_struct { unsigned is_untrusted_process:1; };
struct cred { struct cred_security_struct selinux; struct bbg_cred_security_struct guard; };
static struct cred test_cred;
static bool ksu_domain_present;
static const struct cred *current_cred(void) { return &test_cred; }
static const struct cred_security_struct *selinux_cred(const struct cred *c) { return &c->selinux; }
static struct bbg_cred_security_struct *bbg_cred(const struct cred *c) { return (void *)&c->guard; }
static bool selinux_initialized_compat(void) { return true; }
static int security_secctx_to_secid(const char *context, size_t size, u32 *sid) {
    (void)size;
    if (ksu_domain_present && !strcmp(context, "u:r:ksu:s0")) { *sid = 30; return 0; }
    return -EINVAL;
}
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, value) ((x) = (value))
#define __maybe_unused __attribute__((unused))
''' + cache + "\nstatic struct bbg_domain_cache su_domain, magisk_domain, ksu_domain;\n" + function(source, "bbg_domain_sid") + function(source, "bbg_current_domain_untrusted") + function(header, "current_process_trusted") + r'''
int main(void) {
    test_cred.selinux.sid = 42;
    assert(current_process_trusted());
    ksu_domain_present = true; /* policy appeared after failed lookup */
    test_cred.selinux.sid = 30; /* direct elevation; no exec callback */
    assert(!current_process_trusted());
    test_cred.selinux.sid = 42;
    test_cred.selinux.osid = 30;
    assert(!current_process_trusted());
    test_cred.selinux.osid = 0;
    test_cred.guard.is_untrusted_process = 1;
    assert(!current_process_trusted());
    test_cred.guard.is_untrusted_process = 0;
    assert(current_process_trusted());
    return 0;
}
'''
        self.run_c(text)

    def test_unicode_tables_lengths_hashes_and_creation_only_reserved_names(self):
        def without_includes(src):
            return re.sub(r"(?m)^#include[^\n]*\n", "", src)

        public = (COMMON / "include/linux/unicode.h").read_text()
        enum = re.search(r"enum utf8_normalization\s*\{[^}]*\};", public).group()
        mapping = re.search(r"struct unicode_map\s*\{[^}]*\};", public).group()
        core = (COMMON / "fs/unicode/utf8-core.c").read_text()
        fs = (COMMON / "include/linux/fs.h").read_text()
        stringhash = (COMMON / "include/linux/stringhash.h").read_text()
        text = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#define IS_MODULE(x) 0
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define EXPORT_SYMBOL_GPL(x)
#define MODULE_DESCRIPTION(x)
#define MODULE_LICENSE(x)
struct qstr { const unsigned char *name; unsigned int len, hash; };
''' + enum + mapping + without_includes((COMMON / "fs/unicode/utf8n.h").read_text())
        text += without_includes((COMMON / "fs/unicode/utf8data.c_shipped").read_text())
        text += without_includes((COMMON / "fs/unicode/utf8-norm.c").read_text())
        text += r'''
#define init_name_hash(salt) ((unsigned long)(salt))
static unsigned long hash_long(unsigned long value, unsigned int bits) {
    return (value * UINT64_C(0x61c8864680b583eb)) >> (64 - bits);
}
''' + function(stringhash, "partial_name_hash") + function(stringhash, "end_name_hash")
        text += "\n".join(function(core, name) for name in (
            "utf8_validate", "utf8_casefold", "utf8_normalize", "utf8_casefold_hash",
            "utf8_strncasecmp"))
        text += r'''
struct super_block { struct unicode_map *s_encoding; bool strict; };
struct inode { struct super_block *i_sb; bool casefold; };
#define IS_CASEFOLDED(dir) ((dir)->casefold)
#define sb_has_strict_encoding(sb) ((sb)->strict)
#define WARN_ON_ONCE(x) (x)
''' + function(fs, "generic_ci_validate_strict_name") + function(fs, "generic_ci_validate_new_name")
        text += r'''
static struct qstr name(const char *value) {
    return (struct qstr){ .name=(const unsigned char *)value, .len=strlen(value) };
}
int main(void) {
    struct unicode_map um = { .version=0xc0100,
        .ntab={ &utf8nfdidata[ARRAY_SIZE(utf8nfdidata)-1],
                &utf8nfdicfdata[ARRAY_SIZE(utf8nfdicfdata)-1] },
        .tables=&utf8_data_table };
    struct super_block sb = { .s_encoding=&um, .strict=true };
    struct inode dir = { .i_sb=&sb, .casefold=true };
    const char *valid[] = {
        "ab\xc2\xad" "cd", "ab\xe2\x80\x8b" "cd",
        "AbCd", "a\xc3\xa4", "aa\xcc\x88", "\xc3\x9f", "ss", "file...", ".profile"
    };
    for (size_t i=0; i<ARRAY_SIZE(valid); i++) {
        struct qstr input=name(valid[i]);
        unsigned char folded[64], normalized[64];
        int clen=utf8_casefold(&um,&input,folded,sizeof(folded));
        int nlen=utf8_normalize(&um,&input,normalized,sizeof(normalized));
        assert(clen >= 0 && nlen >= 0);
        assert(clen == utf8nlen(&um,UTF8_NFDICF,valid[i],input.len));
        assert(nlen == utf8nlen(&um,UTF8_NFDI,valid[i],input.len));
        assert((size_t)clen == strlen((const char *)folded));
        assert(generic_ci_validate_new_name(&dir,&input));
    }
    struct qstr soft=name("ab\xc2\xad" "cd"), plain=name("abcd");
    struct qstr zero=name("ab\xe2\x80\x8b" "cd");
    assert(utf8_strncasecmp(&um,&soft,&plain)==0);
    assert(utf8_strncasecmp(&um,&zero,&plain)==0);
    assert(utf8_casefold_hash(&um,NULL,&soft)==0);
    assert(utf8_casefold_hash(&um,NULL,&plain)==0);
    assert(utf8_casefold_hash(&um,NULL,&zero)==0);
    assert(soft.hash==plain.hash && zero.hash==plain.hash);
    const char *reserved[]={ "", ".", "..", "\xc2\xad", "\xe2\x80\x8b",
        ".\xe2\x80\x8b", "\xc2\xad..", ".\xc2\xad." };
    for(size_t i=0;i<ARRAY_SIZE(reserved);i++) {
        struct qstr input=name(reserved[i]);
        unsigned char out[64];
        int len=utf8_casefold(&um,&input,out,sizeof(out));
        assert(len==utf8nlen(&um,UTF8_NFDICF,reserved[i],input.len));
        assert(!generic_ci_validate_new_name(&dir,&input));
        sb.strict=false;
        assert(!generic_ci_validate_new_name(&dir,&input));
        dir.casefold=false;
        assert(generic_ci_validate_new_name(&dir,&input));
        dir.casefold=true;
        sb.strict=true;
    }
    struct qstr invalid=name("\xff");
    assert(!generic_ci_validate_new_name(&dir,&invalid));
    sb.strict=false;
    assert(generic_ci_validate_new_name(&dir,&invalid));
    return 0;
}
'''
        self.run_c(text, ["-Wno-pointer-sign"])

    def test_alarm_timeout_is_positive_and_bounded_for_overdue_timers(self):
        source = (COMMON / "kernel/time/alarmtimer.c").read_text()
        expression = re.search(r"pm_wakeup_event\(dev,\s*(clamp_t\(s64,.*?)\);",
                               source, re.S).group(1)
        text = r'''
#include <assert.h>
#include <stdint.h>
typedef int64_t s64;
#define MSEC_PER_SEC 1000
#define ktime_to_ms(value) ((value) / 1000000)
#define clamp_t(type, value, lower, upper) \
    ((type)(value) < (type)(lower) ? (type)(lower) : \
     (type)(value) > (type)(upper) ? (type)(upper) : (type)(value))
static unsigned int timeout(s64 min) { return ''' + expression + r'''; }
int main(void) {
    assert(timeout(-1000000000)==1);
    assert(timeout(INT64_MIN)==1);
    assert(timeout(0)==1);
    assert(timeout(1000000)==2);
    assert(timeout(1500000000)==1501);
    assert(timeout(1999999999)==2000);
    assert(timeout(INT64_MAX)==2000);
    return 0;
}
'''
        self.run_c(text)

    def test_sqrt_all_bits_boundary_and_random_inputs_in_both_profiles(self):
        source = (COMMON / "lib/math/int_sqrt.c").read_text()
        start = source.index("#ifdef CONFIG_ONYX_PERFORMANCE")
        end = source.index("EXPORT_SYMBOL(int_sqrt);")
        body = source[start:end]
        rng = random.Random(618)
        for bits in (32, 64):
            values = list(range(4097)) + [rng.randrange(1 << bits) for _ in range(5000)]
            for shift in range(bits):
                values += [max(0, (1 << shift) - 1), 1 << shift,
                           min((1 << bits) - 1, (1 << shift) + 1)]
            values += [(1 << bits) - 1, (1 << (bits - 1)) - 1]
            for perf in (False, True):
                with tempfile.TemporaryDirectory(prefix="onyx-sqrt-test-") as tmp:
                    src, lib = Path(tmp) / "sqrt.c", Path(tmp) / "sqrt.so"
                    src.write_text("#define BITS_PER_LONG " + str(bits) + "\n"
                                   "#define __fls(x) (63 - __builtin_clzl(x))\n" + body)
                    subprocess.run(["gcc", "-O2", "-shared", "-fPIC",
                                    *(["-DCONFIG_ONYX_PERFORMANCE"] if perf else []),
                                    str(src), "-o", str(lib)], check=True)
                    kernel = ctypes.CDLL(str(lib))
                    kernel.int_sqrt.argtypes = [ctypes.c_ulong]
                    kernel.int_sqrt.restype = ctypes.c_ulong
                    for value in values:
                        self.assertEqual(kernel.int_sqrt(value), math.isqrt(value),
                                         (bits, perf, value))


if __name__ == "__main__":
    unittest.main()
