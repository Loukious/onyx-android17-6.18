/* SPDX-License-Identifier: GPL-2.0-only */
/* Real production state core; deterministic callback interleavings, no radio. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t s32;

/* INSERT_API */
/* INSERT_CORE */

static unsigned int assertions, failed, cases;
static bool case_ok;
#define CHECK(expr) do { assertions++; if (!(expr)) { case_ok = false; \
    fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #expr); } } while (0)

static const struct hdd_wonder_dwell_owner owner = {7, 91};
static const struct hdd_wonder_dwell_scan scan = {3, 0xa004, 17, 5745};

static void prepare(struct hdd_wonder_dwell *d)
{
    hdd_wonder_dwell_init(d, 100);
    CHECK(hdd_wonder_dwell_set_home(d, 1, 5260));
    CHECK(hdd_wonder_dwell_reserve(d, &owner, &scan, 1000, 1100, 100));
}

static struct hdd_wonder_dwell_event event(enum hdd_wonder_dwell_event_type type)
{
    return (struct hdd_wonder_dwell_event) {
        .owner = owner, .vdev_id = scan.vdev_id, .requester = scan.requester,
        .scan_id = scan.scan_id, .freq = scan.freq, .type = type,
    };
}

static bool send(struct hdd_wonder_dwell *d,
                 enum hdd_wonder_dwell_event_type type, u64 now)
{
    struct hdd_wonder_dwell_event e = event(type);
    if (type == HDD_WONDER_DWELL_BSS_CHANNEL) e.freq = 5260;
    if (type == HDD_WONDER_DWELL_TERMINAL) e.freq = 0;
    return hdd_wonder_dwell_event(d, &e, now);
}

static bool ready(struct hdd_wonder_dwell *d, u64 now)
{ return hdd_wonder_dwell_ready(d, &owner, &scan, now); }

static void reserve_never_authorizes(void)
{
    struct hdd_wonder_dwell d;
    prepare(&d);
    CHECK(!ready(&d, 1000));
    CHECK(send(&d, HDD_WONDER_DWELL_STARTED, 1001));
    CHECK(!ready(&d, 1001));
    CHECK(!hdd_wonder_dwell_reserve(&d, &owner, &scan, 1001, 1100, 50));
    CHECK(send(&d, HDD_WONDER_DWELL_FOREIGN_CHANNEL, 1002));
    CHECK(ready(&d, 1002));
    CHECK(d.home_vdev_id == 1 && d.home_freq == 5260 && d.scan.freq == 5745);
}

static void stale_identity_never_authorizes(void)
{
    for (unsigned int field = 0; field < 6; field++) {
        struct hdd_wonder_dwell d;
        struct hdd_wonder_dwell_event e = event(HDD_WONDER_DWELL_FOREIGN_CHANNEL);
        prepare(&d);
        switch (field) {
        case 0: e.owner.generation++; break;
        case 1: e.owner.helper_cookie++; break;
        case 2: e.vdev_id++; break;
        case 3: e.requester++; break;
        case 4: e.scan_id++; break;
        case 5: e.freq++; break;
        }
        CHECK(!hdd_wonder_dwell_event(&d, &e, 1001));
        CHECK(!ready(&d, 1001));
        e.type = HDD_WONDER_DWELL_TERMINAL;
        if (field != 5) {
            CHECK(!hdd_wonder_dwell_event(&d, &e, 1002));
            CHECK(d.phase != HDD_WONDER_DWELL_IDLE);
        } else {
            CHECK(d.revoked);
            CHECK(hdd_wonder_dwell_event(&d, &e, 1002));
            CHECK(hdd_wonder_dwell_reserve(&d, &owner, &scan, 1002, 1100, 50));
        }
        CHECK(send(&d, HDD_WONDER_DWELL_FOREIGN_CHANNEL, 1003));
        CHECK(ready(&d, 1003));
        struct hdd_wonder_dwell_owner wrong_owner = owner;
        struct hdd_wonder_dwell_scan wrong_scan = scan;
        if (field == 0) wrong_owner.generation++;
        if (field == 1) wrong_owner.helper_cookie++;
        if (field == 2) wrong_scan.vdev_id++;
        if (field == 3) wrong_scan.requester++;
        if (field == 4) wrong_scan.scan_id++;
        if (field == 5) wrong_scan.freq++;
        CHECK(!hdd_wonder_dwell_ready(&d, &wrong_owner, &wrong_scan, 1004));
    }
}

static void revoke_latches_until_terminal(void)
{
    enum hdd_wonder_dwell_event_type revocations[] = {
        HDD_WONDER_DWELL_FOREIGN_CHANNEL_EXIT, HDD_WONDER_DWELL_BSS_CHANNEL,
        HDD_WONDER_DWELL_PREEMPTED, HDD_WONDER_DWELL_SUSPENDED,
        HDD_WONDER_DWELL_RESTARTED,
    };
    for (unsigned int i = 0; i < sizeof(revocations) / sizeof(revocations[0]); i++) {
        for (unsigned int entry_first = 0; entry_first < 2; entry_first++) {
            struct hdd_wonder_dwell d;
            prepare(&d);
            if (entry_first) {
                CHECK(send(&d, HDD_WONDER_DWELL_FOREIGN_CHANNEL, 1001));
                CHECK(ready(&d, 1001));
            }
            CHECK(send(&d, revocations[i], 1002));
            CHECK(!ready(&d, 1002));
            CHECK(d.phase != HDD_WONDER_DWELL_IDLE);
            CHECK(send(&d, HDD_WONDER_DWELL_FOREIGN_CHANNEL, 1003));
            CHECK(!ready(&d, 1003));
            CHECK(send(&d, HDD_WONDER_DWELL_STARTED, 1004));
            CHECK(!ready(&d, 1004));
            CHECK(send(&d, HDD_WONDER_DWELL_TERMINAL, 1005));
            CHECK(d.phase == HDD_WONDER_DWELL_IDLE);
            CHECK(!send(&d, HDD_WONDER_DWELL_FOREIGN_CHANNEL, 1006));
            CHECK(!ready(&d, 1006));
        }
    }
}

static void cancel_retains_pending_and_old_owner(void)
{
    struct hdd_wonder_dwell d;
    struct hdd_wonder_dwell_owner next = {8, 92};
    prepare(&d);
    CHECK(send(&d, HDD_WONDER_DWELL_FOREIGN_CHANNEL, 1001));
    CHECK(hdd_wonder_dwell_cancel(&d, &owner, &scan));
    CHECK(d.phase == HDD_WONDER_DWELL_CANCEL_PENDING && !ready(&d, 1002));
    CHECK(d.owner.generation == owner.generation && d.owner.helper_cookie == 91);
    CHECK(!hdd_wonder_dwell_reserve(&d, &next, &scan, 1002, 1100, 50));
    CHECK(!hdd_wonder_dwell_cancel(&d, &next, &scan));
    CHECK(!hdd_wonder_dwell_submission_failed(&d, &owner, &scan));
    CHECK(send(&d, HDD_WONDER_DWELL_FOREIGN_CHANNEL, 1003));
    CHECK(!ready(&d, 1003));
    CHECK(hdd_wonder_dwell_cancel(&d, &owner, &scan));
    CHECK(send(&d, HDD_WONDER_DWELL_TERMINAL, 1004));
    CHECK(!send(&d, HDD_WONDER_DWELL_TERMINAL, 1004));
    CHECK(hdd_wonder_dwell_reserve(&d, &next, &scan, 1005, 1100, 50));
    CHECK(!send(&d, HDD_WONDER_DWELL_FOREIGN_CHANNEL, 1006));
    CHECK(!send(&d, HDD_WONDER_DWELL_TERMINAL, 1006));
    CHECK(d.phase == HDD_WONDER_DWELL_PENDING);
    struct hdd_wonder_dwell_event e = event(HDD_WONDER_DWELL_FOREIGN_CHANNEL);
    e.owner = next;
    CHECK(hdd_wonder_dwell_event(&d, &e, 1007));
    CHECK(hdd_wonder_dwell_ready(&d, &next, &scan, 1007));
    CHECK(!ready(&d, 1007));
}

static void deadline_is_absolute_and_bounded(void)
{
    struct hdd_wonder_dwell d;
    hdd_wonder_dwell_init(&d, 100);
    CHECK(hdd_wonder_dwell_set_home(&d, 1, 5260));
    CHECK(hdd_wonder_dwell_reserve(&d, &owner, &scan, 1000, 1050, 100));
    CHECK(d.deadline_ns == 1050);
    CHECK(send(&d, HDD_WONDER_DWELL_FOREIGN_CHANNEL, 1040));
    CHECK(ready(&d, 1040));
    CHECK(send(&d, HDD_WONDER_DWELL_FOREIGN_CHANNEL, 1049));
    CHECK(d.deadline_ns == 1050 && ready(&d, 1049));
    CHECK(!ready(&d, 1050));
    CHECK(send(&d, HDD_WONDER_DWELL_FOREIGN_CHANNEL, 1051));
    CHECK(!ready(&d, 1051));
    CHECK(d.phase != HDD_WONDER_DWELL_IDLE);
    CHECK(send(&d, HDD_WONDER_DWELL_TERMINAL, 1052));
    CHECK(hdd_wonder_dwell_reserve(&d, &owner, &scan, 1053, 2000, 500));
    CHECK(d.deadline_ns == 1153);
    hdd_wonder_dwell_expire(&d, 1153);
    CHECK(send(&d, HDD_WONDER_DWELL_FOREIGN_CHANNEL, 1154));
    CHECK(!ready(&d, 1154));
}

static void timestamp_wrap_and_duplicate_entry(void)
{
    struct hdd_wonder_dwell d;
    struct hdd_wonder_dwell_event e = event(HDD_WONDER_DWELL_STARTED);
    prepare(&d);
    e.target_timestamp_valid = true;
    e.target_timestamp = 0xfffffff0U;
    CHECK(hdd_wonder_dwell_event(&d, &e, 1001));
    e.type = HDD_WONDER_DWELL_FOREIGN_CHANNEL;
    CHECK(hdd_wonder_dwell_event(&d, &e, 1002));
    CHECK(!ready(&d, 1002));
    e.target_timestamp = 0xffffffe0U;
    CHECK(hdd_wonder_dwell_event(&d, &e, 1003));
    CHECK(!ready(&d, 1003));
    e.target_timestamp = 0;
    CHECK(hdd_wonder_dwell_event(&d, &e, 1004));
    CHECK(ready(&d, 1004));
    CHECK(d.target_timestamp_valid && d.target_timestamp == 0);
    e.type = HDD_WONDER_DWELL_FOREIGN_CHANNEL_EXIT;
    e.target_timestamp = 1;
    CHECK(hdd_wonder_dwell_event(&d, &e, 1005));
    e.type = HDD_WONDER_DWELL_FOREIGN_CHANNEL;
    e.target_timestamp = 2;
    CHECK(hdd_wonder_dwell_event(&d, &e, 1006));
    CHECK(!ready(&d, 1006));
}

static void invalidation_and_home_identity(void)
{
    for (unsigned int before_entry = 0; before_entry < 2; before_entry++) {
        struct hdd_wonder_dwell d;
        prepare(&d);
        if (!before_entry) CHECK(send(&d, HDD_WONDER_DWELL_FOREIGN_CHANNEL, 1001));
        hdd_wonder_dwell_invalidate(&d);
        CHECK(!d.home_valid && d.phase == HDD_WONDER_DWELL_CANCEL_PENDING);
        CHECK(d.scan.scan_id == scan.scan_id && d.owner.helper_cookie == 91);
        CHECK(!ready(&d, 1002));
        CHECK(hdd_wonder_dwell_set_home(&d, 2, 2462));
        CHECK(send(&d, HDD_WONDER_DWELL_FOREIGN_CHANNEL, 1003));
        CHECK(!ready(&d, 1003));
        CHECK(send(&d, HDD_WONDER_DWELL_TERMINAL, 1004));
    }
    struct hdd_wonder_dwell d;
    prepare(&d);
    CHECK(send(&d, HDD_WONDER_DWELL_FOREIGN_CHANNEL, 1001));
    CHECK(hdd_wonder_dwell_set_home(&d, 1, 5260));
    CHECK(ready(&d, 1002));
    CHECK(hdd_wonder_dwell_set_home(&d, 1, 2462));
    CHECK(!ready(&d, 1003));
    CHECK(d.home_freq == 2462 && d.scan.freq == 5745);
}

static void monotonic_regression_fails_closed(void)
{
    struct hdd_wonder_dwell d;
    prepare(&d);
    CHECK(send(&d, HDD_WONDER_DWELL_FOREIGN_CHANNEL, 1010));
    CHECK(ready(&d, 1010));
    CHECK(!ready(&d, 1009));
    CHECK(!ready(&d, 1011));
    CHECK(send(&d, HDD_WONDER_DWELL_TERMINAL, 1008));
    CHECK(d.phase == HDD_WONDER_DWELL_IDLE);
    CHECK(!hdd_wonder_dwell_reserve(&d, &owner, &scan, 1009, 1100, 50));
}

static void invalid_reservations_and_failed_submission(void)
{
    struct hdd_wonder_dwell d;
    struct hdd_wonder_dwell_owner invalid_owner = owner;
    struct hdd_wonder_dwell_scan invalid_scan = scan;
    hdd_wonder_dwell_init(&d, 100);
    CHECK(!hdd_wonder_dwell_reserve(&d, &owner, &scan, 0, 50, 50));
    CHECK(!hdd_wonder_dwell_set_home(&d, 256, 5260));
    CHECK(!hdd_wonder_dwell_set_home(&d, 1, 0));
    CHECK(!hdd_wonder_dwell_set_home(&d, 1, 65536));
    CHECK(hdd_wonder_dwell_set_home(&d, 1, 5260));
    CHECK(!hdd_wonder_dwell_reserve(&d, NULL, &scan, 0, 50, 50));
    CHECK(!hdd_wonder_dwell_reserve(&d, &owner, NULL, 0, 50, 50));
    invalid_owner.generation = 0;
    CHECK(!hdd_wonder_dwell_reserve(&d, &invalid_owner, &scan, 0, 50, 50));
    invalid_owner = owner; invalid_owner.helper_cookie = 0;
    CHECK(!hdd_wonder_dwell_reserve(&d, &invalid_owner, &scan, 0, 50, 50));
    invalid_scan.freq = 0;
    CHECK(!hdd_wonder_dwell_reserve(&d, &owner, &invalid_scan, 0, 50, 50));
    invalid_scan = scan; invalid_scan.vdev_id = 256;
    CHECK(!hdd_wonder_dwell_reserve(&d, &owner, &invalid_scan, 0, 50, 50));
    invalid_scan = scan; invalid_scan.scan_id = 0xffffffffU;
    CHECK(!hdd_wonder_dwell_reserve(&d, &owner, &invalid_scan, 0, 50, 50));
    invalid_scan.scan_id = 0xfffffffeU;
    CHECK(!hdd_wonder_dwell_reserve(&d, &owner, &invalid_scan, 0, 50, 50));
    CHECK(!hdd_wonder_dwell_reserve(&d, &owner, &scan, 0, 50, 0));
    CHECK(!hdd_wonder_dwell_reserve(&d, &owner, &scan, 50, 50, 50));
    CHECK(!hdd_wonder_dwell_reserve(&d, &owner, &scan, UINT64_MAX - 10, UINT64_MAX, 50));
    hdd_wonder_dwell_init(&d, 100);
    CHECK(hdd_wonder_dwell_set_home(&d, 1, 5260));
    CHECK(hdd_wonder_dwell_reserve(&d, &owner, &scan, 0, 50, 50));
    CHECK(!hdd_wonder_dwell_submission_failed(&d, &invalid_owner, &scan));
    CHECK(hdd_wonder_dwell_submission_failed(&d, &owner, &scan));
    CHECK(d.phase == HDD_WONDER_DWELL_IDLE && !ready(&d, 1));
    CHECK(hdd_wonder_dwell_reserve(&d, &owner, &scan, 1, 50, 40));
    CHECK(send(&d, HDD_WONDER_DWELL_STARTED, 2));
    CHECK(!hdd_wonder_dwell_submission_failed(&d, &owner, &scan));
}

static void all_callback_orderings(void)
{
    enum hdd_wonder_dwell_event_type types[] = {
        HDD_WONDER_DWELL_STARTED, HDD_WONDER_DWELL_FOREIGN_CHANNEL,
        HDD_WONDER_DWELL_FOREIGN_CHANNEL_EXIT, HDD_WONDER_DWELL_TERMINAL,
    };
    unsigned int orderings = 0;
    for (unsigned int a = 0; a < 4; a++) for (unsigned int b = 0; b < 4; b++)
    for (unsigned int c = 0; c < 4; c++) for (unsigned int e = 0; e < 4; e++) {
        if (a == b || a == c || a == e || b == c || b == e || c == e) continue;
        unsigned int order[] = {a, b, c, e};
        struct hdd_wonder_dwell d;
        bool observed_entry = false, departed = false, completed = false;
        prepare(&d);
        orderings++;
        for (unsigned int i = 0; i < 4; i++) {
            enum hdd_wonder_dwell_event_type type = types[order[i]];
            CHECK(send(&d, type, 1001 + i) == !completed);
            if (type == HDD_WONDER_DWELL_FOREIGN_CHANNEL) observed_entry = true;
            if (type == HDD_WONDER_DWELL_FOREIGN_CHANNEL_EXIT) departed = true;
            if (type == HDD_WONDER_DWELL_TERMINAL) completed = true;
            CHECK(ready(&d, 1001 + i) == (observed_entry && !departed && !completed));
        }
        CHECK(d.phase == HDD_WONDER_DWELL_IDLE);
    }
    CHECK(orderings == 24);
}

static void trusted_not_submitted_after_local_revocation(void)
{
    for (unsigned int invalidated = 0; invalidated < 2; invalidated++) {
        struct hdd_wonder_dwell d;
        struct hdd_wonder_dwell_owner wrong = owner;
        prepare(&d);
        if (invalidated) hdd_wonder_dwell_invalidate(&d);
        else CHECK(hdd_wonder_dwell_cancel(&d, &owner, &scan));
        CHECK(d.phase == HDD_WONDER_DWELL_CANCEL_PENDING);
        CHECK(!hdd_wonder_dwell_submission_failed(&d, &owner, &scan));
        wrong.helper_cookie++;
        CHECK(!hdd_wonder_dwell_not_submitted(&d, &wrong, &scan));
        CHECK(d.phase == HDD_WONDER_DWELL_CANCEL_PENDING);
        CHECK(hdd_wonder_dwell_not_submitted(&d, &owner, &scan));
        CHECK(d.phase == HDD_WONDER_DWELL_IDLE && !ready(&d, 1001));
        CHECK(!hdd_wonder_dwell_not_submitted(&d, &owner, &scan));
    }
    for (unsigned int entered = 0; entered < 2; entered++) {
        struct hdd_wonder_dwell d;
        prepare(&d);
        CHECK(send(&d, entered ? HDD_WONDER_DWELL_FOREIGN_CHANNEL :
                                 HDD_WONDER_DWELL_STARTED, 1001));
        CHECK(hdd_wonder_dwell_cancel(&d, &owner, &scan));
        CHECK(!hdd_wonder_dwell_not_submitted(&d, &owner, &scan));
        CHECK(d.phase == HDD_WONDER_DWELL_CANCEL_PENDING);
        CHECK(send(&d, HDD_WONDER_DWELL_TERMINAL, 1002));
        CHECK(d.phase == HDD_WONDER_DWELL_IDLE);
    }
}

static void frequency_and_unknown_event_fail_closed(void)
{
    struct hdd_wonder_dwell d;
    prepare(&d);
    CHECK(send(&d, HDD_WONDER_DWELL_FOREIGN_CHANNEL, 1001));
    struct hdd_wonder_dwell_event e = event(HDD_WONDER_DWELL_BSS_CHANNEL);
    CHECK(!hdd_wonder_dwell_event(&d, &e, 1002));
    CHECK(!ready(&d, 1002));
    e.type = HDD_WONDER_DWELL_FOREIGN_CHANNEL_EXIT; e.freq = 5260;
    CHECK(!hdd_wonder_dwell_event(&d, &e, 1003));
    CHECK(!ready(&d, 1003));
    e.freq = 0;
    CHECK(hdd_wonder_dwell_event(&d, &e, 1004));
    CHECK(!ready(&d, 1004));
    CHECK(send(&d, HDD_WONDER_DWELL_TERMINAL, 1005));
    CHECK(hdd_wonder_dwell_reserve(&d, &owner, &scan, 1006, 1100, 90));
    CHECK(send(&d, HDD_WONDER_DWELL_FOREIGN_CHANNEL, 1007));
    e.type = (enum hdd_wonder_dwell_event_type)999;
    CHECK(!hdd_wonder_dwell_event(&d, &e, 1008));
    CHECK(!ready(&d, 1008));
}

static void attributed_frequency_conflict_revokes_ready(void)
{
    enum hdd_wonder_dwell_event_type types[] = {
        HDD_WONDER_DWELL_FOREIGN_CHANNEL,
        HDD_WONDER_DWELL_FOREIGN_CHANNEL_EXIT,
        HDD_WONDER_DWELL_BSS_CHANNEL,
    };
    for (unsigned i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        struct hdd_wonder_dwell d;
        prepare(&d);
        CHECK(send(&d, HDD_WONDER_DWELL_FOREIGN_CHANNEL, 1001));
        for (unsigned field = 0; field < 5; field++) {
            struct hdd_wonder_dwell_event wrong = event(types[i]);
            wrong.freq = types[i] == HDD_WONDER_DWELL_BSS_CHANNEL ? 5745 : 5260;
            if (field == 0) wrong.owner.generation++;
            if (field == 1) wrong.owner.helper_cookie++;
            if (field == 2) wrong.vdev_id++;
            if (field == 3) wrong.requester++;
            if (field == 4) wrong.scan_id++;
            CHECK(!hdd_wonder_dwell_event(&d, &wrong, 1002));
            CHECK(ready(&d, 1002) && !d.revoked);
        }
        struct hdd_wonder_dwell_event conflict = event(types[i]);
        conflict.freq = types[i] == HDD_WONDER_DWELL_BSS_CHANNEL ? 5745 : 5260;
        CHECK(!hdd_wonder_dwell_event(&d, &conflict, 1003));
        CHECK(d.revoked && !ready(&d, 1003));
        CHECK(send(&d, HDD_WONDER_DWELL_FOREIGN_CHANNEL, 1004));
        CHECK(!ready(&d, 1004));
        CHECK(send(&d, HDD_WONDER_DWELL_TERMINAL, 1005));
        CHECK(hdd_wonder_dwell_reserve(&d, &owner, &scan, 1006, 1100, 90));
        CHECK(send(&d, HDD_WONDER_DWELL_FOREIGN_CHANNEL, 1007));
        CHECK(ready(&d, 1007));
        conflict = event(HDD_WONDER_DWELL_FOREIGN_CHANNEL); conflict.freq = 0;
        CHECK(!hdd_wonder_dwell_event(&d, &conflict, 1008));
        CHECK(ready(&d, 1008));
        conflict.type = types[i] == HDD_WONDER_DWELL_BSS_CHANNEL ?
            HDD_WONDER_DWELL_BSS_CHANNEL : HDD_WONDER_DWELL_FOREIGN_CHANNEL_EXIT;
        CHECK(hdd_wonder_dwell_event(&d, &conflict, 1009));
        CHECK(!ready(&d, 1009));
    }
}

static void run(const char *name, void (*test)(void))
{
    case_ok = true;
    test();
    if (cases++) putchar(',');
    printf("{\"name\":\"%s\",\"passed\":%s}", name, case_ok ? "true" : "false");
    if (!case_ok) failed++;
}

int main(void)
{
    printf("{\"cases\":[");
    run("reserve_never_authorizes", reserve_never_authorizes);
    run("stale_identity_never_authorizes", stale_identity_never_authorizes);
    run("revoke_latches_until_terminal", revoke_latches_until_terminal);
    run("cancel_retains_pending_and_old_owner", cancel_retains_pending_and_old_owner);
    run("deadline_is_absolute_and_bounded", deadline_is_absolute_and_bounded);
    run("timestamp_wrap_and_duplicate_entry", timestamp_wrap_and_duplicate_entry);
    run("invalidation_and_home_identity", invalidation_and_home_identity);
    run("monotonic_regression_fails_closed", monotonic_regression_fails_closed);
    run("invalid_reservations_and_failed_submission", invalid_reservations_and_failed_submission);
    run("all_callback_orderings", all_callback_orderings);
    run("trusted_not_submitted_after_local_revocation", trusted_not_submitted_after_local_revocation);
    run("frequency_and_unknown_event_fail_closed", frequency_and_unknown_event_fail_closed);
    run("attributed_frequency_conflict_revokes_ready", attributed_frequency_conflict_revokes_ready);
    printf("],\"assertions\":%u,\"failed\":%u}\n", assertions, failed);
    return failed ? 1 : 0;
}
