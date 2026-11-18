/* Execute exact userspace probe code with radio/sysfs I/O blocked. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>

static ssize_t fixture_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static ssize_t fixture_recvmsg(int, struct msghdr *, int);
static int fixture_poll(struct pollfd *, nfds_t, int);
static int fixture_clock_gettime(clockid_t, struct timespec *);
static unsigned forbidden_calls;
static int forbidden_socket(int domain, int type, int protocol)
{ (void)domain; (void)type; (void)protocol; forbidden_calls++; errno = EPERM; return -1; }
static int __attribute__((unused)) forbidden_open(const char *path, int flags, ...)
{ (void)path; (void)flags; forbidden_calls++; errno = EPERM; return -1; }
static FILE *forbidden_fopen(const char *path, const char *mode)
{ (void)path; (void)mode; forbidden_calls++; errno = EPERM; return NULL; }
static int forbidden_ioctl(int fd, unsigned long request, ...)
{ (void)fd; (void)request; forbidden_calls++; errno = EPERM; return -1; }
static unsigned forbidden_if_nametoindex(const char *name)
{ (void)name; forbidden_calls++; errno = EPERM; return 0; }

#define socket forbidden_socket
#define open forbidden_open
#define fopen forbidden_fopen
#define ioctl forbidden_ioctl
#define if_nametoindex forbidden_if_nametoindex
#define sendto fixture_sendto
#define recvmsg fixture_recvmsg
#define poll fixture_poll
#define clock_gettime fixture_clock_gettime
#define main probe_application_main
#ifndef PROBE_SOURCE_PATH
#define PROBE_SOURCE_PATH "../validation/wonder_offchan_probe.c"
#endif
#include PROBE_SOURCE_PATH
#undef main
#undef socket
#undef open
#undef fopen
#undef ioctl
#undef if_nametoindex
#undef sendto
#undef recvmsg
#undef poll
#undef clock_gettime

static unsigned assertions, cases;
static const char *case_name;
#define CHECK(value) do { assertions++; if (!(value)) { \
    fprintf(stderr, "%s:%d %s: %s\n", __FILE__, __LINE__, case_name, #value); abort(); \
} } while (0)
#define CASE(name) do { case_name = #name; cases++; } while (0)

static uint16_t get16(const uint8_t *p) { return (uint16_t)p[0] | (uint16_t)p[1] << 8; }
static uint32_t get32(const uint8_t *p)
{ return (uint32_t)get16(p) | (uint32_t)get16(p + 2) << 16; }

static struct probe_options options(void)
{
    struct probe_options value;
    char *argv[] = {"probe", "--frequency", "2437", "--receiver", "02:11:22:33:44:55",
                   "--bssid", "02:22:33:44:55:66", "--source", "02:33:44:55:66:77", NULL};
    CHECK(parse_options(9, argv, &value) == 0);
    return value;
}

static void arguments(void)
{
    struct probe_options value;
    CASE(malformed_arguments);
    value = options();
    CHECK(!value.execute && value.frequency == 2437 && value.count == 1);
    CHECK(value.source_given && !value.data_frame);
    char *help[] = {"probe", "--help", NULL};
    CHECK(parse_options(2, help, &value) == 1);
    const char *invalid[][3] = {
        {"--frequency", "0", NULL}, {"--frequency", "-1", NULL},
        {"--frequency", "4294967296", NULL}, {"--frequency", "2437x", NULL},
        {"--count", "0", NULL}, {"--count", "5", NULL},
        {"--wait-ms", "0", NULL}, {"--wait-ms", "5001", NULL},
        {"--nonce", "4294967296", NULL}, {"--receiver", "01:11:22:33:44:55", NULL},
        {"--receiver", "00:00:00:00:00:00", NULL}, {"--bssid", "ff:ff:ff:ff:ff:ff", NULL},
        {"--source", "02:33:44:55:66:77:88", NULL}, {"--unknown", NULL, NULL},
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        char *argv[12] = {"probe", "--frequency", "2437", "--receiver", "02:11:22:33:44:55",
            "--bssid", "02:22:33:44:55:66", "--source", "02:33:44:55:66:77",
            NULL};
        int argc = 9;
        bool replaced = false;
        for (unsigned j = 1; j < 9; j += 2) {
            if (strcmp(argv[j], invalid[i][0])) continue;
            argv[j + 1] = (char *)invalid[i][1]; replaced = true; break;
        }
        if (!replaced) {
            argv[argc++] = (char *)invalid[i][0];
            if (invalid[i][1]) argv[argc++] = (char *)invalid[i][1];
        }
        CHECK(parse_options(argc, argv, &value) < 0);
    }
    char *no_source[] = {"probe", "--frequency", "2437", "--receiver", "02:11:22:33:44:55",
                        "--bssid", "02:22:33:44:55:66", NULL};
    CHECK(parse_options(7, no_source, &value) < 0);
    char *execute_source[] = {"probe", "--execute", "--frequency", "2437", "--receiver", "02:11:22:33:44:55",
                             "--bssid", "02:22:33:44:55:66", "--source", "02:33:44:55:66:77", NULL};
    CHECK(parse_options(10, execute_source, &value) < 0);
    char *execute[] = {"probe", "--execute", "--frequency", "2437", "--receiver", "02:11:22:33:44:55",
                      "--bssid", "02:22:33:44:55:66", NULL};
    CHECK(parse_options(8, execute, &value) == 0 && value.execute && !value.source_given);
    char *bounds[] = {"probe", "--frequency", "5180", "--receiver", "02:11:22:33:44:55",
        "--bssid", "02:22:33:44:55:66", "--source", "02:33:44:55:66:77",
        "--count", "4", "--wait-ms", "5000", "--nonce", "0xffffffff", "--data", NULL};
    CHECK(parse_options(16, bounds, &value) == 0 && value.count == 4 && value.wait_ms == 5000 &&
          value.nonce == UINT32_MAX && value.data_frame);
    char *duplicate[] = {"probe", "--frequency", "2437", "--receiver", "02:11:22:33:44:55",
        "--bssid", "02:22:33:44:55:66", "--source", "02:33:44:55:66:77", "--frequency", "2437", NULL};
    CHECK(parse_options(11, duplicate, &value) < 0);
}

static void radiotap_and_frames(void)
{
    static const uint8_t expected[] = {0, 0, 14, 0, 12, 0, 0, 0, 12, 0, 0x85, 0x09, 0xc0, 0};
    uint8_t packet[1024], next[1024];
    CASE(radiotap_exact_no_tx_options);
    struct probe_options value = options();
    ssize_t length = build_probe_packet(&value, value.source, 0, packet, sizeof(packet));
    CHECK(length == 71);
    CHECK(!memcmp(packet, expected, sizeof(expected)));
    CHECK(get32(packet + 4) == ((1U << 2) | (1U << 3)));
    CHECK((packet[14] & 0xfc) == 0xd0);
    CHECK(!memcmp(packet + 14 + 4, value.receiver, 6));
    CHECK(!memcmp(packet + 14 + 10, value.source, 6));
    CHECK(!memcmp(packet + 14 + 16, value.bssid, 6));
    CHECK(packet[14 + 24] == 127);
    CHECK(!memcmp(packet + 38, (const uint8_t[]){127, 0, 0x1a, 0x11, 0x57}, 5));
    CHECK(get32(packet + 43) == value.nonce && get32(packet + 47) == 0);
    CHECK(!memcmp(packet + 51, "WONDER-OFFCHAN-PROBE", 20));
    CHECK(build_probe_packet(&value, value.source, 1, next, sizeof(next)) == length);
    CHECK(memcmp(packet + 14 + 24, next + 14 + 24, (size_t)length - 14 - 24));
    CHECK(get16(next + 36) == 16 && get32(next + 47) == 1);
    CHECK(build_probe_packet(&value, value.source, 0, next, (size_t)length - 1) < 0);
    value.data_frame = true;
    length = build_probe_packet(&value, value.source, 0, packet, sizeof(packet));
    CHECK(length == 74);
    CHECK(!memcmp(packet, expected, sizeof(expected)));
    CHECK((packet[14] & 0xfc) == 0x08);
    CHECK((packet[15] & 3) == 0);
    CHECK(!memcmp(packet + 38, (const uint8_t[]){0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0xb5}, 8));
    CHECK(get32(packet + 46) == value.nonce && get32(packet + 50) == 0);
    value.frequency = 5180;
    CHECK(build_probe_packet(&value, value.source, 0, packet, sizeof(packet)) > 0);
    CHECK(get16(packet + 10) == 5180 && get16(packet + 12) == 0x0140);
}

static const uint8_t *attribute(const uint8_t *data, size_t length, uint16_t type,
                                uint16_t *payload_length)
{
    while (length >= 4) {
        uint16_t size = get16(data), kind = get16(data + 2);
        if (size < 4 || size > length) return NULL;
        if ((kind & NLA_TYPE_MASK) == type) {
            *payload_length = size - 4;
            return data + 4;
        }
        size_t skip = (size + 3U) & ~3U;
        if (skip > length) return NULL;
        data += skip; length -= skip;
    }
    return NULL;
}

static void netlink_commands(void)
{
    uint8_t data[256]; uint16_t size;
    CASE(netlink_exact_frequency_bandwidth);
    ssize_t length = build_family_request(data, sizeof(data), 17, 23);
    CHECK(length >= 20 && get32(data) == (uint32_t)length);
    CHECK(get16(data + 4) == GENL_ID_CTRL && get32(data + 8) == 17 && get32(data + 12) == 23);
    CHECK(get16(data + 6) & NLM_F_REQUEST);
    CHECK(data[16] == CTRL_CMD_GETFAMILY);
    const uint8_t *payload = attribute(data + 20, (size_t)length - 20, CTRL_ATTR_FAMILY_NAME, &size);
    CHECK(payload && size == 8 && !memcmp(payload, "nl80211\0", 8));
    length = build_set_frequency(data, sizeof(data), 42, 18, 23, 7, 2437);
    CHECK(length == 64 && get32(data) == 64);
    CHECK(get16(data + 4) == 42 && get32(data + 8) == 18 && get32(data + 12) == 23);
    CHECK((get16(data + 6) & (NLM_F_REQUEST | NLM_F_ACK)) == (NLM_F_REQUEST | NLM_F_ACK));
    CHECK(data[16] == NL80211_CMD_VENDOR);
    payload = attribute(data + 20, (size_t)length - 20, NL80211_ATTR_IFINDEX, &size);
    CHECK(payload && size == 4 && get32(payload) == 7);
    payload = attribute(data + 20, (size_t)length - 20, NL80211_ATTR_VENDOR_ID, &size);
    CHECK(payload && size == 4 && get32(payload) == 0x001a11);
    payload = attribute(data + 20, (size_t)length - 20, NL80211_ATTR_VENDOR_SUBCMD, &size);
    CHECK(payload && size == 4 && get32(payload) == 1);
    payload = attribute(data + 20, (size_t)length - 20, NL80211_ATTR_VENDOR_DATA, &size);
    CHECK(payload && size == 16);
    static const uint8_t expected_vendor[] = {8, 0, 1, 0, 0x85, 9, 0, 0, 6, 0, 2, 0, 0, 0, 0, 0};
    CHECK(!memcmp(payload, expected_vendor, sizeof(expected_vendor)));
    const uint8_t *frequency = attribute(payload, size, 1, &size);
    CHECK(frequency && size == 4 && get32(frequency) == 2437);
    payload = attribute(data + 20, (size_t)length - 20, NL80211_ATTR_VENDOR_DATA, &size);
    const uint8_t *bandwidth = attribute(payload, size, 2, &size);
    CHECK(bandwidth && size == 2 && get16(bandwidth) == 0);
    CHECK(build_set_frequency(data, 63, 42, 18, 23, 7, 2437) < 0);
    CHECK(build_family_request(data, 20, 17, 23) < 0);
}

struct fixture_datagram {
    uint8_t data[512]; size_t length;
    uint32_t sender_pid, sender_groups;
    unsigned flags;
};
static struct {
    bool active, short_send;
    int send_error;
    unsigned sent, next, count;
    uint64_t now;
    struct fixture_datagram datagrams[3];
} network;

static ssize_t fixture_sendto(int fd, const void *data, size_t length, int flags,
                              const struct sockaddr *address, socklen_t size)
{
    if (!network.active) { forbidden_calls++; errno = EPERM; return -1; }
    const struct sockaddr_nl *target = (const struct sockaddr_nl *)address;
    CHECK(fd == 123 && flags == MSG_DONTWAIT && size == sizeof(*target));
    CHECK(target->nl_family == AF_NETLINK && target->nl_pid == 0 && target->nl_groups == 0);
    CHECK(length >= 20 && get32(data) == length);
    network.sent++;
    if (network.send_error) { errno = network.send_error; return -1; }
    return (ssize_t)length - (network.short_send ? 1 : 0);
}
static ssize_t fixture_recvmsg(int fd, struct msghdr *message, int flags)
{
    if (!network.active) { forbidden_calls++; errno = EPERM; return -1; }
    CHECK(fd == 123 && flags == MSG_DONTWAIT && network.next < network.count);
    CHECK(message->msg_iovlen == 1 && message->msg_namelen == sizeof(struct sockaddr_nl));
    const struct fixture_datagram *value = &network.datagrams[network.next++];
    CHECK(message->msg_iov[0].iov_len >= value->length);
    memcpy(message->msg_iov[0].iov_base, value->data, value->length);
    struct sockaddr_nl sender = {.nl_family = AF_NETLINK, .nl_pid = value->sender_pid,
                                .nl_groups = value->sender_groups};
    memcpy(message->msg_name, &sender, sizeof(sender));
    message->msg_flags = (int)value->flags;
    return (ssize_t)value->length;
}
static int fixture_poll(struct pollfd *fds, nfds_t count, int timeout)
{
    if (!network.active) { forbidden_calls++; errno = EPERM; return -1; }
    CHECK(count == 1 && fds[0].fd == 123 && fds[0].events == POLLIN && timeout > 0);
    fds[0].revents = POLLIN;
    return network.next < network.count ? 1 : 0;
}
static int fixture_clock_gettime(clockid_t clock_id, struct timespec *now)
{
    if (!network.active) { forbidden_calls++; errno = EPERM; return -1; }
    CHECK(clock_id == CLOCK_MONOTONIC);
    network.now += 1000;
    now->tv_sec = (time_t)(network.now / 1000000000);
    now->tv_nsec = (long)(network.now % 1000000000);
    return 0;
}

static void fixture_header(struct fixture_datagram *value, uint16_t type, uint32_t seq,
                           uint32_t pid, const void *payload, size_t length)
{
    CHECK(length + 16 <= sizeof(value->data));
    memset(value, 0, sizeof(*value));
    value->length = 16 + length;
    put_le32(value->data, (uint32_t)value->length); put_le16(value->data + 4, type);
    put_le32(value->data + 8, seq); put_le32(value->data + 12, pid);
    memcpy(value->data + 16, payload, length);
}
static void fixture_ack(struct fixture_datagram *value, bool resolve, int error)
{
    struct nlmsgerr reply = {.error = error,
        .msg = {.nlmsg_len = resolve ? 32 : 64, .nlmsg_type = resolve ? GENL_ID_CTRL : 42,
                .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK, .nlmsg_seq = 17, .nlmsg_pid = 23}};
    fixture_header(value, NLMSG_ERROR, 17, 23, &reply, sizeof(reply));
}
static void fixture_family(struct fixture_datagram *value)
{
    const uint8_t payload[] = {CTRL_CMD_NEWFAMILY, 1, 0, 0,
        6, 0, CTRL_ATTR_FAMILY_ID, 0, 42, 0, 0, 0};
    fixture_header(value, GENL_ID_CTRL, 17, 23, payload, sizeof(payload));
}
static void reset_network(void)
{
    memset(&network, 0, sizeof(network)); network.active = true; network.now = 1000000000;
}
static int transact(bool resolve)
{
    struct live_context live = {.netlink_fd = 123, .pid = 23, .family = 42, .wait_ms = 5};
    uint8_t request[128];
    ssize_t length = resolve ? build_family_request(request, sizeof(request), 17, 23) :
        build_set_frequency(request, sizeof(request), 42, 17, 23, 7, 2437);
    CHECK(length > 0);
    int result = netlink_transaction(&live, request, (size_t)length, 17, resolve);
    if (!result) CHECK(live.family == 42);
    network.active = false;
    return result;
}

static void netlink_replies(void)
{
    uint16_t family;
    const uint8_t good[] = {6, 0, CTRL_ATTR_FAMILY_ID, 0, 42, 0, 0, 0};
    uint8_t attributes[16];
    CASE(family_attributes_require_complete_stream);
    CHECK(parse_family_attrs(good, sizeof(good), &family) == 0 && family == 42);
    CHECK(parse_family_attrs(good, 6, &family) == -EBADMSG);
    CHECK(parse_family_attrs(good, 3, &family) == -EBADMSG);
    memcpy(attributes, good, 8); memcpy(attributes + 8, good, 8);
    CHECK(parse_family_attrs(attributes, 16, &family) == -EBADMSG);
    attributes[8] = 3;
    CHECK(parse_family_attrs(attributes, 16, &family) == -EBADMSG);
    memcpy(attributes, good, 8); attributes[4] = 15;
    CHECK(parse_family_attrs(attributes, 8, &family) == -EBADMSG);

    CASE(resolver_consumes_reply_and_ack);
    reset_network(); network.count = 2;
    fixture_ack(&network.datagrams[0], true, 0); fixture_family(&network.datagrams[1]);
    CHECK(transact(true) == 0 && network.next == 2 && network.sent == 1);
    reset_network(); network.count = 2;
    fixture_family(&network.datagrams[0]); fixture_ack(&network.datagrams[1], true, 0);
    CHECK(transact(true) == 0 && network.next == 2);
    reset_network(); network.count = 1; fixture_family(&network.datagrams[0]);
    CHECK(transact(true) == -ETIMEDOUT);
    reset_network(); network.count = 1; fixture_ack(&network.datagrams[0], true, 0);
    CHECK(transact(true) == -ETIMEDOUT);

    CASE(netlink_current_kernel_ack_only);
    reset_network(); network.count = 1; fixture_ack(&network.datagrams[0], false, 0);
    CHECK(transact(false) == 0);
    reset_network(); network.count = 1; fixture_ack(&network.datagrams[0], false, -EAGAIN);
    CHECK(transact(false) == -EAGAIN && network.sent == 1);
    reset_network(); network.count = 1; fixture_ack(&network.datagrams[0], false, 0);
    network.datagrams[0].sender_pid = 1;
    CHECK(transact(false) == -EBADMSG);
    reset_network(); network.count = 1; fixture_ack(&network.datagrams[0], false, 0);
    network.datagrams[0].sender_groups = 1;
    CHECK(transact(false) == -EBADMSG);
    reset_network(); network.count = 1; fixture_ack(&network.datagrams[0], false, 0);
    put_le32(network.datagrams[0].data + 8, 16);
    CHECK(transact(false) == -EBADMSG);
    reset_network(); network.count = 1; fixture_ack(&network.datagrams[0], false, 0);
    put_le32(network.datagrams[0].data + 12, 99);
    CHECK(transact(false) == -EBADMSG);
    reset_network(); network.count = 1; fixture_ack(&network.datagrams[0], false, 0);
    network.datagrams[0].flags = MSG_TRUNC;
    CHECK(transact(false) == -EBADMSG);
    reset_network(); network.count = 1; fixture_ack(&network.datagrams[0], false, 0);
    put_le32(network.datagrams[0].data + 28, 16);
    CHECK(transact(false) == -EBADMSG);
    reset_network(); network.short_send = true;
    CHECK(transact(false) == -EIO && network.next == 0);
    reset_network(); network.send_error = EPERM;
    CHECK(transact(false) == -EPERM && network.next == 0);
}

static struct probe_stats idle_stats(void)
{
    return (struct probe_stats){.generation = 7, .cookie = 9, .home_mhz = 5180,
        .home_vdev = 0, .monitor_vdev = 4, .helper_vdev = 5};
}
static struct probe_stats ready_stats(uint64_t attempt)
{
    struct probe_stats value = idle_stats();
    value.phase = 2; value.requester = 11; value.scan_id = 13;
    value.scan_mhz = value.selected_mhz = 2437; value.firmware_ref = 1;
    value.entry_host_ns = attempt + 1; value.deadline_host_ns = attempt + 32000000;
    return value;
}

static void change_stat(char *out, size_t capacity, const char *input,
                        const char *field, const char *replacement)
{
    const char *begin = strstr(input, field), *end;
    CHECK(begin && (begin == input || begin[-1] == ' ') && begin[strlen(field)] == '=');
    end = begin + strcspn(begin, " \n");
    int length = snprintf(out, capacity, "%.*s%s%s", (int)(begin - input), input,
                          replacement ? replacement : "", end);
    CHECK(length >= 0 && (size_t)length < capacity);
}

static void stat_parsing_and_readiness(void)
{
    static const char stats[] =
        "home_vdev=0 home_mhz=5180 monitor_vdev=4 helper_vdev=5 generation=7 cookie=9 "
        "requester=11 scan_id=13 scan_mhz=2437 selected_mhz=2437 phase=2 revoked=0 firmware_ref=1 "
        "deadline_host_ns=1032000000 entry_host_ns=1000000001 events=2 last_type=1 "
        "last_reason=0 last_mhz=2437 last_notice=0 last_event_host_ns=1000000001 target_timestamp_us=0\n";
    struct probe_stats value, baseline = idle_stats();
    CASE(stats_complete_strict_readiness);
    CHECK(parse_probe_stats(stats, &value) == 0);
    CHECK(value.home_vdev == 0 && value.generation == 7 && value.cookie == 9);
    CHECK(probe_ready(&value, &baseline, 1000000000, 2437, 1000000002));
    CHECK(!probe_ready(&value, &baseline, 1000000000, 2437, value.deadline_host_ns));
    CHECK(!probe_ready(&value, &baseline, 1000000000, 5180, 1000000002));
    char text[2048];
    snprintf(text, sizeof(text), "%sgeneration=8\n", stats);
    CHECK(parse_probe_stats(text, &value) < 0);
    CHECK(parse_probe_stats("active=0\n", &value) < 0);
    CHECK(parse_probe_stats("generation=7\n", &value) < 0);
    change_stat(text, sizeof(text), stats, "generation", "generation=18446744073709551616");
    CHECK(parse_probe_stats(text, &value) < 0);
    change_stat(text, sizeof(text), stats, "generation", "generation=-1");
    CHECK(parse_probe_stats(text, &value) < 0);
    change_stat(text, sizeof(text), stats, "scan_id", "scan_id=4294967296");
    CHECK(parse_probe_stats(text, &value) < 0);
    change_stat(text, sizeof(text), stats, "scan_id", "scan_id=+13");
    CHECK(parse_probe_stats(text, &value) < 0);
    change_stat(text, sizeof(text), stats, "phase", "phase=4");
    CHECK(parse_probe_stats(text, &value) < 0);
    change_stat(text, sizeof(text), stats, "revoked", "revoked=2");
    CHECK(parse_probe_stats(text, &value) < 0);
    change_stat(text, sizeof(text), stats, "firmware_ref", "firmware_ref=2");
    CHECK(parse_probe_stats(text, &value) < 0);
    change_stat(text, sizeof(text), stats, "scan_id", "scan_id=13x");
    CHECK(parse_probe_stats(text, &value) < 0);
    change_stat(text, sizeof(text), stats, "scan_id", "scan_id=");
    CHECK(parse_probe_stats(text, &value) < 0);
    const char *fields[] = {"home_vdev", "home_mhz", "monitor_vdev", "helper_vdev", "generation",
        "cookie", "requester", "scan_id", "scan_mhz", "selected_mhz", "phase", "revoked",
        "firmware_ref", "deadline_host_ns", "entry_host_ns", "events", "last_type", "last_reason",
        "last_mhz", "last_notice", "last_event_host_ns", "target_timestamp_us"};
    for (unsigned i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        change_stat(text, sizeof(text), stats, fields[i], NULL);
        CHECK(parse_probe_stats(text, &value) < 0);
    }
    struct probe_stats ready = ready_stats(1000000000), changed;
    CHECK(same_lease(&ready, &ready));
    changed = ready; changed.scan_id++; CHECK(!same_lease(&ready, &changed));
    changed = ready; changed.deadline_host_ns++; CHECK(!same_lease(&ready, &changed));
    changed = ready; changed.cookie++; CHECK(!same_lease(&ready, &changed));
    changed = ready; changed.generation++; CHECK(!same_lease(&ready, &changed));
    changed = ready; changed.requester++; CHECK(!same_lease(&ready, &changed));
    changed = ready; changed.scan_mhz++; CHECK(!same_lease(&ready, &changed));
    changed = ready; changed.selected_mhz++; CHECK(!probe_ready(&changed, &baseline, 1000000000, 2437, 1000000002));
    changed = ready; changed.phase = 1; CHECK(!probe_ready(&changed, &baseline, 1000000000, 2437, 1000000002));
    changed = ready; changed.revoked = 1; CHECK(!probe_ready(&changed, &baseline, 1000000000, 2437, 1000000002));
    changed = ready; changed.firmware_ref = 0; CHECK(!probe_ready(&changed, &baseline, 1000000000, 2437, 1000000002));
    changed = ready; changed.entry_host_ns = 999999999; CHECK(!probe_ready(&changed, &baseline, 1000000000, 2437, 1000000002));
    changed = ready; changed.generation++; CHECK(!probe_ready(&changed, &baseline, 1000000000, 2437, 1000000002));
    changed = ready; changed.cookie++; CHECK(!probe_ready(&changed, &baseline, 1000000000, 2437, 1000000002));
    changed = ready; changed.home_vdev++; CHECK(!probe_ready(&changed, &baseline, 1000000000, 2437, 1000000002));
    changed = ready; changed.monitor_vdev++; CHECK(!probe_ready(&changed, &baseline, 1000000000, 2437, 1000000002));
    changed = ready; changed.helper_vdev++; CHECK(!probe_ready(&changed, &baseline, 1000000000, 2437, 1000000002));
    changed = ready; changed.requester = 0; CHECK(!probe_ready(&changed, &baseline, 1000000000, 2437, 1000000002));
    changed = ready; changed.scan_id = 0; CHECK(!probe_ready(&changed, &baseline, 1000000000, 2437, 1000000002));
    changed = ready; changed.entry_host_ns = 1000000003; CHECK(!probe_ready(&changed, &baseline, 1000000000, 2437, 1000000002));
    CHECK(!probe_ready(&ready, &baseline, 0, 2437, 1000000002));
    CHECK(!probe_ready(&ready, &baseline, 1000000000, 2437, ready.deadline_host_ns - 1000000));
    CHECK(probe_ready(&ready, &baseline, 1000000000, 2437, ready.deadline_host_ns - 1000001));
}

struct mock_io {
    unsigned preflight_calls, prepare_calls, set_calls, send_calls, stats_calls, ready_reads, closes;
    unsigned sleeps, reports;
    int preflight_error, prepare_error, set_error, send_error;
    bool busy_baseline, stale_entry, changed_second_tuple, expired_second_read, hold_retirement;
    bool short_send, invalid_source, changed_retirement_owner;
    unsigned stats_error_at;
    bool sent_this_lease, retirement_seen;
    uint64_t now, attempt;
};
static int mock_preflight(void *context, const struct probe_options *opts, uint8_t source[6])
{
    struct mock_io *m = context;
    CHECK(opts->execute); CHECK(!m->prepare_calls && !m->set_calls && !m->send_calls);
    m->preflight_calls++;
    static const uint8_t mac[] = {2, 0x33, 0x44, 0x55, 0x66, 0x77};
    memcpy(source, mac, 6);
    if (m->invalid_source) source[0] = 1;
    return m->preflight_error;
}
static int mock_prepare(void *context)
{
    struct mock_io *m = context;
    CHECK(m->preflight_calls == 1 && !m->set_calls && !m->send_calls);
    m->prepare_calls++; return m->prepare_error;
}
static int mock_stats(void *context, struct probe_stats *stats)
{
    struct mock_io *m = context; m->stats_calls++;
    CHECK(m->preflight_calls == 1 && m->prepare_calls == 1);
    if (m->stats_error_at == m->stats_calls) return -EBADMSG;
    if (!m->set_calls) {
        *stats = idle_stats();
        if (m->busy_baseline) { stats->phase = 1; stats->firmware_ref = 1; }
    } else if (!m->sent_this_lease) {
        *stats = ready_stats(m->attempt);
        stats->scan_id += m->set_calls;
        m->ready_reads++;
        if (m->stale_entry) stats->entry_host_ns = m->attempt - 1;
        if (m->changed_second_tuple && m->ready_reads >= 2) stats->scan_id++;
        if (m->expired_second_read && m->ready_reads >= 2) m->now = stats->deadline_host_ns;
    } else {
        *stats = idle_stats();
        if (m->hold_retirement) { stats->phase = 3; stats->firmware_ref = 1; }
        else m->retirement_seen = true;
        if (m->changed_retirement_owner) stats->generation++;
    }
    return 0;
}
static int mock_set(void *context, uint32_t frequency)
{
    struct mock_io *m = context;
    CHECK(frequency == 2437 && m->prepare_calls == 1 && m->stats_calls > 0);
    if (m->set_calls) CHECK(m->retirement_seen);
    m->set_calls++; m->attempt = m->now; m->ready_reads = 0;
    m->sent_this_lease = false; m->retirement_seen = false;
    return m->set_error;
}
static ssize_t mock_send(void *context, const uint8_t *data, size_t length)
{
    struct mock_io *m = context;
    CHECK(m->ready_reads >= 2 && m->prepare_calls == 1);
    CHECK(!m->sent_this_lease && length > 38 && get16(data + 10) == 2437);
    CHECK(m->now < m->attempt + 32000000);
    m->send_calls++; m->sent_this_lease = true;
    return m->send_error ? m->send_error : (ssize_t)length - (m->short_send ? 1 : 0);
}
static uint64_t mock_now(void *context)
{ struct mock_io *m = context; m->now += 100; return m->now; }
static int mock_sleep(void *context, unsigned milliseconds)
{ struct mock_io *m = context; m->sleeps++; m->now += (uint64_t)milliseconds * 1000000; return 0; }
static void mock_report(void *context, const char *event, int result,
                        const struct probe_stats *stats, unsigned index)
{ struct mock_io *m = context; (void)event; (void)result; (void)stats; (void)index; m->reports++; }
static void mock_close(void *context) { struct mock_io *m = context; m->closes++; }
static int execute(struct mock_io *mock, unsigned count)
{
    struct probe_options value = options(); value.execute = true; value.source_given = false;
    value.count = count; value.wait_ms = 5;
    struct probe_io io = {.context = mock, .preflight = mock_preflight, .prepare = mock_prepare,
        .stats = mock_stats, .set_frequency = mock_set, .send_packet = mock_send,
        .now_ns = mock_now, .sleep_ms = mock_sleep, .report = mock_report, .close = mock_close};
    return run_probe(&value, &io);
}

static void control_ordering(void)
{
    struct mock_io m;
    CASE(prepare_ready_send_retirement_order);
    m = (struct mock_io){.now = 1000000000};
    CHECK(execute(&m, 2) == 0);
    CHECK(m.preflight_calls == 1 && m.prepare_calls == 1 && m.set_calls == 2 && m.send_calls == 2);
    CHECK(m.retirement_seen && m.closes == 1);
    CASE(preflight_rejection_has_no_control);
    m = (struct mock_io){.now = 1000000000, .preflight_error = -EPERM};
    CHECK(execute(&m, 1) < 0 && !m.prepare_calls && !m.set_calls && !m.send_calls);
    CASE(prepare_error_has_no_control);
    m = (struct mock_io){.now = 1000000000, .prepare_error = -EACCES};
    CHECK(execute(&m, 1) < 0 && !m.set_calls && !m.send_calls);
    CASE(busy_baseline_denies_new_control);
    m = (struct mock_io){.now = 1000000000, .busy_baseline = true};
    CHECK(execute(&m, 1) < 0 && !m.set_calls && !m.send_calls);
    CASE(failed_set_frequency_is_not_retried);
    m = (struct mock_io){.now = 1000000000, .set_error = -EAGAIN};
    CHECK(execute(&m, 2) < 0 && m.set_calls == 1 && !m.send_calls);
    CASE(old_entry_never_authorizes_send);
    m = (struct mock_io){.now = 1000000000, .stale_entry = true};
    CHECK(execute(&m, 1) < 0 && !m.send_calls);
    CASE(changed_second_tuple_denies_send);
    m = (struct mock_io){.now = 1000000000, .changed_second_tuple = true};
    CHECK(execute(&m, 1) < 0 && !m.send_calls);
    CASE(expiry_on_final_read_denies_send);
    m = (struct mock_io){.now = 1000000000, .expired_second_read = true};
    CHECK(execute(&m, 1) < 0 && !m.send_calls);
    CASE(no_repeat_without_firmware_retirement);
    m = (struct mock_io){.now = 1000000000, .hold_retirement = true};
    CHECK(execute(&m, 2) < 0 && m.set_calls == 1 && m.send_calls == 1);
    CASE(send_error_stops_repetition);
    m = (struct mock_io){.now = 1000000000, .send_error = -EIO};
    CHECK(execute(&m, 2) < 0 && m.set_calls == 1 && m.send_calls == 1);
    CHECK(m.retirement_seen);
    CASE(short_send_is_not_success);
    m = (struct mock_io){.now = 1000000000, .short_send = true};
    CHECK(execute(&m, 2) < 0 && m.set_calls == 1 && m.send_calls == 1 && m.retirement_seen);
    CASE(invalid_source_denies_control);
    m = (struct mock_io){.now = 1000000000, .invalid_source = true};
    CHECK(execute(&m, 1) < 0 && !m.set_calls && !m.send_calls);
    CASE(stats_error_denies_send);
    m = (struct mock_io){.now = 1000000000, .stats_error_at = 1};
    CHECK(execute(&m, 1) < 0 && !m.set_calls && !m.send_calls);
    m = (struct mock_io){.now = 1000000000, .stats_error_at = 2};
    CHECK(execute(&m, 1) < 0 && m.set_calls == 1 && !m.send_calls);
    m = (struct mock_io){.now = 1000000000, .stats_error_at = 3};
    CHECK(execute(&m, 1) < 0 && m.set_calls == 1 && !m.send_calls);
    CASE(retirement_owner_change_stops_repetition);
    m = (struct mock_io){.now = 1000000000, .changed_retirement_owner = true};
    CHECK(execute(&m, 2) < 0 && m.set_calls == 1 && m.send_calls == 1);
    CASE(last_packet_requires_retirement);
    m = (struct mock_io){.now = 1000000000, .hold_retirement = true};
    CHECK(execute(&m, 1) < 0 && m.set_calls == 1 && m.send_calls == 1);
}

static void dry_run_no_radio_or_sysfs(void)
{
    CASE(dry_run_has_no_radio_or_sysfs_io);
    int output[2]; CHECK(pipe(output) == 0);
    fflush(stdout); int saved = dup(STDOUT_FILENO); CHECK(saved >= 0);
    CHECK(dup2(output[1], STDOUT_FILENO) >= 0); close(output[1]);
    char *argv[] = {"probe", "--frequency", "2437", "--receiver", "02:11:22:33:44:55",
                   "--bssid", "02:22:33:44:55:66", "--source", "02:33:44:55:66:77", NULL};
    int result = probe_application_main(9, argv);
    fflush(stdout); CHECK(dup2(saved, STDOUT_FILENO) >= 0); close(saved);
    char text[8192]; ssize_t length = read(output[0], text, sizeof(text) - 1); close(output[0]);
    CHECK(result == 0 && forbidden_calls == 0 && length > 0);
    text[length] = 0;
    CHECK(strstr(text, "2437") && strstr(text, "dry_run"));
    CHECK(strstr(text, "\"rf_verified\":false") && strstr(text, "\"sockets_opened\":false"));
    CHECK(strstr(text, "\"device_state_read\":false") && strstr(text, "\"family_id\":0"));
    CHECK(strstr(text, "\"ifindex\":0") && strstr(text, "00000e000c0000000c008509c000"));
}

int main(void)
{
    arguments(); radiotap_and_frames(); netlink_commands(); netlink_replies(); stat_parsing_and_readiness();
    control_ordering(); dry_run_no_radio_or_sysfs();
    printf("{\"assertions\":%u,\"cases\":%u,\"forbidden_io_calls\":%u}\n",
           assertions, cases, forbidden_calls);
    return 0;
}
