/* Android-local bounded Wonder off-channel probe. No libnl dependency.
 * Default dry-run opens no sockets or files and reads no device state.
 * --execute requires a manually prepared/open Wonder provider session, no
 * competing frequency controller, and explicit wonder_sta_offchan_probe
 * opt-in. Socket acceptance is submission
 * evidence only. This program never claims RF transmission or HOME restoration.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/genetlink.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CONTROL_IF "wonder0"
#define RAW_IF "wondertap0"
#define PARAM_DIR "/sys/module/qca_cld3_wcn7750/parameters/"
#define READY_GUARD_NS UINT64_C(1000000)
#define PACKET_CAPACITY 128U
#define NETLINK_CAPACITY 4096U
#define VENDOR_OUI 0x001a11U

struct probe_options {
    bool execute, data_frame;
    uint32_t frequency, nonce;
    unsigned count, wait_ms;
    uint8_t source[6], receiver[6], bssid[6];
    bool source_given;
};

struct probe_stats {
    uint64_t generation, cookie, deadline_host_ns, entry_host_ns, events;
    uint32_t home_mhz, home_vdev, monitor_vdev, helper_vdev, requester;
    uint32_t scan_id, scan_mhz, selected_mhz, phase, revoked, firmware_ref;
};

struct probe_io {
    void *context;
    int (*preflight)(void *, const struct probe_options *, uint8_t[6]);
    int (*prepare)(void *);
    int (*stats)(void *, struct probe_stats *);
    int (*set_frequency)(void *, uint32_t);
    ssize_t (*send_packet)(void *, const uint8_t *, size_t);
    uint64_t (*now_ns)(void *);
    int (*sleep_ms)(void *, unsigned);
    void (*report)(void *, const char *, int, const struct probe_stats *, unsigned);
    void (*close)(void *);
};

static bool valid_frequency(uint32_t mhz)
{
    return (mhz >= 2412 && mhz <= 2472 && (mhz - 2412) % 5 == 0) ||
           (mhz >= 4900 && mhz <= 5900 && mhz % 5 == 0);
}

static bool valid_mac(const uint8_t mac[6])
{
    unsigned any = 0;
    for (unsigned i = 0; i < 6; i++) any |= mac[i];
    return any != 0 && !(mac[0] & 1);
}

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_mac(const char *text, uint8_t mac[6])
{
    if (!text || strlen(text) != 17) return -EINVAL;
    for (unsigned i = 0; i < 6; i++) {
        int hi = hex_digit(text[i * 3]), lo = hex_digit(text[i * 3 + 1]);
        if (hi < 0 || lo < 0 || (i < 5 && text[i * 3 + 2] != ':')) return -EINVAL;
        mac[i] = (uint8_t)((hi << 4) | lo);
    }
    return valid_mac(mac) ? 0 : -EINVAL;
}

static int parse_number(const char *text, int base, uint64_t limit, uint64_t *value)
{
    char *end;
    unsigned long long parsed;
    if (!text || !*text || *text == '-' || *text == '+' || isspace((unsigned char)*text))
        return -EINVAL;
    errno = 0;
    parsed = strtoull(text, &end, base);
    if (errno || *end || parsed > limit) return -EINVAL;
    *value = (uint64_t)parsed;
    return 0;
}

static int parse_options(int argc, char **argv, struct probe_options *options)
{
    unsigned seen = 0;
    memset(options, 0, sizeof(*options));
    options->count = 1;
    options->wait_ms = 1000;
    options->nonce = 0x574f4e44;
    if (argc == 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))) return 1;
    for (int i = 1; i < argc; i++) {
        unsigned bit;
        const char *arg = argv[i], *value;
        uint64_t number = 0;
        if (!strcmp(arg, "--execute")) bit = 1U << 0;
        else if (!strcmp(arg, "--data")) bit = 1U << 1;
        else if (!strcmp(arg, "--frequency")) bit = 1U << 2;
        else if (!strcmp(arg, "--source")) bit = 1U << 3;
        else if (!strcmp(arg, "--receiver")) bit = 1U << 4;
        else if (!strcmp(arg, "--bssid")) bit = 1U << 5;
        else if (!strcmp(arg, "--count")) bit = 1U << 6;
        else if (!strcmp(arg, "--wait-ms")) bit = 1U << 7;
        else if (!strcmp(arg, "--nonce")) bit = 1U << 8;
        else return -EINVAL;
        if (seen & bit) return -EINVAL;
        seen |= bit;
        if (bit == (1U << 0)) { options->execute = true; continue; }
        if (bit == (1U << 1)) { options->data_frame = true; continue; }
        if (++i >= argc) return -EINVAL;
        value = argv[i];
        if (bit == (1U << 3)) {
            if (parse_mac(value, options->source)) return -EINVAL;
            options->source_given = true;
        } else if (bit == (1U << 4)) {
            if (parse_mac(value, options->receiver)) return -EINVAL;
        } else if (bit == (1U << 5)) {
            if (parse_mac(value, options->bssid)) return -EINVAL;
        } else {
            if (parse_number(value, bit == (1U << 8) ? 0 : 10, UINT32_MAX, &number))
                return -EINVAL;
            if (bit == (1U << 2)) options->frequency = (uint32_t)number;
            if (bit == (1U << 6)) options->count = (unsigned)number;
            if (bit == (1U << 7)) options->wait_ms = (unsigned)number;
            if (bit == (1U << 8)) options->nonce = (uint32_t)number;
        }
    }
    if ((seen & ((1U << 2) | (1U << 4) | (1U << 5))) !=
                ((1U << 2) | (1U << 4) | (1U << 5)) ||
        !valid_frequency(options->frequency) || options->count < 1 || options->count > 4 ||
        options->wait_ms < 1 || options->wait_ms > 5000 ||
        options->source_given == options->execute) return -EINVAL;
    return 0;
}

static void put_le16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)value; p[1] = (uint8_t)(value >> 8);
}

static void put_le32(uint8_t *p, uint32_t value)
{
    for (unsigned i = 0; i < 4; i++) p[i] = (uint8_t)(value >> (8 * i));
}

static ssize_t build_probe_packet(const struct probe_options *options,
        const uint8_t source[6], unsigned index, uint8_t *out, size_t capacity)
{
    static const uint8_t snap[] = { 0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0xb5 };
    static const uint8_t action[] = { 127, 0, 0x1a, 0x11, 0x57 };
    static const char marker[] = "WONDER-OFFCHAN-PROBE";
    size_t prefix = options->data_frame ? sizeof(snap) : sizeof(action);
    size_t length = 14 + 24 + prefix + 8 + sizeof(marker) - 1;
    if (!valid_frequency(options->frequency) || !valid_mac(source) ||
        !valid_mac(options->receiver) || !valid_mac(options->bssid)) return -EINVAL;
    if (capacity < length) return -EMSGSIZE;
    memset(out, 0, length);
    put_le16(out + 2, 14);
    put_le32(out + 4, 0x0c); /* RATE + CHANNEL only; no FLAGS/TX_FLAGS/GI. */
    out[8] = 12; /* 6 Mbps, in 500 kbps units. */
    put_le16(out + 10, (uint16_t)options->frequency);
    put_le16(out + 12, options->frequency < 4900 ? 0x00c0 : 0x0140);
    put_le16(out + 14, options->data_frame ? 0x0008 : 0x00d0);
    memcpy(out + 18, options->receiver, 6);
    memcpy(out + 24, source, 6);
    memcpy(out + 30, options->bssid, 6);
    put_le16(out + 36, (uint16_t)((index & 0xfff) << 4));
    memcpy(out + 38, options->data_frame ? snap : action, prefix);
    put_le32(out + 38 + prefix, options->nonce);
    put_le32(out + 42 + prefix, index);
    memcpy(out + 46 + prefix, marker, sizeof(marker) - 1);
    return (ssize_t)length;
}

static int append_attr(uint8_t *out, size_t capacity, size_t *length,
        uint16_t type, const void *value, size_t size)
{
    size_t raw = NLA_HDRLEN + size, aligned = NLA_ALIGN(raw);
    struct nlattr header;
    if (raw > UINT16_MAX || *length > capacity || aligned > capacity - *length)
        return -EMSGSIZE;
    memset(&header, 0, sizeof(header));
    header.nla_type = type; header.nla_len = (uint16_t)raw;
    memset(out + *length, 0, aligned);
    memcpy(out + *length, &header, sizeof(header));
    memcpy(out + *length + NLA_HDRLEN, value, size);
    *length += aligned;
    return 0;
}

static int start_request(uint8_t *out, size_t capacity, uint16_t family,
        uint8_t command, uint32_t seq, uint32_t pid, size_t *length)
{
    struct nlmsghdr header = { .nlmsg_len = NLMSG_HDRLEN + GENL_HDRLEN,
        .nlmsg_type = family, .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
        .nlmsg_seq = seq, .nlmsg_pid = pid };
    struct genlmsghdr gen = { .cmd = command, .version = 1 };
    *length = NLMSG_HDRLEN + GENL_HDRLEN;
    if (capacity < *length) return -EMSGSIZE;
    memset(out, 0, *length);
    memcpy(out, &header, sizeof(header));
    memcpy(out + NLMSG_HDRLEN, &gen, sizeof(gen));
    return 0;
}

static ssize_t finish_request(uint8_t *out, size_t length)
{
    uint32_t wire_length = (uint32_t)length;
    memcpy(out, &wire_length, sizeof(wire_length));
    return (ssize_t)length;
}

static ssize_t build_family_request(uint8_t *out, size_t capacity,
        uint32_t seq, uint32_t pid)
{
    static const char name[] = "nl80211";
    size_t length;
    if (start_request(out, capacity, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, seq, pid, &length) ||
        append_attr(out, capacity, &length, CTRL_ATTR_FAMILY_NAME, name, sizeof(name)))
        return -EMSGSIZE;
    return finish_request(out, length);
}

static ssize_t build_set_frequency(uint8_t *out, size_t capacity, uint16_t family,
        uint32_t seq, uint32_t pid, uint32_t ifindex, uint32_t frequency)
{
    uint8_t vendor[16];
    size_t length, vendor_length = 0;
    uint32_t oui = VENDOR_OUI, subcommand = 1;
    uint16_t width = 0;
    if (!valid_frequency(frequency)) return -EINVAL;
    if (append_attr(vendor, sizeof(vendor), &vendor_length, 1, &frequency, sizeof(frequency)) ||
        append_attr(vendor, sizeof(vendor), &vendor_length, 2, &width, sizeof(width)) ||
        start_request(out, capacity, family, NL80211_CMD_VENDOR, seq, pid, &length) ||
        append_attr(out, capacity, &length, NL80211_ATTR_IFINDEX, &ifindex, sizeof(ifindex)) ||
        append_attr(out, capacity, &length, NL80211_ATTR_VENDOR_ID, &oui, sizeof(oui)) ||
        append_attr(out, capacity, &length, NL80211_ATTR_VENDOR_SUBCMD, &subcommand, sizeof(subcommand)) ||
        append_attr(out, capacity, &length, NL80211_ATTR_VENDOR_DATA, vendor, vendor_length))
        return -EMSGSIZE;
    return finish_request(out, length);
}

/* Require the entire current formatter schema. Truncated or duplicate tokens
 * must never turn into a permissive readiness observation. */
static int parse_probe_stats(const char *text, struct probe_stats *stats)
{
    static const struct { const char *name; size_t offset; bool wide; } fields[] = {
#define FIELD(name, wide_) { #name, offsetof(struct probe_stats, name), wide_ }
        FIELD(home_vdev, false), FIELD(home_mhz, false), FIELD(monitor_vdev, false),
        FIELD(helper_vdev, false), FIELD(generation, true), FIELD(cookie, true),
        FIELD(requester, false), FIELD(scan_id, false), FIELD(scan_mhz, false),
        FIELD(selected_mhz, false), FIELD(phase, false), FIELD(revoked, false),
        FIELD(firmware_ref, false), FIELD(deadline_host_ns, true),
        FIELD(entry_host_ns, true), FIELD(events, true),
#undef FIELD
        { "last_type", SIZE_MAX, false }, { "last_reason", SIZE_MAX, false },
        { "last_mhz", SIZE_MAX, false }, { "last_notice", SIZE_MAX, false },
        { "last_event_host_ns", SIZE_MAX, true }, { "target_timestamp_us", SIZE_MAX, false }
    };
    char copy[1024], *save = NULL, *token;
    uint32_t seen = 0;
    if (!text || !stats || strlen(text) >= sizeof(copy)) return -EINVAL;
    memset(stats, 0, sizeof(*stats));
    if (!strcmp(text, "active=0\n") || !strcmp(text, "active=0")) return -ENODEV;
    memcpy(copy, text, strlen(text) + 1);
    for (token = strtok_r(copy, " \t\r\n", &save); token;
         token = strtok_r(NULL, " \t\r\n", &save)) {
        char *equals = strchr(token, '=');
        bool found = false;
        if (!equals) return -EINVAL;
        *equals++ = 0;
        for (unsigned i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
            uint64_t value;
            if (strcmp(token, fields[i].name)) continue;
            if ((seen & (1U << i)) ||
                parse_number(equals, 10, fields[i].wide ? UINT64_MAX : UINT32_MAX, &value))
                return -EINVAL;
            seen |= 1U << i; found = true;
            if (fields[i].offset != SIZE_MAX) {
                if (fields[i].wide) memcpy((uint8_t *)stats + fields[i].offset, &value, sizeof(value));
                else { uint32_t small = (uint32_t)value;
                    memcpy((uint8_t *)stats + fields[i].offset, &small, sizeof(small)); }
            }
            break;
        }
        if (!found) return -EINVAL;
    }
    if (seen != (1U << (sizeof(fields) / sizeof(fields[0]))) - 1 ||
        stats->phase > 3 || stats->revoked > 1 || stats->firmware_ref > 1) return -EINVAL;
    return 0;
}

static bool same_owner(const struct probe_stats *a, const struct probe_stats *b)
{
    return a->generation == b->generation && a->cookie == b->cookie &&
        a->home_mhz == b->home_mhz && a->home_vdev == b->home_vdev &&
        a->monitor_vdev == b->monitor_vdev && a->helper_vdev == b->helper_vdev;
}

static bool same_lease(const struct probe_stats *a, const struct probe_stats *b)
{
    return same_owner(a, b) && a->requester == b->requester && a->scan_id == b->scan_id &&
        a->scan_mhz == b->scan_mhz && a->selected_mhz == b->selected_mhz &&
        a->deadline_host_ns == b->deadline_host_ns && a->entry_host_ns == b->entry_host_ns;
}

static bool probe_ready(const struct probe_stats *current, const struct probe_stats *baseline,
        uint64_t attempt_ns, uint32_t frequency, uint64_t now_ns)
{
    return current->phase == 2 && !current->revoked && current->firmware_ref == 1 &&
        current->generation && current->cookie && current->requester && current->scan_id &&
        same_owner(current, baseline) && current->scan_id != baseline->scan_id &&
        current->home_mhz >= 2400 && current->home_mhz <= 7125 &&
        frequency != current->home_mhz && current->selected_mhz == frequency &&
        current->scan_mhz == frequency && attempt_ns && current->entry_host_ns >= attempt_ns &&
        current->entry_host_ns <= now_ns && current->entry_host_ns < current->deadline_host_ns &&
        current->deadline_host_ns > now_ns && current->deadline_host_ns - now_ns > READY_GUARD_NS;
}

static void emit(struct probe_io *io, const char *event, int result,
        const struct probe_stats *stats, unsigned index)
{
    io->report(io->context, event, result, stats, index);
}

static int await_retirement(struct probe_io *io, unsigned wait_ms,
        const struct probe_stats *owner, struct probe_stats *retired)
{
    uint64_t start = io->now_ns(io->context);
    if (!start) return -EIO;
    for (;;) {
        int result = io->stats(io->context, retired);
        uint64_t now;
        if (result) return result;
        if (owner && !same_owner(owner, retired)) return -ESTALE;
        if (!retired->generation || !retired->cookie || retired->home_mhz < 2400 ||
            retired->home_mhz > 7125) return -ENODEV;
        if (retired->phase == 0 && retired->firmware_ref == 0) return 0;
        now = io->now_ns(io->context);
        if (!now || now < start) return -EIO;
        if (now - start >= (uint64_t)wait_ms * 1000000) return -ETIMEDOUT;
        result = io->sleep_ms(io->context, 1);
        if (result) return result;
    }
}

static void print_hex(const uint8_t *bytes, size_t length)
{
    for (size_t i = 0; i < length; i++) printf("%02x", bytes[i]);
}

static int dry_run(const struct probe_options *options)
{
    uint8_t packet[PACKET_CAPACITY], query[128], vendor[128];
    ssize_t qlen = build_family_request(query, sizeof(query), 1, 0);
    ssize_t vlen = build_set_frequency(vendor, sizeof(vendor), 0, 2, 0, 0, options->frequency);
    if (qlen < 0 || vlen < 0) return -EINVAL;
    printf("{\"event\":\"dry_run\",\"rf_verified\":false,\"device_state_read\":false,"
           "\"sockets_opened\":false,\"control_interface\":\"%s\",\"raw_interface\":\"%s\","
           "\"frequency_mhz\":%u,\"rate_mbps\":6,\"bandwidth_mhz\":20,"
           "\"frame\":\"%s\",\"family_query_hex\":\"", CONTROL_IF, RAW_IF,
           options->frequency, options->data_frame ? "data" : "action");
    print_hex(query, (size_t)qlen);
    printf("\",\"vendor_request_hex\":\""); print_hex(vendor, (size_t)vlen);
    printf("\",\"placeholders\":{\"family_id\":0,\"ifindex\":0,\"netlink_pid\":0},"
           "\"placeholder_note\":\"family, interface indices and netlink pid resolve only during execute\"}\n");
    for (unsigned i = 0; i < options->count; i++) {
        ssize_t length = build_probe_packet(options, options->source, i, packet, sizeof(packet));
        if (length < 0) return (int)length;
        printf("{\"event\":\"dry_run_packet\",\"index\":%u,\"nonce\":%u,"
               "\"rf_verified\":false,\"packet_hex\":\"", i, options->nonce);
        print_hex(packet, (size_t)length); printf("\"}\n");
    }
    return ferror(stdout) ? -EIO : 0;
}

static int run_probe(const struct probe_options *options, struct probe_io *io)
{
    uint8_t source[6], packet[PACKET_CAPACITY];
    struct probe_stats baseline, first, second, retired;
    int result;
    if (!options->execute) return dry_run(options);
    if (!io || !io->preflight || !io->prepare || !io->stats || !io->set_frequency ||
        !io->send_packet || !io->now_ns || !io->sleep_ms || !io->report || !io->close)
        return -EINVAL;
    result = io->preflight(io->context, options, source);
    if (result) { emit(io, "preflight_rejected", result, NULL, 0); goto out; }
    result = io->prepare(io->context);
    if (result) { emit(io, "prepare_failed", result, NULL, 0); goto out; }
    result = await_retirement(io, options->wait_ms, NULL, &baseline);
    if (result) { emit(io, "baseline_not_retired", result, NULL, 0); goto out; }
    if (baseline.home_mhz == options->frequency) {
        result = -EINVAL; emit(io, "target_is_home", result, &baseline, 0); goto out;
    }
    for (unsigned i = 0; i < options->count; i++) {
        ssize_t length = build_probe_packet(options, source, i, packet, sizeof(packet));
        uint64_t attempt_ns;
        if (length < 0) { result = (int)length; goto out; }
        attempt_ns = io->now_ns(io->context);
        if (!attempt_ns) { result = -EIO; goto out; }
        result = io->set_frequency(io->context, options->frequency);
        if (result) {
            emit(io, "set_frequency_failed_no_retry", result, &baseline, i); goto out;
        }
        result = io->stats(io->context, &first);
        if (!result && !probe_ready(&first, &baseline, attempt_ns, options->frequency,
                                  io->now_ns(io->context))) result = -ESTALE;
        if (!result) {
            result = io->stats(io->context, &second);
            if (!result && (!same_lease(&first, &second) ||
                !probe_ready(&second, &baseline, attempt_ns, options->frequency,
                             io->now_ns(io->context)))) result = -ESTALE;
        }
        if (result) emit(io, "ready_lease_rejected", result, NULL, i);
        else {
            ssize_t sent = io->send_packet(io->context, packet, (size_t)length);
            result = sent < 0 ? (int)sent : sent != length ? -EIO : 0;
            emit(io, result ? "submission_failed" : "submitted", result, &second, i);
        }
        /* A successful control may own a firmware reference even when a
         * subsequent observation or send fails. Observe retirement, boundedly;
         * never issue another control while that reference remains outstanding. */
        {
            int retirement = await_retirement(io, options->wait_ms, &baseline, &retired);
            emit(io, retirement ? "scan_retirement_unobserved" : "scan_retired_observed",
                 retirement, retirement ? NULL : &retired, i);
            if (!result) result = retirement;
        }
        if (result) goto out;
        baseline = retired;
    }
out:
    io->close(io->context);
    return result;
}

struct live_context {
    int raw_fd, netlink_fd;
    uint32_t control_index, raw_index, pid, sequence;
    uint16_t family;
    unsigned wait_ms;
};

static uint64_t live_now(void *context)
{
    struct timespec now;
    (void)context;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * 1000000000 + (uint64_t)now.tv_nsec;
}

static int live_sleep(void *context, unsigned ms)
{
    struct timespec delay = { .tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000 };
    (void)context;
    while (nanosleep(&delay, &delay)) if (errno != EINTR) return -errno;
    return 0;
}

static int read_text(const char *path, char *buffer, size_t capacity)
{
    FILE *file = fopen(path, "r");
    size_t length;
    int result = 0;
    if (!file) return -errno;
    length = fread(buffer, 1, capacity - 1, file);
    if (ferror(file)) result = -EIO;
    else if (length == capacity - 1 && fgetc(file) != EOF) result = -EOVERFLOW;
    buffer[length] = 0;
    if (fclose(file) && !result) result = -errno;
    return result;
}

static bool parameter_enabled(const char *text)
{
    return !strcmp(text, "Y\n") || !strcmp(text, "1\n") ||
           !strcmp(text, "Y") || !strcmp(text, "1");
}

static int live_preflight(void *context, const struct probe_options *options, uint8_t source[6])
{
    struct live_context *live = context;
    char text[128];
    struct ifreq request;
    int fd, result;
    uint64_t type;
    if (!options->execute || options->source_given) return -EINVAL;
    result = read_text(PARAM_DIR "wonder_enabled", text, sizeof(text));
    if (result) return result;
    if (!parameter_enabled(text)) return -EPERM;
    result = read_text(PARAM_DIR "wonder_sta_offchan_probe", text, sizeof(text));
    if (result) return result;
    if (!parameter_enabled(text)) return -EPERM;
    result = read_text("/sys/class/net/" CONTROL_IF "/phy80211/name", text, sizeof(text));
    if (result) return result;
    if (strcmp(text, "wonder\n") && strcmp(text, "wonder")) return -ENODEV;
    live->control_index = if_nametoindex(CONTROL_IF);
    live->raw_index = if_nametoindex(RAW_IF);
    if (!live->control_index || !live->raw_index || live->control_index == live->raw_index)
        return -ENODEV;
    result = read_text("/sys/class/net/" RAW_IF "/type", text, sizeof(text));
    if (result) return result;
    text[strcspn(text, "\r\n")] = 0;
    if (parse_number(text, 10, UINT32_MAX, &type) || type != ARPHRD_IEEE80211_RADIOTAP)
        return -EPROTOTYPE;
    result = read_text("/sys/class/net/" RAW_IF "/address", text, sizeof(text));
    if (result) return result;
    text[strcspn(text, "\r\n")] = 0;
    if (parse_mac(text, source)) return -EINVAL;
    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -errno;
    for (unsigned i = 0; i < 2; i++) {
        memset(&request, 0, sizeof(request));
        snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", i ? RAW_IF : CONTROL_IF);
        if (ioctl(fd, SIOCGIFFLAGS, &request)) { result = -errno; break; }
        if (!(request.ifr_flags & IFF_UP)) { result = -ENETDOWN; break; }
    }
    close(fd);
    return result;
}

/* Parse an entire aligned attribute stream; reject malformed padding/lengths
 * and duplicate family IDs, including malformed attributes after the ID. */
static int parse_family_attrs(const uint8_t *data, size_t length, uint16_t *family)
{
    bool found = false;
    while (length) {
        struct nlattr attr;
        size_t step;
        if (length < NLA_HDRLEN) return -EBADMSG;
        memcpy(&attr, data, sizeof(attr));
        if (attr.nla_len < NLA_HDRLEN || attr.nla_len > length) return -EBADMSG;
        step = NLA_ALIGN(attr.nla_len);
        if (step > length) return -EBADMSG;
        if ((attr.nla_type & NLA_TYPE_MASK) == CTRL_ATTR_FAMILY_ID) {
            if (found || attr.nla_len != NLA_HDRLEN + sizeof(*family)) return -EBADMSG;
            memcpy(family, data + NLA_HDRLEN, sizeof(*family));
            if (*family < NLMSG_MIN_TYPE) return -EBADMSG;
            found = true;
        }
        data += step; length -= step;
    }
    return found ? 0 : -EBADMSG;
}

/* Only a kernel sender and the current sequence can complete a transaction.
 * Family resolution consumes both the family reply and its requested ACK,
 * so the following SET_FREQ cannot mistake a queued resolver ACK for success. */
static int netlink_transaction(struct live_context *live, const uint8_t *request,
        size_t length, uint32_t seq, bool resolve)
{
    struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
    uint64_t start = live_now(live);
    bool ack = false, reply = false;
    ssize_t sent = sendto(live->netlink_fd, request, length, MSG_DONTWAIT,
                          (struct sockaddr *)&kernel, sizeof(kernel));
    if (sent < 0) return -errno;
    if ((size_t)sent != length) return -EIO;
    if (!start) return -EIO;
    while (!ack || (resolve && !reply)) {
        uint8_t buffer[NETLINK_CAPACITY];
        struct sockaddr_nl sender = { 0 };
        struct iovec vector = { .iov_base = buffer, .iov_len = sizeof(buffer) };
        struct msghdr message = { .msg_name = &sender, .msg_namelen = sizeof(sender),
                                  .msg_iov = &vector, .msg_iovlen = 1 };
        struct pollfd pollfd = { .fd = live->netlink_fd, .events = POLLIN };
        uint64_t now = live_now(live), elapsed;
        int result, remaining;
        ssize_t received;
        size_t offset = 0;
        if (!now || now < start) return -EIO;
        elapsed = now - start;
        if (elapsed >= (uint64_t)live->wait_ms * 1000000) return -ETIMEDOUT;
        remaining = (int)(((uint64_t)live->wait_ms * 1000000 - elapsed + 999999) / 1000000);
        result = poll(&pollfd, 1, remaining);
        if (result < 0) { if (errno == EINTR) continue; return -errno; }
        if (!result) return -ETIMEDOUT;
        if (pollfd.revents & (POLLERR | POLLHUP | POLLNVAL)) return -EIO;
        received = recvmsg(live->netlink_fd, &message, MSG_DONTWAIT);
        if (received < 0) { if (errno == EINTR || errno == EAGAIN) continue; return -errno; }
        if (!received || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
            message.msg_namelen != sizeof(sender) || sender.nl_family != AF_NETLINK ||
            sender.nl_pid != 0 || sender.nl_groups != 0) return -EBADMSG;
        while (offset < (size_t)received) {
            struct nlmsghdr header;
            size_t step, payload;
            if ((size_t)received - offset < NLMSG_HDRLEN) return -EBADMSG;
            memcpy(&header, buffer + offset, sizeof(header));
            if (header.nlmsg_len < NLMSG_HDRLEN || header.nlmsg_len > (size_t)received - offset)
                return -EBADMSG;
            step = NLMSG_ALIGN(header.nlmsg_len);
            if (step > (size_t)received - offset) return -EBADMSG;
            payload = header.nlmsg_len - NLMSG_HDRLEN;
            if (header.nlmsg_seq != seq || header.nlmsg_pid != live->pid ||
                (header.nlmsg_flags & NLM_F_MULTI)) return -EBADMSG;
            if (header.nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr error;
                if (payload < sizeof(error) || ack) return -EBADMSG;
                memcpy(&error, buffer + offset + NLMSG_HDRLEN, sizeof(error));
                if (error.error > 0 || error.error < -4095 || error.msg.nlmsg_seq != seq ||
                    error.msg.nlmsg_type != (resolve ? GENL_ID_CTRL : live->family) ||
                    error.msg.nlmsg_pid != live->pid) return -EBADMSG;
                if (error.error) return error.error;
                ack = true;
            } else if (resolve && header.nlmsg_type == GENL_ID_CTRL) {
                struct genlmsghdr gen;
                if (reply || payload < GENL_HDRLEN) return -EBADMSG;
                memcpy(&gen, buffer + offset + NLMSG_HDRLEN, sizeof(gen));
                if (gen.cmd != CTRL_CMD_NEWFAMILY) return -EBADMSG;
                result = parse_family_attrs(buffer + offset + NLMSG_HDRLEN + GENL_HDRLEN,
                                            payload - GENL_HDRLEN, &live->family);
                if (result) return result;
                reply = true;
            } else return -EBADMSG;
            offset += step;
        }
    }
    return 0;
}

static int live_prepare(void *context)
{
    struct live_context *live = context;
    struct sockaddr_nl local = { .nl_family = AF_NETLINK };
    struct sockaddr_ll raw = { .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL),
                               .sll_ifindex = (int)live->raw_index };
    socklen_t local_length = sizeof(local);
    uint8_t query[128];
    ssize_t length;
    live->raw_fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, htons(ETH_P_ALL));
    if (live->raw_fd < 0) return -errno;
    if (bind(live->raw_fd, (struct sockaddr *)&raw, sizeof(raw))) return -errno;
    live->netlink_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_GENERIC);
    if (live->netlink_fd < 0) return -errno;
    if (bind(live->netlink_fd, (struct sockaddr *)&local, sizeof(local)) ||
        getsockname(live->netlink_fd, (struct sockaddr *)&local, &local_length)) return -errno;
    if (local_length != sizeof(local) || local.nl_family != AF_NETLINK || !local.nl_pid)
        return -EBADMSG;
    live->pid = local.nl_pid;
    length = build_family_request(query, sizeof(query), ++live->sequence, live->pid);
    if (length < 0) return (int)length;
    return netlink_transaction(live, query, (size_t)length, live->sequence, true);
}

static int live_stats(void *context, struct probe_stats *stats)
{
    char text[1024];
    int result;
    (void)context;
    result = read_text(PARAM_DIR "wonder_coex_stats", text, sizeof(text));
    return result ? result : parse_probe_stats(text, stats);
}

static int live_set_frequency(void *context, uint32_t frequency)
{
    struct live_context *live = context;
    uint8_t request[128];
    ssize_t length = build_set_frequency(request, sizeof(request), live->family,
        ++live->sequence, live->pid, live->control_index, frequency);
    if (length < 0) return (int)length;
    return netlink_transaction(live, request, (size_t)length, live->sequence, false);
}

static ssize_t live_send_packet(void *context, const uint8_t *packet, size_t length)
{
    struct live_context *live = context;
    ssize_t result = send(live->raw_fd, packet, length, MSG_DONTWAIT);
    return result < 0 ? -errno : result;
}

static void live_report(void *context, const char *event, int result,
        const struct probe_stats *stats, unsigned index)
{
    (void)context;
    printf("{\"event\":\"%s\",\"index\":%u,\"result\":%d,\"rf_verified\":false",
           event, index, result);
    if (!strcmp(event, "submitted")) printf(",\"evidence\":\"local_syscall_acceptance\"");
    if (stats) printf(",\"stats_scope\":\"userspace_observation\",\"generation\":%" PRIu64 ",\"cookie\":%" PRIu64
        ",\"requester\":%u,\"scan_id\":%u,\"home_mhz\":%u,\"selected_mhz\":%u"
        ",\"phase\":%u,\"firmware_ref\":%u,\"entry_host_ns\":%" PRIu64
        ",\"deadline_host_ns\":%" PRIu64, stats->generation, stats->cookie,
        stats->requester, stats->scan_id, stats->home_mhz, stats->selected_mhz,
        stats->phase, stats->firmware_ref, stats->entry_host_ns, stats->deadline_host_ns);
    printf("}\n");
}

static void live_close(void *context)
{
    struct live_context *live = context;
    if (live->raw_fd >= 0) { close(live->raw_fd); live->raw_fd = -1; }
    if (live->netlink_fd >= 0) { close(live->netlink_fd); live->netlink_fd = -1; }
}

static void usage(FILE *stream)
{
    fprintf(stream, "Usage: wonder_offchan_probe [--execute] --frequency MHz --receiver MAC --bssid MAC\n"
        "       [--source MAC (dry-run only)] [--data] [--count 1..4] [--wait-ms 1..5000] [--nonce u32]\n"
        "Default: dry-run, action frame, 6 Mbps, 20 MHz. Dry-run requires --source.\n"
        "Live: manually prepare/cache/open wonder0; use its provider-owned wondertap0.\n"
        "The prepared session must have no competing frequency controller.\n"
        "Requires wonder_enabled and wonder_sta_offchan_probe enabled. No session setup is performed.\n"
        "A successful raw send reports submission only; RF reception is unverified.\n");
}

#ifndef WONDER_PROBE_TEST
int main(int argc, char **argv)
{
    struct probe_options options;
    struct live_context live = { .raw_fd = -1, .netlink_fd = -1 };
    struct probe_io io = { .context = &live, .preflight = live_preflight,
        .prepare = live_prepare, .stats = live_stats, .set_frequency = live_set_frequency,
        .send_packet = live_send_packet, .now_ns = live_now, .sleep_ms = live_sleep,
        .report = live_report, .close = live_close };
    int result = parse_options(argc, argv, &options);
    if (result) { usage(result == 1 ? stdout : stderr); return result == 1 ? 0 : 2; }
    live.wait_ms = options.wait_ms;
    result = run_probe(&options, &io);
    if (result) fprintf(stderr, "Probe stopped: %s (%d). RF is unverified.\n", strerror(-result), result);
    return result ? 1 : 0;
}
#endif
