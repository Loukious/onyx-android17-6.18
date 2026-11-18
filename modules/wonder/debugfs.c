// SPDX-License-Identifier: GPL-2.0
/*
 * Google Wonder WiFi Virtual Soft-MAC Driver
 *
 * Debugfs implementation for the Wonder driver.
 */
#define pr_fmt(fmt) "[wonder][debugfs] " fmt
#define LOG_MODULE_NAME "debugfs"

#include <linux/debugfs.h>
#include <linux/netdevice.h>
#include <linux/uaccess.h>
#include <linux/etherdevice.h>
#include <linux/seq_file.h>
#include <linux/hex.h>
#include <linux/if_ether.h>

#include "core.h"
#include "mac80211.h"
#include "wondertap_internal.h"


static int wonder_capabilities_show(struct seq_file *m, void *v)
{
	struct wonder_data *wonder = m->private;
	struct wondertap_capability caps;
	int ret;

	if (!wonder) {
		pr_err("wondertap not available\n");
		return -ENODEV;
	}

	ret = wondertap_get_capabilities(wonder->wondertap_data, &caps);
	if (ret) {
		pr_err("Failed to get wondertap capabilities, error: %d\n", ret);
		return -EOPNOTSUPP;
	}

	seq_printf(m, "%08x\n", caps.raw_bits);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(wonder_capabilities);

static int wonder_channel_status_report_show(struct seq_file *m, void *v)
{
	struct wonder_data *wonder = m->private;
	struct wondertap_data *wondertap = wonder->wondertap_data;
	struct wondertap_channel_status_report *report;
	u32 num_channels;
	size_t size;
	int ret, i;

	mutex_lock(&wondertap->lock);
	num_channels = wondertap->cached_channel_schedule.channel_list_len;
	mutex_unlock(&wondertap->lock);

	if (num_channels == 0) {
		seq_puts(m, "Channel hopping list is empty.\n");
		return 0;
	}

	size = sizeof(*report) + num_channels * sizeof(struct wondertap_channel_status);
	report = kzalloc(size, GFP_KERNEL);
	if (!report)
		return -ENOMEM;

	report->channel_status_len = num_channels;
	ret = wondertap_get_channel_status_report(wondertap, report);
	if (ret) {
		seq_printf(m, "Failed to get channel status report: %d\n", ret);
		kfree(report);
		return 0;
	}

	seq_printf(m, "Current Hopping Request TSF: 0x%08x\n",
		report->current_channel_hopping_request_tsf);
	seq_printf(m, "Current Channel Index: %u\n", report->current_channel_index);
	seq_printf(m, "Channel Status Length: %u\n", report->channel_status_len);

	for (i = 0; i < report->channel_status_len; i++) {
		struct wondertap_channel_status *status = &report->status[i];

		seq_printf(m, "\n  [%d] Freq: %u MHz\n", i, status->freq);
		seq_printf(m, "      Switch TSF: 0x%08x\n", status->channel_switch_tsf);
		seq_printf(m, "      Start TSF:  0x%08x\n", status->channel_start_tsf);
		seq_printf(m, "      End TSF:    0x%08x\n", status->channel_end_tsf);
		seq_printf(m, "      TX Traffic Index: %u\n", status->tx_traffic_index);
		seq_printf(m, "      RX Traffic Index: %u\n", status->rx_traffic_index);
	}

	kfree(report);
	return 0;
}

static void wonder_channel_status_report_periodic_work(struct work_struct *work)
{
	struct wonder_data *wonder = container_of(work, struct wonder_data,
						  channel_status_report_work.work);
	struct wondertap_data *wondertap = wonder->wondertap_data;
	struct wondertap_channel_status_report *report;
	const char *tag = "wonder";
	u32 num_channels;
	size_t size;
	int ret, i;

	mutex_lock(&wondertap->lock);
	num_channels = wondertap->cached_channel_schedule.channel_list_len;
	mutex_unlock(&wondertap->lock);

	if (num_channels == 0) {
		pr_info("%s: Channel hopping list is empty.\n", tag);
		goto reschedule;
	}

	size = sizeof(*report) + num_channels * sizeof(struct wondertap_channel_status);
	report = kzalloc(size, GFP_KERNEL);
	if (!report)
		goto reschedule;

	report->channel_status_len = num_channels;
	ret = wondertap_get_channel_status_report(wondertap, report);
	if (ret) {
		pr_info("%s: Failed to get channel status report: %d\n", tag, ret);
		kfree(report);
		goto reschedule;
	}

	pr_info("%s: --- Channel Status Report Dump ---\n", tag);
	pr_info("%s: Current Hopping Request TSF: 0x%08x\n", tag,
		report->current_channel_hopping_request_tsf);
	pr_info("%s: Current Channel Index: %u\n", tag, report->current_channel_index);
	pr_info("%s: Channel Status Length: %u\n", tag, report->channel_status_len);

	for (i = 0; i < report->channel_status_len; i++) {
		struct wondertap_channel_status *status = &report->status[i];

		pr_info("%s:   [%d] Freq: %u MHz\n", tag, i, status->freq);
		pr_info("%s:       Switch TSF: 0x%08x\n", tag, status->channel_switch_tsf);
		pr_info("%s:       Start TSF:  0x%08x\n", tag, status->channel_start_tsf);
		pr_info("%s:       End TSF:    0x%08x\n", tag, status->channel_end_tsf);
		pr_info("%s:       TX Traffic Index: %u\n", tag, status->tx_traffic_index);
		pr_info("%s:       RX Traffic Index: %u\n", tag, status->rx_traffic_index);
	}
	kfree(report);

reschedule:
	mutex_lock(&wondertap->lock);
	if (wonder->channel_status_report_interval > 0) {
		schedule_delayed_work(&wonder->channel_status_report_work,
				      wonder->channel_status_report_interval * HZ);
	}
	mutex_unlock(&wondertap->lock);
}

static ssize_t wonder_channel_status_report_write(struct file *file, const char __user *user_buf,
						  size_t count, loff_t *ppos)
{
	struct seq_file *m = file->private_data;
	struct wonder_data *wonder = m->private;
	struct wondertap_data *wondertap = wonder->wondertap_data;
	u32 val;
	int ret;

	ret = kstrtou32_from_user(user_buf, count, 0, &val);
	if (ret)
		return ret;

	mutex_lock(&wondertap->lock);
	wonder->channel_status_report_interval = val;
	mutex_unlock(&wondertap->lock);

	cancel_delayed_work_sync(&wonder->channel_status_report_work);

	if (val > 0) {
		schedule_delayed_work(&wonder->channel_status_report_work, 0);
	}

	return count;
}

static int wonder_channel_status_report_open(struct inode *inode, struct file *file)
{
	return single_open(file, wonder_channel_status_report_show, inode->i_private);
}

static const struct file_operations wonder_channel_status_report_fops = {
	.open = wonder_channel_status_report_open,
	.read = seq_read,
	.write = wonder_channel_status_report_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static int wonder_channel_schedule_request_show(struct seq_file *m, void *v)
{
	struct wonder_data *wonder = m->private;
	struct wondertap_data *wondertap = wonder->wondertap_data;
	struct channel_schedule_request *schedule;
	int i;

	mutex_lock(&wondertap->lock);
	schedule = &wondertap->cached_channel_schedule;

	if (schedule->channel_list_len == 0) {
		seq_puts(m, "Channel hopping schedule list is empty.\n");
		mutex_unlock(&wondertap->lock);
		return 0;
	}

	seq_printf(m, "Channel List Length: %u\n", schedule->channel_list_len);
	seq_printf(m, "Next Channel Index: %u\n", schedule->next_channel_index);
	seq_printf(m, "Dwell Time (TU): %u\n", schedule->dwell_time_tu);
	seq_printf(m, "Target Switch TSF: 0x%08x\n", schedule->target_switch_time_tsf);

	seq_puts(m, "\nChannel List:\n");
	if (schedule->channel_list) {
		for (i = 0; i < schedule->channel_list_len; i++) {
			seq_printf(m, "  [%d] Freq: %u MHz, BW: %u, Role: %u\n", i,
				   schedule->channel_list[i].freq,
				   schedule->channel_list[i].bandwidth,
				   schedule->channel_list[i].role);
		}
	}

	mutex_unlock(&wondertap->lock);
	return 0;
}

static void wonder_channel_schedule_request_periodic_work(struct work_struct *work)
{
	struct wonder_data *wonder = container_of(work, struct wonder_data,
						  channel_schedule_request_work.work);
	struct wondertap_data *wondertap = wonder->wondertap_data;
	struct channel_schedule_request *schedule;
	const char *tag = "wonder";
	int i;

	mutex_lock(&wondertap->lock);
	schedule = &wondertap->cached_channel_schedule;

	if (schedule->channel_list_len == 0) {
		pr_info("%s: Channel hopping schedule list is empty.\n", tag);
		goto unlock_reschedule;
	}

	pr_info("%s: --- Channel Hopping Schedule Dump ---\n", tag);
	pr_info("%s: Channel List Length: %u\n", tag, schedule->channel_list_len);
	pr_info("%s: Next Channel Index: %u\n", tag, schedule->next_channel_index);
	pr_info("%s: Dwell Time (TU): %u\n", tag, schedule->dwell_time_tu);
	pr_info("%s: Target Switch TSF: 0x%08x\n", tag, schedule->target_switch_time_tsf);

	pr_info("%s: Channel List:\n", tag);
	if (schedule->channel_list) {
		for (i = 0; i < schedule->channel_list_len; i++) {
			pr_info("%s:   [%d] Freq: %u MHz, BW: %u, Role: %u\n", tag, i,
				   schedule->channel_list[i].freq,
				   schedule->channel_list[i].bandwidth,
				   schedule->channel_list[i].role);
		}
	}

unlock_reschedule:
	if (wonder->channel_schedule_request_interval > 0) {
		schedule_delayed_work(&wonder->channel_schedule_request_work,
				      wonder->channel_schedule_request_interval * HZ);
	}
	mutex_unlock(&wondertap->lock);
}

static ssize_t wonder_channel_schedule_request_write(struct file *file, const char __user *user_buf,
						     size_t count, loff_t *ppos)
{
	struct seq_file *m = file->private_data;
	struct wonder_data *wonder = m->private;
	struct wondertap_data *wondertap = wonder->wondertap_data;
	u32 val;
	int ret;

	ret = kstrtou32_from_user(user_buf, count, 0, &val);
	if (ret)
		return ret;

	mutex_lock(&wondertap->lock);
	wonder->channel_schedule_request_interval = val;
	mutex_unlock(&wondertap->lock);

	cancel_delayed_work_sync(&wonder->channel_schedule_request_work);

	if (val > 0) {
		schedule_delayed_work(&wonder->channel_schedule_request_work, 0);
	}

	return count;
}

static int wonder_channel_schedule_request_open(struct inode *inode, struct file *file)
{
	return single_open(file, wonder_channel_schedule_request_show, inode->i_private);
}

static const struct file_operations wonder_channel_schedule_request_fops = {
	.open = wonder_channel_schedule_request_open,
	.read = seq_read,
	.write = wonder_channel_schedule_request_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static int wonder_station_query_show(struct seq_file *m, void *v)
{
	struct wonder_data *wonder = m->private;
	struct wondertap_data *wondertap = wonder->wondertap_data;
	struct wondertap_station_info sta_info = {0};
	int ret;

	mutex_lock(&wondertap->lock);
	if (is_zero_ether_addr(wondertap->query_mac_addr)) {
		seq_puts(m, "Please write a valid MAC address first.\n");
		mutex_unlock(&wondertap->lock);
		return 0;
	}
	memcpy(sta_info.mac, wondertap->query_mac_addr, ETH_ALEN);
	mutex_unlock(&wondertap->lock);

	if (wondertap->wonder_ops && wondertap->wonder_ops->set_station_info) {
		ret = wondertap_set_station_info(wondertap,
				WONDERTAP_STATION_STATE_QUERY, &sta_info);
		if (ret) {
			seq_printf(m, "Failed to query station info: %d\n", ret);
			return 0;
		}

		seq_printf(m, "Station MAC: %pM\n", sta_info.mac);
		seq_printf(m, "AID: %u\n", sta_info.aid);
		seq_printf(m, "Capability Mask: 0x%08x\n", sta_info.capability_mask);

		seq_printf(m, "    HT: %s, VHT: %s, HE: %s, HE_6G: %s\n",
			   (sta_info.capability_mask & BIT(WONDERTAP_STATION_CAP_HT)) ?
				   "Y" : "N",
			   (sta_info.capability_mask & BIT(WONDERTAP_STATION_CAP_VHT)) ?
				   "Y" : "N",
			   (sta_info.capability_mask & BIT(WONDERTAP_STATION_CAP_HE)) ?
				   "Y" : "N",
			   (sta_info.capability_mask & BIT(WONDERTAP_STATION_CAP_HE_6G)) ?
				   "Y" : "N");

		if (sta_info.capability_mask & BIT(WONDERTAP_STATION_CAP_HT))
			seq_hex_dump(m, "    HT_CAP: ", DUMP_PREFIX_NONE,
				     16, 1, &sta_info.ht_capa,
				     sizeof(struct ieee80211_ht_cap), false);

		if (sta_info.capability_mask & BIT(WONDERTAP_STATION_CAP_VHT))
			seq_hex_dump(m, "    VHT_CAP: ", DUMP_PREFIX_NONE,
				     16, 1, &sta_info.vht_capa,
				     sizeof(struct ieee80211_vht_cap), false);

		if ((sta_info.capability_mask & BIT(WONDERTAP_STATION_CAP_HE)) &&
		    sta_info.he_capa_len > 0)
			seq_hex_dump(m, "    HE_CAP: ", DUMP_PREFIX_NONE,
				     16, 1, &sta_info.he_capa,
				     min_t(size_t, sta_info.he_capa_len, sizeof(sta_info.he_capa)),
				     false);

		if (sta_info.capability_mask & BIT(WONDERTAP_STATION_CAP_HE_6G))
			seq_hex_dump(m, "    HE_6G_CAP: ", DUMP_PREFIX_NONE,
				     16, 1, &sta_info.he_6ghz_capa,
				     sizeof(struct ieee80211_he_6ghz_capa), false);
	} else {
		seq_puts(m, "set_station_info op is not implemented by vendor.\n");
	}

	return 0;
}

static ssize_t wonder_station_query_write(struct file *file, const char __user *user_buf,
					  size_t count, loff_t *ppos)
{
	struct seq_file *m = file->private_data;
	struct wonder_data *wonder = m->private;
	struct wondertap_data *wondertap = wonder->wondertap_data;
	char *mac_str;
	char buf[32];
	size_t len;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;
	buf[len] = '\0';

	mac_str = strim(buf);

	mutex_lock(&wondertap->lock);
	if (!mac_pton(mac_str, wondertap->query_mac_addr) || mac_str[MAC_ADDR_STR_LEN] != '\0') {
		pr_err("Invalid MAC address format. Expected xx:xx:xx:xx:xx:xx\n");
		mutex_unlock(&wondertap->lock);
		return -EINVAL;
	}
	mutex_unlock(&wondertap->lock);

	return count;
}


static int wonder_station_query_open(struct inode *inode, struct file *file)
{
	return single_open(file, wonder_station_query_show, inode->i_private);
}

static const struct file_operations wonder_station_query_fops = {
	.open = wonder_station_query_open,
	.read = seq_read,
	.write = wonder_station_query_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static int wonder_station_table_show(struct seq_file *m, void *v)
{
	struct wonder_data *wonder = m->private;
	struct wondertap_data *wondertap = wonder->wondertap_data;
	int i, count = 0;

	mutex_lock(&wondertap->lock);
	seq_puts(m, "--- Wondertap Station Table ---\n");
	for (i = 0; i < WONDERTAP_MAX_STATION_TABLE_SIZE; i++) {
		if (wondertap->station_table[i].in_use) {
			struct wondertap_station_info *info =
				&wondertap->station_table[i].info;
			u32 cap = info->capability_mask;
			bool ht = cap & BIT(WONDERTAP_STATION_CAP_HT);
			bool vht = cap & BIT(WONDERTAP_STATION_CAP_VHT);
			bool he = cap & BIT(WONDERTAP_STATION_CAP_HE);
			bool he_6g = cap & BIT(WONDERTAP_STATION_CAP_HE_6G);

			count++;
			seq_printf(m, "[%2d] MAC: %pM | AID: %u | Cap: 0x%08x (HT:%s VHT:%s HE:%s HE_6G:%s)\n",
				   i, info->mac, info->aid, cap,
				   ht ? "Y" : "N", vht ? "Y" : "N",
				   he ? "Y" : "N", he_6g ? "Y" : "N");
		}
	}
	if (count == 0)
		seq_puts(m, "(No active stations)\n");
	seq_printf(m, "Total active stations: %d\n", count);
	mutex_unlock(&wondertap->lock);

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(wonder_station_table);

static const char *wonder_ver_to_str(enum wondertap_ver ver)
{
	switch (ver) {
	case WONDER_VERSION_3_0: return "WONDER_VERSION_3_0";
	case WONDER_VERSION_3_1: return "WONDER_VERSION_3_1";
	case WONDER_VERSION_3_2: return "WONDER_VERSION_3_2";
	case WONDER_VERSION_3_3: return "WONDER_VERSION_3_3";
	case WONDER_VERSION_3_4: return "WONDER_VERSION_3_4";
	case WONDER_VERSION_3_4_1: return "WONDER_VERSION_3_4_1";
	case WONDER_VERSION_3_5: return "WONDER_VERSION_3_5";
	case WONDER_VERSION_3_5_1: return "WONDER_VERSION_3_5_1";
	case WONDER_VERSION_3_6_1: return "WONDER_VERSION_3_6_1 (or 3_6_2/3_6_3)";
	case WONDER_VERSION_3_6_4: return "WONDER_VERSION_3_6_4";
	case WONDER_VERSION_3_6_5: return "WONDER_VERSION_3_6_5";
	case WONDER_VERSION_3_6_6: return "WONDER_VERSION_3_6_6";
	default: return "UNKNOWN_VERSION";
	}
}

static int wonder_version_show(struct seq_file *m, void *v)
{
	struct wonder_data *wonder = m->private;
	struct wondertap_data *wondertap = wonder->wondertap_data;

	mutex_lock(&wondertap->lock);
	seq_printf(m, "Wonder version: %s\n", wonder_ver_to_str(wondertap->ver));
	seq_printf(m, "WiFi version: %s\n", wonder_ver_to_str(wondertap->wifi_ver));
	mutex_unlock(&wondertap->lock);

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(wonder_version);

static int wonder_stats_show(struct seq_file *m, void *v)
{
	struct wonder_data *wonder = m->private;

	seq_puts(m, "--- Wonder Driver Stats ---\n");
	seq_printf(m, "wonder_tx_entry_cnt:            %lld\n",
		   (long long)atomic64_read(&wonder->stats.tx_entry_cnt));
	seq_printf(m, "wonder_tx_success_cnt:          %lld\n",
		   (long long)atomic64_read(&wonder->stats.tx_success_cnt));
	seq_printf(m, "wonder_tx_skb_cloned_cnt:       %lld\n",
		   (long long)atomic64_read(&wonder->stats.tx_skb_cloned_cnt));
	seq_printf(m, "wonder_tx_skb_clone_fail_cnt:   %lld\n",
		   (long long)atomic64_read(&wonder->stats.tx_skb_clone_fail_cnt));
	seq_printf(m, "tx_xmit_success_cnt:            %lld\n",
		   (long long)atomic64_read(&wonder->stats.tx_xmit_success_cnt));
	seq_printf(m, "tx_xmit_drop_cnt:               %lld\n",
		   (long long)atomic64_read(&wonder->stats.tx_xmit_drop_cnt));
	seq_printf(m, "tx_xmit_cn_cnt:                 %lld\n",
		   (long long)atomic64_read(&wonder->stats.tx_xmit_cn_cnt));
	seq_printf(m, "tx_xmit_err_cnt:                %lld\n\n",
		   (long long)atomic64_read(&wonder->stats.tx_xmit_err_cnt));

	seq_printf(m, "wonder_rx_entry_cnt:            %lld (receiv from wondertap0)\n",
		   (long long)atomic64_read(&wonder->stats.rx_entry_cnt));
	seq_printf(m, "wonder_rx_to_mac_cnt:           %lld (forward to mac80211)\n\n",
		   (long long)atomic64_read(&wonder->stats.rx_to_mac_cnt));

	return 0;
}

static ssize_t wonder_stats_write(struct file *file, const char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	struct seq_file *m = file->private_data;
	struct wonder_data *wonder = m->private;

	/* Reset Wonder internal counters */
	atomic64_set(&wonder->stats.tx_entry_cnt, 0);
	atomic64_set(&wonder->stats.tx_success_cnt, 0);
	atomic64_set(&wonder->stats.tx_skb_cloned_cnt, 0);
	atomic64_set(&wonder->stats.tx_skb_clone_fail_cnt, 0);
	atomic64_set(&wonder->stats.tx_xmit_success_cnt, 0);
	atomic64_set(&wonder->stats.tx_xmit_drop_cnt, 0);
	atomic64_set(&wonder->stats.tx_xmit_cn_cnt, 0);
	atomic64_set(&wonder->stats.tx_xmit_err_cnt, 0);
	atomic64_set(&wonder->stats.rx_entry_cnt, 0);
	atomic64_set(&wonder->stats.rx_to_mac_cnt, 0);

	return count;
}

static int wonder_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, wonder_stats_show, inode->i_private);
}

static const struct file_operations wonder_stats_fops = {
	.open = wonder_stats_open,
	.read = seq_read,
	.write = wonder_stats_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static int wonder_debugfs_mac_algo_get(void *data, u64 *val)
{
	struct wonder_data *wonder = data;

	*val = wonder->mac_algorithm;
	return 0;
}

static int wonder_debugfs_mac_algo_set(void *data, u64 val)
{
	struct wonder_data *wonder = data;

	if (val >= MAC_ALGO_MAX)
		return -EINVAL;

	return wonder_set_mac_algorithm(wonder, (u8)val);
}

DEFINE_SIMPLE_ATTRIBUTE(wonder_debugfs_mac_algo_fops,
			wonder_debugfs_mac_algo_get,
			wonder_debugfs_mac_algo_set,
			"%llu\n");

static int wonder_debugfs_perf_mode_get(void *data, u64 *val)
{
	struct wonder_data *wonder = data;

	*val = READ_ONCE(wonder->perf_mode);
	return 0;
}

static int wonder_debugfs_perf_mode_set(void *data, u64 val)
{
	struct wonder_data *wonder = data;

	if (val >= WONDER_PERF_MODE_MAX)
		return -EINVAL;

	WRITE_ONCE(wonder->perf_mode, (u8)val);
	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(wonder_debugfs_perf_mode_fops,
			wonder_debugfs_perf_mode_get,
			wonder_debugfs_perf_mode_set,
			"%llu\n");

int wonder_debugfs_init(struct wonder_data *wonder)
{
	struct dentry *wonder_debugfs_root;

	wonder_debugfs_root = debugfs_create_dir("wonder", NULL);

	debugfs_create_file("capabilities", 0400, wonder_debugfs_root, wonder,
			    &wonder_capabilities_fops);

	INIT_DELAYED_WORK(&wonder->channel_status_report_work,
			  wonder_channel_status_report_periodic_work);
	INIT_DELAYED_WORK(&wonder->channel_schedule_request_work,
			  wonder_channel_schedule_request_periodic_work);
	wonder->channel_status_report_interval = 0;
	wonder->channel_schedule_request_interval = 0;

	debugfs_create_file("channel_status_report", 0644, wonder_debugfs_root,
			    wonder, &wonder_channel_status_report_fops);
	debugfs_create_file("channel_schedule_request", 0644, wonder_debugfs_root,
			    wonder, &wonder_channel_schedule_request_fops);
	debugfs_create_file("station_query", 0644, wonder_debugfs_root,
			    wonder, &wonder_station_query_fops);
	debugfs_create_file("station_table", 0444, wonder_debugfs_root,
			    wonder, &wonder_station_table_fops);
	debugfs_create_file("version", 0444, wonder_debugfs_root,
			    wonder, &wonder_version_fops);
	debugfs_create_file("stats", 0644, wonder_debugfs_root,
			    wonder, &wonder_stats_fops);
	debugfs_create_bool("amsdu_enable", 0644, wonder_debugfs_root,
			    &wonder->amsdu_enable);
	debugfs_create_bool("ampdu_enable", 0644, wonder_debugfs_root,
			    &wonder->ampdu_enable);
	debugfs_create_bool("channel_hopping_enable", 0644, wonder_debugfs_root,
			    &wonder->channel_hopping_enable);
	debugfs_create_file("perf_mode", 0644, wonder_debugfs_root,
			    wonder, &wonder_debugfs_perf_mode_fops);
	debugfs_create_bool("ra_enable", 0644, wonder_debugfs_root,
			    &wonder->ra_enable);
	debugfs_create_u32("amsdu_threshold", 0644, wonder_debugfs_root,
			    &wonder->amsdu_threshold);
	debugfs_create_u32("amsdu_delay", 0644, wonder_debugfs_root,
			    &wonder->amsdu_delay);
	debugfs_create_bool("syna_support_enable", 0644, wonder_debugfs_root,
			    &wonder->syna_support_enable);
	debugfs_create_file("mac_algorithm", 0644, wonder_debugfs_root,
			    wonder, &wonder_debugfs_mac_algo_fops);
	debugfs_create_u32("mac_timer_interval_minutes", 0644, wonder_debugfs_root,
			   &wonder->mac_timer_interval_minutes);
	return 0;
}

void wonder_debugfs_exit(struct wonder_data *wonder)
{
	if (wonder) {
		cancel_delayed_work_sync(&wonder->channel_status_report_work);
		cancel_delayed_work_sync(&wonder->channel_schedule_request_work);
	}
	debugfs_lookup_and_remove("wonder", NULL);
}
