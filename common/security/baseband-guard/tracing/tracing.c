/* SPDX-License-Identifier: GPL-2.0-only */
#include "kernel_compat.h"
#include <linux/security.h>
#include <linux/errno.h>
#include <linux/cred.h>

int bb_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp);
void bb_cred_transfer(struct cred *new, const struct cred *old);
int bb_bprm_set_creds(struct linux_binprm *bprm);

int __maybe_unused bbg_process_setpermissive(void);
int __maybe_unused bbg_test_domain_transition(u32 target_secid);

#ifdef BBG_USE_DEFINE_LSM
struct lsm_blob_sizes bbg_blob_sizes __ro_after_init = {
	.lbs_cred = sizeof(struct bbg_cred_security_struct),
};
#elif !defined(BBG_COMPAT_SELINUX_CRED)
static inline struct task_security_struct *selinux_cred(const struct cred *cred)
{
	return cred->security;
}
#endif

int bb_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
	const struct bbg_cred_security_struct *old_tsec = bbg_cred(old);
	struct bbg_cred_security_struct *tsec = bbg_cred(new);

	*tsec = *old_tsec;
	return 0;
}
void bb_cred_transfer(struct cred *new, const struct cred *old)
{
	const struct bbg_cred_security_struct *old_tsec = bbg_cred(old);
	struct bbg_cred_security_struct *tsec = bbg_cred(new);

	*tsec = *old_tsec;
}

struct bbg_domain_cache {
	u32 sid;
};

static struct bbg_domain_cache su_domain, magisk_domain, ksu_domain;

static int bbg_domain_sid(const char *context, struct bbg_domain_cache *cached)
{
	u32 sid = READ_ONCE(cached->sid);

	if (sid)
		return sid;
	if (security_secctx_to_secid(context, strlen(context), &sid))
		return -EINVAL;
	/* KernelSU can install its domain after boot; never cache failure forever. */
	WRITE_ONCE(cached->sid, sid);
	return sid;
}

bool bbg_current_domain_untrusted(void)
{
	const struct cred_security_struct *tsec;
	int su_sid, magisk_sid, ksu_sid;

	if (!selinux_initialized_compat())
		return false;
	tsec = selinux_cred(current_cred());
	su_sid = bbg_domain_sid("u:r:su:s0", &su_domain);
	magisk_sid = bbg_domain_sid("u:r:magisk:s0", &magisk_domain);
	ksu_sid = bbg_domain_sid("u:r:ksu:s0", &ksu_domain);
	return tsec->sid == su_sid || tsec->osid == su_sid ||
	       tsec->sid == magisk_sid || tsec->osid == magisk_sid ||
	       tsec->sid == ksu_sid || tsec->osid == ksu_sid;
}

int bb_bprm_set_creds(struct linux_binprm *bprm)
{
	int su_sid, magisk_sid, ksu_sid;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
	struct task_security_struct *new_selinux_tsec;
	const struct task_security_struct *old_selinux_tsec;
#else
	struct cred_security_struct *new_selinux_tsec;
	const struct cred_security_struct *old_selinux_tsec;
#endif
	const struct bbg_cred_security_struct *old_bbg_tsec;
	struct bbg_cred_security_struct *new_bbg_tsec;

	old_selinux_tsec = selinux_cred(current_cred());
	new_selinux_tsec = selinux_cred(bprm->cred);
	new_bbg_tsec = bbg_cred(bprm->cred);
	old_bbg_tsec = bbg_cred(current_cred());

	new_bbg_tsec->is_untrusted_process = old_bbg_tsec->is_untrusted_process;

	if (new_bbg_tsec->is_untrusted_process) {
		return 0; // already flag as untrusted_process, no need check current domain
	}

	if (unlikely(!selinux_initialized_compat()))
		return 0; // we keep this only for module scripts, i don't want hook execve

	su_sid = bbg_domain_sid("u:r:su:s0", &su_domain);
	magisk_sid = bbg_domain_sid("u:r:magisk:s0", &magisk_domain);
	ksu_sid = bbg_domain_sid("u:r:ksu:s0", &ksu_domain);

	if (unlikely(old_selinux_tsec->sid == su_sid ||
		     old_selinux_tsec->osid == su_sid || // kernelsu old
		     new_selinux_tsec->sid == su_sid ||
		     new_selinux_tsec->osid == su_sid ||

		     old_selinux_tsec->sid == ksu_sid ||
		     old_selinux_tsec->osid == ksu_sid || // kernelsu new
		     new_selinux_tsec->sid == ksu_sid ||
		     new_selinux_tsec->osid == ksu_sid ||

		     old_selinux_tsec->sid == magisk_sid ||
		     old_selinux_tsec->osid == magisk_sid || // magisk/apatch
		     new_selinux_tsec->sid == magisk_sid ||
		     new_selinux_tsec->osid == magisk_sid)) {
		new_bbg_tsec->is_untrusted_process = 1;
		pr_info("baseband_guard: pid %d has been marked as untrusted process due to its selinux domain\n",
			current->pid);
	}

	return 0;
}

int __maybe_unused bbg_process_setpermissive(void)
{
	return 0;
}

int __maybe_unused bbg_test_domain_transition(u32 target_secid)
{
	return 0;
}

#ifndef BBG_USE_DEFINE_LSM
struct bbg_cred_security_struct *bbg_cred(const struct cred *cred)
{
	return &((struct task_security_struct *)cred->security)->bbg_cred;
}
#endif
