/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SYSV_TASK_H
#define _LINUX_SYSV_TASK_H

#include <linux/list.h>
#include <linux/sched.h>

struct sem_undo_list;

/*
 * A task owns one state object from dup_task_struct() until free_task().
 * The pointer is immutable while the task is visible; semaphore undo sharing
 * and the creator list retain their existing reference-counting/locking rules.
 * The fourth literal Android kABI reserve stores the pointer bits. Keeping that
 * member's C declaration intact also preserves Rust bindgen's member graph:
 * ANDROID_KABI_USE's anonymous wrapper adds a generated Rust field name even
 * when gendwarfksyms reduces its contents to the original reserved u64.
 */
struct sysv_task_state {
	struct sem_undo_list *undo_list;
	struct list_head shm_clist;
};

#ifdef CONFIG_SYSVIPC
#if !defined(CONFIG_64BIT) || !defined(CONFIG_ANDROID_KABI_RESERVE)
#error "The 6.18 SysV IPC port requires a 64-bit Android kABI reserve"
#endif

_Static_assert(sizeof(((struct task_struct *)0)->__kabi_reserved4) ==
	       sizeof(struct sysv_task_state *), "SysV state must fit the reserve");

static inline struct sysv_task_state *sysv_task_state(const struct task_struct *task)
{
	return (struct sysv_task_state *)(unsigned long)READ_ONCE(task->__kabi_reserved4);
}

static inline void sysv_task_set_state(struct task_struct *task,
				     struct sysv_task_state *state)
{
	WRITE_ONCE(task->__kabi_reserved4, (unsigned long)state);
}
#endif /* CONFIG_SYSVIPC */

#endif /* _LINUX_SYSV_TASK_H */
