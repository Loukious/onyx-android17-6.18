// SPDX-License-Identifier: GPL-2.0
// Compile against baseline/enabled generated configs; compare --stable symtypes.
#include <linux/sched.h>
#include <linux/export.h>
#include <linux/ipc_namespace.h>
#include <linux/shmem_fs.h>
#include <net/net_namespace.h>

void probe_task(struct task_struct *task) {}
void probe_net(struct net *net) {}
void probe_inode(struct inode *inode) {}
void probe_shmem(struct shmem_inode_info *shmem) {}
void probe_ipc(struct ipc_namespace *ipc) {}
void probe_user_ns(struct user_namespace *user_ns) {}

__GENDWARFKSYMS_EXPORT(probe_task);
__GENDWARFKSYMS_EXPORT(probe_net);
__GENDWARFKSYMS_EXPORT(probe_inode);
__GENDWARFKSYMS_EXPORT(probe_shmem);
__GENDWARFKSYMS_EXPORT(probe_ipc);
__GENDWARFKSYMS_EXPORT(probe_user_ns);
