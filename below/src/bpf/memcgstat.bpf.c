// Copyright (c) Meta Platforms, Inc. and its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#ifdef FBCODE_BUILD
#include <bpf/vmlinux/vmlinux.h>
#else
#include "../open_source/vmlinux/vmlinux.h"
#endif // FBCODE_BUILD

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "memcgstat.h"

char _license[] SEC("license") = "GPL";

extern void memcg_flush(struct cgroup *cgrp) __ksym;
extern unsigned long memcg_stat_fetch(struct cgroup *cgrp, int item) __ksym;
extern unsigned long memcg_event_fetch(struct cgroup *cgrp, int event) __ksym;

const volatile size_t nr_items;
//const volatile enum memcg_item items[64];
const volatile unsigned int items[64];
int results[64];

#define stat_fetch(cgrp, item) \
	bpf_core_enum_value_exists(enum node_stat_item, item) ? \
		 memcg_stat_fetch(cgrp, bpf_core_enum_value(enum node_stat_item, item)) \
				 : -1;

#define event_fetch(cgrp, item) \
	bpf_core_enum_value_exists(enum memcg_stat_item, item) ? \
		 memcg_event_fetch(cgrp, bpf_core_enum_value(enum memcg_stat_item, item)) \
				 : -1;

SEC("iter/cgroup")
int BPF_PROG(query, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	struct seq_file *seq = meta->seq;

	bpf_printk("call\n");

	if (!cgrp)
		return 1;

	memcg_flush(cgrp);

	size_t i;
	for (i = 0; i < nr_items; i++) {
		switch (items[i]) {
			case USER_NR_INACTIVE_ANON:
				results[i] = stat_fetch(cgrp, NR_INACTIVE_ANON);
				break;
			case USER_NR_ACTIVE_ANON:
				results[i] = stat_fetch(cgrp, NR_ACTIVE_ANON);
				break;
			case USER_NR_INACTIVE_FILE:
				results[i] = stat_fetch(cgrp, NR_INACTIVE_FILE);
				break;
			case USER_NR_ACTIVE_FILE:
				results[i] = stat_fetch(cgrp, NR_ACTIVE_FILE);
				break;
			case USER_NR_UNEVICTABLE:
				results[i] = stat_fetch(cgrp, NR_UNEVICTABLE);
				break;
			case USER_NR_SLAB_RECLAIMABLE_B:
				results[i] = stat_fetch(cgrp, NR_SLAB_RECLAIMABLE_B);
				break;
			case USER_NR_SLAB_UNRECLAIMABLE_B:
				results[i] = stat_fetch(cgrp, NR_SLAB_UNRECLAIMABLE_B);
				break;
			case USER_WORKINGSET_REFAULT_ANON:
				results[i] = stat_fetch(cgrp, WORKINGSET_REFAULT_ANON);
				break;
			case USER_WORKINGSET_REFAULT_FILE:
				results[i] = stat_fetch(cgrp, WORKINGSET_REFAULT_FILE);
				break;
			case USER_WORKINGSET_ACTIVATE_ANON:
				results[i] = stat_fetch(cgrp, WORKINGSET_ACTIVATE_ANON);
				break;
			case USER_WORKINGSET_ACTIVATE_FILE:
				results[i] = stat_fetch(cgrp, WORKINGSET_ACTIVATE_FILE);
				break;
			case USER_WORKINGSET_RESTORE_ANON:
				results[i] = stat_fetch(cgrp, WORKINGSET_RESTORE_ANON);
				break;
			case USER_WORKINGSET_RESTORE_FILE:
				results[i] = stat_fetch(cgrp, WORKINGSET_RESTORE_FILE);
				break;
			case USER_WORKINGSET_NODERECLAIM:
				results[i] = stat_fetch(cgrp, WORKINGSET_NODERECLAIM);
				break;
			case USER_NR_ANON_MAPPED:
				results[i] = stat_fetch(cgrp, NR_ANON_MAPPED);
				break;
			case USER_NR_FILE_MAPPED:
				results[i] = stat_fetch(cgrp, NR_FILE_MAPPED);
				break;
			case USER_NR_FILE_PAGES:
				results[i] = stat_fetch(cgrp, NR_FILE_PAGES);
				break;
			case USER_NR_FILE_DIRTY:
				results[i] = stat_fetch(cgrp, NR_FILE_DIRTY);
				break;
			case USER_NR_WRITEBACK:
				results[i] = stat_fetch(cgrp, NR_WRITEBACK);
				break;
			case USER_NR_SHMEM:
				results[i] = stat_fetch(cgrp, NR_SHMEM);
				break;
			case USER_NR_SHMEM_THPS:
				results[i] = stat_fetch(cgrp, NR_SHMEM_THPS);
				break;
			case USER_NR_FILE_THPS:
				results[i] = stat_fetch(cgrp, NR_FILE_THPS);
				break;
			case USER_NR_ANON_THPS:
				results[i] = stat_fetch(cgrp, NR_ANON_THPS);
				break;
			case USER_NR_KERNEL_STACK_KB:
				results[i] = stat_fetch(cgrp, NR_KERNEL_STACK_KB);
				break;
			case USER_NR_PAGETABLE:
				results[i] = stat_fetch(cgrp, NR_PAGETABLE);
				break;
			case USER_NR_SECONDARY_PAGETABLE:
				results[i] = stat_fetch(cgrp, NR_SECONDARY_PAGETABLE);
				break;
			case USER_NR_SWAPCACHE:
				results[i] = stat_fetch(cgrp, NR_SWAPCACHE);
				break;
			//case USER_PGPROMOTE_SUCCESS:
			//	results[i] = stat_fetch(cgrp, PGPROMOTE_SUCCESS);
			//	break;
			//case USER_PGDEMOTE_KSWAPD:
			//	results[i] = stat_fetch(cgrp, PGDEMOTE_KSWAPD);
			//	break;
			//case USER_PGDEMOTE_DIRECT:
			//	results[i] = stat_fetch(cgrp, PGDEMOTE_DIRECT);
			//	break;
			//case USER_PGDEMOTE_KHUGEPAGED:
			//	results[i] = stat_fetch(cgrp, PGDEMOTE_KHUGEPAGED);
			//	break;
			//case USER_PGDEMOTE_PROACTIVE:
			//	results[i] = stat_fetch(cgrp, PGDEMOTE_PROACTIVE);
			//	break;
			//case USER_NR_HUGETLB:
			//	results[i] = stat_fetch(cgrp, NR_HUGETLB);
			//	break;
			case USER_MEMCG_SWAP:
				results[i] = event_fetch(cgrp, MEMCG_SWAP);
				break;
			case USER_MEMCG_SOCK:
				results[i] = event_fetch(cgrp, MEMCG_SOCK);
				break;
			case USER_MEMCG_PERCPU_B:
				results[i] = event_fetch(cgrp, MEMCG_PERCPU_B);
				break;
			case USER_MEMCG_VMALLOC:
				results[i] = event_fetch(cgrp, MEMCG_VMALLOC);
				break;
			case USER_MEMCG_KMEM:
				results[i] = event_fetch(cgrp, MEMCG_KMEM);
				break;
			case USER_MEMCG_ZSWAP_B:
				results[i] = event_fetch(cgrp, MEMCG_ZSWAP_B);
				break;
			case USER_MEMCG_ZSWAPPED:
				results[i] = event_fetch(cgrp, MEMCG_ZSWAPPED);
				break;
			default:
				results[i] = -1;
				break;
		}
	}

	bpf_seq_write(seq, results, sizeof(int) * nr_items);

	return 0;
}
