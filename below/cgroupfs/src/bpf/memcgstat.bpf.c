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
#include "../../../src/open_source/vmlinux/vmlinux.h"
#endif // FBCODE_BUILD

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "memcgstat.h"

char _license[] SEC("license") = "GPL";

/* New memcg kfunc API - operates on struct mem_cgroup *, not struct cgroup * */
extern struct mem_cgroup *bpf_get_mem_cgroup(struct cgroup_subsys_state *css) __ksym;
extern void bpf_put_mem_cgroup(struct mem_cgroup *memcg) __ksym;
extern void bpf_mem_cgroup_flush_stats(struct mem_cgroup *memcg) __ksym;
extern unsigned long bpf_mem_cgroup_page_state(struct mem_cgroup *memcg, int idx) __ksym;
extern unsigned long bpf_mem_cgroup_vm_events(struct mem_cgroup *memcg, enum vm_event_item event) __ksym;

s64 results[USER_ITEM_COUNT];

/* page_state handles both node_stat_item (0..NR_VM_NODE_STAT_ITEMS-1) and
 * memcg_stat_item (NR_VM_NODE_STAT_ITEMS..MEMCG_NR_STAT-1) indices */
#define page_state_fetch_if_exists(memcg, item) \
	bpf_core_enum_value_exists(enum node_stat_item, item) ? \
		bpf_mem_cgroup_page_state(memcg, bpf_core_enum_value(enum node_stat_item, item)) \
				 : -1;

#define memcg_stat_fetch_if_exists(memcg, item) \
	bpf_core_enum_value_exists(enum memcg_stat_item, item) ? \
		bpf_mem_cgroup_page_state(memcg, bpf_core_enum_value(enum memcg_stat_item, item)) \
				 : -1;

#define vm_event_fetch_if_exists(memcg, item) \
	bpf_core_enum_value_exists(enum vm_event_item, item) ? \
		bpf_mem_cgroup_vm_events(memcg, bpf_core_enum_value(enum vm_event_item, item)) \
				 : -1;

SEC("iter.s/cgroup")
int BPF_PROG(query, struct bpf_iter_meta *meta, struct cgroup *cgrp)
{
	struct seq_file *seq = meta->seq;
	struct mem_cgroup *memcg;

	if (!cgrp)
		return 1;

	/* Get mem_cgroup from cgroup's self css */
	memcg = bpf_get_mem_cgroup(&cgrp->self);
	if (!memcg)
		return 1;

	bpf_mem_cgroup_flush_stats(memcg);

	enum memcg_item item;
	for (item = 0; item < USER_ITEM_COUNT; item++) {
		switch (item) {
			/* node_stat_item */
			case USER_NR_ANON_MAPPED:
				results[item] = page_state_fetch_if_exists(memcg, NR_ANON_MAPPED);
				break;
			case USER_NR_FILE_PAGES:
				results[item] = page_state_fetch_if_exists(memcg, NR_FILE_PAGES);
				break;
			case USER_NR_KERNEL_STACK_KB:
				results[item] = page_state_fetch_if_exists(memcg, NR_KERNEL_STACK_KB);
				break;
			case USER_NR_SHMEM:
				results[item] = page_state_fetch_if_exists(memcg, NR_SHMEM);
				break;
			case USER_NR_FILE_MAPPED:
				results[item] = page_state_fetch_if_exists(memcg, NR_FILE_MAPPED);
				break;
			case USER_NR_FILE_DIRTY:
				results[item] = page_state_fetch_if_exists(memcg, NR_FILE_DIRTY);
				break;
			case USER_NR_WRITEBACK:
				results[item] = page_state_fetch_if_exists(memcg, NR_WRITEBACK);
				break;
			case USER_NR_FILE_THPS:
				results[item] = page_state_fetch_if_exists(memcg, NR_FILE_THPS);
				break;
			case USER_NR_ANON_THPS:
				results[item] = page_state_fetch_if_exists(memcg, NR_ANON_THPS);
				break;
			case USER_NR_INACTIVE_ANON:
				results[item] = page_state_fetch_if_exists(memcg, NR_INACTIVE_ANON);
				break;
			case USER_NR_ACTIVE_ANON:
				results[item] = page_state_fetch_if_exists(memcg, NR_ACTIVE_ANON);
				break;
			case USER_NR_INACTIVE_FILE:
				results[item] = page_state_fetch_if_exists(memcg, NR_INACTIVE_FILE);
				break;
			case USER_NR_ACTIVE_FILE:
				results[item] = page_state_fetch_if_exists(memcg, NR_ACTIVE_FILE);
				break;
			case USER_NR_UNEVICTABLE:
				results[item] = page_state_fetch_if_exists(memcg, NR_UNEVICTABLE);
				break;
			case USER_NR_SLAB_RECLAIMABLE_B:
				results[item] = page_state_fetch_if_exists(memcg, NR_SLAB_RECLAIMABLE_B);
				break;
			case USER_NR_SLAB_UNRECLAIMABLE_B:
				results[item] = page_state_fetch_if_exists(memcg, NR_SLAB_UNRECLAIMABLE_B);
				break;
			case USER_WORKINGSET_REFAULT_ANON:
				results[item] = page_state_fetch_if_exists(memcg, WORKINGSET_REFAULT_ANON);
				break;
			case USER_WORKINGSET_REFAULT_FILE:
				results[item] = page_state_fetch_if_exists(memcg, WORKINGSET_REFAULT_FILE);
				break;
			case USER_WORKINGSET_ACTIVATE_ANON:
				results[item] = page_state_fetch_if_exists(memcg, WORKINGSET_ACTIVATE_ANON);
				break;
			case USER_WORKINGSET_ACTIVATE_FILE:
				results[item] = page_state_fetch_if_exists(memcg, WORKINGSET_ACTIVATE_FILE);
				break;
			case USER_WORKINGSET_RESTORE_ANON:
				results[item] = page_state_fetch_if_exists(memcg, WORKINGSET_RESTORE_ANON);
				break;
			case USER_WORKINGSET_RESTORE_FILE:
				results[item] = page_state_fetch_if_exists(memcg, WORKINGSET_RESTORE_FILE);
				break;
			case USER_WORKINGSET_NODERECLAIM:
				results[item] = page_state_fetch_if_exists(memcg, WORKINGSET_NODERECLAIM);
				break;
			/* memcg_stat_item */
			case USER_MEMCG_KMEM:
				results[item] = memcg_stat_fetch_if_exists(memcg, MEMCG_KMEM);
				break;
			case USER_MEMCG_SOCK:
				results[item] = memcg_stat_fetch_if_exists(memcg, MEMCG_SOCK);
				break;
			case USER_MEMCG_ZSWAP_B:
				results[item] = memcg_stat_fetch_if_exists(memcg, MEMCG_ZSWAP_B);
				break;
			case USER_MEMCG_ZSWAPPED:
				results[item] = memcg_stat_fetch_if_exists(memcg, MEMCG_ZSWAPPED);
				break;
			/* vm_event_item */
			case USER_PGSCAN_KSWAPD:
				results[item] = vm_event_fetch_if_exists(memcg, PGSCAN_KSWAPD);
				break;
			case USER_PGSCAN_DIRECT:
				results[item] = vm_event_fetch_if_exists(memcg, PGSCAN_DIRECT);
				break;
			case USER_PGSCAN_KHUGEPAGED:
				results[item] = vm_event_fetch_if_exists(memcg, PGSCAN_KHUGEPAGED);
				break;
			case USER_PGSCAN_PROACTIVE:
				results[item] = vm_event_fetch_if_exists(memcg, PGSCAN_PROACTIVE);
				break;
			case USER_PGSTEAL_KSWAPD:
				results[item] = vm_event_fetch_if_exists(memcg, PGSTEAL_KSWAPD);
				break;
			case USER_PGSTEAL_DIRECT:
				results[item] = vm_event_fetch_if_exists(memcg, PGSTEAL_DIRECT);
				break;
			case USER_PGSTEAL_KHUGEPAGED:
				results[item] = vm_event_fetch_if_exists(memcg, PGSTEAL_KHUGEPAGED);
				break;
			case USER_PGSTEAL_PROACTIVE:
				results[item] = vm_event_fetch_if_exists(memcg, PGSTEAL_PROACTIVE);
				break;
			case USER_PGFAULT:
				results[item] = vm_event_fetch_if_exists(memcg, PGFAULT);
				break;
			case USER_PGMAJFAULT:
				results[item] = vm_event_fetch_if_exists(memcg, PGMAJFAULT);
				break;
			case USER_PGREFILL:
				results[item] = vm_event_fetch_if_exists(memcg, PGREFILL);
				break;
			case USER_PGACTIVATE:
				results[item] = vm_event_fetch_if_exists(memcg, PGACTIVATE);
				break;
			case USER_PGDEACTIVATE:
				results[item] = vm_event_fetch_if_exists(memcg, PGDEACTIVATE);
				break;
			case USER_PGLAZYFREE:
				results[item] = vm_event_fetch_if_exists(memcg, PGLAZYFREE);
				break;
			case USER_PGLAZYFREED:
				results[item] = vm_event_fetch_if_exists(memcg, PGLAZYFREED);
				break;
			case USER_THP_FAULT_ALLOC:
				results[item] = vm_event_fetch_if_exists(memcg, THP_FAULT_ALLOC);
				break;
			case USER_THP_COLLAPSE_ALLOC:
				results[item] = vm_event_fetch_if_exists(memcg, THP_COLLAPSE_ALLOC);
				break;
			case USER_ITEM_COUNT:
				/* no-op: this item included to avoid the need for a default case */
				break;
		}
	}

	bpf_seq_write(seq, results, sizeof(results[0]) * USER_ITEM_COUNT);

	bpf_put_mem_cgroup(memcg);
	return 0;
}
