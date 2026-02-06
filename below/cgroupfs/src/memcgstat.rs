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

use std::io::Read;
use std::mem::MaybeUninit;
use std::os::fd::BorrowedFd;

use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::SkelBuilder as _;
use libbpf_rs::{CgroupIterOpts, CgroupIterOrder, Iter, IterOpts, Link, ProgramMut};

use crate::types::*;

mod bpf {
    include!(concat!(env!("OUT_DIR"), "/memcgstat.skel.rs"));
    include!(concat!(env!("OUT_DIR"), "/memcgstat_defs.rs"));
}

pub use bpf::MemcgstatSkelBuilder;

/// Attach a BPF iterator program to a cgroup using the safe libbpf-rs API.
fn attach_cgroup_iter(prog: &ProgramMut, cgroup_fd: BorrowedFd<'_>) -> Result<Link, libbpf_rs::Error> {
    let cgroup_opts = CgroupIterOpts {
        fd: cgroup_fd,
        order: CgroupIterOrder::SelfOnly,
        _non_exhaustive: (),
    };

    prog.attach_iter_with_opts(IterOpts::Cgroup(cgroup_opts))
}

fn fetch_from_slice(item: bpf::memcg_item, buf: &[u8]) -> Option<u64> {
    let i = item as usize;
    let offset = i * 8;
    let chunk = buf.get(offset..offset + 8)?;
    let bytes: [u8; 8] = chunk.try_into().ok()?;
    let n = i64::from_le_bytes(bytes);

    if n < 0 {
        return None;
    }

    Some(n as u64)
}

pub struct MemcgstatDriver {
    link: Link,
}

impl MemcgstatDriver {
    pub fn new(cgroup_fd: BorrowedFd<'_>) -> Self {
        let skel_builder = MemcgstatSkelBuilder::default();
        let mut object = MaybeUninit::uninit();
        let open_skel = skel_builder
            .open(&mut object)
            .expect("failed to open BPF skeleton");
        let skel = open_skel.load().expect("failed to load BPF program");

        let link = attach_cgroup_iter(&skel.progs.query, cgroup_fd)
            .expect("failed to attach cgroup iterator");

        Self { link }
    }

    pub fn read(&self) -> Result<MemoryStat, ()> {
        let mut iter = Iter::new(&self.link).map_err(|_| ())?;
        let mut buf = Vec::new();
        iter.read_to_end(&mut buf).map_err(|_| ())?;

        Ok(MemoryStat {
            anon: fetch_from_slice(bpf::memcg_item_USER_NR_ANON_MAPPED, &buf),
            file: fetch_from_slice(bpf::memcg_item_USER_NR_FILE_PAGES, &buf),
            kernel: fetch_from_slice(bpf::memcg_item_USER_MEMCG_KMEM, &buf),
            kernel_stack: fetch_from_slice(bpf::memcg_item_USER_NR_KERNEL_STACK_KB, &buf),
            sock: fetch_from_slice(bpf::memcg_item_USER_MEMCG_SOCK, &buf),
            shmem: fetch_from_slice(bpf::memcg_item_USER_NR_SHMEM, &buf),
            zswap: fetch_from_slice(bpf::memcg_item_USER_MEMCG_ZSWAP_B, &buf),
            zswapped: fetch_from_slice(bpf::memcg_item_USER_MEMCG_ZSWAPPED, &buf),
            file_mapped: fetch_from_slice(bpf::memcg_item_USER_NR_FILE_MAPPED, &buf),
            file_dirty: fetch_from_slice(bpf::memcg_item_USER_NR_FILE_DIRTY, &buf),
            file_writeback: fetch_from_slice(bpf::memcg_item_USER_NR_WRITEBACK, &buf),
            file_thp: fetch_from_slice(bpf::memcg_item_USER_NR_FILE_THPS, &buf),
            anon_thp: fetch_from_slice(bpf::memcg_item_USER_NR_ANON_THPS, &buf),
            inactive_anon: fetch_from_slice(bpf::memcg_item_USER_NR_INACTIVE_ANON, &buf),
            active_anon: fetch_from_slice(bpf::memcg_item_USER_NR_ACTIVE_ANON, &buf),
            inactive_file: fetch_from_slice(bpf::memcg_item_USER_NR_INACTIVE_FILE, &buf),
            active_file: fetch_from_slice(bpf::memcg_item_USER_NR_ACTIVE_FILE, &buf),
            unevictable: fetch_from_slice(bpf::memcg_item_USER_NR_UNEVICTABLE, &buf),
            slab_reclaimable: fetch_from_slice(bpf::memcg_item_USER_NR_SLAB_RECLAIMABLE_B, &buf),
            slab_unreclaimable: fetch_from_slice(bpf::memcg_item_USER_NR_SLAB_UNRECLAIMABLE_B, &buf),
            slab: fetch_from_slice(bpf::memcg_item_USER_NR_SLAB_RECLAIMABLE_B, &buf).and_then(
                |reclaimable| {
                    fetch_from_slice(bpf::memcg_item_USER_NR_SLAB_UNRECLAIMABLE_B, &buf)
                        .map(|unreclaimable| reclaimable + unreclaimable)
                },
            ),
            pgfault: fetch_from_slice(bpf::memcg_item_USER_PGFAULT, &buf),
            pgmajfault: fetch_from_slice(bpf::memcg_item_USER_PGMAJFAULT, &buf),
            workingset_refault_anon: fetch_from_slice(
                bpf::memcg_item_USER_WORKINGSET_REFAULT_ANON,
                &buf,
            ),
            workingset_refault_file: fetch_from_slice(
                bpf::memcg_item_USER_WORKINGSET_REFAULT_FILE,
                &buf,
            ),
            workingset_activate_anon: fetch_from_slice(
                bpf::memcg_item_USER_WORKINGSET_ACTIVATE_ANON,
                &buf,
            ),
            workingset_activate_file: fetch_from_slice(
                bpf::memcg_item_USER_WORKINGSET_ACTIVATE_FILE,
                &buf,
            ),
            workingset_restore_anon: fetch_from_slice(
                bpf::memcg_item_USER_WORKINGSET_RESTORE_ANON,
                &buf,
            ),
            workingset_restore_file: fetch_from_slice(
                bpf::memcg_item_USER_WORKINGSET_RESTORE_FILE,
                &buf,
            ),
            workingset_nodereclaim: fetch_from_slice(
                bpf::memcg_item_USER_WORKINGSET_NODERECLAIM,
                &buf,
            ),
            pgrefill: fetch_from_slice(bpf::memcg_item_USER_PGREFILL, &buf),
            pgscan: fetch_from_slice(bpf::memcg_item_USER_PGSCAN_KSWAPD, &buf).and_then(|kswapd| {
                fetch_from_slice(bpf::memcg_item_USER_PGSCAN_DIRECT, &buf).and_then(|direct| {
                    fetch_from_slice(bpf::memcg_item_USER_PGSCAN_KHUGEPAGED, &buf).and_then(
                        |khugepaged| {
                            fetch_from_slice(bpf::memcg_item_USER_PGSCAN_PROACTIVE, &buf)
                                .map(|proactive| kswapd + direct + khugepaged + proactive)
                        },
                    )
                })
            }),
            pgsteal: fetch_from_slice(bpf::memcg_item_USER_PGSTEAL_KSWAPD, &buf).and_then(
                |kswapd| {
                    fetch_from_slice(bpf::memcg_item_USER_PGSTEAL_DIRECT, &buf).and_then(|direct| {
                        fetch_from_slice(bpf::memcg_item_USER_PGSTEAL_KHUGEPAGED, &buf).and_then(
                            |khugepaged| {
                                fetch_from_slice(bpf::memcg_item_USER_PGSTEAL_PROACTIVE, &buf)
                                    .map(|proactive| kswapd + direct + khugepaged + proactive)
                            },
                        )
                    })
                },
            ),
            pgactivate: fetch_from_slice(bpf::memcg_item_USER_PGACTIVATE, &buf),
            pgdeactivate: fetch_from_slice(bpf::memcg_item_USER_PGDEACTIVATE, &buf),
            pglazyfree: fetch_from_slice(bpf::memcg_item_USER_PGLAZYFREE, &buf),
            pglazyfreed: fetch_from_slice(bpf::memcg_item_USER_PGLAZYFREED, &buf),
            thp_fault_alloc: fetch_from_slice(bpf::memcg_item_USER_THP_FAULT_ALLOC, &buf),
            thp_collapse_alloc: fetch_from_slice(bpf::memcg_item_USER_THP_COLLAPSE_ALLOC, &buf),
            // TODO: Add BPF support for these new fields
            swapcached: None,
            shmem_thp: None,
            hugetlb: None,
        })
    }
}
