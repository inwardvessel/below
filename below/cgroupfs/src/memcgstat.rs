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

use core::ptr::NonNull;
use std::env;
use std::path::PathBuf;
use std::fs::{File,OpenOptions};
use std::io::Read;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd,AsRawFd,RawFd};
use libbpf_rs::{
    AsRawLibbpf,
    Iter,
    Link,
    ObjectBuilder,
    OpenObject,
};
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::Skel as _;
use libbpf_rs::skel::SkelBuilder as _;
use libbpf_rs::libbpf_sys::{
    bpf_iter_link_info,
    bpf_iter_attach_opts,
    bpf_iter_create,
    bpf_link__fd,
    bpf_program__attach_iter,
};

use crate::types::*;

mod bpf {
    include!(concat!(env!("OUT_DIR"), "/memcgstat.skel.rs"));
    include!(concat!(env!("OUT_DIR"), "/memcgstat_defs.rs"));
}

pub use bpf::MemcgstatSkelBuilder;
pub use bpf::MemcgstatSkel;
pub use bpf::OpenMemcgstatSkel;

fn fetch_from_slice(item: bpf::memcg_item, buf: &Vec<u8>, name: &str) -> Option<u64> {
    let i = item as usize;
    let offset = i * 8;
    let chunk = &buf[offset..offset + 8];
    let _buf: [u8; 8] = chunk.try_into().unwrap();
    let n = i64::from_le_bytes(_buf);
    println!("i:{}, name:{}, n:{}", i, name, n);

    if n < 0 {
        return None;
    }

    Some(n.try_into().unwrap())
}

pub struct MemcgstatDriver {
    cgroup_fd: RawFd,
    //pub skel_builder: MemcgstatSkelBuilder,
    //pub open_skel: OpenMemcgstatSkel<'a>,
    //pub object: MaybeUninit<'a, libbpf_rs::OpenObject>,
    //pub skel: MemcgstatSkel<'a>,
}

impl MemcgstatDriver {
    pub fn new(cgroup_fd: RawFd) -> Self {
        // TODO - figure out borrowing/moving and move all initialization out of read() and here instead
        Self {
            cgroup_fd: cgroup_fd,
        }
    }

    pub fn read(&self) -> Result<MemoryStat, ()> {
        let skel_builder = MemcgstatSkelBuilder::default();
        let mut object = MaybeUninit::uninit();
        let open_skel = skel_builder.open(&mut object).expect("failed to open skel");
        let skel = open_skel.load().expect("load error: {error:?}");
        //let mut cgroup_dir = File::open(self.cgroup_path.clone()).expect("failed to open cgroup dir");
        let mut link_info = unsafe {
            let mut _link_info: bpf_iter_link_info = std::mem::zeroed();
            _link_info.cgroup.cgroup_fd = self.cgroup_fd as u32;
            _link_info.cgroup.order = 1; /* BPF_CGROUP_ITER_SELF_ONLY = 1 */
            _link_info
        };

        let mut attach_opts = unsafe {
            let mut _attach_opts: bpf_iter_attach_opts = std::mem::zeroed();
            _attach_opts.sz = std::mem::size_of::<bpf_iter_attach_opts>() as u64;
            _attach_opts.link_info = &mut link_info as *mut _;
            _attach_opts.link_info_len = std::mem::size_of::<bpf_iter_link_info>() as u32;
            _attach_opts
        };

        let link_ptr = unsafe {
            bpf_program__attach_iter(skel.progs.query.as_libbpf_object().as_ptr(), &mut attach_opts)
        };
        if link_ptr.is_null() {
            panic!("link is null");
        }

        let link_x = NonNull::new(link_ptr).expect("pointer");
        let link = unsafe {
            Link::from_ptr(link_x)
        };

        let mut iter = Iter::new(&link).unwrap();
        let mut buf = Vec::new();
        let bytes = iter.read_to_end(&mut buf).expect("fail iter read");
        println!("read bytes:{}, item count:{}", bytes, bpf::memcg_item_USER_ITEM_COUNT);

        Ok(MemoryStat {
            anon: fetch_from_slice(bpf::memcg_item_USER_NR_ANON_MAPPED, &buf, "anon"),
            file: fetch_from_slice(bpf::memcg_item_USER_NR_FILE_PAGES, &buf, "file"),
            kernel: fetch_from_slice(bpf::memcg_item_USER_MEMCG_KMEM, &buf, "kernel"),
            kernel_stack: fetch_from_slice(bpf::memcg_item_USER_NR_KERNEL_STACK_KB, &buf, "kernel_stack"),
            slab: fetch_from_slice(bpf::memcg_item_USER_NR_SLAB_UNRECLAIMABLE_B, &buf, "slab"),
            sock: fetch_from_slice(bpf::memcg_item_USER_MEMCG_SOCK, &buf, "sock"),
            shmem: fetch_from_slice(bpf::memcg_item_USER_NR_SHMEM, &buf, "shmem"),
            zswap: fetch_from_slice(bpf::memcg_item_USER_MEMCG_ZSWAP_B, &buf, "zswap"),
            zswapped: fetch_from_slice(bpf::memcg_item_USER_MEMCG_ZSWAPPED, &buf, "zswapped"),
            file_mapped: fetch_from_slice(bpf::memcg_item_USER_NR_FILE_MAPPED, &buf, "file_mapped"),
            file_dirty: fetch_from_slice(bpf::memcg_item_USER_NR_FILE_DIRTY, &buf, "file_dirty"),
            file_writeback: fetch_from_slice(bpf::memcg_item_USER_NR_WRITEBACK, &buf, "file_writeback"),
            file_thp: fetch_from_slice(bpf::memcg_item_USER_NR_FILE_THPS, &buf, "file_thp"),
            anon_thp: fetch_from_slice(bpf::memcg_item_USER_NR_ANON_THPS, &buf, "anon_thp"),
            inactive_anon: fetch_from_slice(bpf::memcg_item_USER_NR_INACTIVE_ANON, &buf, "inactive_anon"),
            active_anon: fetch_from_slice(bpf::memcg_item_USER_NR_ACTIVE_ANON, &buf, "active_anon"),
            inactive_file: fetch_from_slice(bpf::memcg_item_USER_NR_INACTIVE_FILE, &buf, "inactive_file"),
            active_file: fetch_from_slice(bpf::memcg_item_USER_NR_ACTIVE_FILE, &buf, "active_file"),
            unevictable: fetch_from_slice(bpf::memcg_item_USER_NR_UNEVICTABLE, &buf, "unevictable"),
            slab_reclaimable: fetch_from_slice(bpf::memcg_item_USER_NR_SLAB_RECLAIMABLE_B, &buf, "slab_reclaimable"),
            slab_unreclaimable: fetch_from_slice(bpf::memcg_item_USER_NR_SLAB_UNRECLAIMABLE_B, &buf, "slab_unreclaimable"),
            pgfault: fetch_from_slice(bpf::memcg_item_USER_PGFAULT, &buf, "pgfault"),
            pgmajfault: fetch_from_slice(bpf::memcg_item_USER_PGMAJFAULT, &buf, "pgmajfault"),
            workingset_refault_anon: fetch_from_slice(bpf::memcg_item_USER_WORKINGSET_REFAULT_ANON, &buf, "workingset_refault_anon"),
            workingset_refault_file: fetch_from_slice(bpf::memcg_item_USER_WORKINGSET_REFAULT_FILE, &buf, "workingset_refault_file"),
            workingset_activate_anon: fetch_from_slice(bpf::memcg_item_USER_WORKINGSET_ACTIVATE_ANON, &buf, "workingset_activate_anon"),
            workingset_activate_file: fetch_from_slice(bpf::memcg_item_USER_WORKINGSET_ACTIVATE_FILE, &buf, "workingset_activate_file"),
            workingset_restore_anon: fetch_from_slice(bpf::memcg_item_USER_WORKINGSET_RESTORE_ANON, &buf, "workingset_restore_anon"),
            workingset_restore_file: fetch_from_slice(bpf::memcg_item_USER_WORKINGSET_RESTORE_FILE, &buf, "workingset_restore_file"),
            workingset_nodereclaim: fetch_from_slice(bpf::memcg_item_USER_WORKINGSET_NODERECLAIM, &buf, "workingset_nodereclaim"),
            pgrefill: fetch_from_slice(bpf::memcg_item_USER_PGREFILL, &buf, "pgrefill"),
            pgscan:
                fetch_from_slice(bpf::memcg_item_USER_PGSCAN_KSWAPD, &buf, "pgscan_kswapd").and_then(|kswapd|
                fetch_from_slice(bpf::memcg_item_USER_PGSCAN_DIRECT, &buf, "pgscan_direct").and_then(|direct|
                fetch_from_slice(bpf::memcg_item_USER_PGSCAN_KHUGEPAGED, &buf, "pgscan_khugepaged").and_then(|khugepaged|
                fetch_from_slice(bpf::memcg_item_USER_PGSCAN_PROACTIVE, &buf, "pgscan_proactive").map(|proactive|
                    kswapd + direct + khugepaged + proactive)))),
            pgsteal:
                fetch_from_slice(bpf::memcg_item_USER_PGSTEAL_KSWAPD, &buf, "pgsteal_kswapd").and_then(|kswapd|
                fetch_from_slice(bpf::memcg_item_USER_PGSTEAL_DIRECT, &buf, "pgsteal_direct").and_then(|direct|
                fetch_from_slice(bpf::memcg_item_USER_PGSTEAL_KHUGEPAGED, &buf, "pgsteal_khugepaged").and_then(|khugepaged|
                fetch_from_slice(bpf::memcg_item_USER_PGSTEAL_PROACTIVE, &buf, "pgsteal_proactive").map(|proactive|
                    kswapd + direct + khugepaged + proactive)))),
            pgactivate: fetch_from_slice(bpf::memcg_item_USER_PGACTIVATE, &buf, "pgactivate"),
            pgdeactivate: fetch_from_slice(bpf::memcg_item_USER_PGDEACTIVATE, &buf, "pgdeactivate"),
            pglazyfree: fetch_from_slice(bpf::memcg_item_USER_PGLAZYFREE, &buf, "pglazyfree"),
            pglazyfreed: fetch_from_slice(bpf::memcg_item_USER_PGLAZYFREED, &buf, "pglazyfreed"),
            thp_fault_alloc: fetch_from_slice(bpf::memcg_item_USER_THP_FAULT_ALLOC, &buf, "thp_fault_alloc"),
            thp_collapse_alloc: fetch_from_slice(bpf::memcg_item_USER_THP_COLLAPSE_ALLOC, &buf, "thp_collapse_alloc"),
        })
    }
}
