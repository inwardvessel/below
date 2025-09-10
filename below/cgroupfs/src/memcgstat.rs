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
use std::os::fd::{AsFd,AsRawFd};
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

macro_rules! get_from_slice {
    ($item:path, $buf:ident) => {
        Some(u64::from_le_bytes($buf[$item as usize .. $item as usize + 4].try_into().unwrap()))
    }
}

struct Pair<'a> {
    key: bpf::memcg_item,
    val: &'a str,
}

static items: [Pair; bpf::memcg_item_USER_ITEM_COUNT as usize] = [
    Pair {
        key: bpf::memcg_item_USER_NR_ANON_MAPPED,
        val: "nr_anon_mapped",
    },
    Pair {
        key: bpf::memcg_item_USER_NR_FILE_PAGES,
        val: "nr_file_pages",
    },
    Pair {
        key: bpf::memcg_item_USER_NR_KERNEL_STACK_KB,
        val: "nr_kernel_stack_kb",
    },
    Pair {
        key: bpf::memcg_item_USER_NR_SHMEM,
        val: "nr_shmem",
    },
    Pair {
        key: bpf::memcg_item_USER_NR_FILE_MAPPED,
        val: "nr_file_mapped",
    },
    Pair {
        key: bpf::memcg_item_USER_NR_FILE_DIRTY,
        val: "nr_file_dirty",
    },
    Pair {
        key: bpf::memcg_item_USER_NR_WRITEBACK,
        val: "nr_writeback",
    },
    Pair {
        key: bpf::memcg_item_USER_NR_FILE_THPS,
        val: "nr_file_thps",
    },
    Pair {
        key: bpf::memcg_item_USER_NR_ANON_THPS,
        val: "nr_anon_thps",
    },
    Pair {
        key: bpf::memcg_item_USER_NR_INACTIVE_ANON,
        val: "nr_inactive_anon",
    },
    Pair {
        key: bpf::memcg_item_USER_NR_ACTIVE_ANON,
        val: "nr_active_anon",
    },
    Pair {
        key: bpf::memcg_item_USER_NR_INACTIVE_FILE,
        val: "nr_inactive_file",
    },
    Pair {
        key: bpf::memcg_item_USER_NR_ACTIVE_FILE,
        val: "nr_active_file",
    },
    Pair {
        key: bpf::memcg_item_USER_NR_UNEVICTABLE,
        val: "nr_unevictable",
    },
    Pair {
        key: bpf::memcg_item_USER_NR_SLAB_RECLAIMABLE_B,
        val: "nr_slab_reclaimable_b",
    },
    Pair {
        key: bpf::memcg_item_USER_NR_SLAB_UNRECLAIMABLE_B,
        val: "nr_slab_unreclaimable_b",
    },
    Pair {
        key: bpf::memcg_item_USER_WORKINGSET_REFAULT_ANON,
        val: "workingset_refault_anon",
    },
    Pair {
        key: bpf::memcg_item_USER_WORKINGSET_REFAULT_FILE,
        val: "workingset_refault_file",
    },
    Pair {
        key: bpf::memcg_item_USER_WORKINGSET_ACTIVATE_ANON,
        val: "workingset_activate_anon",
    },
    Pair {
        key: bpf::memcg_item_USER_WORKINGSET_ACTIVATE_FILE,
        val: "workingset_activate_file",
    },
    Pair {
        key: bpf::memcg_item_USER_WORKINGSET_RESTORE_ANON,
        val: "workingset_restore_anon",
    },
    Pair {
        key: bpf::memcg_item_USER_WORKINGSET_RESTORE_FILE,
        val: "workingset_restore_file",
    },
    Pair {
        key: bpf::memcg_item_USER_WORKINGSET_NODERECLAIM,
        val: "workingset_nodereclaim",
    },
    Pair {
        key: bpf::memcg_item_USER_MEMCG_KMEM,
        val: "memcg_kmem",
    },
    Pair {
        key: bpf::memcg_item_USER_MEMCG_SOCK,
        val: "memcg_sock",
    },
    Pair {
        key: bpf::memcg_item_USER_MEMCG_ZSWAP_B,
        val: "memcg_zswap_b",
    },
    Pair {
        key: bpf::memcg_item_USER_MEMCG_ZSWAPPED,
        val: "memcg_zswapped",
    },
    Pair {
        key: bpf::memcg_item_USER_PGFAULT,
        val: "pgfault",
    },
    Pair {
        key: bpf::memcg_item_USER_PGMAJFAULT,
        val: "pgmajfault",
    },
    Pair {
        key: bpf::memcg_item_USER_PGREFILL,
        val: "pgrefill",
    },
    Pair {
        key: bpf::memcg_item_USER_PGACTIVATE,
        val: "pgactivate",
    },
    Pair {
        key: bpf::memcg_item_USER_PGDEACTIVATE,
        val: "pgdeactivate",
    },
    Pair {
        key: bpf::memcg_item_USER_PGLAZYFREE,
        val: "pglazyfree",
    },
    Pair {
        key: bpf::memcg_item_USER_PGLAZYFREED,
        val: "pglazyfreed",
    },
    Pair {
        key: bpf::memcg_item_USER_THP_FAULT_ALLOC,
        val: "thp_fault_alloc",
    },
    Pair {
        key: bpf::memcg_item_USER_THP_COLLAPSE_ALLOC,
        val: "thp_collapse_alloc",
    },
];


pub struct MemcgstatDriver {
    relative_path: PathBuf,
    //pub skel_builder: MemcgstatSkelBuilder,
    //pub open_skel: OpenMemcgstatSkel<'a>,
    //pub object: MaybeUninit<'a, libbpf_rs::OpenObject>,
    //pub skel: MemcgstatSkel<'a>,
}

impl MemcgstatDriver {
    pub fn new(relative_path: PathBuf) -> Self {
        // TODO - figure out borrowing/moving and move all initialization out of read() and here instead
        Self {
            relative_path: relative_path,
        }
    }

    pub fn read(&self) -> Result<MemoryStat, ()> {
        let skel_builder = MemcgstatSkelBuilder::default();
        let mut object = MaybeUninit::uninit();
        let open_skel = skel_builder.open(&mut object).expect("failed to open skel");
        let skel = open_skel.load().expect("load error: {error:?}");
        let mut cgroup_dir = File::open(self.relative_path.clone()).expect("failed to open cgroup dir");
        let mut link_info = unsafe {
            let mut _link_info: bpf_iter_link_info = std::mem::zeroed();
            _link_info.cgroup.cgroup_fd = cgroup_dir.as_raw_fd() as u32;
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
        let bytes = iter.read_to_end(&mut buf);

        for item in items.iter() {
            let i = item.key as usize;
            let chunk = &buf[i*4..i*4 + 4];
            let _buf: [u8; 4] = chunk.try_into().unwrap();
            let n = i32::from_le_bytes(_buf);
            println!("{} - {}: {}", i, item.val, n);
        }

        Ok(MemoryStat {
            anon: get_from_slice!(bpf::memcg_item_USER_NR_ANON_MAPPED, buf),
            file: get_from_slice!(bpf::memcg_item_USER_NR_FILE_PAGES, buf),
            kernel: get_from_slice!(bpf::memcg_item_USER_MEMCG_KMEM, buf),
            kernel_stack: get_from_slice!(bpf::memcg_item_USER_NR_KERNEL_STACK_KB, buf),
            slab: None,
            sock: get_from_slice!(bpf::memcg_item_USER_MEMCG_SOCK, buf),
            shmem: get_from_slice!(bpf::memcg_item_USER_NR_SHMEM, buf),
            zswap: get_from_slice!(bpf::memcg_item_USER_MEMCG_ZSWAP_B, buf),
            zswapped: get_from_slice!(bpf::memcg_item_USER_MEMCG_ZSWAPPED, buf),
            file_mapped: get_from_slice!(bpf::memcg_item_USER_NR_FILE_MAPPED, buf),
            file_dirty: get_from_slice!(bpf::memcg_item_USER_NR_FILE_DIRTY, buf),
            file_writeback: get_from_slice!(bpf::memcg_item_USER_NR_WRITEBACK, buf),
            file_thp: get_from_slice!(bpf::memcg_item_USER_NR_FILE_THPS, buf),
            anon_thp: get_from_slice!(bpf::memcg_item_USER_NR_ANON_THPS, buf),
            inactive_anon: get_from_slice!(bpf::memcg_item_USER_NR_INACTIVE_ANON, buf),
            active_anon: get_from_slice!(bpf::memcg_item_USER_NR_ACTIVE_ANON, buf),
            inactive_file: get_from_slice!(bpf::memcg_item_USER_NR_INACTIVE_FILE, buf),
            active_file: get_from_slice!(bpf::memcg_item_USER_NR_ACTIVE_FILE, buf),
            unevictable: get_from_slice!(bpf::memcg_item_USER_NR_UNEVICTABLE, buf),
            slab_reclaimable: get_from_slice!(bpf::memcg_item_USER_NR_SLAB_RECLAIMABLE_B, buf),
            slab_unreclaimable: get_from_slice!(bpf::memcg_item_USER_NR_SLAB_UNRECLAIMABLE_B, buf),
            pgfault: get_from_slice!(bpf::memcg_item_USER_PGFAULT, buf),
            pgmajfault: get_from_slice!(bpf::memcg_item_USER_PGMAJFAULT, buf),
            workingset_refault_anon: get_from_slice!(bpf::memcg_item_USER_WORKINGSET_REFAULT_ANON, buf),
            workingset_refault_file: get_from_slice!(bpf::memcg_item_USER_WORKINGSET_REFAULT_FILE, buf),
            workingset_activate_anon: get_from_slice!(bpf::memcg_item_USER_WORKINGSET_ACTIVATE_ANON, buf),
            workingset_activate_file: get_from_slice!(bpf::memcg_item_USER_WORKINGSET_ACTIVATE_FILE, buf),
            workingset_restore_anon: get_from_slice!(bpf::memcg_item_USER_WORKINGSET_RESTORE_ANON, buf),
            workingset_restore_file: get_from_slice!(bpf::memcg_item_USER_WORKINGSET_RESTORE_FILE, buf),
            workingset_nodereclaim: get_from_slice!(bpf::memcg_item_USER_WORKINGSET_NODERECLAIM, buf),
            pgrefill: get_from_slice!(bpf::memcg_item_USER_PGREFILL, buf),
            pgscan: None,
            pgsteal: None,
            pgactivate: None,
            pgdeactivate: None,
            pglazyfree: None,
            pglazyfreed: None,
            thp_fault_alloc: get_from_slice!(bpf::memcg_item_USER_THP_FAULT_ALLOC, buf),
            thp_collapse_alloc: get_from_slice!(bpf::memcg_item_USER_THP_COLLAPSE_ALLOC, buf),
        })
    }
}
