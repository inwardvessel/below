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

mod bpf {
    include!(concat!(env!("OUT_DIR"), "/memcgstat.skel.rs"));
    include!(concat!(env!("OUT_DIR"), "/memcgstat_defs.rs"));
}

pub use bpf::MemcgstatSkelBuilder;


pub struct MemcgstatDriver {
    pub buffer: String,
}

impl MemcgstatDriver {
    pub fn new() -> Self {
        let mut skel_builder = MemcgstatSkelBuilder::default();

        let mut object = MaybeUninit::uninit();
        let mut open_skel = skel_builder.open(&mut object).expect("failed to open skel");

        let mut skel = open_skel.load().expect("load error: {error:?}");

        let mut cgroup_dir = File::open("/sys/fs/cgroup").expect("failed to open dir");

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

        for chunk in buf.chunks_exact(4) {
            let _buf: [u8; 4] = chunk.try_into().unwrap();
            let i = i32::from_le_bytes(_buf);
            println!("i: {}", i);
        }

        Self {
            buffer: String::from("works"),
        }
    }
}
