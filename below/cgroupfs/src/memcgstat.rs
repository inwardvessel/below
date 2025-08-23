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

use std::fs::File;
use std::io::Read;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd,AsRawFd};
use libbpf_rs::Iter;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::Skel as _;
use libbpf_rs::skel::SkelBuilder as _;

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
        let mut open_skel = skel_builder.open(&mut object).unwrap();
        let rodata = open_skel.maps.rodata_data
            .as_deref_mut()
            .expect("no rodata");

        //rodata.nr_items = 1;
        rodata.items[0] = bpf::memcg_item_USER_NR_SHMEM as bpf::memcg_item;

        let mut skel = match open_skel.load() {
            Ok(res) => res,
            Err(error) => panic!("load error: {error:?}"),
        };
        skel.attach();

        let mut file = match File::open("/sys/fs/cgroup/memory.stat") {
            Ok(res) => res,
            Err(error) => panic!("open error: {error:?}"),
        };

        //let prog = skel.links.query.unwrap();
        let link = skel.progs.query.attach_iter(file.as_fd()).unwrap();
        //let link = match prog.attach_iter(file.as_fd()) {
        //    Ok(res) => res,
        //    Err(error) => panic!("attach error: {error:?}"),
        //};
        let mut iter = Iter::new(&link).unwrap();
        let mut buf = String::new();
        let bytes = iter.read_to_string(&mut buf);

        Self {
            buffer: buf,
        }
    }
}
