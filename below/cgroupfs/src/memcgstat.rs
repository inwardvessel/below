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
use std::os::fd::AsFd;
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
    pub buffer: i32,
}

impl MemcgstatDriver {
    pub fn new() -> Self {
        let mut skel_builder = MemcgstatSkelBuilder::default();

        let mut object = MaybeUninit::uninit();
        let mut open_skel = skel_builder.open(&mut object).unwrap();
        let rodata = open_skel.maps.rodata_data
            .as_deref_mut()
            .expect("no rodata");

        rodata.nr_items = 1;
        rodata.items[0] = bpf::memcg_item_USER_NR_SHMEM as bpf::memcg_item;

        let mut skel = open_skel.load().unwrap();
        skel.attach();

        let mut file = File::open("/sys/fs/cgroup/memory.stat").unwrap();
        //let prog = skel.links.query.unwrap();
        let prog = skel.progs.query;
        let link = prog.attach_iter(file.as_fd()).unwrap();
        let mut iter = Iter::new(&link).unwrap();
        let mut buf = Vec::new();
        let bytes = iter.read_to_end(&mut buf);

        Self {
            buffer: 1,
        }
    }

}
