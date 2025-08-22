use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC_memcgstat: &str = "./src/bpf/memcgstat.bpf.c";
fn main() {
    {
        let mut out =
            PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
        out.push("memcgstat.skel.rs");

        let mut builder = SkeletonBuilder::new();
        builder.source(SRC_memcgstat);
        if let Some(clang) = option_env!("CLANG") {
            builder.clang(clang);
        }
        builder.build_and_generate(out).unwrap();
        println!("cargo:rerun-if-changed={}", SRC_memcgstat);
    }

    {
        let bindings = bindgen::Builder::default()
            .header("src/bpf/memcgstat.h")
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .generate()
            .expect("bindgen fail");

        let out = PathBuf::from(env::var("OUT_DIR").unwrap());
        bindings
            .write_to_file(out.join("memcgstat_defs.rs"))
            .expect("out write fail");
    }

}
