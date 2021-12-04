use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::Command;

use regex::Regex;
use structopt::StructOpt;
use walkdir::{DirEntry, WalkDir};

#[derive(Debug, Copy, Clone)]
pub enum Architecture {
    BpfEl,
    BpfEb,
}

impl std::str::FromStr for Architecture {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "bpfel-unknown-none" => Architecture::BpfEl,
            "bpfeb-unknown-none" => Architecture::BpfEb,
            _ => return Err("invalid target".to_owned()),
        })
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Architecture::BpfEl => "bpfel-unknown-none",
            Architecture::BpfEb => "bpfeb-unknown-none",
        })
    }
}

#[derive(StructOpt)]
pub struct Options {
    #[structopt(default_value = "bpfel-unknown-none", long)]
    target: Architecture,
    #[structopt(long)]
    release: bool,
}

#[derive(Clone, Copy)]
struct KernelVersion {
    pub major: u8,
    pub minor: u8,
}

impl KernelVersion {
    fn to_string(&self) -> String {
        return format!("{}.{}", self.major, self.minor);
    }
}

fn check_kernel_compat(dir: &PathBuf) -> KernelVersion {

    let hashmap = HashMap::from([
        ("bpf_probe_read_str", KernelVersion{major: 4, minor: 11}),
        ("bpf_get_current_comm",KernelVersion{major: 4, minor: 2}),
        ("bpf_get_current_pid_tgid", KernelVersion{major: 4, minor: 2}),
    ]);

    let mut files = Vec::<DirEntry>::new();

    for entry in WalkDir::new(&dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            files.push(entry);
        }
    }
    let re = Regex::new(r"bpf_[a-zA-Z0-9_]+").unwrap();

    let mut highest_version = KernelVersion{major:0, minor:0};
    for file_path in files {
        let file = File::open(&file_path.path()).unwrap();
        for line in BufReader::new(file).lines() {

            let r = line.unwrap();

            match re.captures(&r) {
                Some(caps) => {

                    if hashmap.contains_key(&caps.get(0).unwrap().as_str()) {
                        let function_version = hashmap[&caps.get(0).unwrap().as_str()];
                        if function_version.major > highest_version.major {
                            highest_version = function_version;
                        } else if function_version.major == highest_version.major {
                            if function_version.minor > highest_version.minor {
                                highest_version = function_version;
                            }
                        }
                    }
                }
                None => {}

            }
        }
    }
    return highest_version;
}

pub fn build(opts: Options) -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("echo-ebpf");
    let max_kernel_support = check_kernel_compat(&dir).to_string();
    let target = format!("--target={}", opts.target);
    let kernel_ver = format!("--target-dir=../target/{}",max_kernel_support);
    let mut args = vec![
        "+nightly",
        "build",
        "--verbose",
        target.as_str(),
        "-Z",
        "unstable-options",
        kernel_ver.as_str(),
        "-Z",
        "build-std=core",
    ];
    if opts.release {
        args.push("--release")
    }
    let status = Command::new("cargo")
        .current_dir(&dir)
        .args(&args)
        .status()
        .expect("failed to build bpf examples");
    assert!(status.success());
    Ok(())
}
