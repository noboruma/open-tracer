use std::os::linux::fs::MetadataExt;

//use nix::libc::{S_IXGRP, S_IXUSR, S_IXOTH};

pub fn is_harmful_file(path: &str) -> std::io::Result<bool> {
    let meta = std::fs::metadata(path)?;
    Ok(!meta.is_dir() && meta.st_size() != 0) //&& (meta.st_mode() & (S_IXGRP | S_IXUSR | S_IXOTH)) != 0)
}

pub fn cstringify(input: &[u8], capacity: usize) -> String {
    let mut res = String::with_capacity(capacity);
    for v in input.iter() {
        if *v != 0 {
            res.push(*v as char);
        }
    }
    return res;
}
