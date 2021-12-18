use core::fmt;
use std::fmt::Display;
use regex::Regex;

#[derive(Debug)]
pub struct KernelError {
    desc: &'static str,
}

impl std::error::Error for KernelError {}
impl Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Kernel error: {}", &self.desc)
    }
}

pub fn extract_num(s: &str) -> Result<i32, KernelError> {
    let num: Option<i32> = s.parse().ok();
    return match num {
        Some(n) => Ok(n),
        None => Err(KernelError{desc: "Major/Minor not numeric"}),
    };
}

pub const UNKNOWN_KERNEL_VERSION: (i32, i32) = (0, 0);

pub fn extract_kernel_version(input: &str) -> Result<(i32, i32), KernelError> {
    let re = Regex::new(r"([0-9]+)\.([0-9]+)").unwrap();
    let caps = match re.captures(input) {
        Some(s) => s,
        None => return Err(KernelError{desc: "No version"}),
    };

    let major = match &caps.get(1) {
        Some(s) => extract_num(s.as_str())?,
        None => return Err(KernelError{desc: "Major retireval failed"}),
    };
    let minor = match &caps.get(2) {
        Some(s) => extract_num(s.as_str())?,
        None => return Err(KernelError{desc: "Minor retireval failed"}),
    };
    return Ok((major, minor))
}

pub fn get_kernel_version() -> Result<(i32, i32), KernelError> {
    let res = nix::sys::utsname::uname();
    return extract_kernel_version(res.release());
}
