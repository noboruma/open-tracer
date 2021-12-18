#![no_std]

pub const PATH_MAX_LEN: usize= 4096;
pub const COMM_MAX_LEN: usize= 16;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct OpenEvent {
    pub path: [u8; PATH_MAX_LEN],
    pub comm: [u8; COMM_MAX_LEN],
    pub pid: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct KernelVersion {
    pub major: u8,
    pub minor: u8,
}

pub const fn env_to_kernelversion(s: &str) -> KernelVersion {
    let mut read_major = true;
    let mut major: u8 = 0;
    let mut minor: u8 = 0;
    let mut i = 0;
    loop {
        if i == s.len() {
            break;
        }

        let c = s.as_bytes()[i];
        if c == '.' as u8 {
            read_major = false;
        } else if read_major {
            major *= 10;
            major += c-'0' as u8;
        } else {
            minor *= 10;
            minor += c-'0' as u8;
        }
        i+=1;
    }
    return KernelVersion{
        major,
        minor
    }
}
