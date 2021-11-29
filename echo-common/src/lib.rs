#![no_std]

const PATH_MAX_LEN: usize= 4096;
const COMM_MAX_LEN: usize= 16;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct OpenEvent {
    pub path: [u8; PATH_MAX_LEN],
    pub comm: [u8; COMM_MAX_LEN],
    pub pid: u32,
}
