#![no_std]
use core::mem;

pub const MAX_BUFFER_SIZE: usize = 1024 * 7 - mem::size_of::<usize>();

#[derive(Clone)]
#[repr(C)]
pub struct SslEntry {
    pub buffer: [u8; MAX_BUFFER_SIZE],
    pub size: usize,
}
