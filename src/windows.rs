// Copyright 2018 Developers of the Rand project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::Error;
use core::{ffi::c_void, num::NonZeroU32, ptr};

const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x00000002;

#[link(name = "advapi32")]
extern "system" {
    #[link_name = "SystemFunction036"]
    fn RtlGenRandom(RandomBuffer: *mut u8, RandomBufferLength: u32) -> u8;
}

#[link(name = "bcrypt")]
extern "system" {
    fn BCryptGenRandom(
        hAlgorithm: *mut c_void,
        pBuffer: *mut u8,
        cbBuffer: u32,
        dwFlags: u32,
    ) -> u32;
}

#[cfg(target_pointer_width = "64")]
pub fn getrandom_inner(dest: &mut [u8]) -> Result<(), Error> {
    // Prevent overflow of u32
    for chunk in dest.chunks_mut(u32::max_value() as usize) {
        let ret = unsafe {
            BCryptGenRandom(
                ptr::null_mut(),
                chunk.as_mut_ptr(),
                chunk.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        // NTSTATUS codes use the two highest bits for severity status.
        if ret >> 30 == 0b11 {
            // We zeroize the highest bit, so the error code will reside
            // inside the range designated for OS codes.
            let code = ret ^ (1 << 31);
            // SAFETY: the second highest bit is always equal to one,
            // so it's impossible to get zero. Unfortunately the type
            // system does not have a way to express this yet.
            let code = unsafe { NonZeroU32::new_unchecked(code) };
            return Err(Error::from(code));
        }
    }
    Ok(())
}

#[cfg(not(target_pointer_width = "64"))]
pub fn getrandom_inner(dest: &mut [u8]) -> Result<(), Error> {
    // Prevent overflow of u32
    for chunk in dest.chunks_mut(u32::max_value() as usize) {
        let ret = unsafe { RtlGenRandom(chunk.as_mut_ptr(), chunk.len() as u32) };
        if ret == 0 {
            return Err(Error::WINDOWS_RTL_GEN_RANDOM);
        }
    }
    Ok(())
}
