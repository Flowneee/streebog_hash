//! This is documentation for the `streebog_hash` crate.
//!
//! The `streebog_hash` crate contains implementation of cryptographic hash
//! functions defined in the Russian national standard GOST R 34.11-2012
//! _Information Technology - Cryptographic Information Security -
//! Hash Function_ aka _Streebog_ with digest sizes 256 and 512 bit
//! (https://www.tc26.ru/en/standard/gost/GOST_R_34_11-2012_eng.pdf).

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

mod const_data;
mod precomp_data;
mod transformations;

use transformations::*;
use std::cmp::{Eq, PartialEq};

enum StreebogHasherDigest {
    StreebogHasher256,
    StreebogHasher512,
}

struct StreebogHasherCtx {
    hash: [u8; 64],
    N: [u8; 64],
    sigma: [u8; 64],
    data: Vec<u8>,
}

/// A trait which represents the ability to hash an arbitrary stream of bytes with Streebog
/// algorithm.
pub trait StreebogHasher {
    /// Creates new hasher object.
    fn new() -> Self;
    /// Writes some data into this hasher.
    fn update(&mut self, data_chunk: &[u8]);
    /// Completes a round of hashing.
    fn finish(&mut self);
    /// Returns result of hashing as Box<[u8]> (result is big-endian, i.e. bytes arranged in the
    /// same order as in String representation).
    ///
    /// If hasher is not finished (i.e. finish is not called), it returns empty array.
    fn get_result(&self) -> Box<[u8]>;
    /// Returns result of hashing as String.
    ///
    /// If hasher is not finished (i.e. finish is not called), it returns empty String.
    fn get_result_str(&self) -> String;
    /// Reset hasher to default state and mark as not finished.
    ///
    /// **Note!** After calling this all processed data will be lost!
    fn reset(&mut self);
}

/// An implementation of Streebog algorithm with digest size 512 bit.
///
/// # Examples
///
/// ```
/// use streebog_hash::*;
/// let mut hasher = StreebogHasher512::new();
/// let data = [0xfc as u8; 128];
/// hasher.update(&data[0..64]);
/// hasher.update(&data[64..128]);
/// hasher.finish();
/// let result = hasher.get_result();
/// println!("{}", hasher.get_result_str());
/// ```
pub struct StreebogHasher512 {
    ctx: StreebogHasherCtx,
    is_finished: bool,
    result: [u8; 64],
}

impl StreebogHasher for StreebogHasher512 {
    fn new() -> StreebogHasher512 {
        StreebogHasher512 {
            ctx: StreebogHasherCtx {
                hash: [0 as u8; 64],
                N: [0 as u8; 64],
                sigma: [0 as u8; 64],
                data: Vec::new(),
            },
            is_finished: false,
            result: [0 as u8; 64],
        }
    }

    fn update(&mut self, data_chunk: &[u8]) {
        if !self.is_finished {
            streebog_update(&mut self.ctx, data_chunk);
        }
    }

    fn finish(&mut self) {
        if !self.is_finished {
            for i in self.result
                    .iter_mut()
                    .zip(streebog_finish(&mut self.ctx,
                                         StreebogHasherDigest::StreebogHasher512)
                                 .iter()
                                 .rev()) {
                *i.0 = *i.1;
            }
            self.is_finished = true;
        };
    }

    fn get_result(&self) -> Box<[u8]> {
        if self.is_finished {
            Box::new(self.result)
        } else {
            Box::new([])
        }
    }

    fn get_result_str(&self) -> String {
        if self.is_finished {
            let mut result_string = String::from("0x");
            for i in self.result.iter() {
                result_string.push_str(&format!("{:02x}", *i));
            }
            result_string
        } else {
            String::from("")
        }
    }

    fn reset(&mut self) {
        self.is_finished = false;
        self.ctx.hash = [0 as u8; 64];
        self.ctx.N = [0 as u8; 64];
        self.ctx.sigma = [0 as u8; 64];
        self.ctx.data.clear();
        self.result = [0 as u8; 64];
    }
}


/// An implementation of Streebog algorithm with digest size 256 bit.
///
/// # Examples
///
/// ```
/// use streebog_hash::*;
/// let mut hasher = StreebogHasher256::new();
/// let data = [0xfc as u8; 128];
/// hasher.update(&data[0..64]);
/// hasher.update(&data[64..128]);
/// hasher.finish();
/// let result = hasher.get_result();
/// println!("{}", hasher.get_result_str());
/// ```
pub struct StreebogHasher256 {
    ctx: StreebogHasherCtx,
    is_finished: bool,
    result: [u8; 32],
}

impl StreebogHasher for StreebogHasher256 {
    fn new() -> StreebogHasher256 {
        StreebogHasher256 {
            ctx: StreebogHasherCtx {
                hash: [1 as u8; 64],
                N: [0 as u8; 64],
                sigma: [0 as u8; 64],
                data: Vec::new(),
            },
            is_finished: false,
            result: [0 as u8; 32],
        }
    }

    fn update(&mut self, data_chunk: &[u8]) {
        if !self.is_finished {
            streebog_update(&mut self.ctx, data_chunk);
        }
    }

    fn finish(&mut self) {
        if !self.is_finished {
            for i in self.result
                    .iter_mut()
                    .zip(streebog_finish(&mut self.ctx,
                                         StreebogHasherDigest::StreebogHasher256)
                                 .iter()
                                 .rev()) {
                *i.0 = *i.1;
            }
            self.is_finished = true;
        };
    }

    fn get_result(&self) -> Box<[u8]> {
        if self.is_finished {
            Box::new(self.result)
        } else {
            Box::new([])
        }
    }

    fn get_result_str(&self) -> String {
        if self.is_finished {
            let mut result_string = String::from("0x");
            for i in self.result.iter() {
                result_string.push_str(&format!("{:02x}", *i));
            }
            result_string
        } else {
            String::from("")
        }
    }

    fn reset(&mut self) {
        self.is_finished = false;
        self.ctx.hash = [0 as u8; 64];
        self.ctx.N = [0 as u8; 64];
        self.ctx.sigma = [0 as u8; 64];
        self.ctx.data.clear();
        self.result = [0 as u8; 32];
    }
}

impl PartialEq for StreebogHasherCtx {
    fn eq(&self, other: &StreebogHasherCtx) -> bool {
        fn cmp_arrays(l: [u8; 64], r: [u8; 64]) -> bool {
            for i in l.iter().zip(r.iter()) {
                if *i.0 != *i.1 {
                    return false;
                }
            }
            return true;
        }
        //cmp_arrays(self.iv, other.iv) &&
        cmp_arrays(self.hash, other.hash) && cmp_arrays(self.N, other.N)
            && cmp_arrays(self.sigma, other.sigma) && (self.data == other.data)
    }
}
impl Eq for StreebogHasherCtx {}

// Data come in Little-endian
fn pad_data(data: Vec<u8>) -> [u8; 64] {
    let mut padded_data = [0 as u8; 64];
    let data_len = data.len();
    for i in 0..data_len {
        padded_data[i] = data[i];
    }
    padded_data[data_len] = 0x1;
    padded_data
}

fn streebog_update(ctx: &mut StreebogHasherCtx, data: &[u8]) -> usize {
    let mut bytes512 = [0 as u8; 64];
    bytes512[1] = 0x2;

    ctx.data.extend_from_slice(data);

    let mut data_len: usize;
    loop {
        // Check length of data in context
        data_len = ctx.data.len();
        if data_len < 64 {
            return data_len;
        }


        let mut data_chunk = [0 as u8; 64];
        for i in 0..64 {
            data_chunk[i] = ctx.data[i];
        }
        ctx.hash = g_N(ctx.N, ctx.hash, data_chunk);
        ctx.N = add_modulo512(ctx.N, bytes512);
        ctx.sigma = add_modulo512(ctx.sigma, data_chunk);
        ctx.data = ctx.data.split_off(64);
    }
}

fn streebog_finish(ctx: &mut StreebogHasherCtx, mode: StreebogHasherDigest) -> Vec<u8> {
    let padded_data = pad_data(ctx.data.clone());
    let data_len = ctx.data.len() as i32 * 8;
    let mut bytes_len = [0 as u8; 64];
    bytes_len[0] = data_len as u8 & 0xff;
    bytes_len[1] = (data_len >> 8) as u8;
    ctx.hash = g_N(ctx.N, ctx.hash, padded_data);
    ctx.N = add_modulo512(ctx.N, bytes_len);
    ctx.sigma = add_modulo512(ctx.sigma, padded_data);
    ctx.hash = g_N([0 as u8; 64], ctx.hash, ctx.N);
    ctx.hash = g_N([0 as u8; 64], ctx.hash, ctx.sigma);
    let result_temp = match mode {
        StreebogHasherDigest::StreebogHasher256 => &ctx.hash[32..64],
        StreebogHasherDigest::StreebogHasher512 => &ctx.hash[..],
    };
    let mut result = Vec::new();
    result.extend_from_slice(result_temp);
    // Result in Little-endian cuz of internal representation of all data
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    static data_1: &'static [u8] =
        &[0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
          0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
          0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31,
          0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
          0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32];

    static data_2: &'static [u8] =
        &[0xd1, 0xe5, 0x20, 0xe2, 0xe5, 0xf2, 0xf0, 0xe8, 0x2c, 0x20, 0xd1, 0xf2, 0xf0, 0xe8,
          0xe1, 0xee, 0xe6, 0xe8, 0x20, 0xe2, 0xed, 0xf3, 0xf6, 0xe8, 0x2c, 0x20, 0xe2, 0xe5,
          0xfe, 0xf2, 0xfa, 0x20, 0xf1, 0x20, 0xec, 0xee, 0xf0, 0xff, 0x20, 0xf1, 0xf2, 0xf0,
          0xe5, 0xeb, 0xe0, 0xec, 0xe8, 0x20, 0xed, 0xe0, 0x20, 0xf5, 0xf0, 0xe0, 0xe1, 0xf0,
          0xfb, 0xff, 0x20, 0xef, 0xeb, 0xfa, 0xea, 0xfb, 0x20, 0xc8, 0xe3, 0xee, 0xf0, 0xe5,
          0xe2, 0xfb];

    static data_2_part_1: &'static [u8] =
        &[0xd1, 0xe5, 0x20, 0xe2, 0xe5, 0xf2, 0xf0, 0xe8, 0x2c, 0x20, 0xd1, 0xf2, 0xf0, 0xe8,
          0xe1, 0xee, 0xe6, 0xe8, 0x20, 0xe2, 0xed, 0xf3, 0xf6, 0xe8, 0x2c, 0x20, 0xe2, 0xe5,
          0xfe, 0xf2, 0xfa, 0x20, 0xf1, 0x20, 0xec, 0xee, 0xf0];

    static data_2_part_2: &'static [u8] = &[0xff, 0x20, 0xf1, 0xf2, 0xf0, 0xe5, 0xeb, 0xe0, 0xec,
                                            0xe8, 0x20, 0xed, 0xe0, 0x20, 0xf5, 0xf0, 0xe0, 0xe1,
                                            0xf0, 0xfb, 0xff, 0x20, 0xef, 0xeb, 0xfa, 0xea, 0xfb,
                                            0x20, 0xc8, 0xe3, 0xee, 0xf0, 0xe5, 0xe2, 0xfb];

    #[test]
    #[should_panic]
    fn test_streebog_update_1() {
        let mut data = Vec::new();
        data.extend_from_slice(data_1);
        let should_be = [0xfd, 0x10, 0x2c, 0xf8, 0x81, 0x2c, 0xcb, 0x11, 0x91, 0xea, 0x34, 0xaf,
                         0x21, 0x39, 0x4f, 0x38, 0x17, 0xa8, 0x66, 0x41, 0x44, 0x5a, 0xa9, 0xa6,
                         0x26, 0x48, 0x8a, 0xdb, 0x33, 0x73, 0x8e, 0xbd, 0x27, 0x54, 0xf6, 0x90,
                         0x8c, 0xbb, 0xba, 0xc5, 0xd3, 0xed, 0x0f, 0x52, 0x2c, 0x50, 0x81, 0x5c,
                         0x95, 0x41, 0x35, 0x79, 0x3f, 0xb1, 0xf5, 0xd9, 0x05, 0xfe, 0xe4, 0x73,
                         0x6b, 0x3b, 0xda, 0xe2];
        let mut hasher = StreebogHasher512::new();
        hasher.update(&super::pad_data(data)[..]);
        assert_eq!(hasher.ctx.data, Vec::new());
        assert_eq!(&hasher.ctx.hash[..], &should_be[..]);
    }

    #[test]
    fn test_streebog512_final_1() {
        let mut should_be = [0x1b, 0x54, 0xd0, 0x1a, 0x4a, 0xf5, 0xb9, 0xd5, 0xcc, 0x3d, 0x86, 0xd6,
                             0x8d, 0x28, 0x54, 0x62, 0xb1, 0x9a, 0xbc, 0x24, 0x75, 0x22, 0x2f, 0x35,
                             0xc0, 0x85, 0x12, 0x2b, 0xe4, 0xba, 0x1f, 0xfa, 0x00, 0xad, 0x30, 0xf8,
                             0x76, 0x7b, 0x3a, 0x82, 0x38, 0x4c, 0x65, 0x74, 0xf0, 0x24, 0xc3, 0x11,
                             0xe2, 0xa4, 0x81, 0x33, 0x2b, 0x08, 0xef, 0x7f, 0x41, 0x79, 0x78, 0x91,
                             0xc1, 0x64, 0x6f, 0x48];
        // reverse order cuz output should be in big-endian
        should_be.reverse();
        let mut hasher = StreebogHasher512::new();
        hasher.update(data_1);
        hasher.finish();
        let result = hasher.get_result();
        assert_eq!(&result[..], &should_be[..]);
    }

    #[test]
    fn test_streebog256_final_1() {
        let mut should_be = [0x9d, 0x15, 0x1e, 0xef, 0xd8, 0x59, 0x0b, 0x89, 0xda, 0xa6, 0xba, 0x6c,
                             0xb7, 0x4a, 0xf9, 0x27, 0x5d, 0xd0, 0x51, 0x02, 0x6b, 0xb1, 0x49, 0xa4,
                             0x52, 0xfd, 0x84, 0xe5, 0xe5, 0x7b, 0x55, 0x00];
        // reverse order cuz output should be in big-endian
        should_be.reverse();
        let mut hasher = StreebogHasher256::new();
        hasher.update(data_1);
        hasher.finish();
        let result = hasher.get_result();
        assert_eq!(&result[..], &should_be[..]);
    }

    #[test]
    fn test_streebog512_final_2() {
        let mut should_be = [0x1e, 0x88, 0xe6, 0x22, 0x26, 0xbf, 0xca, 0x6f, 0x99, 0x94, 0xf1, 0xf2,
                             0xd5, 0x15, 0x69, 0xe0, 0xda, 0xf8, 0x47, 0x5a, 0x3b, 0x0f, 0xe6, 0x1a,
                             0x53, 0x00, 0xee, 0xe4, 0x6d, 0x96, 0x13, 0x76, 0x03, 0x5f, 0xe8, 0x35,
                             0x49, 0xad, 0xa2, 0xb8, 0x62, 0x0f, 0xcd, 0x7c, 0x49, 0x6c, 0xe5, 0xb3,
                             0x3f, 0x0c, 0xb9, 0xdd, 0xdc, 0x2b, 0x64, 0x60, 0x14, 0x3b, 0x03, 0xda,
                             0xba, 0xc9, 0xfb, 0x28];
        should_be.reverse();
        let mut hasher = StreebogHasher512::new();
        hasher.update(data_2);
        hasher.finish();
        let result = hasher.get_result();
        assert_eq!(&result[..], &should_be[..]);
    }

    #[test]
    fn test_streebog256_final_2() {
        let mut should_be = [0x9d, 0xd2, 0xfe, 0x4e, 0x90, 0x40, 0x9e, 0x5d, 0xa8, 0x7f, 0x53, 0x97,
                             0x6d, 0x74, 0x05, 0xb0, 0xc0, 0xca, 0xc6, 0x28, 0xfc, 0x66, 0x9a, 0x74,
                             0x1d, 0x50, 0x06, 0x3c, 0x55, 0x7e, 0x8f, 0x50];
        should_be.reverse();
        let mut hasher = StreebogHasher256::new();
        hasher.update(data_2);
        hasher.finish();
        let result = hasher.get_result();
        assert_eq!(&result[..], &should_be[..]);
    }

    #[test]
    fn test_streebog_with_multiple_parts_of_data() {
        let mut should_be = [0x1e, 0x88, 0xe6, 0x22, 0x26, 0xbf, 0xca, 0x6f, 0x99, 0x94, 0xf1, 0xf2,
                             0xd5, 0x15, 0x69, 0xe0, 0xda, 0xf8, 0x47, 0x5a, 0x3b, 0x0f, 0xe6, 0x1a,
                             0x53, 0x00, 0xee, 0xe4, 0x6d, 0x96, 0x13, 0x76, 0x03, 0x5f, 0xe8, 0x35,
                             0x49, 0xad, 0xa2, 0xb8, 0x62, 0x0f, 0xcd, 0x7c, 0x49, 0x6c, 0xe5, 0xb3,
                             0x3f, 0x0c, 0xb9, 0xdd, 0xdc, 0x2b, 0x64, 0x60, 0x14, 0x3b, 0x03, 0xda,
                             0xba, 0xc9, 0xfb, 0x28];
        should_be.reverse();
        let mut hasher = StreebogHasher512::new();
        hasher.update(data_2_part_1);
        hasher.update(data_2_part_2);
        hasher.finish();
        let result = hasher.get_result();
        assert_eq!(&result[..], &should_be[..]);
    }

    #[test]
    fn test_pad_data() {
        let mut data = Vec::new();
        data.extend_from_slice(data_1);
        let should_be: [u8; 64] =
            [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
             0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
             0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31,
             0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
             0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x01];
        assert_eq!(&super::pad_data(data)[..], &should_be[..]);
    }
}
