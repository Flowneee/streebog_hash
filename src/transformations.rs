#![allow(mutable_transmutes)]

use std::slice;

use const_data;
use precomp_data;

/*pub fn xor512(l: [u8; 64], r: [u8; 64]) -> [u8; 64] {
    let mut result = [0 as u8; 64];
    let ptr_result: &mut [u64; 8] = unsafe { mem::transmute(&result) };
    let ptr_l: &[u64; 8] = unsafe { mem::transmute(&l) };
    let ptr_r: &[u64; 8] = unsafe { mem::transmute(&r) };
    for i in 0..8 {
        ptr_result[i] = ptr_l[i] ^ ptr_r[i];
    }
    result
}*/

pub fn xor512(l: [u8; 64], r: [u8; 64]) -> [u8; 64] {
    let mut result = [0 as u8; 64];
    for i in 0..64 {
        result[i] = l[i] ^ r[i];
    }
    result
}

pub fn add_modulo512(l: [u8; 64], r: [u8; 64]) -> [u8; 64] {
    let mut result = [0 as u8; 64];
    let mut t = 0;
    for i in 0..64 {
        t = l[i] as i32 + r[i] as i32 + (t >> 8);
        result[i] = t as u8;
    }
    result
}

pub fn S(a: [u8; 64]) -> [u8; 64] {
    let mut result = [0 as u8; 64];
    for i in 0..64 {
        result[i] = const_data::pi[a[i] as usize];
    }
    result
}

pub fn P(a: [u8; 64]) -> [u8; 64] {
    let mut result = [0 as u8; 64];
    for i in 0..64 {
        result[i] = a[const_data::tau[i] as usize];
    }
    result
}

/*pub fn L(a: [u8; 64]) -> [u8; 64] {
    let ptr = &a[0] as *const u8 as *mut u64;
    let mut a_u64 = unsafe { slice::from_raw_parts_mut::<u64>(ptr, 8) };
    let i_constants: [usize; 8] = [7, 15, 23, 31, 39, 47, 55, 63];
    for (i, a_element) in (0..8).zip(a_u64.iter_mut()) {
        let mut temp = 0 as u64;
        for j in 0..8 {
            for k in 0..8 {
                if (a[i_constants[i] - j] & (0x1 << (7 - k))) != 0 {
                    temp ^= const_data::A[j * 8 + k]
                }
            }
        }
        *a_element = temp;
    }
    a
}*/
pub fn L(a: [u8; 64]) -> [u8; 64] {
    let ptr = &a[0] as *const u8 as *mut u64;
    let mut a_u64 = unsafe { slice::from_raw_parts_mut::<u64>(ptr, 8) };
    let i_constants: [usize; 8] = [7, 15, 23, 31, 39, 47, 55, 63];
    for (i, a_element) in (0..8).zip(a_u64.iter_mut()) {
        let mut temp = 0 as u64;
        for j in 0..8 {
            temp ^= precomp_data::A_precomp[j][a[i_constants[i] - j] as usize];
        }
        *a_element = temp;
    }
    a
}

// TODO: reverse C constants in cosnt_data.rs and change _xor512 to xor512
pub fn key_schedule(k: [u8; 64], i: usize) -> [u8; 64] {
    // Temporary workaround, cuz in C all arrays reversed
    fn _xor512(l: [u8; 64], r: [u8; 64]) -> [u8; 64] {
        let mut result = [0 as u8; 64];
        for i in 0..64 {
            result[i] = l[i] ^ r[63 - i];
        }
        result
    }
    L(P(S(_xor512(k, const_data::C[i]))))
}

pub fn E(k_init: [u8; 64], m: [u8; 64]) -> [u8; 64] {
    let mut k = k_init;
    let mut temp = xor512(k, m);
    for i in 0..12 {
        temp = L(P(S(temp)));
        k = key_schedule(k, i);
        temp = xor512(temp, k);
    }
    temp
}

// Compression function
pub fn g_N(N: [u8; 64], h: [u8; 64], m: [u8; 64]) -> [u8; 64] {
    xor512(xor512(E(L(P(S(xor512(h, N)))), m), h), m)
}

#[cfg(test)]
mod tests {
    use super::*;

    static m: [u8; 64] = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31,
                          0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
                          0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
                          0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                          0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
                          0x30, 0x31, 0x32, 0x01];
    static h: [u8; 64] = [0 as u8; 64];
    static N: [u8; 64] = [0 as u8; 64];

    #[test]
    fn test_xor512() {
        let l = [1 as u8; 64];
        let r = [2 as u8; 64];
        let should_be = [3 as u8; 64];
        assert_eq!(&xor512(l, r)[..], &should_be[..]);
    }

    #[test]
    fn test_S_xor512_initial_256() {
        let l = [0x0 as u8; 64];
        let r = [0x1 as u8; 64];
        let should_be = [0xee as u8; 64];
        assert_eq!(&S(xor512(l, r))[..], &should_be[..]);
    }

    #[test]
    fn test_S() {
        let should_be = [0xfc as u8; 64];
        assert_eq!(&S(xor512(h, N))[..], &should_be[..]);
    }

    #[test]
    fn test_P() {
        let should_be = [0xfc as u8; 64];
        assert_eq!(&P(S(xor512(h, N)))[..], &should_be[..]);
    }

    #[test]
    fn test_L() {
        let should_be = [0x74, 0xa5, 0xd4, 0xce, 0x2e, 0xfc, 0x83, 0xb3, 0x74, 0xa5, 0xd4, 0xce,
                         0x2e, 0xfc, 0x83, 0xb3, 0x74, 0xa5, 0xd4, 0xce, 0x2e, 0xfc, 0x83, 0xb3,
                         0x74, 0xa5, 0xd4, 0xce, 0x2e, 0xfc, 0x83, 0xb3, 0x74, 0xa5, 0xd4, 0xce,
                         0x2e, 0xfc, 0x83, 0xb3, 0x74, 0xa5, 0xd4, 0xce, 0x2e, 0xfc, 0x83, 0xb3,
                         0x74, 0xa5, 0xd4, 0xce, 0x2e, 0xfc, 0x83, 0xb3, 0x74, 0xa5, 0xd4, 0xce,
                         0x2e, 0xfc, 0x83, 0xb3];
        let result = L(P(S(xor512(h, N))));
        assert_eq!(&result[..], &should_be[..]);
    }

    #[test]
    fn test_L_2() {
        let a = [0xea, 0xfd, 0x2c, 0xeb, 0x48, 0xea, 0xfd, 0x2c, 0x7a, 0x4e, 0xec, 0xe0, 0xb0,
                 0x7a, 0x4e, 0xec, 0x09, 0x2d, 0xbe, 0x67, 0x20, 0x09, 0x2d, 0xbe, 0x4b, 0xb6,
                 0xc0, 0x66, 0xc2, 0x4b, 0xb6, 0xc0, 0xf1, 0x14, 0x5f, 0x99, 0x17, 0xf1, 0x14,
                 0x5f, 0x37, 0x89, 0xd9, 0xac, 0xe4, 0x37, 0x89, 0xd9, 0x5e, 0x2f, 0x45, 0x92,
                 0x7d, 0x5e, 0x2f, 0x45, 0x3e, 0x43, 0xdf, 0x24, 0xd6, 0x3e, 0x43, 0x46];
        let should_be = [0xb9, 0x1b, 0x12, 0x28, 0x50, 0xf6, 0xcd, 0x90, 0xf6, 0x2c, 0xad, 0x0d,
                         0xb2, 0x5f, 0x46, 0xbe, 0x35, 0x1e, 0xc0, 0x71, 0x4b, 0xfc, 0x43, 0xfc,
                         0xd4, 0x2f, 0x5c, 0x47, 0xdf, 0xa8, 0x78, 0xce, 0xa0, 0x12, 0xe2, 0xc0,
                         0xeb, 0x53, 0x79, 0x1e, 0xc2, 0xe4, 0x2a, 0x60, 0x89, 0x91, 0x57, 0x56,
                         0x3f, 0x65, 0x83, 0x31, 0x6f, 0x3f, 0xc7, 0x24, 0x80, 0x75, 0xe0, 0xd8,
                         0xd4, 0x59, 0x00, 0xe6];
        assert_eq!(&L(a)[..], &should_be[..]);
    }

    #[test]
    fn test_key_schedule() {
        let should_be = [0x1e, 0xcf, 0x46, 0x0c, 0xf7, 0x8a, 0xd1, 0xf4, 0x33, 0xec, 0x7e, 0x1d,
                         0xbd, 0x28, 0xf7, 0x36, 0x10, 0x30, 0x51, 0xa0, 0x2b, 0xcd, 0x69, 0x35,
                         0x97, 0x27, 0xda, 0xb2, 0xf0, 0x14, 0xbe, 0x88, 0xc1, 0xe9, 0xda, 0x07,
                         0x08, 0x01, 0x3d, 0xa7, 0xe9, 0x2e, 0xef, 0x3a, 0xd2, 0x02, 0xe9, 0xe0,
                         0x0d, 0xe8, 0x74, 0xc7, 0xeb, 0xc3, 0xf2, 0x13, 0x8f, 0xd7, 0x2f, 0x64,
                         0x07, 0x08, 0xb0, 0xd0];
        // K1 in GOST
        let K1 = L(P(S(xor512(h, N))));
        assert_eq!(&key_schedule(K1, 0)[..], &should_be[..]);
    }

    #[test]
    fn test_E() {
        // K1 in GOST
        let K1 = L(P(S(xor512(h, N))));
        let should_be = [0xd2, 0xeb, 0x09, 0x58, 0x47, 0xd1, 0xc8, 0x32, 0xe1, 0xcc, 0x81, 0x0e,
                         0x4b, 0x06, 0x75, 0xa0, 0x6a, 0xb6, 0x68, 0x15, 0x62, 0x3e, 0xdf, 0xe0,
                         0xf1, 0x8f, 0x8d, 0xbb, 0xa8, 0xcf, 0x64, 0x16, 0x8f, 0xbd, 0x47, 0x06,
                         0xed, 0xbd, 0x70, 0x1f, 0x96, 0x98, 0x68, 0x77, 0x75, 0x53, 0x9e, 0x20,
                         0x00, 0x76, 0x09, 0x10, 0x9d, 0x07, 0xde, 0xa4, 0x27, 0xfc, 0x14, 0xb8,
                         0xc8, 0x1d, 0x22, 0xfc];
        assert_eq!(&E(K1, m)[..], &should_be[..])
    }

    #[test]
    fn test_g_N() {
        let should_be = [0xe2, 0xda, 0x3b, 0x6b, 0x73, 0xe4, 0xfe, 0x05, 0xd9, 0xf5, 0xb1, 0x3f,
                         0x79, 0x35, 0x41, 0x95, 0x5c, 0x81, 0x50, 0x2c, 0x52, 0x0f, 0xed, 0xd3,
                         0xc5, 0xba, 0xbb, 0x8c, 0x90, 0xf6, 0x54, 0x27, 0xbd, 0x8e, 0x73, 0x33,
                         0xdb, 0x8a, 0x48, 0x26, 0xa6, 0xa9, 0x5a, 0x44, 0x41, 0x66, 0xa8, 0x17,
                         0x38, 0x4f, 0x39, 0x21, 0xaf, 0x34, 0xea, 0x91, 0x11, 0xcb, 0x2c, 0x81,
                         0xf8, 0x2c, 0x10, 0xfd];
        assert_eq!(&g_N(N, h, m)[..], &should_be[..]);
    }
}
