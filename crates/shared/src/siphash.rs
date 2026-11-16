// SPDX-License-Identifier: CC0-1.0
//! `siphash24.c`: SipHash-2-4.

fn rotl(x: u64, b: u32) -> u64 {
    x.rotate_left(b)
}

fn sipround(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = rotl(v[1], 13);
    v[1] ^= v[0];
    v[0] = rotl(v[0], 32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = rotl(v[3], 16);
    v[3] ^= v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = rotl(v[3], 21);
    v[3] ^= v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = rotl(v[1], 17);
    v[1] ^= v[2];
    v[2] = rotl(v[2], 32);
}

/// `siphash24(in, inlen, k)`.
pub fn siphash24(data: &[u8], k: &[u8; 16]) -> u64 {
    let k0 = u64::from_le_bytes(k[0..8].try_into().expect("8 bytes"));
    let k1 = u64::from_le_bytes(k[8..16].try_into().expect("8 bytes"));
    let mut v = [
        0x736f6d6570736575u64 ^ k0,
        0x646f72616e646f6du64 ^ k1,
        0x6c7967656e657261u64 ^ k0,
        0x7465646279746573u64 ^ k1,
    ];
    let (chunks, rest) = data.as_chunks::<8>();
    for c in chunks {
        let m = u64::from_le_bytes(*c);
        v[3] ^= m;
        sipround(&mut v);
        sipround(&mut v);
        v[0] ^= m;
    }
    let mut b: u64 = (data.len() as u64) << 56;
    for (i, &c) in rest.iter().enumerate() {
        b |= (c as u64) << (8 * i);
    }
    v[3] ^= b;
    sipround(&mut v);
    sipround(&mut v);
    v[0] ^= b;
    v[2] ^= 0xff;
    for _ in 0..4 {
        sipround(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}
