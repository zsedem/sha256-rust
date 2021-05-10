//Copyright 2017 Adam Oliver Zsigmond
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of 
// this software and associated documentation files (the "Software"), to deal in 
// the Software without restriction, including without limitation the rights to 
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is furnished to do
// so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

use std::env;
use std::path::Path;
use std::fs::File;
use std::io::Read;
use std::io::Error;
use std::process::exit;

fn main() {
    let mut iterator = env::args();
    iterator.next();
    loop {
        let may_next_file = iterator.next();
        match may_next_file {
            Some(file_name) => {
                let file_result: Result<File, Error> = File::open(Path::new(&file_name));
                match file_result {
                    Ok(x) => {
                        let z = calc_sha_sum(&x);
                        println!("{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}  {}",
                                 z.hash[0].to_le(),
                                 z.hash[1].to_le(),
                                 z.hash[2].to_le(),
                                 z.hash[3].to_le(),
                                 z.hash[4].to_le(),
                                 z.hash[5].to_le(),
                                 z.hash[6].to_le(),
                                 z.hash[7].to_le(),
                                 file_name);
                    }
                    Err(e) => {
                        use std::error::Error;
                        println!("Error occured {}", e.description());
                        exit(1)
                    }
                }
            }
            None => {
                exit(0);
            }
        };
    }
}

fn calc_sha_sum(mut x: impl Read) -> Sha256State {
    let mut shasum = Sha256State { word_count: 0, m: [0; 64], hash: SHA256_INITIAL_CONST, bit_length: 0 };
    let mut buffer: [u8; CHUNK_SIZE] = [0; CHUNK_SIZE];

    loop {
        let result = x.read(buffer.as_mut());
        match result {
            Ok(datalen) => {
                if datalen < buffer.len() {
                    let bit_length = shasum.bit_length + (datalen * 8) as u64;
                    let mut i = datalen;

                    // Pad whatever data is left in the buffer.
                    if datalen < 56 {
                        println!("{}<56", datalen);
                        buffer[i] = 0x80;
                        i += 1;
                        while i < 56 {
                            buffer[i] = 0x00;
                            i += 1;
                        }
                    } else {
                        println!("{}>=56", datalen);
                        buffer[i] = 0x80;
                        i += 1;
                        while i < 64 {
                            buffer[i] = 0x00;
                            i += 1;
                        }
                        iterate_algorithm(&mut shasum, &buffer);
                        i = 0;
                        while i < 56 {
                            buffer[i] = 0x00;
                            i += 1;
                        }
                    }

                    buffer[63] = bit_length as u8;
                    buffer[62] = (bit_length >> 8 ) as u8;
                    buffer[61] = (bit_length >> 16) as u8;
                    buffer[60] = (bit_length >> 24) as u8;
                    buffer[59] = (bit_length >> 32) as u8;
                    buffer[58] = (bit_length >> 40) as u8;
                    buffer[57] = (bit_length >> 48) as u8;
                    buffer[56] = (bit_length >> 56) as u8;
                    iterate_algorithm(&mut shasum, &buffer);
                    return shasum;
                } else {
                    iterate_algorithm(&mut shasum, &buffer);
                }
            }
            Err(_) => {
                return shasum;
            }
        }
    }
}

struct Sha256State {
    word_count: u64,
    m: [u32; 64],
    hash: [u32; 8],
    bit_length: u64,
}


fn iterate_algorithm(shasum: &mut Sha256State, next_chunk: &[u8; CHUNK_SIZE]) -> () {
    let mut i = 0;
    let mut j: usize;
    //println!("[{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?},{:?}]", next_chunk[0], next_chunk[1], next_chunk[2], next_chunk[3], next_chunk[4], next_chunk[5], next_chunk[6], next_chunk[7], next_chunk[8], next_chunk[9], next_chunk[10], next_chunk[11], next_chunk[12], next_chunk[13], next_chunk[14], next_chunk[15], next_chunk[16], next_chunk[17], next_chunk[18], next_chunk[19], next_chunk[20], next_chunk[21], next_chunk[22], next_chunk[23], next_chunk[24], next_chunk[25], next_chunk[26], next_chunk[27], next_chunk[28], next_chunk[29], next_chunk[30], next_chunk[31], next_chunk[32], next_chunk[33], next_chunk[34], next_chunk[35], next_chunk[36], next_chunk[37], next_chunk[38], next_chunk[39], next_chunk[40], next_chunk[41], next_chunk[42], next_chunk[43], next_chunk[44], next_chunk[45], next_chunk[46], next_chunk[47], next_chunk[48], next_chunk[49], next_chunk[50], next_chunk[51], next_chunk[52], next_chunk[53], next_chunk[54], next_chunk[55], next_chunk[56], next_chunk[57], next_chunk[58], next_chunk[59], next_chunk[60], next_chunk[61], next_chunk[62], next_chunk[63]);
    while i < 16 {
        j = i * 4;
        shasum.m[i] = ((next_chunk[j] as u32) << 24) | ((next_chunk[j + 1] as u32) << 16) | ((next_chunk[j + 2] as u32) << 8) | (next_chunk[j + 3] as u32);
        i += 1;
    }
    while i < 64 {
        shasum.m[i] = sig1(shasum.m[i - 2]).wrapping_add(shasum.m[i - 7]).wrapping_add(sig0(shasum.m[i - 15])).wrapping_add(shasum.m[i - 16]);
        i += 1;
    }
    let mut t1: u32;
    let mut t2: u32;
    let mut a: u32 = shasum.hash[0];
    let mut b: u32 = shasum.hash[1];
    let mut c: u32 = shasum.hash[2];
    let mut d: u32 = shasum.hash[3];
    let mut e: u32 = shasum.hash[4];
    let mut f: u32 = shasum.hash[5];
    let mut g: u32 = shasum.hash[6];
    let mut h: u32 = shasum.hash[7];

    shasum.word_count += (CHUNK_SIZE / 4) as u64;
    shasum.bit_length += 512;
    i = 0;
    while i < 64 {
        t1 = h.wrapping_add(ep1(e)).wrapping_add(ch(e, f, g)).wrapping_add(SHA256_K_CONST[i]).wrapping_add(shasum.m[i]);
        t2 = epo(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
        i += 1;
    }
    shasum.hash[0] = shasum.hash[0].wrapping_add(a);
    shasum.hash[1] = shasum.hash[1].wrapping_add(b);
    shasum.hash[2] = shasum.hash[2].wrapping_add(c);
    shasum.hash[3] = shasum.hash[3].wrapping_add(d);
    shasum.hash[4] = shasum.hash[4].wrapping_add(e);
    shasum.hash[5] = shasum.hash[5].wrapping_add(f);
    shasum.hash[6] = shasum.hash[6].wrapping_add(g);
    shasum.hash[7] = shasum.hash[7].wrapping_add(h);
}

#[inline]
fn rot_right(a: u32, b: usize) -> u32 {
    (((a) >> (b)) | ((a) << (32 - (b))))
}

#[inline]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (((x) & (y)) ^ (!(x) & (z)))
}

#[inline]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
}

#[inline]
fn epo(x: u32) -> u32 {
    (rot_right(x, 2) ^ rot_right(x, 13) ^ rot_right(x, 22))
}

#[inline]
fn ep1(x: u32) -> u32 {
    (rot_right(x, 6) ^ rot_right(x, 11) ^ rot_right(x, 25))
}

#[inline]
fn sig0(x: u32) -> u32 {
    (rot_right(x, 7) ^ rot_right(x, 18) ^ (x >> 3))
}

#[inline]
fn sig1(x: u32) -> u32 {
    (rot_right(x, 17) ^ rot_right(x, 19) ^ (x >> 10))
}

const CHUNK_SIZE: usize = 64;
const SHA256_INITIAL_CONST: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

const SHA256_K_CONST: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
