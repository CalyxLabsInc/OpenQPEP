// OpenQPEP Official Release 1.2.7 (v1.2.7)
//! Bit-exact 7-layer NTT_3329 over Z_3329[X]/(X^256 + 1) matching OpenQPEP KATs.
pub const QLX_Q: i32 = 3329;
pub const INV_128_3329: i32 = 3303;

fn bitrev7(mut x: usize) -> usize {
    let mut r = 0usize;
    for _ in 0..7 { r = (r << 1) | (x & 1); x >>= 1; }
    r
}

fn mod_pow(mut base: i32, mut exp: usize) -> i32 {
    let mut res = 1i32;
    base %= QLX_Q;
    while exp > 0 {
        if (exp & 1) == 1 { res = (res * base) % QLX_Q; }
        base = (base * base) % QLX_Q;
        exp >>= 1;
    }
    res
}

#[inline]
pub fn ct_barrett_3329(x: i64) -> i32 {
    let t = (x * 20642678i64) >> 36;
    let mut r = (x - t * (QLX_Q as i64)) as i32;
    r += (r >> 31) & QLX_Q;
    let d = r - QLX_Q;
    d + ((d >> 31) & QLX_Q)
}

pub fn ntt_3329(p: &mut [i32; 256]) {
    let mut zetas = [0i32; 128];
    for i in 0..128 { zetas[i] = mod_pow(17, bitrev7(i)); }
    let mut k = 1usize;
    let mut length = 128usize;
    while length >= 2 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = zetas[k];
            k += 1;
            for j in start..(start + length) {
                let t = ct_barrett_3329((zeta as i64) * (p[j + length] as i64));
                let diff = p[j] - t;
                let v = diff + ((diff >> 31) & QLX_Q);
                let sum_m = (p[j] + t) - QLX_Q;
                let w = sum_m + ((sum_m >> 31) & QLX_Q);
                p[j + length] = v;
                p[j] = w;
            }
            start += 2 * length;
        }
        length >>= 1;
    }
}
