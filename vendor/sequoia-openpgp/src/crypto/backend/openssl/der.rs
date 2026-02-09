//! Encoding and decoding support for a subset of DER.

use crate::{Error, Result};

pub fn parse_sig_r_s(signature: &[u8]) -> Result<(&[u8], &[u8])> {
    let mut ints = parse_sequence_of_unsigned(&signature)?;
    let r = ints.next().ok_or_else(not_set)??;
    let s = ints.next().ok_or_else(not_set)??;
    if ints.next().is_some() {
        return Err(unexpected_data());
    }
    Ok((r, s))
}

fn decode_length(der: &[u8]) -> Result<(usize, usize)> {
    let len = *der.get(0).ok_or_else(unexpected_data)? as usize;
    if len < 128 {
        return Ok((1, len));
    }

    let octets = len ^ 0x80;
    if octets > 4 {
        return Err(unexpected_data());
    }
    let len_len = 1 + octets;
    if der.len() < len_len {
        return Err(unexpected_data());
    }

    let mut value_len = 0;
    for b in &der[1..len_len] {
        value_len <<= 8;
        value_len |= *b as usize;
    }

    Ok((len_len, value_len))
}

fn parse_sequence_of_unsigned<'der>(
    der: &'der [u8]
)
    -> Result<impl Iterator<Item=Result<&'der [u8]>> + 'der>
{
    if false {
        let mut hd = crate::fmt::hex::Dumper::new(std::io::stderr(), "");
        hd.write(&der, "SEQUENCE")?;
    }

    let typ = *der.get(0).ok_or_else(unexpected_data)?;
    let der = &der[1..];
    if typ != TAG_SEQUENCE {
        return Err(unexpected_data());
    }

    let (len_len, value_len) = decode_length(der)?;
    let mut der = &der[len_len..];
    if der.len() != value_len {
        return Err(unexpected_data());
    }

    Ok(std::iter::from_fn(move || -> Option<Result<&'der [u8]>> {
        if der.is_empty() {
            return None;
        }

        let for_debugging = der;

        let typ = if let Some(t) = der.get(0) {
            *t
        } else {
            return Some(Err(unexpected_data()));
        };
        der = &der[1..];
        if typ != TAG_INTEGER {
            return Some(Err(unexpected_data()));
        }

        let len = if let Ok((len_len, value_len)) = decode_length(der) {
            der = &der[len_len..];
            value_len
        } else {
            return Some(Err(unexpected_data()));
        };
        if der.len() < len {
            return Some(Err(unexpected_data()));
        }

        let mut v = &der[..len];
        der = &der[len..];

        // Skip the zero octet, if any.
        if v.get(0) == Some(&0) {
            v = &v[1..];
        }

        if false {
            let mut hd = crate::fmt::hex::Dumper::new(std::io::stderr(), "  ");
            let l = for_debugging.len() - der.len();
            hd.write(&for_debugging[..l], "INTEGER").unwrap();
        }

        Some(Ok(v))
    }))
}

pub fn encode_sig_r_s(w: &mut Vec<u8>, r: &[u8], s: &[u8]) -> Result<()> {
    let body_len = encoded_len_unsigned(r) + encoded_len_unsigned(s);

    w.reserve(1 + encoded_len_len(body_len) + body_len);

    w.push(TAG_SEQUENCE);
    encode_len(w, body_len)?;
    encode_unsigned(w, r)?;
    encode_unsigned(w, s)?;
    Ok(())
}

fn encode_len(w: &mut Vec<u8>, mut len: usize) -> Result<()> {
    if len < 128 {
        w.push(len as u8);
    } else {
        let mut bytes = Vec::new();
        while len > 0 {
            bytes.push((len & 0xff) as u8);
            len >>= 8;
        }
        bytes.reverse();
        w.push(0x80 | bytes.len() as u8);
        w.extend_from_slice(&bytes);
    }

    Ok(())
}

fn encode_unsigned(w: &mut Vec<u8>, v: &[u8]) -> Result<()> {
    w.push(TAG_INTEGER);

    if leftmost_bit_set(v) {
        // Add a zero octet to prevent the leftmost bit from being
        // interpreted as sign bit.
        encode_len(w, 1 + v.len())?;
        w.push(0); // Sign bit.
    } else {
        encode_len(w, v.len())?;
    }

    w.extend_from_slice(v);
    Ok(())
}

fn encoded_len_len(len: usize) -> usize {
    if len < 128 {
        1
    } else {
        1 + ((usize::BITS - len.leading_zeros() + 7) / 8) as usize
    }
}

fn encoded_len_unsigned(v: &[u8]) -> usize {
    let payload_len =
        if leftmost_bit_set(v) { 1 } else { 0 } + v.len();
    1 + encoded_len_len(payload_len) + payload_len
}

fn leftmost_bit_set(v: &[u8]) -> bool {
    v.get(0).map(|l| l & 0x80 == 0x80).unwrap_or(false)
}

/// Signals that OpenSSL failed to return some property.
fn not_set() -> anyhow::Error {
    Error::InvalidOperation("a required value was not set".into())
        .into()
}

/// Signals that OpenSSL failed to return the expected data.
fn unexpected_data() -> anyhow::Error {
    Error::InvalidOperation("data returned has an unexpected shape".into())
        .into()
}

const TAG_INTEGER: u8 = 0x02;
const TAG_SEQUENCE: u8 = 0x30;

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn signature_roundtrip(r: Vec<u8>, s: Vec<u8>) -> bool {
            // Strip leading zeros.
            let mut r = &r[..];
            while r.get(0) == Some(&0) {
                r = &r[1..];
            }
            let mut s = &s[..];
            while s.get(0) == Some(&0) {
                s = &s[1..];
            }

            let mut buf = Vec::new();
            encode_sig_r_s(&mut buf, r, s).unwrap();
            let (r_, s_) = parse_sig_r_s(&buf).unwrap();
            assert_eq!(r, r_);
            assert_eq!(s, s_);
            true
        }
    }
}
