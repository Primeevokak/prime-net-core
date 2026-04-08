//! MTProto obfuscated-transport handshake parser and AES-256-CTR cipher.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use sha2::{Digest, Sha256};

/// MTProto obfuscated transport variant encoded in bytes 56–60 of the init packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MtProtoTransport {
    /// 0xEFEFEFEF — 1-byte length header, data in 4-byte aligned chunks.
    Abridged,
    /// 0xEEEEEEEE — 4-byte LE length header.
    Intermediate,
    /// 0xDDDDDDDD — 4-byte LE length header, top bit = padding present.
    Padded,
}

impl MtProtoTransport {
    fn from_tag(tag: [u8; 4]) -> Option<Self> {
        match u32::from_le_bytes(tag) {
            0xEFEF_EFEF => Some(Self::Abridged),
            0xEEEE_EEEE => Some(Self::Intermediate),
            0xDDDD_DDDD => Some(Self::Padded),
            _ => None,
        }
    }

    /// Return the 4-byte LE proto tag bytes for this transport variant.
    pub fn tag_bytes(self) -> [u8; 4] {
        match self {
            Self::Abridged => 0xEFEF_EFEFu32.to_le_bytes(),
            Self::Intermediate => 0xEEEE_EEEEu32.to_le_bytes(),
            Self::Padded => 0xDDDD_DDDDu32.to_le_bytes(),
        }
    }
}

/// Parsed MTProto obfuscated init packet, with derived cipher keys.
pub struct ParsedInit {
    /// Target Telegram DC (negative = media DC).
    pub dc_id: i16,
    /// Transport variant selected by the client.
    pub transport: MtProtoTransport,
    /// Key used to DECRYPT bytes coming from this side (client-to-server).
    pub cs_key: [u8; 32],
    /// IV used to DECRYPT bytes coming from this side.
    pub cs_iv: [u8; 16],
    /// Key used to ENCRYPT bytes going to this side (server-to-client).
    pub sc_key: [u8; 32],
    /// IV used to ENCRYPT bytes going to this side.
    pub sc_iv: [u8; 16],
}

/// Parse a 64-byte MTProto obfuscated init packet and derive cipher keys.
///
/// Returns `None` if bytes 56–60 do not contain a recognised proto tag.
pub fn parse_init(raw: &[u8; 64], secret: &[u8]) -> Option<ParsedInit> {
    let tag: [u8; 4] = raw[56..60].try_into().ok()?;
    let transport = MtProtoTransport::from_tag(tag)?;
    let dc_id = i16::from_le_bytes([raw[60], raw[61]]);

    let prekey = &raw[8..40]; // 32 bytes
    let iv = &raw[40..56]; // 16 bytes

    // cs = client-to-server direction: proxy decrypts data arriving from this side.
    let cs_key: [u8; 32] = sha256_pair(prekey, secret);
    let cs_iv: [u8; 16] = iv.try_into().ok()?;

    // sc = server-to-client direction: proxy encrypts data sent to this side.
    let mut rev_prekey = [0u8; 32];
    rev_prekey.copy_from_slice(prekey);
    rev_prekey.reverse();
    let sc_key: [u8; 32] = sha256_pair(&rev_prekey, secret);
    let sc_iv: [u8; 16] = {
        let mut tmp: [u8; 16] = iv.try_into().ok()?;
        tmp.reverse();
        tmp
    };

    Some(ParsedInit {
        dc_id,
        transport,
        cs_key,
        cs_iv,
        sc_key,
        sc_iv,
    })
}

fn sha256_pair(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

/// AES-256-CTR streaming cipher with big-endian counter.
///
/// MTProto uses AES-256-CTR where the counter is a big-endian 128-bit integer
/// initialised from the IV.  Both encrypt and decrypt are the same XOR operation.
pub struct AesCtr {
    cipher: Aes256,
    counter: u128,
    keystream: [u8; 16],
    /// Position within the current keystream block (0–15).
    pos: usize,
}

impl AesCtr {
    /// Create a new cipher with a 32-byte key and 16-byte IV (big-endian counter seed).
    pub fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        // GenericArray from fixed-size array is infallible; the key size is statically known.
        let key_arr = aes::cipher::generic_array::GenericArray::from(*key);
        let cipher = Aes256::new(&key_arr);
        let counter = u128::from_be_bytes(*iv);
        Self {
            cipher,
            counter,
            keystream: [0u8; 16],
            pos: 16, // force keystream generation on first use
        }
    }

    fn refill(&mut self) {
        let block_in = self.counter.to_be_bytes();
        let mut block = aes::cipher::generic_array::GenericArray::from(block_in);
        self.cipher.encrypt_block(&mut block);
        self.keystream.copy_from_slice(&block);
        self.counter = self.counter.wrapping_add(1);
        self.pos = 0;
    }

    /// Apply the keystream (XOR) to `buf` in-place.  Works for both encrypt and decrypt.
    pub fn apply(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            if self.pos >= 16 {
                self.refill();
            }
            *byte ^= self.keystream[self.pos];
            self.pos += 1;
        }
    }

    /// Apply the keystream to `data` and return a new owned `Vec<u8>`.
    pub fn process(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        self.apply(&mut out);
        out
    }
}
