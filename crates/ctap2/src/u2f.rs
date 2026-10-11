//! Minimal CTAP1/U2F over CTAPHID_MSG so browsers that probe VERSION work.
//!
//! Only U2F_VERSION is implemented. REGISTER and AUTHENTICATE return
//! SW_INS_NOT_SUPPORTED (0x6d00). Full U2F is not required for CTAP2 RPs.

use alloc::vec;
use alloc::vec::Vec;

const INS_REGISTER: u8 = 0x01;
const INS_AUTHENTICATE: u8 = 0x02;
const INS_VERSION: u8 = 0x03;
const SW_NO_ERROR: u16 = 0x9000;
const SW_INS_NOT_SUPPORTED: u16 = 0x6d00;
const SW_WRONG_LENGTH: u16 = 0x6700;

fn sw(code: u16) -> Vec<u8> {
    vec![(code >> 8) as u8, code as u8]
}

/// Process a raw U2F APDU (CLA INS P1 P2 ...). Returns response body + SW.
pub fn process(apdu: &[u8]) -> Vec<u8> {
    if apdu.len() < 4 {
        return sw(SW_WRONG_LENGTH);
    }
    let ins = apdu[1];
    match ins {
        INS_VERSION => {
            let mut out = b"U2F_V2".to_vec();
            out.extend(sw(SW_NO_ERROR));
            out
        }
        INS_REGISTER | INS_AUTHENTICATE => sw(SW_INS_NOT_SUPPORTED),
        _ => sw(SW_INS_NOT_SUPPORTED),
    }
}
