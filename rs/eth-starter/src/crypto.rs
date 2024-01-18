use crate::utils::*;

use ethers_core::abi::ethereum_types::H160;
use ethers_core::utils::keccak256;
use ic_stable_structures::{storable::Bound, Storable};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use std::borrow::Cow;

#[derive(Clone, candid::CandidType, serde::Serialize, serde::Deserialize)]
#[repr(C)]
pub struct EcdsaSignature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u64,
}

impl Storable for EcdsaSignature {
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let mut bytes = bytes.into_owned();
        let v = bytes.split_off(64);
        let s = bytes.split_off(32);
        Self {
            r: bytes.try_into().unwrap(),
            s: s.try_into().unwrap(),
            v: u64::from_le_bytes(v.try_into().unwrap()),
        }
    }

    fn to_bytes(&self) -> Cow<[u8]> {
        let mut bytes = Vec::with_capacity(72);
        bytes.extend_from_slice(&self.r);
        bytes.extend_from_slice(&self.s);
        bytes.extend_from_slice(&self.v.to_le_bytes());
        bytes.into()
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 72,
        is_fixed_size: false,
    };
}

impl std::string::ToString for EcdsaSignature {
    fn to_string(&self) -> String {
        let mut bytes = Vec::with_capacity(72);
        bytes.extend_from_slice(&self.r);
        bytes.extend_from_slice(&self.s);
        bytes.extend_from_slice(&self.v.to_le_bytes());
        hex_encode(&bytes)
    }
}

impl EcdsaSignature {
    // pub fn from_sec1(bytes: &[u8]) -> Self {
    //     let mut bytes = bytes.to_vec();
    //     let s = bytes.split_off(32);
    //     Self {
    //         r: bytes.try_into().unwrap(),
    //         s: s.try_into().unwrap(),
    //         v: 0,
    //     }
    // }

    pub fn from_rsv(r: &[u8], s: &[u8], v: u64) -> Self {
        Self {
            r: r.try_into().unwrap(),
            s: s.try_into().unwrap(),
            v,
        }
    }

    pub fn from_signature_v(signature: &[u8], v: u64) -> Self {
        let mut signature = signature.to_vec();
        let s = signature.split_off(32);
        Self {
            r: signature.try_into().unwrap(),
            s: s.try_into().unwrap(),
            v,
        }
    }

    pub fn from_prehash(prehash: &[u8], signature: &[u8], pubkey: &[u8]) -> Self {
        let orig_key = VerifyingKey::from_sec1_bytes(pubkey).expect("failed to parse the pubkey");
        let recid = RecoveryId::trial_recovery_from_prehash(
            &orig_key,
            prehash,
            &Signature::try_from(signature).unwrap(),
        )
        .unwrap();
        let v = recid.is_y_odd() as u64;
        Self::from_signature_v(signature, v)
    }

    // normalize_v normalizes the v value to be 0 or 1.
    pub fn normalize_v(&mut self) {
        self.v = self.v % 2;
    }

    // expands the v value according to EIP-155.
    pub fn expand_v(&mut self, chain_id: u64, eip155: bool) {
        assert!(chain_id <= 4503599627370476, "chain_id out of range"); // https://github.com/ethereum/EIPs/issues/2294#issuecomment-1297145918
        if eip155 {
            self.v += chain_id * 2 + 35;
        } else {
            self.v += 27;
        }
    }

    /// Converts to a compact string with 1 byte v value.
    pub fn to_string_compact(&self) -> String {
        let mut bytes = Vec::with_capacity(72);
        bytes.extend_from_slice(&self.r);
        bytes.extend_from_slice(&self.s);
        bytes.push(u8::try_from(self.v).unwrap());
        hex_encode(&bytes)
    }
}

pub fn ethereum_address_from_public_key(public_key: &[u8]) -> Result<[u8; 20], String> {
    let encoded_point = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| "Pubkey parse error")?
        //.unwrap()
        .to_encoded_point(false);
    let uncompressed_pubkey_bytes = encoded_point.as_bytes();
    if (uncompressed_pubkey_bytes[0] != 0x04) || (uncompressed_pubkey_bytes.len() != 65) {
        return Err("Invalid pubkey".to_string());
    }
    let ethereum_pubkey = &uncompressed_pubkey_bytes[1..]; // trim off the first 0x04 byte
    let hash = keccak256(ethereum_pubkey);
    Ok((&hash[12..32]).try_into().unwrap())
}

pub fn parse_eth_address(address: &str) -> [u8; 20] {
    match address.parse() {
        Ok(H160(addr)) => addr,
        Err(err) => ic_cdk::trap(&format!(
            "failed to parse contract address {address}: {err}",
        )),
    }
}

#[test]
fn test_calculate_eth_address() {
    let public_key = hex::decode("04A4A4C5160DFA830E9D5FAD6DBA5248E7A9C783C30974A3382247DCE5A815DBAA4CB31812FD016561DE57A5A53EF527499031705BE824016842688B498F61FDE7").unwrap();

    let tecdsa_signer_address: [u8; 20] = ethereum_address_from_public_key(&public_key).unwrap();
    assert_eq!(
        tecdsa_signer_address,
        hex::decode("3b75ea5c82e96d9489ed740d455da4900f152f95")
            .unwrap()
            .as_slice()
    );
}
