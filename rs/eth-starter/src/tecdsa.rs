use candid::{CandidType, Principal};
use ic_cdk::api::call::CallResult;
use ic_cdk::api::management_canister::ecdsa::{
    ecdsa_public_key, sign_with_ecdsa, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgument,
    EcdsaPublicKeyResponse, SignWithEcdsaArgument, SignWithEcdsaResponse,
};
use ic_cdk::call;
use serde::Serialize;

#[derive(CandidType, Serialize, Debug)]
pub struct PublicKeyReply {
    pub public_key: Vec<u8>,
}

#[derive(CandidType, Serialize, Debug)]
pub struct SignatureReply {
    pub signature: Vec<u8>,
}

pub async fn raw_rand() -> CallResult<(Vec<u8>,)> {
    call(Principal::management_canister(), "raw_rand", ()).await
}

pub async fn ecdsa_pubkey_of(
    derivation_path: Vec<Vec<u8>>,
    key_name: String,
) -> CallResult<(EcdsaPublicKeyResponse,)> {
    let request = EcdsaPublicKeyArgument {
        canister_id: None, // defaults to the caller
        derivation_path,
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: key_name,
        },
    };
    ecdsa_public_key(request).await
}

pub async fn sign(
    message_hash: Vec<u8>,
    derivation_path: Vec<Vec<u8>>,
    key_name: String,
) -> CallResult<(SignWithEcdsaResponse,)> {
    let request = SignWithEcdsaArgument {
        message_hash,
        derivation_path,
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: key_name,
        },
    };
    sign_with_ecdsa(request).await
}

/// Returns the public key and a message signature for the specified principal.
pub async fn pubkey_and_signature(
    message_hash: Vec<u8>,
    derivation_path: Vec<Vec<u8>>,
    key_name: String,
) -> (Vec<u8>, Vec<u8>) {
    // Fetch the pubkey and the signature concurrently to reduce latency.
    let (pubkey, response) = futures::join!(
        ecdsa_pubkey_of(derivation_path.clone(), key_name.clone()),
        sign(message_hash, derivation_path, key_name),
    );
    (
        pubkey.expect("failed to get the public key").0.public_key,
        response.expect("failed to sign the message").0.signature,
    )
}
