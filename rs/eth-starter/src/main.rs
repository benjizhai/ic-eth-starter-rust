#![allow(clippy::unwrap_used)]
#![allow(unused_imports)]

use eth_starter::crypto::*;
use eth_starter::memory::*;
use eth_starter::tecdsa::*;
use eth_starter::utils::*;
use ic_cdk::api::management_canister::ecdsa::EcdsaPublicKeyResponse;

use candid::{CandidType, Decode, Encode, Nat, Principal};
use ethers_core::abi::ethereum_types::{Address, H160, U256, U64};
use ethers_core::types::Bytes;
use ethers_core::utils::keccak256;
use ic_canister_log::{declare_log_buffer, export};
use ic_cdk::api::call::CallResult;
use ic_cdk::api::management_canister::ecdsa::{
    ecdsa_public_key, sign_with_ecdsa, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgument,
    SignWithEcdsaArgument,
};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, StableCell, StableVec, Storable};

use rustic::access_control::*;
use rustic::inter_canister::*;
use rustic::memory_map::*;
use rustic::reentrancy_guard::*;
use rustic::types::*;
use rustic::utils::*;
use rustic_macros::modifiers;

use serde_bytes::ByteBuf;
use serde_json::{json, Value};
use sha3::Keccak256;

use std::borrow::Cow;
use std::cell::RefCell;
use std::convert::From;
use std::str::FromStr;
use std::time::Duration;

use k256::{
    ecdsa::{RecoveryId, Signature, VerifyingKey},
    elliptic_curve::{
        generic_array::{typenum::Unsigned, GenericArray},
        Curve,
    },
    EncodedPoint, PublicKey, Secp256k1,
};

use icrc_ledger_types::icrc1;
use icrc_ledger_types::icrc2;

type Amount = u64;
type MsgId = u128;

#[derive(CandidType, candid::Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum EthRpcError {
    NoPermission,
    TooFewCycles(String),
    ServiceUrlParseError,
    ServiceUrlHostMissing,
    ServiceUrlHostNotAllowed(String),
    ProviderNotFound,
    HttpRequestError { code: u32, message: String },
}

#[derive(CandidType, candid::Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ReturnError {
    GenericError,
    InputError,
    Unauthorized,
    Expired,
    InterCanisterCallError(String),
    TecdsaSignatureError(String),
    CryptoError,
    EventSeen,
    MemoryError,
    TransferError(String),
    EthRpcError(EthRpcError),
    JsonParseError(String),
    EventLogError(EventError),
    OutOfMemory,
    MaxResponseBytesExceeded,
    MaxResponseBytesNotEnoughForBlock(u64),
}

#[derive(CandidType, serde::Deserialize)]
pub struct InitArg {}

#[derive(CandidType, serde::Deserialize)]
enum Arg {
    Init(InitArg),
    Upgrade,
}

#[init]
fn init(arg: Arg) {
    match arg {
        Arg::Init(InitArg {}) => {
            rustic::rustic_init();

            // Insert init code for your canister here
        }
        Arg::Upgrade => ic_cdk::trap("upgrade args in init"),
    }
}

#[post_upgrade]
pub fn post_upgrade() {
    rustic::rustic_post_upgrade(false, false, false);

    // Insert post upgrade code for your canister here
}

#[query]
pub fn get_canister_config() -> CanisterConfig {
    CANISTER_CONFIG.with(|canister_config| {
        let canister_config = canister_config.borrow();
        canister_config.get().0.clone().unwrap()
    })
}

#[query]
pub fn get_canister_state() -> CanisterState {
    CANISTER_STATE.with(|canister_state| {
        let canister_state = canister_state.borrow();
        canister_state.get().0.clone().unwrap_or_default()
    })
}

// #[query]
// pub fn get_nonce() -> u32 {
//     let caller = ic_cdk::caller();
//     let caller_subaccount = subaccount_from_principal(&caller);
//     NONCE_MAP.with(|nonce_map| {
//         let nonce_map = nonce_map.borrow();
//         nonce_map.get(&caller_subaccount).unwrap_or(0)
//     })
// }

// The following defines log level.
#[derive(Copy, Clone, Debug)]
pub enum LogLevel {
    ERROR = 0,
    WARN = 1,
    INFO = 2,
    DEBUG = 3,
}

use LogLevel::*;

#[derive(Clone, CandidType, serde::Deserialize)]
pub struct LogView {
    from: Option<u64>,
    to: Option<u64>,
}

/// View debug logs in the given range (not including 'to').
/// If 'from' is missing, 0 is used.
/// If 'to' is missing, current length of all logs is used.
#[query]
#[modifiers("only_owner")]
pub async fn view_debug_log(view: LogView) -> Vec<String> {
    let debug_log_len = DEBUG_LOG.with(|log| log.borrow().len());
    let from = view.from.unwrap_or_default();
    let to = view.to.unwrap_or(debug_log_len).min(debug_log_len);
    let mut logs = Vec::new();
    DEBUG_LOG.with(|log| {
        let debug_log = log.borrow();
        for i in from..to {
            logs.push(debug_log.get(i).clone().unwrap_or_default())
        }
    });
    logs
}

/// Add a line of given log level to the debug log, only when
/// the given level is smaller than or equal to config.debug_log_level.
pub fn debug_log(level: LogLevel, line: String) -> Result<(), ReturnError> {
    let config = get_canister_config();
    if (level as u8) <= config.debug_log_level {
        DEBUG_LOG.with(|log| {
            log.borrow()
                .append(&format!(
                    "{} {:?} {}",
                    canister_time() / 1_000_000,
                    level,
                    line
                ))
                .map(|_| ())
                .map_err(|_| ReturnError::OutOfMemory)
        })
    } else {
        Ok(())
    }
}

#[derive(CandidType, serde::Deserialize)]
pub struct SignRequest {
    pub chain_id: Nat,
    pub to: String,
    pub gas: Nat,
    pub max_fee_per_gas: Nat,
    pub max_priority_fee_per_gas: Nat,
    pub value: Nat,
    pub nonce: Nat,
    pub data: Option<String>,
}

/// Computes a signature for an [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) transaction.
#[update]
#[modifiers("only_owner")]
async fn sign_transaction(req: SignRequest) -> String {
    use ethers_core::types::transaction::eip1559::Eip1559TransactionRequest;
    use ethers_core::types::Signature;

    const EIP1559_TX_ID: u8 = 2;

    let config = get_canister_config();

    let data = req
        .data
        .as_ref()
        .map(|s| Bytes::from(hex_decode_0x(s).expect("hex decode error")));

    let tx = Eip1559TransactionRequest {
        chain_id: Some(nat_to_u64(&req.chain_id)),
        from: None,
        to: Some(
            Address::from_str(&req.to)
                .expect("failed to parse the destination address")
                .into(),
        ),
        gas: Some(nat_to_u256(&req.gas)),
        value: Some(nat_to_u256(&req.value)),
        nonce: Some(nat_to_u256(&req.nonce)),
        data,
        access_list: Default::default(),
        max_priority_fee_per_gas: Some(nat_to_u256(&req.max_priority_fee_per_gas)),
        max_fee_per_gas: Some(nat_to_u256(&req.max_fee_per_gas)),
    };

    let mut unsigned_tx_bytes = tx.rlp().to_vec();
    unsigned_tx_bytes.insert(0, EIP1559_TX_ID);

    let txhash = keccak256(&unsigned_tx_bytes);

    let (pubkey, signature) =
        pubkey_and_signature(txhash.to_vec(), vec![], config.ecdsa_key_name).await;

    let signature = EcdsaSignature::from_prehash(&txhash, &signature, &pubkey);
    let sig = Signature {
        r: U256::from_big_endian(&signature.r),
        s: U256::from_big_endian(&signature.s),
        v: signature.v.into(),
    };

    let mut signed_tx_bytes = tx.rlp_signed(&sig).to_vec();
    signed_tx_bytes.insert(0, EIP1559_TX_ID);

    hex_encode_0x(&signed_tx_bytes)
}

/// Computes a signature for a hex-encoded message according to [EIP-191](https://eips.ethereum.org/EIPS/eip-191).
#[update]
#[modifiers("only_owner")]
async fn personal_sign(plaintext: String) -> String {
    let config = get_canister_config();

    let bytes = hex_decode_0x(&plaintext).expect("hex decode error");

    let message = [
        b"\x19Ethereum Signed Message:\n",
        bytes.len().to_string().as_bytes(),
        bytes.as_ref(),
    ]
    .concat();

    let msg_hash = keccak256(&message);

    let (pubkey, signature) =
        pubkey_and_signature(msg_hash.to_vec(), vec![], config.ecdsa_key_name).await;

    EcdsaSignature::from_prehash(&msg_hash, &signature, &pubkey).to_string()
}

/// Computes a signature for a precomputed hash.
#[update]
#[modifiers("only_owner")]
async fn sign_prehash(prehash: String) -> String {
    let config = get_canister_config();

    let hash_bytes = hex_decode_0x(&prehash).expect("hex decode error");

    let (pubkey, signature) =
        pubkey_and_signature(hash_bytes.to_vec(), vec![], config.ecdsa_key_name).await;

    EcdsaSignature::from_prehash(&hash_bytes, &signature, &pubkey).to_string()
}

// async fn eth_rpc_call(
//     json_rpc_payload: Value,
//     cycles: u128,
// ) -> Result<Result<Vec<u8>, EthRpcError>, ReturnError> {
//     let config: canisterConfig = get_canister_config();
//     debug_log(
//         DEBUG,
//         format!("Sending json_rpc_request {}", json_rpc_payload),
//     )?;
//     let rpc_result: Result<Result<Vec<u8>, EthRpcError>, _> = canister_call_with_payment(
//         config.eth_rpc_canister_id,
//         "json_rpc_request",
//         (
//             json_rpc_payload.to_string(),
//             config.eth_rpc_service_url.clone(),
//             config.max_response_bytes,
//         ),
//         candid::encode_args,
//         |r| candid::decode_one(r),
//         cycles,
//     )
//     .await;
//     match rpc_result {
//         Ok(Ok(bytes)) => {
//             debug_log(
//                 DEBUG,
//                 format!(
//                     "Received rpc result {}",
//                     String::from_utf8(bytes.clone())
//                         .unwrap_or_else(|_| "(invalid utf8 encoding)".to_string())
//                 ),
//             )?;
//             Ok(Ok(bytes))
//         }
//         Ok(Err(err)) => {
//             debug_log(DEBUG, format!("Received rpc error {:?}", err))?;
//             Ok(Err(err))
//         }
//         Err((err_code, err_msg)) => {
//             let err = format!("{{code: {:?}, message: {}}}", err_code, err_msg);
//             debug_log(DEBUG, format!("Received error {}", err))?;
//             Err(ReturnError::InterCanisterCallError(err))
//         }
//     }
// }

// /// Look up ethereum event log of the given block for Burn events.
// /// Process those that have not yet been processed.
// ///
// /// This is can only be called by owner and only meant for debugging purposes.
// #[update]
// #[modifiers("only_owner")]
// pub async fn process_block(block_hash: String) -> Result<(), ReturnError> {
//     // get log events from block with the given block_hash
//     // NOTE: if log exceeds pre-allocated space, we need manual intervention.
//     let config: canisterConfig = get_canister_config();
//     let json_rpc_payload = json!({
//         "jsonrpc":"2.0",
//         "method":"eth_getLogs",
//         "params":[{
//             "address": config.zkf_staking_address,
//             "blockHash": block_hash,
//         }],
//     });

//     let result = eth_rpc_call(json_rpc_payload, config.cycle_cost_of_eth_getlogs).await?;
//     let logs: Value = match result {
//         Ok(bytes) => serde_json::from_slice(&bytes)
//             .map_err(|err| ReturnError::JsonParseError(err.to_string()))?,
//         Err(err) => return Err(ReturnError::EthRpcError(err)),
//     };
//     process_logs(logs).await
// }

// /// Given some event logs, process burn events in them.
// async fn process_logs(logs: Value) -> Result<(), ReturnError> {
//     let entries = read_event_logs(&logs).map_err(ReturnError::EventLogError)?;
//     debug_log(DEBUG, format!("Processing {} log entries", entries.len()))?;
//     for entry in entries {
//         match parse_burn_event(&entry) {
//             Ok(_burn) => {}
//             Err(err) => {
//                 // parsing error? unknown event type? They should be investigated!
//                 debug_log(
//                     WARN,
//                     format!(
//                         "Skip processing event {:?} due to error {:?}",
//                         entry.event_id, err,
//                     ),
//                 )?;
//             }
//         }
//     }

//     Ok(())
// }

// /// Sync event logs of the canister ERC-20 contract via RPC.
// /// This is meant to be called from a timer.
// pub async fn sync_event_logs() -> Result<(), ReturnError> {
//     let _guard = ReentrancyGuard::new();
//     // get log events from block with the given block_hash
//     // NOTE: if log exceeds pre-allocated space, we need manual intervention.
//     let config: canisterConfig = get_canister_config();
//     let mut state: canisterState = get_canister_state();
//     let next_block = state
//         .next_blocks
//         .pop_front()
//         .map(|x| format!("{:#x}", x))
//         .unwrap_or_else(|| "safe".to_string());

//     // get logs between last_block and next_block.
//     let json_rpc_payload = json!({
//         "jsonrpc":"2.0",
//         "method":"eth_getLogs",
//         "params":[{
//             "address": config.zkf_staking_address,
//             "fromBlock": format!("{:#x}", state.last_block + 1),
//             "toBlock": next_block,
//             "topics": [ config.canister_getlogs_topics ],
//         }],
//     });
//     debug_log(
//         INFO,
//         format!(
//             "Syncing event logs from block {} to {}",
//             state.last_block + 1,
//             hex_decode_0x_u64(&next_block)
//                 .map(|x| x.to_string())
//                 .unwrap_or_else(|| next_block.clone())
//         ),
//     )?;
//     match eth_rpc_call(json_rpc_payload, config.cycle_cost_of_eth_getlogs).await? {
//         Err(EthRpcError::HttpRequestError { code: _, message })
//             if message.contains("body exceeds size limit") =>
//         {
//             debug_log(
//                 WARN,
//                 format!(
//                     "RPC result exceeds buffer size limit, trying to halve range [{}, {})",
//                     state.last_block + 1,
//                     hex_decode_0x_u64(&next_block)
//                         .map(|x| x.to_string())
//                         .unwrap_or_else(|| next_block.clone())
//                 ),
//             )?;
//             let last_block = if let Some(last_block) = hex_decode_0x_u64(&next_block) {
//                 (last_block - state.last_block) / 2 + state.last_block
//             } else {
//                 let json_rpc_payload = json!({
//                     "jsonrpc":"2.0",
//                     "method":"eth_blockNumber",
//                     "params":[]
//                 });
//                 let result =
//                     eth_rpc_call(json_rpc_payload, config.cycle_cost_of_eth_blocknumber).await;
//                 debug_log(DEBUG, format!("Syncing event logs received {:?}", result))?;
//                 let result: Value = match result? {
//                     Ok(bytes) => serde_json::from_slice(&bytes)
//                         .map_err(|err| ReturnError::JsonParseError(err.to_string()))?,
//                     Err(err) => {
//                         return Err(ReturnError::JsonParseError(format!("{:?}", err)));
//                     }
//                 };
//                 let block_number = result
//                     .as_object()
//                     .and_then(|x| x.get("result"))
//                     .and_then(|x| x.as_str())
//                     .and_then(hex_decode_0x_u64)
//                     .ok_or_else(|| {
//                         ReturnError::JsonParseError(
//                             "No valid result block number is found".to_string(),
//                         )
//                     })?;
//                 debug_log(
//                     INFO,
//                     format!("Received latest block number {:?}", block_number),
//                 )?;
//                 (block_number - state.last_block) / 2 + state.last_block
//             };
//             if last_block == state.last_block + 1 {
//                 return Err(ReturnError::MaxResponseBytesNotEnoughForBlock(last_block));
//             }

//             canister_STATE.with(|canister_state| {
//                 let mut canister_state = canister_state.borrow_mut();
//                 let mut state = canister_state.get().0.clone();
//                 if let Some(s) = state.as_mut() {
//                     s.next_blocks.push_front(last_block);
//                 };
//                 canister_state.set(Cbor(state)).unwrap();
//             });
//             Err(ReturnError::MaxResponseBytesExceeded)
//         }
//         Err(err) => Err(ReturnError::EthRpcError(err)),
//         Ok(bytes) => {
//             let logs: Value = serde_json::from_slice(&bytes)
//                 .map_err(|err| ReturnError::JsonParseError(err.to_string()))?;
//             // Find the highest block number from log. This is an estimate since
//             // we don't know the block number of the latest "safe" block.
//             let last_block = last_block_number_from_event_logs(&logs);
//             process_logs(logs).await?;
//             canister_STATE.with(|canister_state| {
//                 let mut canister_state = canister_state.borrow_mut();
//                 let mut state = canister_state.get().0.clone();
//                 if let Some(s) = state.as_mut() {
//                     if let Some(last_block) = s.next_blocks.pop_front() {
//                         s.last_block = last_block;
//                     } else if let Some(last_block) = last_block {
//                         s.last_block = last_block;
//                     }
//                 }
//                 canister_state.set(Cbor(state)).unwrap();
//             });
//             Ok(())
//         }
//     }
// }

#[query]
pub fn get_signature(msg_id: MsgId) -> Option<EcdsaSignature> {
    SIGNATURE_MAP.with(|sm| {
        let sm = sm.borrow();
        sm.get(&msg_id)
    })
}

// // Call sync_event_logs(), and if it requires re-run, call it again.
// // Also log errors returned as warning.
// async fn periodic_task() {
//     loop {
//         match sync_event_logs().await {
//             Err(ReturnError::MaxResponseBytesExceeded) => (), // re-run
//             Err(ReturnError::MaxResponseBytesNotEnoughForBlock(block)) => {
//                 // NOTE: This error requires a manual fix. We'll stop the timer first.
//                 debug_log(
//                     ERROR,
//                     format!("Block {} returns events exceeding max buffer size. It requires manual intervention!", block),
//                 ).unwrap();
//                 TIMER_ID.with(|id| {
//                     if let Some(timer_id) = *id.borrow() {
//                         ic_cdk_timers::clear_timer(timer_id);
//                     }
//                 });
//             }
//             Err(err) => {
//                 debug_log(WARN, format!("sync_event_logs returns error {:?}", err)).unwrap();
//                 break;
//             }
//             Ok(_) => break,
//         }
//     }
// }

// /// Set the configuration. Must be called at least once after deployment.
// /// It also starts syncing of event logs on a timer, based on the given
// /// configuration parameter.
// #[update]
// #[modifiers("only_owner")]
// pub fn set_canister_config(config: canisterConfig) -> Result<(), ReturnError> {
//     canister_CONFIG
//         .with(|canister_config| {
//             let mut canister_config = canister_config.borrow_mut();
//             canister_config.set(Cbor(Some(config)))
//         })
//         .map(|_| ())
//         .map_err(|_| ReturnError::MemoryError)?;

//     TIMER_ID.with(|id| {
//         if let Some(timer_id) = *id.borrow() {
//             ic_cdk_timers::clear_timer(timer_id);
//         }
//         let timer_id = ic_cdk_timers::set_timer_interval(
//             Duration::from_secs(get_canister_config().sync_interval_secs),
//             || ic_cdk::spawn(periodic_task()),
//         );
//         *id.borrow_mut() = Some(timer_id);
//     });
//     Ok(())
// }

/// Set the configuration. Must be called at least once after deployment.
#[update]
#[modifiers("only_owner")]
pub fn set_canister_config(config: CanisterConfig) -> Result<(), ReturnError> {
    CANISTER_CONFIG
        .with(|canister_config| {
            let mut canister_config = canister_config.borrow_mut();
            canister_config.set(Cbor(Some(config)))
        })
        .map(|_| ())
        .map_err(|_| ReturnError::MemoryError)?;
    Ok(())
}

// Update pub key and last_block stored in state.
#[update]
#[modifiers("only_owner")]
pub async fn update_canister_state() -> Result<(), ReturnError> {
    let config: CanisterConfig = get_canister_config();
    let mut state: CanisterState = get_canister_state();
    state.last_block = config.last_synced_block_number;

    // Update tecdsa signer key and calculate signer ETH address
    let (res,): (EcdsaPublicKeyResponse,) = ecdsa_pubkey_of(vec![], config.ecdsa_key_name)
        .await
        .map_err(|err| ReturnError::TecdsaSignatureError(err.1))?;
    state.tecdsa_pubkey = res.public_key.clone();

    state.tecdsa_signer_address =
        ethereum_address_from_public_key(&res.public_key).map_err(|_| ReturnError::CryptoError)?;

    CANISTER_STATE
        .with(|canister_state| {
            let mut canister_state = canister_state.borrow_mut();
            canister_state.set(Cbor(Some(state)))
        })
        .map(|_| ())
        .map_err(|_| ReturnError::MemoryError)
}

#[query]
pub fn get_tecdsa_signer_address_hex() -> String {
    let state: CanisterState = get_canister_state();
    hex_encode_0x(&state.tecdsa_signer_address)
}

fn main() {}

#[cfg(any(target_arch = "wasm32", test))]
ic_cdk::export_candid!();
