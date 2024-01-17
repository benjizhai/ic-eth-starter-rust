use candid::{CandidType, Decode, Encode, Principal};
use ic_stable_structures::memory_manager::MemoryId;
use ic_stable_structures::storable::Bound;
use ic_stable_structures::DefaultMemoryImpl;
use ic_stable_structures::{Log, StableBTreeMap, StableCell, Storable};
use rustic::memory_map::MEMORY_MANAGER;
use rustic::types::{Cbor, RM, VM};
use std::borrow::Cow;
use std::cell::RefCell;

use crate::crypto::EcdsaSignature;

type Amount = u64;
type MsgId = u128;

#[derive(Clone, CandidType, serde::Serialize, serde::Deserialize)]
pub struct CanisterConfig {
    pub eth_rpc_service_url: String,
    pub eth_rpc_canister_id: Principal,
    pub sample_erc20_address: String,
    pub canister_fee: Amount,
    pub canister_getlogs_topics: Vec<String>,
    pub expiry_seconds: u64,
    pub target_chain_ids: Vec<u64>,
    pub max_response_bytes: u64,
    pub sync_interval_secs: u64,
    pub last_synced_block_number: u64,
    pub cycle_cost_of_eth_getlogs: u128,
    pub cycle_cost_of_eth_blocknumber: u128,
    pub debug_log_level: u8,
    pub ecdsa_key_name: String,
}

#[derive(Clone, CandidType, serde::Serialize, serde::Deserialize, Default)]
pub struct CanisterState {
    pub tecdsa_pubkey: Vec<u8>,
    pub tecdsa_signer_address: [u8; 20],
    pub last_block: u64,
    pub next_blocks: std::collections::VecDeque<u64>,
}

// #[derive(
//     CandidType, serde::Serialize, serde::Deserialize, Default, Clone, Debug, PartialEq, Eq,
// )]
// pub enum MintState {
//     #[default]
//     Init,
//     FundReceived,
//     Signed,
//     Confirmed,
//     Expired,
// }

// impl Storable for MintState {
//     fn from_bytes(bytes: Cow<[u8]>) -> Self {
//         match bytes[0] {
//             0 => MintState::Init,
//             1 => MintState::FundReceived,
//             2 => MintState::Signed,
//             3 => MintState::Confirmed,
//             4 => MintState::Expired,
//             _ => panic!("invalid mint state"),
//         }
//     }

//     fn to_bytes(&self) -> Cow<[u8]> {
//         Cow::Owned(vec![match self {
//             MintState::Init => 0,
//             MintState::FundReceived => 1,
//             MintState::Signed => 2,
//             MintState::Confirmed => 3,
//             MintState::Expired => 4,
//         }])
//     }

//     const BOUND: Bound = Bound::Bounded {
//         max_size: 1,
//         is_fixed_size: true,
//     };
// }

// #[derive(Clone, CandidType, serde::Serialize, serde::Deserialize)]
// pub struct MintStatus {
//     pub amount: Amount,
//     pub expiry: u64, // seconds since UNIX epoch
//     pub state: MintState,
// }

// impl Storable for MintStatus {
//     fn from_bytes(bytes: Cow<[u8]>) -> Self {
//         Decode!(bytes.as_ref(), Self).unwrap()
//     }

//     fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
//         Cow::Owned(Encode!(self).unwrap())
//     }

//     const BOUND: Bound = Bound::Unbounded;
// }

const CANISTER_CONFIG_SIZE: u64 = 512;
const CANISTER_STATE_SIZE: u64 = 256;

const CANISTER_CONFIG_PAGE_START: u64 = rustic::memory_map::USER_PAGE_START;
const CANISTER_CONFIG_PAGE_END: u64 = CANISTER_CONFIG_PAGE_START + CANISTER_CONFIG_SIZE;
const CANISTER_STATE_PAGE_START: u64 = CANISTER_CONFIG_PAGE_END;
const CANISTER_STATE_PAGE_END: u64 = CANISTER_STATE_PAGE_START + CANISTER_STATE_SIZE;

const NONCE_MAP_MEM_ID: MemoryId = MemoryId::new(0);
const STATUS_MAP_MEM_ID: MemoryId = MemoryId::new(1);
const SIGNATURE_MAP_MEM_ID: MemoryId = MemoryId::new(2);
const EVENT_ID_MAP_MEM_ID: MemoryId = MemoryId::new(3);
const DEBUG_LOG_IDX_ID: MemoryId = MemoryId::new(4);
const DEBUG_LOG_MEM_ID: MemoryId = MemoryId::new(5);

thread_local! {

    pub static CANISTER_CONFIG: RefCell<StableCell<Cbor<Option<CanisterConfig>>, RM>> =
        RefCell::new(StableCell::init(
            RM::new(DefaultMemoryImpl::default(), CANISTER_CONFIG_PAGE_START..CANISTER_CONFIG_PAGE_END),
            Cbor::default(),
        ).expect("failed to initialize")
    );

    pub static CANISTER_STATE: RefCell<StableCell<Cbor<Option<CanisterState>>, RM>> =
        RefCell::new(StableCell::init(
            RM::new(DefaultMemoryImpl::default(), CANISTER_STATE_PAGE_START..CANISTER_STATE_PAGE_END),
            Cbor::default(),
        ).expect("failed to initialize")
    );

    // // map caller -> nonce
    // pub static NONCE_MAP: RefCell<StableBTreeMap<[u8;32], u32, VM>> =
    //     MEMORY_MANAGER.with(|mm| {
    //         RefCell::new(StableBTreeMap::init(mm.borrow().get(NONCE_MAP_MEM_ID)))
    // });

    // // map msgid -> status
    // pub static STATUS_MAP: RefCell<StableBTreeMap<MsgId, MintStatus, VM>> =
    //     MEMORY_MANAGER.with(|mm| {
    //         RefCell::new(StableBTreeMap::init(mm.borrow().get(STATUS_MAP_MEM_ID)))
    // });

    // map msgid -> signature
    pub static SIGNATURE_MAP: RefCell<StableBTreeMap<MsgId, EcdsaSignature, VM>> =
        MEMORY_MANAGER.with(|mm| {
            RefCell::new(StableBTreeMap::init(mm.borrow().get(SIGNATURE_MAP_MEM_ID)))
    });

    // map eventid -> bool
    pub static EVENT_ID_MAP: RefCell<StableBTreeMap<u128, u8, VM>> =
        MEMORY_MANAGER.with(|mm| {
            RefCell::new(StableBTreeMap::new(mm.borrow().get(EVENT_ID_MAP_MEM_ID)))
    });

    // TODO: make this persistent
    pub static DEBUG_LOG: RefCell<Log<String, VM, VM>> =
        MEMORY_MANAGER.with(|mm| {
            RefCell::new(Log::new(mm.borrow().get(DEBUG_LOG_IDX_ID), mm.borrow().get(DEBUG_LOG_MEM_ID)))
    });

    // TimerId
    pub static TIMER_ID: RefCell<Option<ic_cdk_timers::TimerId>> =
        RefCell::new(None);
}
