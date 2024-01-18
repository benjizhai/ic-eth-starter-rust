use crate::utils::EventError;
use candid::{CandidType, Decode, Encode, Nat, Principal};

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
