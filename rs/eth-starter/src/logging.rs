use crate::memory::*;
use crate::types::*;
use candid::{CandidType, Decode, Encode, Nat, Principal};
use rustic::utils::*;

use ic_cdk_macros::{query, update};
use rustic::access_control::only_owner;
use rustic_macros::modifiers;

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
