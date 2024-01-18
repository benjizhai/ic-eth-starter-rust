use candid::{CandidType, Decode, Encode, Nat, Principal};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};

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
