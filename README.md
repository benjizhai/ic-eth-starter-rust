# IC ETH Starter Project using Rust

ETH integration starter project on the Internet Computer.

** Warning: The code in this repo is not of production quailty and should not be used in production.**

## How to Use

### Clone this repo

```shell
git clone git@github.com:benjizhai/ic-eth-starter-rust.git
```

### Install Toolchain

```shell
sh -ci "$(curl -fsSL https://internetcomputer.org/install.sh)"
curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash
cargo binstall --no-confirm ic-wasm
rustup target add wasm32-unknown-unknown
```

### Build

```shell
export RUSTIC_USER_PAGE_END=1024
make
```

### Run

```shell
dfx stop
dfx start --background --clean
dfx deploy --network=local eth-starter --argument '(variant {Init = record {}})'
dfx deploy evm_rpc 
source .env
dfx canister call eth-starter set_canister_config "(record {
  eth_rpc_service_url = \"$ETH_RPC_URL\";
  eth_rpc_canister_id = principal \"$ETHRPC_CANISTER_ID\";
  sample_erc20_address = \"0x50DE675A89bB4eEBFFdA4AcC37490D0e45469Ec6\";
  canister_getlogs_topics = vec { \"0xa6a16062bb41b9bcfb300790709ad9b778bcb5cdcf87dfa633ab3adfd8a7ab59\"; \"0x7fe818d2b919ac5cc197458482fab0d4285d783795541be06864b0baa6ac2f5c\" } : vec text;
  expiry_seconds = 18000: nat64;
  max_response_bytes = 4000: nat64;
  target_chain_ids = vec {5}: vec nat64;
  last_synced_block_number = 9_721_763 : nat64;
  sync_interval_secs = 180 : nat64;
  cycle_cost_of_eth_getlogs = 900000000 : nat;
  cycle_cost_of_eth_blocknumber = 900000000 : nat;
  debug_log_level = 3;
  ecdsa_key_name = \"$ECDSA_KEY_NAME\";
})"
```
