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
```
