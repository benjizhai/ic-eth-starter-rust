PRJ_WASM=target/wasm32-unknown-unknown/release/eth-starter.wasm
PRJ_SRCS=$(wildcard rs/eth-starter/src/*.rs)

rs/eth-starter/eth-starter.did: $(PRJ_WASM)
	candid-extractor $< > $@

$(PRJ_WASM): $(PRJ_SRCS)
	cargo build --target wasm32-unknown-unknown --release -p eth-starter
