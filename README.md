# aa-pam-sidecar

Rust security proxy for ERC-4337 bundlers + M2M agent keys.

## Architecture

agent -> bundler-proxy:3000/rpc -> bundler:8545 -> EntryPoint
               |-> EIP-712 domain allowlist
               |-> size + gas caps
               |-> post-sim storage filter
key-vault: mlock + dontdump + zeroize on drop. No Clone. No Debug.

## Policy

- chainId: 84532
- EntryPoint: 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789
- MAX_CALLDATA 8192, MAX_INITCODE 10240
- MAX_VERIFICATION_GAS 2000000, MAX_CALL_GAS 5000000

## Live proof (Base Sepolia)

- Counter deploy: https://sepolia.basescan.org/tx/<DEPLOY_HASH>
- setNumber(42): https://sepolia.basescan.org/tx/<SET_HASH>
- Blocked gas-drain UserOp: see `logs/blocked.json`
- Allowed UserOp: https://sepolia.basescan.org/tx/<USEROP_HASH>

## Bench

```
cargo bench 2>&1 | tee logs/bench.log
proxy p50 __ ms / p99 __ ms, blocked __ / __ malicious
```

## Run

```sh
cargo build --release
BUNDLER_URL=http://127.0.0.1:8545 ./target/release/bundler-proxy
```

Proof logs: `logs/`.
