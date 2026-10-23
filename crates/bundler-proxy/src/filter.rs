use serde_json::Value;

pub const ALLOWED_CHAIN_ID: u64 = 84532; // Base Sepolia
pub const ALLOWED_ENTRYPOINT: &str = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789";
pub const MAX_CALLDATA: usize = 8192;
pub const MAX_INITCODE: usize = 10240;
pub const MAX_PAYMASTER_DATA: usize = 2048;
pub const MAX_VERIFICATION_GAS: u64 = 2_000_000;
pub const MAX_CALL_GAS: u64 = 5_000_000;
pub const MAX_STORAGE_WRITES: usize = 16;

fn hex_len(v: &Value, key: &str) -> usize {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|s| {
            let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
            s.len() / 2
        })
        .unwrap_or(0)
}

fn u64_from_hex(v: &Value, key: &str) -> u64 {
    v.get(key)
        .and_then(|x| {
            if let Some(n) = x.as_u64() {
                return Some(n);
            }
            let s = x.as_str()?;
            let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
            u64::from_str_radix(h, 16).ok()
        })
        .unwrap_or(0)
}

pub fn check_size_bounds(uop: &Value) -> Result<(), &'static str> {
    if hex_len(uop, "callData") > MAX_CALLDATA {
        return Err("calldata too large");
    }
    if hex_len(uop, "initCode") > MAX_INITCODE {
        return Err("initCode too large");
    }
    if hex_len(uop, "paymasterAndData") > MAX_PAYMASTER_DATA {
        return Err("paymaster data too large");
    }
    Ok(())
}

pub fn check_gas_bounds(uop: &Value) -> Result<(), &'static str> {
    if u64_from_hex(uop, "verificationGasLimit") > MAX_VERIFICATION_GAS {
        return Err("verificationGas drain");
    }
    if u64_from_hex(uop, "callGasLimit") > MAX_CALL_GAS {
        return Err("callGas drain");
    }
    Ok(())
}

/// Post-simulation gate.
/// `storage_writes` = SSTORE count from trace / access list.
/// `selfdestruct_seen` = SELFDESTRUCT in trace.
/// `create2_count` = CREATE2 ops in trace.
pub fn should_drop_post_sim(
    storage_writes: usize,
    selfdestruct_seen: bool,
    create2_count: usize,
) -> Option<&'static str> {
    if selfdestruct_seen {
        return Some("SELFDESTRUCT in simulation");
    }
    if create2_count > 1 {
        return Some("CREATE2 fan-out");
    }
    if storage_writes > MAX_STORAGE_WRITES {
        return Some("storage-write DoS");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_oversize_calldata() {
        let uop = json!({"callData": format!("0x{}", "ab".repeat(MAX_CALLDATA + 1))});
        assert!(check_size_bounds(&uop).is_err());
    }

    #[test]
    fn rejects_gas_drain() {
        let uop = json!({"verificationGasLimit": "0xFFFFFF", "callGasLimit": "0x1"});
        // 0xFFFFFF = 16777215 > 2M
        assert!(check_gas_bounds(&uop).is_err());
    }

    #[test]
    fn drops_storage_dos() {
        assert_eq!(
            should_drop_post_sim(MAX_STORAGE_WRITES + 1, false, 0),
            Some("storage-write DoS")
        );
        assert!(should_drop_post_sim(1, false, 0).is_none());
    }
}
