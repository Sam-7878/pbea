#[cfg(target_os = "openbsd")]
fn main() -> anyhow::Result<()> {
    use std::fs;
    use std::net::TcpListener;
    use std::time::Instant;

    use anyhow::{Context, bail};
    use chrono::Utc;
    use poa_protocol::{PolicyRepository, canonicalize, validate_value};
    use poa_sandbox::{OpenBsdBackend, ProcessConstraintBackend};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    fn elapsed_us(started: Instant) -> u64 {
        let nanos = started.elapsed().as_nanos();
        u64::try_from(nanos.div_ceil(1_000)).unwrap_or(u64::MAX)
    }

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        bail!("usage: openbsd_startup_probe SCHEMA BASE_POLICY CHILD_POLICY LISTEN_ADDR");
    }
    let source_commit = std::env::var("SOURCE_COMMIT").context("SOURCE_COMMIT is required")?;
    let cache_condition =
        std::env::var("CACHE_CONDITION").unwrap_or_else(|_| "warm_unspecified".into());
    let run_id = Uuid::new_v4();
    let timestamp = Utc::now().to_rfc3339();
    let total_started = Instant::now();

    let stage = Instant::now();
    let schema_bytes = fs::read(&args[1]).context("load protocol schema")?;
    let base_bytes = fs::read(&args[2]).context("load base policy")?;
    let child_bytes = fs::read(&args[3]).context("load child policy")?;
    let t_load_us = elapsed_us(stage);

    let stage = Instant::now();
    let schema: Value = serde_json::from_slice(&schema_bytes).context("parse protocol schema")?;
    let base_value: Value = serde_json::from_slice(&base_bytes).context("parse base policy")?;
    let child_value: Value = serde_json::from_slice(&child_bytes).context("parse child policy")?;
    let base = validate_value(&base_value, &schema).context("validate base policy")?;
    let child = validate_value(&child_value, &schema).context("validate child policy")?;
    let t_schema_us = elapsed_us(stage);

    let stage = Instant::now();
    let effective = PolicyRepository::new([base, child])
        .resolve("hete.verifier.payment")
        .context("resolve effective policy")?
        .policy;
    let t_inheritance_us = elapsed_us(stage);

    let stage = Instant::now();
    let canonical = canonicalize(&effective).context("canonicalize effective policy")?;
    let t_canonicalize_us = elapsed_us(stage);

    let stage = Instant::now();
    let policy_digest = format!("sha256:{}", hex::encode(Sha256::digest(&canonical)));
    let t_digest_us = elapsed_us(stage);

    let backend = OpenBsdBackend;
    let stage = Instant::now();
    backend.validate_policy(&effective)?;
    backend.prepare_resources(&effective)?;
    let t_resource_prepare_us = elapsed_us(stage);

    let stage = Instant::now();
    let listener = TcpListener::bind(&args[4]).context("bind listener")?;
    let t_listener_bind_us = elapsed_us(stage);

    let stage = Instant::now();
    backend.apply_unveil_rules(&effective.process_constraints)?;
    let t_unveil_apply_us = elapsed_us(stage);

    let stage = Instant::now();
    backend.lock_unveil()?;
    let t_unveil_lock_us = elapsed_us(stage);

    let stage = Instant::now();
    backend.apply_pledge(&effective.process_constraints)?;
    let t_pledge_apply_us = elapsed_us(stage);

    let stage = Instant::now();
    std::hint::black_box(listener.local_addr()?);
    let t_business_loop_ready_us = elapsed_us(stage);
    let t_total_startup_us = elapsed_us(total_started);

    println!(
        "{}",
        json!({
            "run_id": run_id,
            "test_id": "STARTUP-OPENBSD-001",
            "timestamp": timestamp,
            "platform": "openbsd-7.9",
            "source_commit": source_commit,
            "protocol_id": effective.protocol_id,
            "policy_digest": policy_digest,
            "build_profile": "release",
            "cache_condition": cache_condition,
            "t_load_us": t_load_us,
            "t_schema_us": t_schema_us,
            "t_inheritance_us": t_inheritance_us,
            "t_canonicalize_us": t_canonicalize_us,
            "t_digest_us": t_digest_us,
            "t_resource_prepare_us": t_resource_prepare_us,
            "t_listener_bind_us": t_listener_bind_us,
            "t_unveil_apply_us": t_unveil_apply_us,
            "t_unveil_lock_us": t_unveil_lock_us,
            "t_pledge_apply_us": t_pledge_apply_us,
            "t_business_loop_ready_us": t_business_loop_ready_us,
            "t_total_startup_us": t_total_startup_us,
            "success": true
        })
    );
    drop(listener);
    Ok(())
}

#[cfg(not(target_os = "openbsd"))]
fn main() {
    eprintln!("openbsd_startup_probe is OpenBSD-only and produces no evidence on this platform");
    std::process::exit(69);
}
