use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;

use anyhow::{Context, bail};
use poa_protocol::{PolicyRepository, load_and_validate, load_schema};
use poa_sandbox::{OpenBsdBackend, StartupEnforcement};
use poa_verifier_example::Verifier;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 7 || args[1] != "serve" {
        bail!(
            "usage: poa-verifier-example serve SCHEMA BASE_POLICY CHILD_POLICY AUDIT_JSONL LISTEN_ADDR"
        );
    }
    let schema = load_schema(&args[2]).context("load protocol schema")?;
    let base = load_and_validate(&args[3], &schema).context("validate base policy")?;
    let child = load_and_validate(&args[4], &schema).context("validate child policy")?;
    let effective = PolicyRepository::new([base, child])
        .resolve("hete.verifier.payment")?
        .policy;
    let request_schema_path = PathBuf::from(&effective.data_constraints.input_schema);
    let request_schema = serde_json::from_slice(
        &fs::read(&request_schema_path)
            .with_context(|| format!("read {}", request_schema_path.display()))?,
    )?;
    let mut verifier = Verifier::new(effective.clone(), request_schema)?;

    let backend = OpenBsdBackend;
    let mut startup = StartupEnforcement::default();
    startup
        .prepare(&backend, &effective)
        .context("prepare required resources before listener")?;
    let mut audit = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&args[5])
        .context("open audit before sandbox")?;
    let listener = TcpListener::bind(&args[6]).context("bind listener before sandbox")?;
    startup.listener_initialized = true;
    startup
        .enforce_after_listener(&backend, &effective)
        .context("fail-closed sandbox application")?;
    eprintln!(
        "BUSINESS_LOOP_ENTERED policy_digest={}",
        verifier.policy_digest()
    );

    for stream in listener.incoming() {
        let mut stream = stream?;
        let peer = stream.peer_addr()?;
        if !verifier.authorize_inbound(peer.ip(), listener.local_addr()?.port(), "tcp") {
            eprintln!("NETWORK_DENIED source={peer}");
            continue;
        }
        let mut input = Vec::new();
        BufReader::new(stream.try_clone()?).read_until(b'\n', &mut input)?;
        if input.last() == Some(&b'\n') {
            input.pop();
        }
        let result = verifier.process_bytes(&input);
        serde_json::to_writer(&mut audit, &result.audit)?;
        audit.write_all(b"\n")?;
        audit.flush()?;
        serde_json::to_writer(&mut stream, &result.outcome)?;
        stream.write_all(b"\n")?;
    }
    Ok(())
}
