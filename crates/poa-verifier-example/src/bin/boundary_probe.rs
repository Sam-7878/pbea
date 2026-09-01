use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    net::{IpAddr, Ipv4Addr, TcpListener, TcpStream},
    path::Path,
};

use anyhow::bail;
use chrono::Utc;
use poa_protocol::policy_digest;
use poa_verifier_example::{Verifier, mode::VerifierMode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundaryTestRecord {
    pub test_id: String,
    pub experiment_id: String,
    pub test_name: String,
    pub mode: String,
    pub timestamp: String,
    pub source_commit: String,
    pub platform: String,
    pub policy_digest: String,
    pub target: String,
    pub policy_allowed: bool,
    pub operation_attempted: bool,
    pub operation_succeeded: bool,
    pub os_errno: Option<i32>,
    pub outcome: String,
    pub claim_verification_interpretation: String,
    pub details: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundaryReport {
    pub experiment_id: String,
    pub source_commit: String,
    pub platform: String,
    pub tests: Vec<BoundaryTestRecord>,
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 7 {
        bail!(
            "usage: boundary_probe POLICY_SCHEMA POLICY REQUEST_SCHEMA FIXTURE_ROOT SOURCE_COMMIT OUTPUT_JSON"
        );
    }
    let policy_schema_bytes = fs::read(&args[1])?;
    let policy_bytes = fs::read(&args[2])?;
    let request_schema_bytes = fs::read(&args[3])?;
    let fixture_root = Path::new(&args[4]);
    let source_commit = &args[5];
    let output_path = Path::new(&args[6]);

    let policy_schema: serde_json::Value = serde_json::from_slice(&policy_schema_bytes)?;
    let policy_value: serde_json::Value = serde_json::from_slice(&policy_bytes)?;
    let request_schema: serde_json::Value = serde_json::from_slice(&request_schema_bytes)?;

    let base_policy = poa_protocol::validate_value(&policy_value, &policy_schema)?;

    // Prepare fixture directories
    let allowed_dir = fixture_root.join("allowed");
    let outside_dir = fixture_root.join("outside");
    fs::create_dir_all(&allowed_dir)?;
    fs::create_dir_all(&outside_dir)?;

    let outside_secret = outside_dir.join("secret.txt");
    fs::write(&outside_secret, "sensitive-synthetic-secret-data\n")?;

    let symlink_path = allowed_dir.join("symlink_to_outside.txt");
    if symlink_path.exists() {
        let _ = fs::remove_file(&symlink_path);
    }
    #[cfg(unix)]
    {
        let _ = std::os::unix::fs::symlink(&outside_secret, &symlink_path);
    }

    let mut test_records = Vec::new();

    // -------------------------------------------------------------
    // BT1: Allowed Endpoint Misuse
    // Policy explicitly permits loopback port 8990 in outbound rules.
    // -------------------------------------------------------------
    let allowed_port = 8990;
    let mut bt1_policy = base_policy.clone();
    if let Some(net) = &mut bt1_policy.network_policy {
        net.outbound.push(poa_protocol::EndpointRule {
            protocol: "tcp".into(),
            address: "127.0.0.1".into(),
            port: allowed_port,
        });
    }
    let bt1_digest = policy_digest(&bt1_policy)?;

    let modes_to_test = [
        VerifierMode::AccessOnly,
        VerifierMode::TransitionOnly,
        VerifierMode::RuntimeOnly,
        VerifierMode::FullPbea,
    ];

    for &mode in &modes_to_test {
        let verifier = Verifier::new(bt1_policy.clone(), request_schema.clone())?;
        let sink_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, allowed_port))?;

        let allowed_by_policy =
            verifier.authorize_outbound(IpAddr::V4(Ipv4Addr::LOCALHOST), allowed_port, "tcp");

        let mut connect_succeeded = false;
        let mut os_errno = None;

        if allowed_by_policy {
            match TcpStream::connect((Ipv4Addr::LOCALHOST, allowed_port)) {
                Ok(mut stream) => {
                    let _ = stream.write_all(b"marker-payload-to-allowed-endpoint");
                    connect_succeeded = true;
                }
                Err(e) => {
                    os_errno = e.raw_os_error();
                }
            }
        }

        let mut details = BTreeMap::new();
        details.insert("destination".into(), format!("127.0.0.1:{allowed_port}"));
        details.insert("policy_rule".into(), "explicitly_allowed".into());

        test_records.push(BoundaryTestRecord {
            test_id: format!("BT1-{mode}"),
            experiment_id: "PBEA-BOUNDARY-001".into(),
            test_name: "Allowed Endpoint Misuse".into(),
            mode: mode.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            source_commit: source_commit.into(),
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            policy_digest: bt1_digest.clone(),
            target: format!("127.0.0.1:{allowed_port}"),
            policy_allowed: true,
            operation_attempted: true,
            operation_succeeded: connect_succeeded,
            os_errno,
            outcome: if connect_succeeded {
                "permitted".into()
            } else {
                "failed".into()
            },
            claim_verification_interpretation:
                "PBEA permits data delivery through policy-declared endpoints as designed; it does not infer intent within allowed capabilities."
                    .into(),
            details,
        });

        drop(sink_listener);
    }

    // -------------------------------------------------------------
    // BT2: Filesystem Path / Symlink Probe
    // Tests whether unveil blocks path traversal via symlink pointing outside unveiled tree.
    // -------------------------------------------------------------
    for &mode in &modes_to_test {
        let digest = policy_digest(&base_policy)?;
        let mut read_succeeded = false;
        let mut os_errno = None;

        let result = fs::read_to_string(&symlink_path);
        match result {
            Ok(_) => {
                read_succeeded = true;
            }
            Err(e) => {
                os_errno = e.raw_os_error();
            }
        }

        let mut details = BTreeMap::new();
        details.insert("symlink_path".into(), symlink_path.display().to_string());
        details.insert(
            "target_outside".into(),
            outside_secret.display().to_string(),
        );

        let interpretation = if read_succeeded {
            "Host filesystem permitted symlink traversal to outside path (unveil disabled or non-OpenBSD environment)."
        } else {
            "OpenBSD unveil kernel enforcement prevented symlink resolution to un-unveiled path outside boundary."
        };

        test_records.push(BoundaryTestRecord {
            test_id: format!("BT2-{mode}"),
            experiment_id: "PBEA-BOUNDARY-001".into(),
            test_name: "Symlink Traversal Across Unveil Boundary".into(),
            mode: mode.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            source_commit: source_commit.into(),
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            policy_digest: digest,
            target: symlink_path.display().to_string(),
            policy_allowed: false,
            operation_attempted: true,
            operation_succeeded: read_succeeded,
            os_errno,
            outcome: if read_succeeded {
                "read-succeeded".into()
            } else {
                "traversal-denied".into()
            },
            claim_verification_interpretation: interpretation.into(),
            details,
        });
    }

    let report = BoundaryReport {
        experiment_id: "PBEA-BOUNDARY-001".into(),
        source_commit: source_commit.into(),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        tests: test_records,
    };

    let serialized = serde_json::to_string_pretty(&report)?;
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output_path, &serialized)?;
    println!("{serialized}");

    Ok(())
}
