use poa_protocol::{OsBackend, ProcessConstraints, UnveilPath};
use poa_sandbox::mapper::{normalized_unveil, pledge_string, unveil_plan};

fn constraints() -> ProcessConstraints {
    ProcessConstraints {
        os_backend: OsBackend::Openbsd,
        pledge_promises: vec!["stdio".into(), "rpath".into()],
        unveil_paths: vec![],
        lock_after_initialization: true,
    }
}

#[test]
fn sbox_002_mapper_does_not_add_promises() {
    assert_eq!(pledge_string(&constraints()).unwrap(), "rpath stdio");
}

#[test]
fn sbox_003_traversal_rejected() {
    let mut p = constraints();
    p.unveil_paths.push(UnveilPath {
        path: "/var/hete/../etc".into(),
        permissions: "r".into(),
    });
    assert!(normalized_unveil(&p).is_err());
}

#[test]
fn duplicate_path_conflict_rejected() {
    let mut p = constraints();
    p.unveil_paths = vec![
        UnveilPath {
            path: "/var/hete".into(),
            permissions: "r".into(),
        },
        UnveilPath {
            path: "/var/hete".into(),
            permissions: "rw".into(),
        },
    ];
    assert!(normalized_unveil(&p).is_err());
}

#[test]
fn empty_unveil_policy_masks_root_before_lock() {
    assert_eq!(
        unveil_plan(&constraints()).unwrap(),
        vec![UnveilPath {
            path: "/".into(),
            permissions: String::new(),
        }]
    );
}
