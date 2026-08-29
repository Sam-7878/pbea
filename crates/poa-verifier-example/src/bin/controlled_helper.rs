use std::{fs, path::PathBuf};

fn main() -> anyhow::Result<()> {
    let marker = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("usage: controlled_helper MARKER_PATH"))?;
    fs::write(marker, b"controlled-helper-executed\n")?;
    Ok(())
}
