//! Short-lived private copies of large link previews, shared by CGI processes.
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use sockrocket_core::config::{rule_list::MAX_RULE_LIST_BYTES, storage::MutationGuard};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const THRESHOLD: usize = 64 * 1024;
const SLOTS: usize = 4;
const TTL: Duration = Duration::from_secs(15 * 60);

pub(super) fn root() -> PathBuf {
    let scope = Sha256::digest(super::sockrocket_dir().as_os_str().as_encoded_bytes());
    std::env::temp_dir().join(format!("sockrocket-rule-previews-{:x}", scope))
}

fn private_dir(dir: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    if let Err(e) = builder.create(dir)
        && e.kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err(e.into());
    }
    let metadata = fs::symlink_metadata(dir)?;
    ensure!(metadata.is_dir(), "Invalid preview directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0,
            "Invalid preview directory permissions"
        );
    }
    Ok(())
}

fn valid_token(token: &str) -> bool {
    token.len() == 96
        && token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) fn store(text: &str) -> Option<String> {
    if text.len() <= THRESHOLD || text.len() > MAX_RULE_LIST_BYTES {
        return None;
    }
    store_at(&root(), text).ok()
}

fn store_at(dir: &Path, text: &str) -> Result<String> {
    private_dir(dir)?;
    let _guard = MutationGuard::acquire(&dir.join("previews"))?;
    let mut live = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !valid_token(&entry.file_name().to_string_lossy()) {
            continue;
        }
        let modified = entry.metadata()?.modified()?;
        if modified.elapsed().is_ok_and(|age| age <= TTL) {
            live.push((modified, entry.path()));
        } else {
            fs::remove_file(entry.path())?;
        }
    }
    live.sort_unstable();
    for (_, path) in live.iter().take(live.len().saturating_sub(SLOTS - 1)) {
        fs::remove_file(path)?;
    }

    let token = format!("{:032x}{:x}", rand::random::<u128>(), Sha256::digest(text));
    let path = dir.join(&token);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path)?;
    if let Err(error) = file.write_all(text.as_bytes()) {
        let _ = fs::remove_file(path);
        return Err(error.into());
    }
    Ok(token)
}

pub(super) fn load(token: &str) -> Result<String> {
    load_at(&root(), token, SystemTime::now())
}

fn load_at(dir: &Path, token: &str, now: SystemTime) -> Result<String> {
    ensure!(valid_token(token), "Invalid preview token");
    private_dir(dir)?;
    let _guard = MutationGuard::acquire(&dir.join("previews"))?;
    let path = dir.join(token);
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(&path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.len() > MAX_RULE_LIST_BYTES as u64
        || !now
            .duration_since(meta.modified()?)
            .is_ok_and(|age| age <= TTL)
    {
        fs::remove_file(path)?;
        anyhow::bail!("Preview expired or invalid");
    }
    let mut text = String::with_capacity(meta.len() as usize);
    file.take(MAX_RULE_LIST_BYTES as u64 + 1)
        .read_to_string(&mut text)?;
    ensure!(
        text.len() <= MAX_RULE_LIST_BYTES && format!("{:x}", Sha256::digest(&text)) == token[32..],
        "Preview changed"
    );
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn previews_are_bounded_verified_and_reusable_across_requests() {
        let dir =
            std::env::temp_dir().join(format!("sr-preview-test-{:032x}", rand::random::<u128>()));
        assert!(store("small").is_none());
        let first = store_at(&dir, "first").unwrap();
        assert_eq!(load_at(&dir, &first, SystemTime::now()).unwrap(), "first");
        assert_eq!(load_at(&dir, &first, SystemTime::now()).unwrap(), "first");
        assert!(load_at(&dir, "../config.yaml", SystemTime::now()).is_err());
        fs::write(dir.join(&first), "changed").unwrap();
        assert!(load_at(&dir, &first, SystemTime::now()).is_err());
        let second = store_at(&dir, "second").unwrap();
        assert!(
            load_at(
                &dir,
                &second,
                SystemTime::now() + TTL + Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(!dir.join(second).exists());
        std::thread::scope(|scope| {
            for _ in 0..SLOTS * 2 {
                scope.spawn(|| store_at(&dir, "concurrent").unwrap());
            }
        });
        let files = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|entry| valid_token(&entry.file_name().to_string_lossy()))
            .count();
        assert_eq!(files, SLOTS);
        fs::remove_dir_all(dir).unwrap();
    }
}
