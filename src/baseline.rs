//! Baselines: what a set of files looked like at a known-good moment, and how to compare that with
//! the present.

use globset::{Glob, GlobSet, GlobSetBuilder};
use hmac::{Hmac, Mac};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::UNIX_EPOCH;
use walkdir::WalkDir;

pub const VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Algo {
    Sha256,
    Blake3,
}

impl Algo {
    /// Hex digest of everything `r` yields.
    pub fn hash_reader<R: Read>(self, mut r: R) -> io::Result<String> {
        let mut buf = vec![0u8; 1 << 20];
        match self {
            Algo::Sha256 => {
                let mut h = Sha256::new();
                loop {
                    let n = r.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    h.update(&buf[..n]);
                }
                Ok(hex::encode(h.finalize()))
            }
            Algo::Blake3 => {
                let mut h = blake3::Hasher::new();
                loop {
                    let n = r.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    h.update(&buf[..n]);
                }
                Ok(h.finalize().to_hex().to_string())
            }
        }
    }

    pub fn hash_file(self, path: &Path) -> io::Result<String> {
        self.hash_reader(File::open(path)?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub size: u64,
    /// Modification time in nanoseconds since the Unix epoch.
    pub mtime_ns: i64,
    pub hash: String,
    pub readonly: bool,
    /// Unix permission bits; absent on Windows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub algo: Algo,
    pub created_unix: u64,
    pub roots: Vec<String>,
    pub excludes: Vec<String>,
    pub entries: BTreeMap<String, Entry>,
    /// HMAC-SHA256 over the rest of the file, when signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac: Option<String>,
}

#[derive(Debug)]
pub enum BaselineError {
    Io(io::Error),
    Parse(serde_json::Error),
    Version(u32),
    Unsigned,
    BadSignature,
}

impl std::fmt::Display for BaselineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BaselineError::Io(e) => write!(f, "{e}"),
            BaselineError::Parse(e) => write!(f, "baseline is not valid: {e}"),
            BaselineError::Version(v) => write!(f, "baseline version {v} is not supported (expected {VERSION})"),
            BaselineError::Unsigned => write!(f, "a key was given but the baseline is not signed"),
            BaselineError::BadSignature => write!(f, "baseline signature does not match: the file was modified or the key is wrong"),
        }
    }
}

impl std::error::Error for BaselineError {}

impl From<io::Error> for BaselineError {
    fn from(e: io::Error) -> Self {
        BaselineError::Io(e)
    }
}

type HmacSha256 = Hmac<Sha256>;

impl Baseline {
    /// The bytes that are signed: this baseline serialized without its signature.
    fn signed_bytes(&self) -> Vec<u8> {
        let mut c = self.clone();
        c.hmac = None;
        serde_json::to_vec(&c).expect("a baseline always serializes")
    }

    pub fn sign(&mut self, key: &[u8]) {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(&self.signed_bytes());
        self.hmac = Some(hex::encode(mac.finalize().into_bytes()));
    }

    pub fn verify(&self, key: &[u8]) -> Result<(), BaselineError> {
        let sig = self.hmac.as_ref().ok_or(BaselineError::Unsigned)?;
        let want = hex::decode(sig).map_err(|_| BaselineError::BadSignature)?;
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(&self.signed_bytes());
        mac.verify_slice(&want).map_err(|_| BaselineError::BadSignature)
    }

    /// Writes through a temporary file and renames it over `path`, so an interrupted write cannot
    /// leave a half-written baseline.
    pub fn save(&self, path: &Path) -> Result<(), BaselineError> {
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(self).map_err(BaselineError::Parse)?)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Loads a baseline. With a key, the signature must verify; without one, a signature is not checked.
    pub fn load(path: &Path, key: Option<&[u8]>) -> Result<Baseline, BaselineError> {
        let b: Baseline = serde_json::from_slice(&fs::read(path)?).map_err(BaselineError::Parse)?;
        if b.version != VERSION {
            return Err(BaselineError::Version(b.version));
        }
        if let Some(k) = key {
            b.verify(k)?;
        }
        Ok(b)
    }
}

/// Glob patterns for paths to leave out. Matched against the full path with `/` separators.
pub struct Filter {
    set: GlobSet,
}

impl Filter {
    pub fn new(patterns: &[String]) -> Result<Filter, globset::Error> {
        let mut b = GlobSetBuilder::new();
        for p in patterns {
            b.add(Glob::new(p)?);
        }
        Ok(Filter { set: b.build()? })
    }

    pub fn excludes(&self, path: &Path) -> bool {
        !self.set.is_empty() && self.set.is_match(key(path))
    }
}

/// The string used for a path in a baseline: absolute, forward slashes.
pub fn key(path: &Path) -> String {
    let abs = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    abs.to_string_lossy().replace('\\', "/")
}

pub struct Scan {
    pub entries: BTreeMap<String, Entry>,
    /// Human-readable messages for files or directories that could not be read.
    pub errors: Vec<String>,
    /// Keys of files that exist but could not be hashed. They are not evidence of removal.
    pub unreadable: std::collections::BTreeSet<String>,
    /// Symlinks and other non-regular files, which are not hashed.
    pub skipped: u64,
}

/// Describes one file. `previous` lets an unchanged size and mtime reuse the earlier hash.
pub fn entry_for(path: &Path, algo: Algo, previous: Option<&Entry>) -> io::Result<Entry> {
    let md = fs::metadata(path)?;
    let mtime_ns = match md.modified()?.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i64,
        Err(e) => -(e.duration().as_nanos() as i64),
    };
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        Some(md.permissions().mode() & 0o7777)
    };
    #[cfg(not(unix))]
    let mode = None;
    let hash = match previous {
        Some(p) if p.size == md.len() && p.mtime_ns == mtime_ns => p.hash.clone(),
        _ => algo.hash_file(path)?,
    };
    Ok(Entry { size: md.len(), mtime_ns, hash, readonly: md.permissions().readonly(), mode })
}

/// Hashes every regular file under `roots`, in parallel. When `previous` is given, files whose size
/// and modification time are unchanged are not read again.
pub fn snapshot(roots: &[PathBuf], filter: &Filter, algo: Algo, previous: Option<&BTreeMap<String, Entry>>) -> Scan {
    let mut files: Vec<PathBuf> = Vec::new();
    let (mut errors, mut skipped) = (Vec::new(), 0u64);
    for root in roots {
        for e in WalkDir::new(root).follow_links(false).into_iter().filter_entry(|e| !filter.excludes(e.path())) {
            match e {
                Ok(e) if e.file_type().is_file() => files.push(e.into_path()),
                Ok(e) if e.file_type().is_dir() => {}
                Ok(_) => skipped += 1,
                Err(err) => errors.push(err.to_string()),
            }
        }
    }
    let errs = Mutex::new(errors);
    let unreadable = Mutex::new(std::collections::BTreeSet::new());
    let entries: BTreeMap<String, Entry> = files
        .par_iter()
        .filter_map(|p| {
            let k = key(p);
            match entry_for(p, algo, previous.and_then(|m| m.get(&k))) {
                Ok(e) => Some((k, e)),
                Err(err) => {
                    errs.lock().unwrap().push(format!("{}: {err}", p.display()));
                    unreadable.lock().unwrap().insert(k);
                    None
                }
            }
        })
        .collect();
    let mut errors = errs.into_inner().unwrap();
    errors.sort();
    Scan { entries, errors, unreadable: unreadable.into_inner().unwrap(), skipped }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Change {
    Added { path: String, hash: String, size: u64 },
    Removed { path: String, hash: String },
    Modified { path: String, old_hash: String, new_hash: String, old_size: u64, new_size: u64 },
    /// Same content, different permissions (or, with `strict_time`, a different modification time).
    Metadata { path: String, details: String },
}

impl Change {
    pub fn path(&self) -> &str {
        match self {
            Change::Added { path, .. } | Change::Removed { path, .. } | Change::Modified { path, .. } | Change::Metadata { path, .. } => path,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Change::Added { .. } => "added",
            Change::Removed { .. } => "removed",
            Change::Modified { .. } => "modified",
            Change::Metadata { .. } => "metadata",
        }
    }
}

/// How one entry differs from the baseline's, or `None` if it does not.
pub fn compare_entry(path: &str, old: &Entry, new: &Entry, strict_time: bool) -> Option<Change> {
    if old.hash != new.hash {
        return Some(Change::Modified { path: path.into(), old_hash: old.hash.clone(), new_hash: new.hash.clone(), old_size: old.size, new_size: new.size });
    }
    let mut what = Vec::new();
    if old.readonly != new.readonly {
        what.push(format!("read-only {} -> {}", old.readonly, new.readonly));
    }
    if old.mode != new.mode {
        if let (Some(a), Some(b)) = (old.mode, new.mode) {
            what.push(format!("mode {a:o} -> {b:o}"));
        }
    }
    if strict_time && old.mtime_ns != new.mtime_ns {
        what.push("modification time changed".to_string());
    }
    (!what.is_empty()).then(|| Change::Metadata { path: path.into(), details: what.join(", ") })
}

/// All differences between two snapshots, ordered by path.
pub fn diff(old: &BTreeMap<String, Entry>, new: &BTreeMap<String, Entry>, strict_time: bool) -> Vec<Change> {
    let mut out = Vec::new();
    for (p, o) in old {
        match new.get(p) {
            None => out.push(Change::Removed { path: p.clone(), hash: o.hash.clone() }),
            Some(n) => out.extend(compare_entry(p, o, n, strict_time)),
        }
    }
    for (p, n) in new {
        if !old.contains_key(p) {
            out.push(Change::Added { path: p.clone(), hash: n.hash.clone(), size: n.size });
        }
    }
    out.sort_by(|a, b| a.path().cmp(b.path()));
    out
}

/// `2026-10-01T12:00:00Z` from Unix seconds.
pub fn iso_utc(unix: u64) -> String {
    let z = (unix / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (m <= 2) as i64;
    let r = unix % 86_400;
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", r / 3600, r % 3600 / 60, r % 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write(p: &Path, content: &[u8]) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::File::create(p).unwrap().write_all(content).unwrap();
    }

    fn no_filter() -> Filter {
        Filter::new(&[]).unwrap()
    }

    #[test]
    fn known_answer_hashes() {
        assert_eq!(Algo::Sha256.hash_reader(&b"abc"[..]).unwrap(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(Algo::Sha256.hash_reader(&b""[..]).unwrap(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(Algo::Blake3.hash_reader(&b"abc"[..]).unwrap(), "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85");
    }

    #[test]
    fn hashing_a_file_larger_than_the_buffer() {
        let t = tempfile::tempdir().unwrap();
        let data = vec![0xabu8; (1 << 20) * 2 + 17];
        write(&t.path().join("big.bin"), &data);
        let a = Algo::Sha256.hash_file(&t.path().join("big.bin")).unwrap();
        assert_eq!(a, hex::encode(Sha256::digest(&data)));
    }

    #[test]
    fn snapshot_and_diff_find_every_kind_of_change() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        write(&r.join("keep.txt"), b"same");
        write(&r.join("edit.txt"), b"before");
        write(&r.join("gone.txt"), b"bye");
        write(&r.join("sub/deep.txt"), b"deep");
        let before = snapshot(&[r.to_path_buf()], &no_filter(), Algo::Sha256, None);
        assert_eq!((before.entries.len(), before.errors.len()), (4, 0));

        write(&r.join("edit.txt"), b"after!");
        fs::remove_file(r.join("gone.txt")).unwrap();
        write(&r.join("new.txt"), b"hello");
        let after = snapshot(&[r.to_path_buf()], &no_filter(), Algo::Sha256, None);
        let changes = diff(&before.entries, &after.entries, false);
        let kinds: Vec<(&str, String)> = changes.iter().map(|c| (c.label(), c.path().rsplit('/').next().unwrap().to_string())).collect();
        assert_eq!(kinds, [("modified", "edit.txt".into()), ("removed", "gone.txt".into()), ("added", "new.txt".into())]);
        match &changes[0] {
            Change::Modified { old_size, new_size, old_hash, new_hash, .. } => {
                assert_eq!((*old_size, *new_size), (6, 6));
                assert_ne!(old_hash, new_hash);
            }
            other => panic!("{other:?}"),
        }
        assert!(diff(&before.entries, &before.entries, true).is_empty());
    }

    #[test]
    fn same_size_edit_is_still_detected() {
        let t = tempfile::tempdir().unwrap();
        write(&t.path().join("f"), b"AAAA");
        let a = snapshot(&[t.path().to_path_buf()], &no_filter(), Algo::Blake3, None);
        write(&t.path().join("f"), b"AAAB");
        let b = snapshot(&[t.path().to_path_buf()], &no_filter(), Algo::Blake3, None);
        assert_eq!(diff(&a.entries, &b.entries, false).len(), 1);
    }

    #[test]
    fn metadata_changes_and_strict_time() {
        let base = Entry { size: 3, mtime_ns: 100, hash: "h".into(), readonly: false, mode: Some(0o644) };
        let mut touched = base.clone();
        touched.mtime_ns = 200;
        assert!(compare_entry("p", &base, &touched, false).is_none(), "a touch alone is not a change by default");
        assert_eq!(compare_entry("p", &base, &touched, true).unwrap().label(), "metadata");
        let mut ro = base.clone();
        ro.readonly = true;
        ro.mode = Some(0o444);
        match compare_entry("p", &base, &ro, false).unwrap() {
            Change::Metadata { details, .. } => assert!(details.contains("read-only false -> true") && details.contains("mode 644 -> 444"), "{details}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn fast_mode_reuses_hashes_only_when_size_and_time_match() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("f.txt");
        write(&p, b"one");
        let first = snapshot(&[t.path().to_path_buf()], &no_filter(), Algo::Sha256, None);
        let k = key(&p);
        // Poison the stored hash: if fast mode reuses it, the poison survives.
        let mut poisoned = first.entries.clone();
        poisoned.get_mut(&k).unwrap().hash = "poison".into();
        let reused = snapshot(&[t.path().to_path_buf()], &no_filter(), Algo::Sha256, Some(&poisoned));
        assert_eq!(reused.entries[&k].hash, "poison", "unchanged size and mtime: hash reused");
        // Same size, different mtime: the file is read again.
        let mut older = poisoned.clone();
        older.get_mut(&k).unwrap().mtime_ns -= 1;
        let reread = snapshot(&[t.path().to_path_buf()], &no_filter(), Algo::Sha256, Some(&older));
        assert_eq!(reread.entries[&k].hash, first.entries[&k].hash);
    }

    #[test]
    fn exclusions_prune_directories_and_files() {
        let t = tempfile::tempdir().unwrap();
        write(&t.path().join("src/a.rs"), b"a");
        write(&t.path().join("target/debug/b.o"), b"b");
        write(&t.path().join("notes.log"), b"c");
        let f = Filter::new(&["**/target".into(), "**/*.log".into()]).unwrap();
        let s = snapshot(&[t.path().to_path_buf()], &f, Algo::Sha256, None);
        let names: Vec<&str> = s.entries.keys().map(|k| k.rsplit('/').next().unwrap()).collect();
        assert_eq!(names, ["a.rs"]);
        assert!(Filter::new(&["[".into()]).is_err());
    }

    #[test]
    fn signing_detects_tampering_and_wrong_keys() {
        let mut b = Baseline { version: VERSION, algo: Algo::Sha256, created_unix: 1, roots: vec!["/r".into()], excludes: vec![], entries: BTreeMap::new(), hmac: None };
        b.entries.insert("/r/f".into(), Entry { size: 1, mtime_ns: 2, hash: "aa".into(), readonly: false, mode: None });
        assert!(matches!(b.verify(b"k"), Err(BaselineError::Unsigned)));
        b.sign(b"secret");
        assert!(b.verify(b"secret").is_ok());
        assert!(matches!(b.verify(b"other"), Err(BaselineError::BadSignature)));
        let mut tampered = b.clone();
        tampered.entries.get_mut("/r/f").unwrap().hash = "bb".into();
        assert!(matches!(tampered.verify(b"secret"), Err(BaselineError::BadSignature)));
        let mut removed = b.clone();
        removed.entries.clear();
        assert!(matches!(removed.verify(b"secret"), Err(BaselineError::BadSignature)));
    }

    #[test]
    fn save_load_round_trip_and_rejects_bad_files() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("base.json");
        let mut b = Baseline { version: VERSION, algo: Algo::Blake3, created_unix: 5, roots: vec!["/x".into()], excludes: vec!["*.tmp".into()], entries: BTreeMap::new(), hmac: None };
        b.sign(b"k");
        b.save(&p).unwrap();
        assert_eq!(Baseline::load(&p, Some(b"k")).unwrap(), b);
        assert!(matches!(Baseline::load(&p, Some(b"wrong")), Err(BaselineError::BadSignature)));
        assert!(Baseline::load(&p, None).is_ok(), "no key, no signature check");
        fs::write(&p, b"not json").unwrap();
        assert!(matches!(Baseline::load(&p, None), Err(BaselineError::Parse(_))));
        fs::write(&p, br#"{"version":99,"algo":"sha256","created_unix":0,"roots":[],"excludes":[],"entries":{}}"#).unwrap();
        assert!(matches!(Baseline::load(&p, None), Err(BaselineError::Version(99))));
        assert!(matches!(Baseline::load(&t.path().join("missing.json"), None), Err(BaselineError::Io(_))));
    }

    #[test]
    fn iso_dates() {
        assert_eq!(iso_utc(1_696_946_136), "2023-10-10T13:55:36Z");
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00Z");
    }
}
