//! Live monitoring with filesystem notifications.
//!
//! Notifications are only hints about *which paths to look at*: every path they name is hashed again
//! and compared with the last known state, so a missed or duplicated event cannot hide a change that
//! the next event on that path would reveal. Events are debounced, because saving one file usually
//! produces several, and a file that is still being written (or locked) is retried.

use crate::baseline::{compare_entry, diff, entry_for, key, snapshot, Algo, Change, Entry, Filter};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub struct WatchConfig<'a> {
    /// Absolute roots: directories are watched recursively, files by their parent directory.
    pub roots: &'a [PathBuf],
    pub filter: &'a Filter,
    pub algo: Algo,
    pub debounce: Duration,
    pub strict_time: bool,
}

fn in_scope(roots: &[PathBuf], p: &Path) -> bool {
    roots.iter().any(|r| if r.is_dir() { p.starts_with(r) } else { p == r })
}

/// Compares the named paths with `state`, updates `state`, and returns what changed. Paths that
/// could not be read yet are returned for another attempt.
pub fn settle(paths: &BTreeSet<PathBuf>, cfg: &WatchConfig, state: &mut BTreeMap<String, Entry>) -> (Vec<Change>, BTreeSet<PathBuf>) {
    let mut changes = Vec::new();
    let mut retry = BTreeSet::new();
    let apply = |k: String, new: Entry, state: &mut BTreeMap<String, Entry>, changes: &mut Vec<Change>| {
        match state.get(&k) {
            None => changes.push(Change::Added { path: k.clone(), hash: new.hash.clone(), size: new.size }),
            Some(old) => changes.extend(compare_entry(&k, old, &new, cfg.strict_time)),
        }
        state.insert(k, new);
    };
    for p in paths {
        if cfg.filter.excludes(p) {
            continue;
        }
        let k = key(p);
        match fs::symlink_metadata(p) {
            Ok(md) if md.is_file() => match entry_for(p, cfg.algo, None) {
                Ok(e) => apply(k, e, state, &mut changes),
                Err(_) => {
                    retry.insert(p.clone());
                }
            },
            Ok(md) if md.is_dir() => {
                // A new or renamed directory: everything inside it is new to us.
                let s = snapshot(std::slice::from_ref(p), cfg.filter, cfg.algo, None);
                for (fk, e) in s.entries {
                    apply(fk, e, state, &mut changes);
                }
            }
            Ok(_) => {}
            Err(_) => {
                // Gone: the file itself, or everything that was under a removed directory.
                let prefix = format!("{k}/");
                let gone: Vec<String> = state.keys().filter(|s| **s == k || s.starts_with(&prefix)).cloned().collect();
                for g in gone {
                    if let Some(old) = state.remove(&g) {
                        changes.push(Change::Removed { path: g, hash: old.hash });
                    }
                }
            }
        }
    }
    changes.sort_by(|a, b| a.path().cmp(b.path()));
    (changes, retry)
}

/// Watches until `stop` is set. `ready` runs once the watches are in place. `on_change` is called
/// for every change in order. `state` starts as the baseline and follows the files from then on.
pub fn watch(cfg: &WatchConfig, state: &mut BTreeMap<String, Entry>, stop: &AtomicBool, ready: &mut dyn FnMut(), on_change: &mut dyn FnMut(Change)) -> notify::Result<()> {
    let (tx, rx) = mpsc::channel();
    let mut watcher: RecommendedWatcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })?;
    for r in cfg.roots {
        if r.is_dir() {
            watcher.watch(r, RecursiveMode::Recursive)?;
        } else {
            watcher.watch(r.parent().unwrap_or(Path::new(".")), RecursiveMode::NonRecursive)?;
        }
    }
    ready();

    let mut pending: BTreeSet<PathBuf> = BTreeSet::new();
    let mut last_event = Instant::now();
    let mut attempts = 0u32;
    let mut rescan = false;
    while !stop.load(Ordering::SeqCst) {
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(Ok(ev)) => {
                if ev.need_rescan() {
                    rescan = true;
                }
                if !matches!(ev.kind, EventKind::Access(_)) {
                    for p in ev.paths {
                        if in_scope(cfg.roots, &p) {
                            pending.insert(p);
                        }
                    }
                }
                last_event = Instant::now();
            }
            // The OS dropped events (queue overflow): fall back to comparing everything.
            Ok(Err(_)) => {
                rescan = true;
                last_event = Instant::now();
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if (rescan || !pending.is_empty()) && last_event.elapsed() >= cfg.debounce {
            if rescan {
                rescan = false;
                let now = snapshot(cfg.roots, cfg.filter, cfg.algo, Some(state));
                for c in diff(state, &now.entries, cfg.strict_time) {
                    on_change(c);
                }
                *state = now.entries;
            }
            let batch = std::mem::take(&mut pending);
            let (changes, retry) = settle(&batch, cfg, state);
            for c in changes {
                on_change(c);
            }
            // Locked or half-written files get a few more chances, a debounce apart.
            if retry.is_empty() {
                attempts = 0;
            } else if attempts < 20 {
                attempts += 1;
                pending = retry;
            } else {
                attempts = 0;
            }
            last_event = Instant::now();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write(p: &Path, c: &[u8]) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::File::create(p).unwrap().write_all(c).unwrap();
    }

    fn cfg<'a>(roots: &'a [PathBuf], f: &'a Filter) -> WatchConfig<'a> {
        WatchConfig { roots, filter: f, algo: Algo::Sha256, debounce: Duration::from_millis(50), strict_time: false }
    }

    #[test]
    fn settle_reports_added_modified_removed_and_updates_state() {
        let t = tempfile::tempdir().unwrap();
        let root = std::path::absolute(t.path()).unwrap();
        write(&root.join("a.txt"), b"one");
        write(&root.join("dir/b.txt"), b"bee");
        let filter = Filter::new(&[]).unwrap();
        let roots = vec![root.clone()];
        let mut state = snapshot(&roots, &filter, Algo::Sha256, None).entries;
        let c = cfg(&roots, &filter);

        write(&root.join("a.txt"), b"two");
        write(&root.join("c.txt"), b"new");
        let batch: BTreeSet<PathBuf> = [root.join("a.txt"), root.join("c.txt")].into();
        let (changes, retry) = settle(&batch, &c, &mut state);
        assert!(retry.is_empty());
        assert_eq!(changes.iter().map(|c| c.label()).collect::<Vec<_>>(), ["modified", "added"]);
        // State follows: the same batch again reports nothing.
        assert!(settle(&batch, &c, &mut state).0.is_empty());

        // Removing a directory removes everything that was under it.
        fs::remove_dir_all(root.join("dir")).unwrap();
        let (changes, _) = settle(&[root.join("dir")].into(), &c, &mut state);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].label(), "removed");
        assert!(changes[0].path().ends_with("dir/b.txt"));
        assert!(!state.keys().any(|k| k.contains("/dir/")));
    }

    #[test]
    fn settle_handles_new_directories_and_exclusions() {
        let t = tempfile::tempdir().unwrap();
        let root = std::path::absolute(t.path()).unwrap();
        write(&root.join("seed.txt"), b"s");
        let filter = Filter::new(&["**/*.tmp".into()]).unwrap();
        let roots = vec![root.clone()];
        let mut state = snapshot(&roots, &filter, Algo::Sha256, None).entries;
        write(&root.join("newdir/x.txt"), b"x");
        write(&root.join("newdir/y.tmp"), b"ignored");
        let (changes, _) = settle(&[root.join("newdir")].into(), &cfg(&roots, &filter), &mut state);
        assert_eq!(changes.len(), 1);
        assert!(changes[0].path().ends_with("newdir/x.txt"));
        let (none, _) = settle(&[root.join("newdir/y.tmp")].into(), &cfg(&roots, &filter), &mut state);
        assert!(none.is_empty());
    }

    #[test]
    fn scope_check() {
        let t = tempfile::tempdir().unwrap();
        let dir = std::path::absolute(t.path()).unwrap();
        write(&dir.join("f.txt"), b"x");
        assert!(in_scope(std::slice::from_ref(&dir), &dir.join("sub/deep.txt")));
        assert!(!in_scope(std::slice::from_ref(&dir), Path::new("/somewhere/else.txt")));
        let file_root = dir.join("f.txt");
        assert!(in_scope(std::slice::from_ref(&file_root), &file_root));
        assert!(!in_scope(&[file_root], &dir.join("other.txt")));
    }
}
