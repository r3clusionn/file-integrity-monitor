//! The real binary against real directories, including live watching with file system events.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn fim(args: &[&str]) -> (i32, String, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_fim")).args(args).output().unwrap();
    (o.status.code().unwrap(), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

fn write(p: &Path, c: &[u8]) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::File::create(p).unwrap().write_all(c).unwrap();
}

struct Fixture {
    _dir: TempDir,
    data: PathBuf,
    base: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    write(&data.join("config.ini"), b"setting=1\n");
    write(&data.join("bin/tool.exe"), b"MZ-pretend-binary");
    write(&data.join("notes/readme.txt"), b"hello");
    let base = dir.path().join("baseline.json");
    Fixture { _dir: dir, data, base }
}

fn p(x: &Path) -> &str {
    x.to_str().unwrap()
}

#[test]
fn clean_then_every_kind_of_change_then_accept() {
    let f = fixture();
    let (code, out, err) = fim(&["init", p(&f.data), "-b", p(&f.base)]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("baseline of 3 files"), "{out}");

    let (code, out, _) = fim(&["check", "-b", p(&f.base)]);
    assert_eq!((code, out.contains("no changes")), (0, true), "{out}");

    write(&f.data.join("config.ini"), b"setting=2\n");
    fs::remove_file(f.data.join("notes/readme.txt")).unwrap();
    write(&f.data.join("dropped.dll"), b"new file");
    let (code, out, _) = fim(&["check", "-b", p(&f.base)]);
    assert_eq!(code, 1, "{out}");
    assert!(out.lines().any(|l| l.starts_with("modified") && l.contains("config.ini")), "{out}");
    assert!(out.lines().any(|l| l.starts_with("removed") && l.contains("readme.txt")), "{out}");
    assert!(out.lines().any(|l| l.starts_with("added") && l.contains("dropped.dll")), "{out}");
    assert!(out.contains("1 modified, 1 added, 1 removed, 0 metadata, 0 unreadable"), "{out}");

    // JSON output carries the same facts.
    let (code, json, _) = fim(&["check", "-b", p(&f.base), "--json"]);
    assert_eq!(code, 1);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let kinds: Vec<&str> = v["changes"].as_array().unwrap().iter().map(|c| c["kind"].as_str().unwrap()).collect();
    assert_eq!(kinds.len(), 3);
    assert!(kinds.contains(&"modified") && kinds.contains(&"added") && kinds.contains(&"removed"));

    // Accepting makes the current state the new baseline.
    let (code, out, _) = fim(&["accept", "-b", p(&f.base)]);
    assert_eq!(code, 0);
    assert!(out.contains("3 changes accepted"), "{out}");
    assert_eq!(fim(&["check", "-b", p(&f.base)]).0, 0);
}

#[test]
fn init_refuses_to_overwrite_and_rejects_bad_input() {
    let f = fixture();
    assert_eq!(fim(&["init", p(&f.data), "-b", p(&f.base)]).0, 0);
    let (code, _, err) = fim(&["init", p(&f.data), "-b", p(&f.base)]);
    assert_eq!(code, 2);
    assert!(err.contains("already exists"), "{err}");
    assert_eq!(fim(&["init", p(&f.data), "-b", p(&f.base), "--force"]).0, 0);
    assert_eq!(fim(&["init", "no-such-dir", "-b", "x.json"]).0, 2);
    assert_eq!(fim(&["init", p(&f.data), "-b", "y.json", "--exclude", "["]).0, 2);
    assert_eq!(fim(&["check", "-b", "missing-baseline.json"]).0, 2);
}

#[test]
fn excludes_are_stored_and_applied_by_check() {
    let f = fixture();
    write(&f.data.join("app.log"), b"noise");
    assert_eq!(fim(&["init", p(&f.data), "-b", p(&f.base), "--exclude", "**/*.log"]).0, 0);
    write(&f.data.join("app.log"), b"more noise");
    write(&f.data.join("other.log"), b"x");
    assert_eq!(fim(&["check", "-b", p(&f.base)]).0, 0, "excluded files never count");
}

#[test]
fn signed_baselines_reject_tampering_and_wrong_keys() {
    let f = fixture();
    let key = f.base.with_extension("key");
    fs::write(&key, "correct horse battery staple\n").unwrap();
    let other = f.base.with_extension("key2");
    fs::write(&other, "something else").unwrap();
    let (code, out, _) = fim(&["init", p(&f.data), "-b", p(&f.base), "--key-file", p(&key)]);
    assert_eq!(code, 0);
    assert!(out.contains("signed"), "{out}");
    assert_eq!(fim(&["check", "-b", p(&f.base), "--key-file", p(&key)]).0, 0);

    let (code, _, err) = fim(&["check", "-b", p(&f.base), "--key-file", p(&other)]);
    assert_eq!(code, 2);
    assert!(err.contains("signature"), "{err}");

    // An attacker rewrites the stored hash of the config file to match their edit.
    let text = fs::read_to_string(&f.base).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let k = v["entries"].as_object().unwrap().keys().find(|k| k.ends_with("config.ini")).unwrap().clone();
    v["entries"][&k]["hash"] = "00".repeat(32).into();
    fs::write(&f.base, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    let (code, _, err) = fim(&["check", "-b", p(&f.base), "--key-file", p(&key)]);
    assert_eq!(code, 2, "a tampered baseline must not be trusted");
    assert!(err.contains("signature"), "{err}");

    // A signed baseline cannot be silently replaced by an unsigned one: accept demands the key.
    let f2 = fixture();
    fs::write(&key, "k").unwrap();
    assert_eq!(fim(&["init", p(&f2.data), "-b", p(&f2.base), "--key-file", p(&key)]).0, 0);
    let (code, _, err) = fim(&["accept", "-b", p(&f2.base)]);
    assert_eq!(code, 2);
    assert!(err.contains("signed"), "{err}");
    assert_eq!(fim(&["accept", "-b", p(&f2.base), "--key-file", p(&key)]).0, 0);
    assert_eq!(fim(&["check", "-b", p(&f2.base), "--key-file", p(&key)]).0, 0, "the new baseline is signed too");
}

#[test]
fn fast_check_trusts_size_and_mtime_and_full_check_does_not() {
    let f = fixture();
    let file = f.data.join("config.ini");
    assert_eq!(fim(&["init", p(&f.data), "-b", p(&f.base)]).0, 0);
    let mtime = fs::metadata(&file).unwrap().modified().unwrap();
    // Same size, different content, original modification time restored.
    write(&file, b"setting=9\n");
    fs::OpenOptions::new().write(true).open(&file).unwrap().set_modified(mtime).unwrap();
    assert_eq!(fim(&["check", "-b", p(&f.base), "--fast"]).0, 0, "fast mode cannot see a same-size edit with a restored mtime");
    let (code, out, _) = fim(&["check", "-b", p(&f.base)]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("modified") && out.contains("config.ini"));
}

#[test]
fn metadata_only_changes_are_separate() {
    let f = fixture();
    let file = f.data.join("bin/tool.exe");
    assert_eq!(fim(&["init", p(&f.data), "-b", p(&f.base)]).0, 0);
    let mut perm = fs::metadata(&file).unwrap().permissions();
    perm.set_readonly(true);
    fs::set_permissions(&file, perm).unwrap();
    let (code, out, _) = fim(&["check", "-b", p(&f.base)]);
    assert_eq!(code, 1, "{out}");
    assert!(out.lines().any(|l| l.starts_with("metadata") && l.contains("tool.exe") && l.contains("read-only false -> true")), "{out}");
    assert!(out.contains("0 modified"), "content is unchanged");
    // Allow cleanup of the temp dir.
    let mut perm = fs::metadata(&file).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perm.set_readonly(false);
    fs::set_permissions(&file, perm).unwrap();
}

/// A running `fim watch` with its stdout lines available through a channel.
struct Watcher {
    child: Child,
    lines: Receiver<String>,
}

impl Watcher {
    fn start(args: &[&str]) -> Watcher {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fim")).args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let (tx, rx) = mpsc::channel();
        let out = child.stdout.take().unwrap();
        let tx2 = tx.clone();
        std::thread::spawn(move || {
            for l in BufReader::new(out).lines().map_while(Result::ok) {
                let _ = tx.send(l);
            }
        });
        // Readiness is announced on stderr; forward it so tests can wait for it.
        let err = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            for l in BufReader::new(err).lines().map_while(Result::ok) {
                let _ = tx2.send(format!("stderr: {l}"));
            }
        });
        let mut w = Watcher { child, lines: rx };
        w.expect("stderr: watching", 15);
        w
    }

    /// Waits for a line containing `needle`; panics with everything seen if it does not come.
    fn expect(&mut self, needle: &str, secs: u64) -> String {
        let deadline = Instant::now() + Duration::from_secs(secs);
        let mut seen = Vec::new();
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.lines.recv_timeout(left) {
                Ok(l) if l.contains(needle) => return l,
                Ok(l) => seen.push(l),
                Err(_) => break,
            }
        }
        panic!("no line containing {needle:?} within {secs}s; saw {seen:#?}");
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn watch_reports_modify_add_and_remove_as_they_happen() {
    let f = fixture();
    assert_eq!(fim(&["init", p(&f.data), "-b", p(&f.base)]).0, 0);
    let log = f.base.with_extension("log.jsonl");
    let mut w = Watcher::start(&["watch", "-b", p(&f.base), "--debounce-ms", "150", "--log", p(&log)]);

    write(&f.data.join("config.ini"), b"setting=changed\n");
    let l = w.expect("modified", 15);
    assert!(l.contains("config.ini"), "{l}");

    write(&f.data.join("notes/new-file.txt"), b"fresh");
    let l = w.expect("added", 15);
    assert!(l.contains("new-file.txt"), "{l}");

    fs::remove_file(f.data.join("bin/tool.exe")).unwrap();
    let l = w.expect("removed", 15);
    assert!(l.contains("tool.exe"), "{l}");

    // A directory created with files in it is reported file by file.
    write(&f.data.join("fresh-dir/a.txt"), b"a");
    let l = w.expect("added", 15);
    assert!(l.contains("fresh-dir/a.txt"), "{l}");

    let logged = fs::read_to_string(&log).unwrap();
    let kinds: Vec<String> = logged.lines().map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["kind"].as_str().unwrap().to_string()).collect();
    assert!(kinds.contains(&"modified".to_string()) && kinds.contains(&"added".to_string()) && kinds.contains(&"removed".to_string()), "{kinds:?}");
    assert!(logged.lines().all(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["time"].as_str().unwrap().ends_with('Z')));
}

#[test]
fn watch_stays_quiet_for_excluded_files_and_touches() {
    let f = fixture();
    assert_eq!(fim(&["init", p(&f.data), "-b", p(&f.base), "--exclude", "**/*.log"]).0, 0);
    let mut w = Watcher::start(&["watch", "-b", p(&f.base), "--debounce-ms", "150"]);
    write(&f.data.join("noise.log"), b"ignored");
    // Rewriting a file with identical content is a touch, not a change.
    write(&f.data.join("config.ini"), b"setting=1\n");
    // The real change after them is the first thing reported.
    std::thread::sleep(Duration::from_millis(600));
    write(&f.data.join("notes/readme.txt"), b"changed");
    let l = w.expect("modified", 15);
    assert!(l.contains("readme.txt"), "the first report must be the real change: {l}");
}

#[cfg(windows)]
#[test]
fn watch_runs_the_exec_command_with_the_details_in_the_environment() {
    let f = fixture();
    assert_eq!(fim(&["init", p(&f.data), "-b", p(&f.base)]).0, 0);
    let out = f.base.with_extension("alert.txt");
    let cmd = format!("cmd /C echo %FIM_KIND% %FIM_PATH% >> {}", p(&out));
    let mut w = Watcher::start(&["watch", "-b", p(&f.base), "--debounce-ms", "150", "--exec", &cmd]);
    write(&f.data.join("config.ini"), b"setting=exec\n");
    w.expect("modified", 15);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut text = String::new();
    while Instant::now() < deadline {
        text = fs::read_to_string(&out).unwrap_or_default();
        if text.contains("config.ini") {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(text.contains("modified") && text.contains("config.ini"), "{text:?}");
}

#[cfg(windows)]
#[test]
fn a_locked_file_is_unreadable_not_removed() {
    use std::os::windows::fs::OpenOptionsExt;
    let f = fixture();
    assert_eq!(fim(&["init", p(&f.data), "-b", p(&f.base)]).0, 0);
    // Hold the file open with no sharing at all, so hashing it fails with a sharing violation.
    let _lock = fs::OpenOptions::new().read(true).share_mode(0).open(f.data.join("config.ini")).unwrap();
    let (code, out, _) = fim(&["check", "-b", p(&f.base)]);
    assert_eq!(code, 1, "{out}");
    assert!(out.lines().any(|l| l.starts_with("unreadable") && l.contains("config.ini")), "{out}");
    assert!(!out.lines().any(|l| l.starts_with("removed")), "a locked file still exists: {out}");
    assert!(out.contains("0 removed") && out.contains("1 unreadable"), "{out}");
}
