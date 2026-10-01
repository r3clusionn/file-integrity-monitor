use clap::{Parser, Subcommand, ValueEnum};
use fim::baseline::{diff, iso_utc, key, snapshot, Algo, Baseline, Change, Filter, VERSION};
use fim::watch::{watch, WatchConfig};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, ValueEnum)]
enum AlgoArg {
    Sha256,
    Blake3,
}

#[derive(Parser)]
#[command(version, about = "File integrity monitor")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Args)]
struct Common {
    /// Baseline file
    #[arg(short, long, default_value = "fim-baseline.json")]
    baseline: PathBuf,
    /// Key for the baseline's HMAC signature (signs on init and accept, verifies otherwise)
    #[arg(long, value_name = "FILE")]
    key_file: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Hash files and write a new baseline
    Init {
        /// Files and directories to protect
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[command(flatten)]
        common: Common,
        #[arg(long, value_enum, default_value = "sha256")]
        algo: AlgoArg,
        /// Glob of paths to leave out, for example "**/*.log" (repeatable)
        #[arg(short, long)]
        exclude: Vec<String>,
        /// Overwrite an existing baseline
        #[arg(long)]
        force: bool,
    },
    /// Compare the files with the baseline (exit status 1 if anything changed)
    Check {
        #[command(flatten)]
        common: Common,
        /// Skip hashing files whose size and modification time are unchanged
        #[arg(long)]
        fast: bool,
        /// Also report files whose only change is the modification time
        #[arg(long)]
        strict_time: bool,
        #[arg(long)]
        json: bool,
    },
    /// Rescan and replace the baseline with the current state, after reviewing a check
    Accept {
        #[command(flatten)]
        common: Common,
    },
    /// Watch the files and report changes as they happen
    Watch {
        #[command(flatten)]
        common: Common,
        /// Wait this long after the last event before reading the files
        #[arg(long, default_value_t = 300)]
        debounce_ms: u64,
        #[arg(long)]
        strict_time: bool,
        /// Append every change as a JSON line to this file
        #[arg(long, value_name = "FILE")]
        log: Option<PathBuf>,
        /// Run this command for every change, with FIM_KIND, FIM_PATH and FIM_HASH in its environment
        #[arg(long, value_name = "COMMAND")]
        exec: Option<String>,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("fim: {e}");
            ExitCode::from(2)
        }
    }
}

fn read_key(path: &Option<PathBuf>) -> Result<Option<Vec<u8>>, String> {
    match path {
        None => Ok(None),
        Some(p) => {
            let k = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
            let trimmed = k.trim_ascii().to_vec();
            if trimmed.is_empty() { Err(format!("{}: key file is empty", p.display())) } else { Ok(Some(trimmed)) }
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn load(common: &Common, key: &Option<Vec<u8>>) -> Result<Baseline, String> {
    Baseline::load(&common.baseline, key.as_deref()).map_err(|e| format!("{}: {e}", common.baseline.display()))
}

fn roots_of(b: &Baseline) -> Vec<PathBuf> {
    b.roots.iter().map(PathBuf::from).collect()
}

fn run(cli: Cli) -> Result<u8, String> {
    match cli.cmd {
        Cmd::Init { paths, common, algo, exclude, force } => {
            if common.baseline.exists() && !force {
                return Err(format!("{} already exists, use --force to replace it", common.baseline.display()));
            }
            let key_bytes = read_key(&common.key_file)?;
            let filter = Filter::new(&exclude).map_err(|e| format!("bad --exclude pattern: {e}"))?;
            for p in &paths {
                if !p.exists() {
                    return Err(format!("{}: no such file or directory", p.display()));
                }
            }
            let algo = match algo {
                AlgoArg::Sha256 => Algo::Sha256,
                AlgoArg::Blake3 => Algo::Blake3,
            };
            let roots: Vec<PathBuf> = paths.iter().map(|p| std::path::absolute(p).unwrap_or_else(|_| p.clone())).collect();
            let scan = snapshot(&roots, &filter, algo, None);
            let mut b = Baseline {
                version: VERSION,
                algo,
                created_unix: now_unix(),
                roots: roots.iter().map(|r| key(r)).collect(),
                excludes: exclude,
                entries: scan.entries,
                hmac: None,
            };
            if let Some(k) = &key_bytes {
                b.sign(k);
            }
            b.save(&common.baseline).map_err(|e| e.to_string())?;
            println!("baseline of {} files written to {} ({}{})", b.entries.len(), common.baseline.display(), if algo == Algo::Sha256 { "sha256" } else { "blake3" }, if key_bytes.is_some() { ", signed" } else { "" });
            for e in scan.errors.iter().take(5) {
                eprintln!("warning: {e}");
            }
            if !scan.errors.is_empty() {
                eprintln!("{} entries could not be read and are not in the baseline", scan.errors.len());
            }
            if scan.skipped > 0 {
                eprintln!("{} symlinks or special files were skipped", scan.skipped);
            }
            Ok(0)
        }
        Cmd::Check { common, fast, strict_time, json } => {
            let key_bytes = read_key(&common.key_file)?;
            let b = load(&common, &key_bytes)?;
            let filter = Filter::new(&b.excludes).map_err(|e| e.to_string())?;
            let now = snapshot(&roots_of(&b), &filter, b.algo, fast.then_some(&b.entries));
            let all = diff(&b.entries, &now.entries, strict_time);
            // A file that exists but cannot be read is not evidence that it was removed.
            let (unreadable, changes): (Vec<Change>, Vec<Change>) = all.into_iter().partition(|c| matches!(c, Change::Removed { path, .. } if now.unreadable.contains(path)));
            if json {
                let out = serde_json::json!({
                    "baseline": common.baseline.display().to_string(),
                    "baseline_created": iso_utc(b.created_unix),
                    "files_in_baseline": b.entries.len(),
                    "changes": changes,
                    "unreadable": unreadable.iter().map(|c| c.path()).collect::<Vec<_>>(),
                    "errors": now.errors,
                });
                println!("{}", serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?);
            } else {
                println!("baseline {} from {}, {} files", common.baseline.display(), iso_utc(b.created_unix), b.entries.len());
                for c in &changes {
                    println!("{}", describe(c));
                }
                for c in &unreadable {
                    println!("unreadable {}", c.path());
                }
                let n = |l: &str| changes.iter().filter(|c| c.label() == l).count();
                if changes.is_empty() && unreadable.is_empty() {
                    println!("no changes");
                } else {
                    println!("{} modified, {} added, {} removed, {} metadata, {} unreadable", n("modified"), n("added"), n("removed"), n("metadata"), unreadable.len());
                }
                for e in now.errors.iter().take(5) {
                    eprintln!("warning: {e}");
                }
            }
            Ok(u8::from(!changes.is_empty() || !unreadable.is_empty()))
        }
        Cmd::Accept { common } => {
            let key_bytes = read_key(&common.key_file)?;
            let old = load(&common, &key_bytes)?;
            if old.hmac.is_some() && key_bytes.is_none() {
                return Err("the baseline is signed: pass --key-file so the new one can be signed too".into());
            }
            let filter = Filter::new(&old.excludes).map_err(|e| e.to_string())?;
            let now = snapshot(&roots_of(&old), &filter, old.algo, None);
            let accepted = diff(&old.entries, &now.entries, false).len();
            let mut b = Baseline { created_unix: now_unix(), entries: now.entries, hmac: None, ..old };
            if let Some(k) = &key_bytes {
                b.sign(k);
            }
            b.save(&common.baseline).map_err(|e| e.to_string())?;
            println!("baseline updated: {} files, {accepted} changes accepted", b.entries.len());
            Ok(0)
        }
        Cmd::Watch { common, debounce_ms, strict_time, log, exec } => {
            let key_bytes = read_key(&common.key_file)?;
            let b = load(&common, &key_bytes)?;
            let filter = Filter::new(&b.excludes).map_err(|e| e.to_string())?;
            let roots = roots_of(&b);
            let mut state = b.entries.clone();
            let stop: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
            ctrlc::set_handler(move || stop.store(true, Ordering::SeqCst)).map_err(|e| e.to_string())?;
            let mut logfile = match &log {
                Some(p) => Some(OpenOptions::new().create(true).append(true).open(p).map_err(|e| format!("{}: {e}", p.display()))?),
                None => None,
            };
            let cfg = WatchConfig { roots: &roots, filter: &filter, algo: b.algo, debounce: Duration::from_millis(debounce_ms), strict_time };
            let n = b.entries.len();
            let result = watch(
                &cfg,
                &mut state,
                stop,
                &mut || eprintln!("watching {n} files under {} root(s), Ctrl+C to stop", roots.len()),
                &mut |c| {
                    let stamp = iso_utc(now_unix());
                    println!("{stamp} {}", describe(&c));
                    let _ = std::io::stdout().flush();
                    if let Some(f) = logfile.as_mut() {
                        let mut v = serde_json::to_value(&c).unwrap_or_default();
                        v["time"] = serde_json::Value::String(stamp);
                        let _ = writeln!(f, "{v}");
                    }
                    if let Some(cmd) = &exec {
                        run_exec(cmd, &c);
                    }
                },
            );
            result.map_err(|e| e.to_string())?;
            Ok(0)
        }
    }
}

fn short(h: &str) -> &str {
    &h[..h.len().min(12)]
}

fn describe(c: &Change) -> String {
    match c {
        Change::Added { path, hash, size } => format!("added     {path}  ({size} bytes, {})", short(hash)),
        Change::Removed { path, hash } => format!("removed   {path}  (was {})", short(hash)),
        Change::Modified { path, old_hash, new_hash, old_size, new_size } => format!("modified  {path}  ({} -> {}, {old_size} -> {new_size} bytes)", short(old_hash), short(new_hash)),
        Change::Metadata { path, details } => format!("metadata  {path}  ({details})"),
    }
}

/// Runs a user command for one change. The command is split on spaces, not passed to a shell, so a
/// file name can never inject anything into it; details travel in environment variables.
fn run_exec(cmd: &str, c: &Change) {
    let mut parts = cmd.split_whitespace();
    let Some(prog) = parts.next() else { return };
    let hash = match c {
        Change::Added { hash, .. } | Change::Removed { hash, .. } => hash.as_str(),
        Change::Modified { new_hash, .. } => new_hash.as_str(),
        Change::Metadata { .. } => "",
    };
    let status = Command::new(prog).args(parts).env("FIM_KIND", c.label()).env("FIM_PATH", c.path()).env("FIM_HASH", hash).status();
    if let Err(e) = status {
        eprintln!("fim: could not run {prog}: {e}");
    }
}
