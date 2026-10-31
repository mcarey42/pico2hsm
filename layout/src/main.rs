//! `pico2hsm-layout`: query the flash map and generate or check the
//! committed partition tables.  Used by build scripts and CI.

use pico2hsm_layout::render::{partition_json, table_file_name, Table};
use pico2hsm_layout::{board, Profile, BOARDS, PROFILES};
use std::path::PathBuf;
use std::process::ExitCode;

const DEFAULT_BOARDS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../boards");

fn usage(msg: &str) -> ExitCode {
    let boards: Vec<&str> = BOARDS.iter().map(|b| b.feature).collect();
    let profiles: Vec<&str> = PROFILES.iter().map(|p| p.name).collect();
    eprintln!("error: {msg}");
    eprintln!("usage: pico2hsm-layout <command>");
    eprintln!("  profile <board>");
    eprintln!("  slot-size <board>");
    eprintln!("  regions <board>");
    eprintln!("  pt <profile> [--prod]");
    eprintln!("  write [--boards-dir <dir>]");
    eprintln!("  check [--boards-dir <dir>]");
    eprintln!("boards: {}", boards.join(" "));
    eprintln!("profiles: {}", profiles.join(" "));
    ExitCode::from(2)
}

fn profile_by_name(name: &str) -> Option<&'static Profile> {
    PROFILES.iter().copied().find(|p| p.name == name)
}

/// Every committed table: file name and expected content.
fn tables() -> Vec<(&'static str, String)> {
    let mut v = Vec::new();
    for p in PROFILES {
        for t in [Table::Dev, Table::Prod] {
            v.push((table_file_name(p, t), partition_json(p, t)));
        }
    }
    v
}

fn boards_dir(rest: &[String]) -> Result<PathBuf, String> {
    match rest {
        [] => Ok(PathBuf::from(DEFAULT_BOARDS_DIR)),
        [flag, dir] if flag == "--boards-dir" => Ok(PathBuf::from(dir)),
        _ => Err("expected [--boards-dir <dir>]".into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        return usage("missing command");
    };
    let rest = &args[1..];
    match cmd.as_str() {
        "profile" | "slot-size" | "regions" => {
            let [name] = rest else {
                return usage("expected one board name");
            };
            let Some(b) = board(name) else {
                return usage(&format!("unknown board `{name}`"));
            };
            let p = b.profile;
            match cmd.as_str() {
                "profile" => println!("{}", p.name),
                "slot-size" => println!("{}", p.slot_size),
                _ => {
                    for r in p.regions {
                        println!(
                            "{} {:#x} {:#x}",
                            r.partition,
                            p.region_offset(r.partition),
                            r.size
                        );
                    }
                    println!(
                        "keystore {:#x} {:#x}",
                        p.keystore_start,
                        p.keystore_end - p.keystore_start
                    );
                }
            }
            ExitCode::SUCCESS
        }
        "pt" => {
            let (name, prod) = match rest {
                [n] => (n, false),
                [n, f] if f == "--prod" => (n, true),
                _ => return usage("expected <profile> [--prod]"),
            };
            let Some(p) = profile_by_name(name) else {
                return usage(&format!("unknown profile `{name}`"));
            };
            let t = if prod { Table::Prod } else { Table::Dev };
            print!("{}", partition_json(p, t));
            ExitCode::SUCCESS
        }
        "write" | "check" => {
            let dir = match boards_dir(rest) {
                Ok(d) => d,
                Err(e) => return usage(&e),
            };
            if cmd == "write" {
                for (name, content) in tables() {
                    if let Err(e) = std::fs::write(dir.join(name), content) {
                        eprintln!("error: writing {name}: {e}");
                        return ExitCode::from(1);
                    }
                }
                return ExitCode::SUCCESS;
            }
            let mut bad = false;
            for (name, content) in tables() {
                match std::fs::read_to_string(dir.join(name)) {
                    Ok(c) if c == content => {}
                    Ok(_) => {
                        eprintln!("differs: {name}");
                        bad = true;
                    }
                    Err(_) => {
                        eprintln!("missing: {name}");
                        bad = true;
                    }
                }
            }
            if bad {
                eprintln!("run `pico2hsm-layout write` to regenerate");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        other => usage(&format!("unknown command `{other}`")),
    }
}
