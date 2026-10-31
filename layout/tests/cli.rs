use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pico2hsm-layout"))
        .args(args)
        .output()
        .unwrap()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

struct Tmp(PathBuf);

impl Tmp {
    fn new(name: &str) -> Tmp {
        let p =
            std::env::temp_dir().join(format!("pico2hsm-layout-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
    fn s(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn written(name: &str) -> Tmp {
    let t = Tmp::new(name);
    let o = run(&["write", "--boards-dir", t.s()]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    t
}

#[test]
fn profile_names() {
    assert_eq!(out(&run(&["profile", "pico2_4m"])), "4m\n");
    assert_eq!(out(&run(&["profile", "rp2350_geek_sdcard"])), "16m\n");
}

#[test]
fn unknown_board_is_usage_error() {
    let o = run(&["profile", "nope"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("pico2_4m"));
}

#[test]
fn unknown_profile_and_command_are_usage_errors() {
    let o = run(&["pt", "8m"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("16m"));
    assert_eq!(run(&["bogus"]).status.code(), Some(2));
    assert_eq!(run(&[]).status.code(), Some(2));
}

#[test]
fn slot_size() {
    assert_eq!(out(&run(&["slot-size", "pico2_4m"])), "1925120\n");
}

#[test]
fn regions() {
    let o = run(&["regions", "waveshare_rp2350_lcd_16m"]);
    assert_eq!(o.status.code(), Some(0));
    let s = out(&o);
    let lines: Vec<&str> = s.lines().collect();
    assert_eq!(lines[0], "binding 0x801000 0x8000");
    let names: Vec<&str> = lines.iter().map(|l| l.split(' ').next().unwrap()).collect();
    assert_eq!(
        names,
        ["binding", "counters", "rsa-pool", "spare", "keystore"]
    );
}

#[test]
fn pt_prints_json() {
    let s = out(&run(&["pt", "4m"]));
    assert!(s.starts_with("{\n"));
    assert_ne!(s, out(&run(&["pt", "4m", "--prod"])));
}

#[test]
fn check_after_write_passes() {
    let t = written("ok");
    let o = run(&["check", "--boards-dir", t.s()]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
}

#[test]
fn check_detects_modified_file() {
    let t = written("mod");
    let f = t.path().join("pt_4m.json");
    let mut c = std::fs::read_to_string(&f).unwrap();
    c.push(' ');
    std::fs::write(&f, c).unwrap();
    let o = run(&["check", "--boards-dir", t.s()]);
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).contains("pt_4m.json"));
}

#[test]
fn check_detects_missing_file() {
    let t = written("missing");
    std::fs::remove_file(t.path().join("pt_16m_prod.json")).unwrap();
    let o = run(&["check", "--boards-dir", t.s()]);
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).contains("pt_16m_prod.json"));
}

#[test]
fn check_detects_missing_final_newline() {
    let t = written("nonl");
    let f = t.path().join("pt_16m.json");
    let c = std::fs::read_to_string(&f).unwrap();
    std::fs::write(&f, c.trim_end_matches('\n')).unwrap();
    let o = run(&["check", "--boards-dir", t.s()]);
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).contains("pt_16m.json"));
}

#[test]
fn check_real_boards_dir() {
    let o = run(&["check"]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
}
