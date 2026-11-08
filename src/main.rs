//! wmng — UNIX-style Windows management applets.
//!
//! Multi-call binary: the applet is the basename of argv[0] (a hard-link
//! shim normally puts `getfacl.exe` etc. on PATH), or the first argument
//! when invoked as `wmng <applet> ...`.

mod applets;
mod providers;

use std::process::ExitCode;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let prog = argv
        .first()
        .map(|p| {
            std::path::Path::new(p)
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| p.clone())
        })
        .unwrap_or_default();

    let (name, rest): (&str, &[String]) = match argv.get(1) {
        Some(first) if applets::APPLETS.contains(&first.as_str()) => (first, &argv[2..]),
        _ if applets::APPLETS.contains(&prog.as_str()) => (prog.as_str(), &argv[1..]),
        _ => {
            // Invoked as wmng with no applet: --list / --help, or nothing.
            match argv.get(1).map(|s| s.as_str()) {
                Some("--list") => {
                    for a in applets::APPLETS {
                        println!("{a}");
                    }
                    return ExitCode::SUCCESS;
                }
                Some("--help") | None => {
                    print_help();
                    return ExitCode::SUCCESS;
                }
                Some(other) => {
                    eprintln!("wmng: {other}: unknown applet (try --list)");
                    return ExitCode::from(2);
                }
            }
        }
    };

    let code = match name {
        "getfacl" => applets::getfacl::run(rest),
        "setfacl" => applets::setfacl::run(rest),
        "shutdown" => applets::power::run_shutdown(rest),
        "reboot" => applets::power::run_reboot(rest),
        "poweroff" => applets::power::run_poweroff(rest),
        _ => unreachable!("applet list and dispatch agree"),
    };
    ExitCode::from(code as u8)
}

fn print_help() {
    println!("wmng — UNIX-style Windows management applets");
    println!();
    println!("usage: wmng <applet> [options] [operands]");
    println!("       wmng --list");
    println!();
    println!("applets:");
    println!("  getfacl   {}", applets::getfacl::USAGE);
    println!("  setfacl   {}", applets::setfacl::USAGE);
    println!("  shutdown  {}", applets::power::SHUTDOWN_USAGE);
    println!("  reboot    [-f]");
    println!("  poweroff  [-f]");
}
