mod app;
mod clipboard;
mod config;
mod db;
mod export;
mod import;
mod input;
mod terminal_clipboard;
mod theme;
mod ui;
mod util;

use std::io;

fn main() -> io::Result<()> {
    let slim_mode = handle_cli_flags();

    let mut terminal = ratatui::init();

    let result = app::run(&mut terminal, slim_mode);

    ratatui::restore();

    result
}

fn handle_cli_flags() -> bool {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args
        .iter()
        .any(|a| a == "--version" || a == "-V" || a == "-v")
    {
        println!(
            "{} {}{}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
            option_env!("JAIBA_BUILD_LABEL")
                .map(|label| format!(" ({label})"))
                .unwrap_or_default()
        );
        std::process::exit(0);
    }

    if args.iter().any(|a| a == "--help" || a == "-H" || a == "-h") {
        println!(
            "{} {}\n{}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_DESCRIPTION")
        );
        std::process::exit(0);
    }

    args.iter().any(|a| a == "--slim")
}
