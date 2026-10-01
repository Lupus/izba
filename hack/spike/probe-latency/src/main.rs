//! `probe-latency <sandbox-name> [--iterations N] [--interval-ms M]
//! [--parallel K] [--bound-ms B]` — see the crate docs and README.

use std::path::PathBuf;
use std::process::ExitCode;

use izba_core::paths::Paths;
use probe_latency::args::{self, Parsed, USAGE};
use probe_latency::measure::Sample;
use probe_latency::{run, summary};

fn main() -> ExitCode {
    let args = match args::parse(std::env::args().skip(1)) {
        Ok(Parsed::Run(args)) => args,
        Ok(Parsed::Help) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("probe-latency: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    // The same resolution as `izba` itself (crates/izba-cli/src/main.rs).
    let paths = Paths::from_env_or_default(std::env::var_os("IZBA_DATA_DIR").map(PathBuf::from));

    // `println!` takes the stdout lock per call, so lines from concurrent
    // workers never interleave.
    let emit = |sample: &Sample| match serde_json::to_string(sample) {
        Ok(line) => println!("{line}"),
        Err(e) => eprintln!("probe-latency: cannot serialize a sample: {e}"),
    };
    let samples = run::run(&args, &paths, &emit);

    let line = summary::summarize(&args, &paths.root().display().to_string(), &samples);
    match serde_json::to_string(&line) {
        Ok(line) => println!("{line}"),
        Err(e) => eprintln!("probe-latency: cannot serialize the summary: {e}"),
    }
    ExitCode::from(summary::exit_code(&samples))
}
