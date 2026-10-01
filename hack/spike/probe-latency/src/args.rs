//! Command-line parsing. Hand-rolled: five options do not justify a clap
//! dependency in a throwaway tool.

pub const USAGE: &str = "\
usage: probe-latency <sandbox-name> [--iterations N] [--interval-ms M] [--parallel K] [--bound-ms B]

Times the phases of izbad's container-state probe against a RUNNING sandbox,
talking to the guest directly (no daemon). One JSON line per measurement on
stdout, then one {\"summary\": ...} line.

  --iterations N    iterations per worker                      (default 20, >= 1)
  --interval-ms M   pause between iterations                   (default 250)
  --parallel K      concurrent workers, each doing N iterations (default 1, >= 1)
  --bound-ms B      the time bound to compare against          (default 5000, >= 1)

The data root is $IZBA_DATA_DIR when set, else the per-OS default, as in `izba`.
Exit status: 0 every measurement saw `some:running`, 1 otherwise, 2 usage error.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub sandbox: String,
    pub iterations: u32,
    pub interval_ms: u64,
    pub parallel: u32,
    pub bound_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    Run(Args),
    Help,
}

/// Parse the arguments AFTER `argv[0]`. `Err` is a usage error (exit 2).
pub fn parse<I, S>(argv: I) -> Result<Parsed, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let argv: Vec<String> = argv.into_iter().map(Into::into).collect();
    if argv.iter().any(|a| a == "--help" || a == "-h") {
        return Ok(Parsed::Help);
    }

    let mut sandbox: Option<String> = None;
    let mut iterations: u32 = 20;
    let mut interval_ms: u64 = 250;
    let mut parallel: u32 = 1;
    let mut bound_ms: u64 = 5000;

    let mut rest = argv.into_iter();
    while let Some(arg) = rest.next() {
        if !arg.starts_with('-') {
            if sandbox.is_some() {
                return Err(format!("unexpected extra argument '{arg}'"));
            }
            sandbox = Some(arg);
            continue;
        }
        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) => (flag.to_string(), Some(value.to_string())),
            None => (arg, None),
        };
        if !matches!(
            flag.as_str(),
            "--iterations" | "--interval-ms" | "--parallel" | "--bound-ms"
        ) {
            return Err(format!("unknown option '{flag}'"));
        }
        let value = match inline.or_else(|| rest.next()) {
            Some(value) => value,
            None => return Err(format!("{flag} needs a value")),
        };
        match flag.as_str() {
            "--iterations" => iterations = number(&flag, &value, 1)?,
            "--interval-ms" => interval_ms = number(&flag, &value, 0)?,
            "--parallel" => parallel = number(&flag, &value, 1)?,
            _ => bound_ms = number(&flag, &value, 1)?,
        }
    }

    let sandbox = sandbox.ok_or_else(|| "missing <sandbox-name>".to_string())?;
    Ok(Parsed::Run(Args {
        sandbox,
        iterations,
        interval_ms,
        parallel,
        bound_ms,
    }))
}

/// A non-negative integer of at least `min`, or a usage error naming `flag`.
fn number<T>(flag: &str, value: &str, min: T) -> Result<T, String>
where
    T: std::str::FromStr + PartialOrd + std::fmt::Display,
{
    match value.parse::<T>() {
        Ok(n) if n >= min => Ok(n),
        Ok(_) => Err(format!("{flag} must be at least {min}, got '{value}'")),
        Err(_) => Err(format!(
            "{flag} needs a non-negative integer, got '{value}'"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(argv: &[&str]) -> Args {
        match parse(argv.iter().copied()) {
            Ok(Parsed::Run(a)) => a,
            other => panic!("expected a run, got {other:?}"),
        }
    }

    fn err(argv: &[&str]) -> String {
        match parse(argv.iter().copied()) {
            Err(e) => e,
            other => panic!("expected a usage error, got {other:?}"),
        }
    }

    #[test]
    fn defaults() {
        assert_eq!(
            run(&["box"]),
            Args {
                sandbox: "box".into(),
                iterations: 20,
                interval_ms: 250,
                parallel: 1,
                bound_ms: 5000,
            }
        );
    }

    #[test]
    fn each_flag_sets_only_its_own_field() {
        let d = run(&["box"]);
        assert_eq!(
            run(&["box", "--iterations", "7"]),
            Args {
                iterations: 7,
                ..d.clone()
            }
        );
        assert_eq!(
            run(&["box", "--interval-ms", "0"]),
            Args {
                interval_ms: 0,
                ..d.clone()
            }
        );
        assert_eq!(
            run(&["box", "--parallel", "8"]),
            Args {
                parallel: 8,
                ..d.clone()
            }
        );
        assert_eq!(
            run(&["box", "--bound-ms", "1500"]),
            Args {
                bound_ms: 1500,
                ..d
            }
        );
    }

    #[test]
    fn all_flags_in_any_position_and_equals_form() {
        let want = Args {
            sandbox: "my-sandbox".into(),
            iterations: 3,
            interval_ms: 10,
            parallel: 4,
            bound_ms: 900,
        };
        assert_eq!(
            run(&[
                "--iterations",
                "3",
                "my-sandbox",
                "--interval-ms=10",
                "--parallel",
                "4",
                "--bound-ms=900",
            ]),
            want
        );
    }

    #[test]
    fn help_wins() {
        assert_eq!(parse(["--help"]), Ok(Parsed::Help));
        assert_eq!(parse(["-h"]), Ok(Parsed::Help));
        assert_eq!(parse(["box", "--help"]), Ok(Parsed::Help));
    }

    #[test]
    fn bad_value_is_a_usage_error_naming_the_flag() {
        for flag in ["--iterations", "--interval-ms", "--parallel", "--bound-ms"] {
            let e = err(&["box", flag, "abc"]);
            assert!(e.contains(flag), "{e}");
            assert!(e.contains("abc"), "{e}");
            let e = err(&["box", flag, "-3"]);
            assert!(e.contains(flag), "{e}");
            let e = err(&["box", &format!("{flag}=1.5")]);
            assert!(e.contains(flag), "{e}");
        }
    }

    #[test]
    fn zero_is_refused_where_it_cannot_mean_anything() {
        assert!(err(&["box", "--iterations", "0"]).contains("--iterations"));
        assert!(err(&["box", "--parallel", "0"]).contains("--parallel"));
        // A zero bound would make the fraction-of-bound a division by zero.
        assert!(err(&["box", "--bound-ms", "0"]).contains("--bound-ms"));
    }

    #[test]
    fn missing_value_is_a_usage_error() {
        let e = err(&["box", "--iterations"]);
        assert!(e.contains("--iterations"), "{e}");
    }

    #[test]
    fn unknown_flag_is_a_usage_error() {
        let e = err(&["box", "--frobnicate"]);
        assert!(e.contains("--frobnicate"), "{e}");
    }

    #[test]
    fn sandbox_name_is_required_exactly_once() {
        assert!(err(&[]).contains("sandbox"));
        assert!(err(&["--iterations", "3"]).contains("sandbox"));
        let e = err(&["one", "two"]);
        assert!(e.contains("two"), "{e}");
    }
}
