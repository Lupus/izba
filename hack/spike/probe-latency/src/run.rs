//! The measurement loop. Needs a running sandbox, so it has no unit tests;
//! everything it calls does.

use std::time::{Duration, Instant};

use izba_core::paths::Paths;
use izba_core::sandbox::default_connector;

use crate::args::Args;
use crate::measure::{io_cap, measure_direct, measure_probe, Kind, Sample};

/// Run `args.parallel` workers, each doing `args.iterations` iterations of
/// probe-then-direct with `args.interval_ms` between iterations. `emit` is
/// called for every sample as it is taken. Returns all samples.
pub fn run(args: &Args, paths: &Paths, emit: &(dyn Fn(&Sample) + Sync)) -> Vec<Sample> {
    let epoch = Instant::now();
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..args.parallel)
            .map(|worker| scope.spawn(move || run_worker(worker, args, paths, epoch, emit)))
            .collect();
        workers
            .into_iter()
            .flat_map(|w| w.join().expect("a worker thread panicked"))
            .collect()
    })
}

fn run_worker(
    worker: u32,
    args: &Args,
    paths: &Paths,
    epoch: Instant,
    emit: &(dyn Fn(&Sample) + Sync),
) -> Vec<Sample> {
    let connector = default_connector();
    let cap = io_cap(args.bound_ms);
    let mut samples = Vec::with_capacity(2 * args.iterations as usize);
    for iteration in 0..args.iterations {
        if iteration > 0 {
            std::thread::sleep(Duration::from_millis(args.interval_ms));
        }
        for kind in [Kind::Probe, Kind::Direct] {
            let started_ms = u64::try_from(epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
            let m = match kind {
                Kind::Probe => measure_probe(paths, &args.sandbox, &connector, cap),
                Kind::Direct => measure_direct(paths, &args.sandbox, &connector, cap),
            };
            let sample = Sample {
                worker,
                iteration,
                started_ms,
                kind,
                m,
            };
            emit(&sample);
            samples.push(sample);
        }
    }
    samples
}
