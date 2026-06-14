//! Drives the real `izba` (or any) binary through a PTY/ConPTY and scrapes the
//! rendered screen with a vt100 parser.
//!
//! ConPTY renders asynchronously and runs its own reflow, so assertions are
//! always made against the parsed grid (never raw master bytes), and
//! [`TerminalSession::wait_stable`] polls until the grid quiesces.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};

/// Outcome of the child process exiting.
pub struct ExitOutcome {
    pub code: Option<i32>,
}

/// Reader-thread telemetry, for ConPTY diagnostics. A master that yields
/// `bytes=0 eof=true` shortly after spawn is the signature of the hosted-runner
/// ConPTY-output-loss failure (child runs but nothing reaches the parent).
#[derive(Default)]
struct ReaderStats {
    bytes: AtomicU64,
    reads: AtomicU64,
    eof: AtomicBool,
}

pub struct TerminalSession {
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    parser: Arc<Mutex<vt100::Parser>>,
    child: Box<dyn Child + Send + Sync>,
    stats: Arc<ReaderStats>,
    _reader: std::thread::JoinHandle<()>,
}

impl TerminalSession {
    /// Open a PTY/ConPTY of `cols`x`rows`, spawn `cmd` on the slave, and start a
    /// background thread feeding master output into a vt100 parser.
    pub fn spawn(cmd: CommandBuilder, cols: u16, rows: u16) -> Result<Self> {
        let pty = native_pty_system();
        let pair = pty
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("openpty")?;
        let child = pair
            .slave
            .spawn_command(cmd)
            .context("spawn on pty slave")?;
        // Drop the slave handle so the master sees EOF when the child exits.
        drop(pair.slave);

        let mut reader = pair.master.try_clone_reader().context("clone reader")?;
        let writer = pair.master.take_writer().context("take writer")?;
        let parser = Arc::new(Mutex::new(vt100::Parser::new(rows, cols, 0)));

        let sink = Arc::clone(&parser);
        let stats = Arc::new(ReaderStats::default());
        let stats_w = Arc::clone(&stats);
        let reader_thread = std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => {
                        stats_w.eof.store(true, Ordering::Relaxed);
                        return;
                    }
                    Ok(n) => {
                        stats_w.bytes.fetch_add(n as u64, Ordering::Relaxed);
                        stats_w.reads.fetch_add(1, Ordering::Relaxed);
                        sink.lock().unwrap().process(&buf[..n]);
                    }
                }
            }
        });

        Ok(Self {
            master: pair.master,
            writer,
            parser,
            child,
            stats,
            _reader: reader_thread,
        })
    }

    /// Reader-thread telemetry for ConPTY diagnostics: bytes/reads observed on
    /// the master and whether EOF/err was hit. `bytes=0 eof=true` is the
    /// hosted-runner output-loss signature.
    pub fn read_report(&self) -> String {
        format!(
            "reader bytes={} reads={} eof={}",
            self.stats.bytes.load(Ordering::Relaxed),
            self.stats.reads.load(Ordering::Relaxed),
            self.stats.eof.load(Ordering::Relaxed),
        )
    }

    pub fn send_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer.write_all(bytes).context("write to pty")?;
        self.writer.flush().context("flush pty")?;
        Ok(())
    }

    pub fn send_keys(&mut self, s: &str) -> Result<()> {
        self.send_bytes(s.as_bytes())
    }

    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        self.master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("resize pty")?;
        self.parser
            .lock()
            .unwrap()
            .screen_mut()
            .set_size(rows, cols);
        Ok(())
    }

    /// The size the parser currently tracks, as `(cols, rows)`.
    pub fn size(&self) -> (u16, u16) {
        let p = self.parser.lock().unwrap();
        let (rows, cols) = p.screen().size();
        (cols, rows)
    }

    pub fn screen_text(&self) -> String {
        self.parser.lock().unwrap().screen().contents()
    }

    pub fn screen_contains(&self, needle: &str) -> bool {
        self.screen_text().contains(needle)
    }

    /// Text of one cell (row, col), or None if out of range.
    pub fn cell(&self, row: u16, col: u16) -> Option<String> {
        self.parser
            .lock()
            .unwrap()
            .screen()
            .cell(row, col)
            .map(|c| c.contents().to_owned())
    }

    pub fn wait_for_text(&self, needle: &str, timeout: Duration) -> Result<()> {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if self.screen_contains(needle) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        bail!(
            "timed out after {timeout:?} waiting for {needle:?}; {}; screen was:\n{}",
            self.read_report(),
            self.screen_text()
        );
    }

    /// Poll until the grid stops changing for `idle` (the ConPTY quiescence
    /// gate). Use before snapshotting after sending input.
    pub fn wait_stable(&self, idle: Duration, timeout: Duration) -> Result<()> {
        let start = Instant::now();
        let mut last = self.screen_text();
        let mut stable_since = Instant::now();
        loop {
            std::thread::sleep(Duration::from_millis(20));
            let now = self.screen_text();
            if now != last {
                last = now;
                stable_since = Instant::now();
            } else if stable_since.elapsed() >= idle {
                return Ok(());
            }
            if start.elapsed() > timeout {
                bail!(
                    "screen not stable within {timeout:?}; screen was:\n{}",
                    self.screen_text()
                );
            }
        }
    }

    pub fn is_child_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    pub fn wait_exit(&mut self, timeout: Duration) -> Result<ExitOutcome> {
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().context("try_wait")? {
                return Ok(ExitOutcome {
                    code: Some(status.exit_code() as i32),
                });
            }
            if start.elapsed() > timeout {
                bail!(
                    "child did not exit within {timeout:?}; screen was:\n{}",
                    self.screen_text()
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
