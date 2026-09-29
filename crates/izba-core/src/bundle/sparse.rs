//! Sparse-aware disk streaming: enumerate allocated extents, cut them into
//! block-aligned non-zero chunks, and a canonical content digest that is the
//! same for a sparse file and its fully-allocated twin (save/load spec §4.2).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use anyhow::Context;
use sha2::{Digest, Sha256};

use super::{MAX_CHUNK, ZERO_BLOCK};

pub struct Chunk {
    pub offset: u64,
    pub data: Vec<u8>,
}

/// Possibly-non-hole regions of `f` as `(offset, len)`, ascending. Any
/// enumeration failure falls back to one full extent (always correct, just
/// slower — zero elision still keeps the archive small).
pub fn data_extents(f: &File, len: u64) -> std::io::Result<Vec<(u64, u64)>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    Ok(os_extents(f, len).unwrap_or_else(|_| vec![(0, len)]))
}

#[cfg(target_os = "linux")]
fn os_extents(f: &File, len: u64) -> std::io::Result<Vec<(u64, u64)>> {
    use std::os::fd::AsRawFd;
    let fd = f.as_raw_fd();
    let mut out = Vec::new();
    let mut pos: i64 = 0;
    while (pos as u64) < len {
        // SAFETY: lseek on an owned, open fd.
        let data = unsafe { libc::lseek(fd, pos, libc::SEEK_DATA) };
        if data < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENXIO) {
                break; // no more data
            }
            return Err(e);
        }
        // SAFETY: as above.
        let hole = unsafe { libc::lseek(fd, data, libc::SEEK_HOLE) };
        if hole < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let end = (hole as u64).min(len);
        if end > data as u64 {
            out.push((data as u64, end - data as u64));
        }
        pos = hole;
    }
    Ok(out)
}

#[cfg(windows)]
fn os_extents(f: &File, len: u64) -> std::io::Result<Vec<(u64, u64)>> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Ioctl::{
        FILE_ALLOCATED_RANGE_BUFFER, FSCTL_QUERY_ALLOCATED_RANGES,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;
    let mut out = Vec::new();
    let mut start: i64 = 0;
    loop {
        let query = FILE_ALLOCATED_RANGE_BUFFER {
            FileOffset: start,
            Length: len as i64 - start,
        };
        let mut buf = vec![
            FILE_ALLOCATED_RANGE_BUFFER {
                FileOffset: 0,
                Length: 0
            };
            512
        ];
        let mut returned: u32 = 0;
        // SAFETY: valid handle; in/out buffers sized as passed.
        let ok = unsafe {
            DeviceIoControl(
                f.as_raw_handle() as _,
                FSCTL_QUERY_ALLOCATED_RANGES,
                &query as *const _ as _,
                std::mem::size_of::<FILE_ALLOCATED_RANGE_BUFFER>() as u32,
                buf.as_mut_ptr() as _,
                (buf.len() * std::mem::size_of::<FILE_ALLOCATED_RANGE_BUFFER>()) as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        let more = ok == 0
            && std::io::Error::last_os_error().raw_os_error()
                == Some(windows_sys::Win32::Foundation::ERROR_MORE_DATA as i32);
        if ok == 0 && !more {
            return Err(std::io::Error::last_os_error());
        }
        let n = returned as usize / std::mem::size_of::<FILE_ALLOCATED_RANGE_BUFFER>();
        for r in &buf[..n] {
            out.push((r.FileOffset as u64, r.Length as u64));
        }
        if !more || n == 0 {
            break;
        }
        let last = buf[n - 1];
        start = last.FileOffset + last.Length;
    }
    Ok(out)
}

#[cfg(not(any(target_os = "linux", windows)))]
fn os_extents(_f: &File, len: u64) -> std::io::Result<Vec<(u64, u64)>> {
    Ok(vec![(0, len)])
}

/// Stream every maximal run of non-zero `ZERO_BLOCK`-aligned blocks (split at
/// `MAX_CHUNK`) to `f`, in offset order. Returns the logical length.
pub fn for_each_chunk(
    path: &Path,
    mut f: impl FnMut(Chunk) -> anyhow::Result<()>,
) -> anyhow::Result<u64> {
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let len = file.metadata()?.len();
    let extents = data_extents(&file, len)?;
    let mut pending: Option<Chunk> = None;
    let mut block = vec![0u8; ZERO_BLOCK as usize];
    // First offset not yet examined: filesystems report extents at page
    // granularity, so two extents can share one 64 KiB block; aligning each
    // extent outward would otherwise read and emit that block twice.
    let mut next_unread = 0u64;
    for (ext_off, ext_len) in extents {
        // Align the extent outward to whole blocks, but never re-read.
        let mut off = (ext_off - ext_off % ZERO_BLOCK).max(next_unread);
        let end = (ext_off + ext_len).min(len);
        while off < end {
            let n = ZERO_BLOCK.min(len - off) as usize;
            file.seek(SeekFrom::Start(off))?;
            file.read_exact(&mut block[..n])
                .with_context(|| format!("reading {} @{off}", path.display()))?;
            let nonzero = block[..n].iter().any(|&b| b != 0);
            if nonzero {
                match &mut pending {
                    Some(c)
                        if c.offset + c.data.len() as u64 == off
                            && (c.data.len() as u64 + n as u64) <= MAX_CHUNK =>
                    {
                        c.data.extend_from_slice(&block[..n])
                    }
                    _ => {
                        if let Some(c) = pending.take() {
                            f(c)?;
                        }
                        pending = Some(Chunk {
                            offset: off,
                            data: block[..n].to_vec(),
                        });
                    }
                }
            } else if let Some(c) = pending.take() {
                f(c)?;
            }
            off += n as u64;
            next_unread = off;
        }
    }
    if let Some(c) = pending.take() {
        f(c)?;
    }
    Ok(len)
}

/// Canonical digest: sha256(len_le ‖ Σ over non-zero blocks: off_le ‖ n_le ‖ bytes).
pub struct DigestBuilder(Sha256);

impl DigestBuilder {
    pub fn new(logical_len: u64) -> Self {
        let mut h = Sha256::new();
        h.update(logical_len.to_le_bytes());
        Self(h)
    }

    /// Feed one chunk; re-split into blocks so merging never changes the digest.
    pub fn chunk(&mut self, c: &Chunk) {
        for (i, blk) in c.data.chunks(ZERO_BLOCK as usize).enumerate() {
            if blk.iter().all(|&b| b == 0) {
                continue;
            }
            let off = c.offset + (i as u64) * ZERO_BLOCK;
            self.0.update(off.to_le_bytes());
            self.0.update((blk.len() as u32).to_le_bytes());
            self.0.update(blk);
        }
    }

    pub fn finish(self) -> String {
        hex::encode(self.0.finalize())
    }
}

pub fn content_digest(path: &Path) -> anyhow::Result<String> {
    let len = std::fs::metadata(path)?.len();
    let mut d = DigestBuilder::new(len);
    for_each_chunk(path, |c| {
        d.chunk(&c);
        Ok(())
    })?;
    Ok(d.finish())
}

/// Create (truncating) a sparse file of `logical_len` (NTFS sparse flag set).
pub fn create_sparse(path: &Path, logical_len: u64) -> anyhow::Result<File> {
    let f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    crate::sandbox::mark_sparse(&f);
    f.set_len(logical_len)
        .with_context(|| format!("sizing {}", path.display()))?;
    Ok(f)
}

pub fn chunk_entry_name(prefix: &str, offset: u64) -> String {
    format!("{prefix}.d/{offset:016x}")
}

pub fn parse_chunk_entry(name: &str) -> Option<(&str, u64)> {
    let (prefix, hexoff) = name.rsplit_once(".d/")?;
    if hexoff.len() != 16 {
        return None;
    }
    Some((prefix, u64::from_str_radix(hexoff, 16).ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};

    fn write_at(path: &Path, len: u64, parts: &[(u64, &[u8])]) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .unwrap();
        f.set_len(len).unwrap();
        for (off, bytes) in parts {
            f.seek(SeekFrom::Start(*off)).unwrap();
            f.write_all(bytes).unwrap();
        }
    }

    fn collect(path: &Path) -> (u64, Vec<(u64, usize)>) {
        let mut v = Vec::new();
        let len = for_each_chunk(path, |c| {
            v.push((c.offset, c.data.len()));
            Ok(())
        })
        .unwrap();
        (len, v)
    }

    #[test]
    fn all_hole_file_yields_no_chunks() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("a.img");
        write_at(&p, 10 * 1024 * 1024, &[]);
        assert_eq!(collect(&p), (10 * 1024 * 1024, vec![]));
    }

    #[test]
    fn data_blocks_become_block_aligned_chunks() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("a.img");
        write_at(&p, 1 << 22, &[(100, b"x"), (3 * ZERO_BLOCK + 5, b"y")]);
        assert_eq!(
            collect(&p).1,
            vec![
                (0, ZERO_BLOCK as usize),
                (3 * ZERO_BLOCK, ZERO_BLOCK as usize)
            ]
        );
    }

    #[test]
    fn two_extents_in_one_block_yield_one_chunk() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("a.img");
        write_at(&p, 1 << 20, &[(0, b"a"), (8192, b"b")]);
        assert_eq!(collect(&p).1, vec![(0, ZERO_BLOCK as usize)]);
    }

    #[test]
    fn adjacent_blocks_merge_up_to_max_chunk() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("a.img");
        let big = vec![7u8; (MAX_CHUNK + ZERO_BLOCK) as usize];
        write_at(&p, MAX_CHUNK * 2, &[(0, &big)]);
        assert_eq!(
            collect(&p).1,
            vec![(0, MAX_CHUNK as usize), (MAX_CHUNK, ZERO_BLOCK as usize)]
        );
    }

    #[test]
    fn unaligned_tail_is_a_short_chunk() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("a.img");
        write_at(&p, ZERO_BLOCK + 10, &[(ZERO_BLOCK + 3, b"z")]);
        assert_eq!(collect(&p), (ZERO_BLOCK + 10, vec![(ZERO_BLOCK, 10)]));
    }

    #[test]
    fn zero_blocks_are_elided_and_digest_matches_sparse_twin() {
        let t = tempfile::tempdir().unwrap();
        let dense = t.path().join("dense.img");
        let sparse = t.path().join("sparse.img");
        let mut content = vec![0u8; (4 * ZERO_BLOCK) as usize];
        content[(2 * ZERO_BLOCK) as usize] = 9;
        std::fs::write(&dense, &content).unwrap(); // fully allocated zeros
        write_at(&sparse, 4 * ZERO_BLOCK, &[(2 * ZERO_BLOCK, &[9])]);
        assert_eq!(
            collect(&dense).1,
            vec![(2 * ZERO_BLOCK, ZERO_BLOCK as usize)]
        );
        assert_eq!(
            content_digest(&dense).unwrap(),
            content_digest(&sparse).unwrap()
        );
    }

    #[test]
    fn digest_distinguishes_length_and_content() {
        let t = tempfile::tempdir().unwrap();
        let a = t.path().join("a");
        let b = t.path().join("b");
        let c = t.path().join("c");
        write_at(&a, 1 << 20, &[(5, b"q")]);
        write_at(&b, 2 << 20, &[(5, b"q")]);
        write_at(&c, 1 << 20, &[(5, b"r")]);
        let (da, db, dc) = (
            content_digest(&a).unwrap(),
            content_digest(&b).unwrap(),
            content_digest(&c).unwrap(),
        );
        assert_ne!(da, db);
        assert_ne!(da, dc);
    }

    #[test]
    fn digest_is_independent_of_chunk_merging() {
        let mut one = DigestBuilder::new(2 * ZERO_BLOCK);
        one.chunk(&Chunk {
            offset: 0,
            data: vec![1u8; (2 * ZERO_BLOCK) as usize],
        });
        let mut two = DigestBuilder::new(2 * ZERO_BLOCK);
        two.chunk(&Chunk {
            offset: 0,
            data: vec![1u8; ZERO_BLOCK as usize],
        });
        two.chunk(&Chunk {
            offset: ZERO_BLOCK,
            data: vec![1u8; ZERO_BLOCK as usize],
        });
        assert_eq!(one.finish(), two.finish());
    }

    #[test]
    fn create_sparse_then_write_chunks_round_trips() {
        let t = tempfile::tempdir().unwrap();
        let src = t.path().join("src");
        write_at(&src, 3 << 20, &[(0, b"head"), ((2 << 20) + 1, b"tail")]);
        let dst = t.path().join("dst");
        let mut f = create_sparse(&dst, 3 << 20).unwrap();
        for_each_chunk(&src, |c| {
            f.seek(SeekFrom::Start(c.offset))?;
            f.write_all(&c.data)?;
            Ok(())
        })
        .unwrap();
        drop(f);
        assert_eq!(std::fs::read(&src).unwrap(), std::fs::read(&dst).unwrap());
        assert_eq!(content_digest(&src).unwrap(), content_digest(&dst).unwrap());
    }

    #[test]
    fn chunk_entry_names_round_trip() {
        let n = chunk_entry_name("sandboxes/a/rw.img", 0x1_0000);
        assert_eq!(n, "sandboxes/a/rw.img.d/0000000000010000");
        assert_eq!(
            parse_chunk_entry(&n),
            Some(("sandboxes/a/rw.img", 0x1_0000))
        );
        assert_eq!(parse_chunk_entry("sandboxes/a/rw.img.d/xyz"), None);
        assert_eq!(parse_chunk_entry("sandboxes/a/config.json"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_extents_skip_holes() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("a.img");
        write_at(&p, 64 << 20, &[(32 << 20, b"x")]);
        let f = std::fs::File::open(&p).unwrap();
        let ext = data_extents(&f, 64 << 20).unwrap();
        let covered: u64 = ext.iter().map(|e| e.1).sum();
        assert!(covered < 64 << 20, "tmpfs/ext4 report holes: {ext:?}");
        assert!(ext.iter().any(|&(o, l)| o <= 32 << 20 && 32 << 20 < o + l));
    }
}
