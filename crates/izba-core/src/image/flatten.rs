//! OCI layer flattening: merge a stack of layer tars (lowest first) into a
//! single tar, applying OCI whiteout/opaque semantics, without ever
//! materializing files on the host filesystem.

use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tar::EntryType;

/// One surviving entry: where its data lives in the staged layer files plus
/// the metadata needed to re-emit it.
struct Node {
    layer: usize,
    offset: u64,
    size: u64,
    header: tar::Header,
    link_name: Option<PathBuf>,
}

/// Merge OCI layers (lowest first) into a single tar written to `out`.
///
/// Each reader yields one layer: gzipped tar OR plain tar (detected by the
/// gzip magic `0x1f 0x8b`). Layer data is staged in unlinked temp files;
/// nothing is ever unpacked onto the host filesystem.
pub fn flatten_layers<W: Write>(layers: Vec<Box<dyn Read>>, out: W) -> Result<()> {
    let staged = stage_layers(layers)?;
    let map = index_layers(&staged)?;
    emit(&staged, &map, out)
}

/// Pass 0: decompress (if gzipped) each layer into an anonymous, unlinked
/// temp file so we can seek into it later.
fn stage_layers(layers: Vec<Box<dyn Read>>) -> Result<Vec<File>> {
    let mut staged = Vec::with_capacity(layers.len());
    for (i, mut reader) in layers.into_iter().enumerate() {
        let mut magic = [0u8; 2];
        let mut filled = 0;
        while filled < magic.len() {
            let n = reader
                .read(&mut magic[filled..])
                .with_context(|| format!("read layer {i}"))?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        let chained = Cursor::new(magic[..filled].to_vec()).chain(reader);
        let mut tmp = tempfile::tempfile().context("create unlinked temp file")?;
        if magic == [0x1f, 0x8b] {
            std::io::copy(&mut flate2::read::GzDecoder::new(chained), &mut tmp)
        } else {
            std::io::copy(&mut { chained }, &mut tmp)
        }
        .with_context(|| format!("stage layer {i}"))?;
        staged.push(tmp);
    }
    Ok(staged)
}

/// Pass 1: build the merged index, applying whiteout/opaque semantics.
///
/// Per layer, whiteouts/opaques are applied first (they only affect content
/// from lower layers), then the layer's regular entries are inserted (tar
/// last-wins within a layer).
fn index_layers(staged: &[File]) -> Result<BTreeMap<String, Node>> {
    let mut map: BTreeMap<String, Node> = BTreeMap::new();
    for (i, file) in staged.iter().enumerate() {
        // Sub-pass (a): whiteouts and opaque markers.
        let mut f = file.try_clone()?;
        f.seek(SeekFrom::Start(0))?;
        let mut ar = tar::Archive::new(f);
        for entry in ar.entries().with_context(|| format!("read layer {i}"))? {
            let entry = entry.with_context(|| format!("read layer {i}"))?;
            if is_metadata(entry.header().entry_type()) {
                continue;
            }
            let Some(path) = normalize(&entry.path()?)? else {
                continue;
            };
            let (parent, base) = split(&path);
            if base == ".wh..wh..opq" {
                remove_subtree(&mut map, parent);
            } else if let Some(name) = base.strip_prefix(".wh.") {
                let target = join(parent, name);
                map.remove(&target);
                remove_subtree(&mut map, &target);
            }
        }

        // Sub-pass (b): regular entries.
        let mut f = file.try_clone()?;
        f.seek(SeekFrom::Start(0))?;
        let mut ar = tar::Archive::new(f);
        for entry in ar.entries().with_context(|| format!("read layer {i}"))? {
            let entry = entry.with_context(|| format!("read layer {i}"))?;
            let ty = entry.header().entry_type();
            if is_metadata(ty) {
                continue;
            }
            let Some(path) = normalize(&entry.path()?)? else {
                continue;
            };
            let (_, base) = split(&path);
            if base.starts_with(".wh.") {
                continue; // consumed in sub-pass (a)
            }
            // A non-dir replacing anything hides everything that was under
            // that path (dir replaced by file drops the subtree). A dir over
            // a dir just replaces the node and keeps children.
            if ty != EntryType::Directory {
                remove_subtree(&mut map, &path);
            }
            map.insert(
                path,
                Node {
                    layer: i,
                    offset: entry.raw_file_position(),
                    size: entry.size(),
                    header: entry.header().clone(),
                    link_name: entry.link_name()?.map(|c| c.into_owned()),
                },
            );
        }
    }
    Ok(map)
}

/// Pass 2: write the merged tar. Non-hardlinks go first in lexicographic
/// order (so parents precede children), hardlinks last (after their targets).
fn emit<W: Write>(staged: &[File], map: &BTreeMap<String, Node>, out: W) -> Result<()> {
    let mut builder = tar::Builder::new(out);
    let (links, regular): (Vec<_>, Vec<_>) = map
        .iter()
        .partition(|(_, n)| n.header.entry_type() == EntryType::Link);
    for (path, node) in regular.into_iter().chain(links) {
        emit_node(&mut builder, staged, path, node)
            .with_context(|| format!("write entry {path:?}"))?;
    }
    builder.finish()?;
    Ok(())
}

fn emit_node<W: Write>(
    builder: &mut tar::Builder<W>,
    staged: &[File],
    path: &str,
    node: &Node,
) -> Result<()> {
    let mut header = node.header.clone();
    match header.entry_type() {
        EntryType::Link | EntryType::Symlink => {
            let target = node
                .link_name
                .as_ref()
                .context("link entry without target")?;
            builder.append_link(&mut header, path, target)?;
        }
        _ if node.size > 0 => {
            let mut f = staged[node.layer].try_clone()?;
            f.seek(SeekFrom::Start(node.offset))?;
            builder.append_data(&mut header, path, f.take(node.size))?;
        }
        _ => builder.append_data(&mut header, path, std::io::empty())?,
    }
    Ok(())
}

/// PAX/GNU metadata entry types that must never become real nodes.
/// `Archive::entries()` resolves long names transparently; skipping these is
/// defense in depth.
fn is_metadata(ty: EntryType) -> bool {
    matches!(
        ty,
        EntryType::XGlobalHeader
            | EntryType::XHeader
            | EntryType::GNULongName
            | EntryType::GNULongLink
    )
}

/// Normalize a tar entry path: strip leading `./` and `/` and any trailing
/// `/`. Returns `None` for entries that normalize to nothing (e.g. `./`).
/// Errors on `..` components (path traversal).
fn normalize(path: &Path) -> Result<Option<String>> {
    let raw = path.to_str().context("non-UTF-8 path in layer")?;
    let mut parts = Vec::new();
    for comp in raw.split('/') {
        match comp {
            "" | "." => continue,
            ".." => bail!("path traversal in layer entry: {raw:?}"),
            c => parts.push(c),
        }
    }
    if parts.is_empty() {
        return Ok(None);
    }
    Ok(Some(parts.join("/")))
}

/// Split a normalized path into (parent, basename); parent is "" at root.
fn split(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

fn join(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

/// Remove all map keys strictly under `dir` (i.e. `dir/...`). An empty `dir`
/// means the root: everything currently in the map is removed.
fn remove_subtree(map: &mut BTreeMap<String, Node>, dir: &str) {
    if dir.is_empty() {
        map.clear();
        return;
    }
    let prefix = format!("{dir}/");
    let doomed: Vec<String> = map
        .range(prefix.clone()..)
        .map(|(k, _)| k)
        .take_while(|k| k.starts_with(&prefix))
        .cloned()
        .collect();
    for key in doomed {
        map.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use tar::EntryType;

    enum E<'a> {
        /// path, mode, content
        File(&'a str, u32, &'a [u8]),
        /// path; mode 0o755
        Dir(&'a str),
        /// path, target
        Symlink(&'a str, &'a str),
        /// path, target
        Hardlink(&'a str, &'a str),
        /// e.g. `Whiteout("a/b")` appends zero-len file `a/.wh.b`
        Whiteout(&'a str),
        /// `Opaque("d")` appends zero-len file `d/.wh..wh..opq`
        Opaque(&'a str),
    }

    fn add_file<W: Write>(b: &mut tar::Builder<W>, path: &str, mode: u32, content: &[u8]) {
        let mut h = tar::Header::new_gnu();
        h.set_size(content.len() as u64);
        h.set_mode(mode);
        h.set_entry_type(EntryType::Regular);
        b.append_data(&mut h, path, content).unwrap();
    }

    /// Build a gzipped layer tar from entries.
    fn layer(entries: &[E]) -> Vec<u8> {
        let gz = GzEncoder::new(Vec::new(), Compression::fast());
        let mut b = tar::Builder::new(gz);
        for e in entries {
            match e {
                E::File(path, mode, content) => add_file(&mut b, path, *mode, content),
                E::Dir(path) => {
                    let mut h = tar::Header::new_gnu();
                    h.set_size(0);
                    h.set_mode(0o755);
                    h.set_entry_type(EntryType::Directory);
                    b.append_data(&mut h, path, std::io::empty()).unwrap();
                }
                E::Symlink(path, target) => {
                    let mut h = tar::Header::new_gnu();
                    h.set_size(0);
                    h.set_mode(0o777);
                    h.set_entry_type(EntryType::Symlink);
                    b.append_link(&mut h, path, target).unwrap();
                }
                E::Hardlink(path, target) => {
                    let mut h = tar::Header::new_gnu();
                    h.set_size(0);
                    h.set_mode(0o644);
                    h.set_entry_type(EntryType::Link);
                    b.append_link(&mut h, path, target).unwrap();
                }
                E::Whiteout(path) => {
                    let (parent, base) = match path.rsplit_once('/') {
                        Some((p, b)) => (p, b),
                        None => ("", *path),
                    };
                    let wh = if parent.is_empty() {
                        format!(".wh.{base}")
                    } else {
                        format!("{parent}/.wh.{base}")
                    };
                    add_file(&mut b, &wh, 0o644, b"");
                }
                E::Opaque(dir) => {
                    add_file(&mut b, &format!("{dir}/.wh..wh..opq"), 0o644, b"");
                }
            }
        }
        b.into_inner().unwrap().finish().unwrap()
    }

    type Parsed = (BTreeMap<String, (EntryType, Vec<u8>, u32)>, Vec<String>);

    /// Run `flatten_layers` over the given layers and parse the resulting tar
    /// back. For Link/Symlink entries, the link target is stored as the
    /// content bytes. Also returns the raw ordered path list for order tests.
    fn flat(layers: &[Vec<u8>]) -> Parsed {
        let readers: Vec<Box<dyn Read>> = layers
            .iter()
            .map(|l| Box::new(Cursor::new(l.clone())) as Box<dyn Read>)
            .collect();
        let mut out = Vec::new();
        flatten_layers(readers, &mut out).unwrap();

        let mut ar = tar::Archive::new(Cursor::new(out));
        let mut map = BTreeMap::new();
        let mut order = Vec::new();
        for entry in ar.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry
                .path()
                .unwrap()
                .to_string_lossy()
                .trim_end_matches('/')
                .to_string();
            let et = entry.header().entry_type();
            let mode = entry.header().mode().unwrap();
            let content = match et {
                EntryType::Link | EntryType::Symlink => entry
                    .link_name()
                    .unwrap()
                    .expect("link entry must have a target")
                    .to_string_lossy()
                    .into_owned()
                    .into_bytes(),
                _ => {
                    let mut v = Vec::new();
                    entry.read_to_end(&mut v).unwrap();
                    v
                }
            };
            order.push(path.clone());
            map.insert(path, (et, content, mode));
        }
        (map, order)
    }

    #[test]
    fn merge_disjoint() {
        let l1 = layer(&[E::File("a.txt", 0o644, b"aaa")]);
        let l2 = layer(&[E::File("b.txt", 0o600, b"bbb")]);
        let (map, _) = flat(&[l1, l2]);
        assert_eq!(map["a.txt"], (EntryType::Regular, b"aaa".to_vec(), 0o644));
        assert_eq!(map["b.txt"], (EntryType::Regular, b"bbb".to_vec(), 0o600));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn upper_overrides() {
        let l1 = layer(&[E::File("etc/cfg", 0o644, b"old contents")]);
        let l2 = layer(&[E::File("etc/cfg", 0o600, b"new")]);
        let (map, _) = flat(&[l1, l2]);
        assert_eq!(map["etc/cfg"], (EntryType::Regular, b"new".to_vec(), 0o600));
    }

    #[test]
    fn whiteout_deletes() {
        let l1 = layer(&[E::Dir("etc"), E::File("etc/passwd", 0o644, b"root:x:0:0")]);
        let l2 = layer(&[E::Whiteout("etc/passwd")]);
        let (map, order) = flat(&[l1, l2]);
        assert!(!map.contains_key("etc/passwd"));
        assert!(map.contains_key("etc"));
        assert!(
            order.iter().all(|p| !p.contains(".wh.")),
            "no whiteout markers may appear in output: {order:?}"
        );
    }

    #[test]
    fn whiteout_deletes_whole_dir() {
        let l1 = layer(&[
            E::Dir("opt"),
            E::File("opt/x", 0o644, b"x"),
            E::Dir("opt/y"),
            E::File("opt/y/z", 0o644, b"z"),
        ]);
        let l2 = layer(&[E::Whiteout("opt")]);
        let (map, _) = flat(&[l1, l2]);
        assert!(
            map.keys().all(|k| k != "opt" && !k.starts_with("opt/")),
            "nothing at or under opt may survive: {:?}",
            map.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn opaque_dir() {
        let l1 = layer(&[
            E::Dir("cfg"),
            E::File("cfg/a", 0o644, b"a"),
            E::File("cfg/b", 0o644, b"b"),
        ]);
        let l2 = layer(&[E::Opaque("cfg"), E::File("cfg/c", 0o644, b"ccc")]);
        let (map, order) = flat(&[l1, l2]);
        let keys: Vec<&str> = map.keys().map(|s| s.as_str()).collect();
        assert_eq!(keys, ["cfg", "cfg/c"]);
        assert_eq!(map["cfg"].0, EntryType::Directory);
        assert_eq!(map["cfg/c"].1, b"ccc");
        assert!(
            order.iter().all(|p| !p.contains(".wh.")),
            "no opaque markers may appear in output: {order:?}"
        );
    }

    #[test]
    fn symlink_preserved() {
        let l1 = layer(&[E::Dir("bin"), E::Symlink("bin/sh", "/bin/busybox")]);
        let (map, _) = flat(&[l1]);
        let (et, target, _) = &map["bin/sh"];
        assert_eq!(*et, EntryType::Symlink);
        assert_eq!(target, b"/bin/busybox");
    }

    #[test]
    fn modes_preserved() {
        let l1 = layer(&[E::File("usr/bin/su", 0o4755, b"#!/bin/sh")]);
        let (map, _) = flat(&[l1]);
        assert_eq!(map["usr/bin/su"].2, 0o4755);
    }

    #[test]
    fn parents_before_children() {
        // Deliberately appended out of order within the layers.
        let l1 = layer(&[
            E::File("usr/bin/ls", 0o755, b"ls"),
            E::Dir("usr"),
            E::Dir("usr/bin"),
            E::File("etc/hosts", 0o644, b"localhost"),
            E::Dir("etc"),
        ]);
        let l2 = layer(&[
            E::File("var/log/syslog", 0o640, b"boot"),
            E::Dir("var/log"),
            E::Dir("var"),
        ]);
        let (_, order) = flat(&[l1, l2]);
        for (i, p) in order.iter().enumerate() {
            let prefix = format!("{p}/");
            for (j, q) in order.iter().enumerate() {
                if q.starts_with(&prefix) {
                    assert!(i < j, "{p} (index {i}) must precede {q} (index {j})");
                }
            }
        }
    }

    #[test]
    fn hardlink_after_target() {
        // Naive lexicographic order would put aaa.link before zzz.bin.
        let l1 = layer(&[
            E::Hardlink("aaa.link", "zzz.bin"),
            E::File("zzz.bin", 0o644, b"data"),
        ]);
        let (map, order) = flat(&[l1]);
        let bin = order.iter().position(|p| p == "zzz.bin").unwrap();
        let link = order.iter().position(|p| p == "aaa.link").unwrap();
        assert!(bin < link, "target must precede hardlink: {order:?}");
        assert_eq!(map["aaa.link"].0, EntryType::Link);
        assert_eq!(map["aaa.link"].1, b"zzz.bin");
    }

    #[test]
    fn dir_replaced_by_file() {
        let l1 = layer(&[E::Dir("x"), E::File("x/f", 0o644, b"f")]);
        let l2 = layer(&[E::File("x", 0o644, b"now a file")]);
        let (map, _) = flat(&[l1, l2]);
        assert_eq!(
            map["x"],
            (EntryType::Regular, b"now a file".to_vec(), 0o644)
        );
        assert!(!map.contains_key("x/f"));
    }

    #[test]
    fn rejects_path_traversal() {
        // tar::Builder refuses to set `..` paths, so write the name field raw.
        let gz = GzEncoder::new(Vec::new(), Compression::fast());
        let mut b = tar::Builder::new(gz);
        let mut h = tar::Header::new_gnu();
        let name = b"../evil";
        h.as_old_mut().name[..name.len()].copy_from_slice(name);
        h.set_size(4);
        h.set_mode(0o644);
        h.set_entry_type(EntryType::Regular);
        h.set_cksum();
        b.append(&h, &b"pwnd"[..]).unwrap();
        let bytes = b.into_inner().unwrap().finish().unwrap();

        let layers: Vec<Box<dyn Read>> = vec![Box::new(Cursor::new(bytes))];
        assert!(flatten_layers(layers, &mut Vec::new()).is_err());
    }
}
