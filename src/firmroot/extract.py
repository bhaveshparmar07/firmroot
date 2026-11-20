"""Firmware extraction: firmware image -> extracted root filesystem tree(s).

Strategy (no hardcoded offsets, works by magic/structure):
  1. If input is a directory, treat it as an already-extracted rootfs.
  2. Scan raw image for filesystem magics directly (squashfs hsqs/sqsh,
     cramfs, jffs2, ubifs) and carve each by its own size fields.
  3. Scan for UBI erase-count headers ("UBI#"), group PEBs into runs by
     stride, reconstruct the per-PEB data stream (skipping EC/VID headers),
     then scan each stream for filesystem magics.
  4. Fallback: run `binwalk -e` and adopt any extracted filesystem dirs.

Each candidate filesystem is extracted with the matching tool and scored;
the best rootfs (has etc/ + init scripts) is returned as primary, with all
candidates listed for evidence.
"""

import os
import re
import struct
import subprocess
import hashlib
from pathlib import Path

SQFS_MAGIC_LE = b"hsqs"
SQFS_MAGIC_BE = b"sqsh"
CRAMFS_MAGIC = b"Compressed ROMFS"
UBIFS_MAGIC = b"\x31\x18\x10\x06"  # UBIFS node magic (LE u32 0x06101831)
JFFS2_MAGIC = b"\x85\x19"  # JFFS2 node magic (0x1985) - weak, used only w/ cleanmarkers
UBI_EC_MAGIC = b"UBI#"


def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def _squashfs_size(data, off):
    """Return bytes_used from a squashfs superblock at off, or None."""
    if off + 96 > len(data):
        return None
    sb = data[off:off + 96]
    magic = sb[:4]
    if magic == SQFS_MAGIC_LE:
        endian = "<"
    elif magic == SQFS_MAGIC_BE:
        endian = ">"
    else:
        return None
    try:
        s_major, s_minor = struct.unpack(endian + "HH", sb[28:32])
        if s_major != 4:
            return None
        bytes_used = struct.unpack(endian + "Q", sb[40:48])[0]
        inodes = struct.unpack(endian + "I", sb[4:8])[0]
        if not (0 < bytes_used <= len(data) - off) or inodes == 0 or inodes > 10_000_000:
            return None
        return bytes_used
    except struct.error:
        return None


def _find_ubi_runs(data):
    """Find runs of UBI PEBs. Returns list of (base_offset, peb_size, [peb_offsets])."""
    positions = [m.start() for m in re.finditer(re.escape(UBI_EC_MAGIC), data)]
    if not positions:
        return []
    # determine stride from the most common small difference
    diffs = {}
    for i in range(len(positions) - 1):
        d = positions[i + 1] - positions[i]
        if 0x1000 <= d <= 0x400000:
            diffs[d] = diffs.get(d, 0) + 1
    if not diffs:
        return []
    stride = max(diffs, key=diffs.get)

    runs = []
    cur = [positions[0]]
    for p in positions[1:]:
        if p - cur[-1] == stride:
            cur.append(p)
        else:
            if len(cur) >= 4:
                runs.append((cur[0], stride, cur))
            cur = [p]
    if len(cur) >= 4:
        runs.append((cur[0], stride, cur))
    return runs


def _ubi_streams(data, runs):
    """Reconstruct data streams for each UBI run, skipping EC/VID headers.

    This firmware family uses UBI headers with scrubbed/absent VID data;
    we treat the region between data_offset and the next PEB as a raw
    stream. Returns list of (run_base, stream_bytes).
    """
    streams = []
    for base, stride, pebs in runs:
        # read data_offset from first EC header
        data_offset = 0x1000
        try:
            data_offset = struct.unpack(">I", data[base + 20:base + 24])[0]
            if not (0x200 <= data_offset < stride):
                data_offset = 0x1000
        except struct.error:
            pass
        out = bytearray()
        for peb in pebs:
            # include only PEBs that still carry an EC magic
            if data[peb:peb + 4] != UBI_EC_MAGIC:
                continue
            end = min(peb + stride, len(data))
            out += data[peb + data_offset:end]
        if out:
            streams.append((base, bytes(out)))
    return streams


def _carve_squashfs(stream, workdir, tag):
    """Find and carve all squashfs filesystems in a byte stream."""
    carved = []
    for magic in (SQFS_MAGIC_LE, SQFS_MAGIC_BE):
        start = 0
        while True:
            off = stream.find(magic, start)
            if off < 0:
                break
            size = _squashfs_size(stream, off)
            if size:
                path = Path(workdir) / f"carved-{tag}-{off:x}.sqfs"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(stream[off:off + size])
                carved.append(path)
                start = off + size
            else:
                start = off + 4
    return carved


def _unsquashfs(sqfs_path, dest):
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    r = _run(["unsquashfs", "-d", str(dest), "-f", str(sqfs_path)])
    return dest if (dest / "etc").exists() or any(dest.iterdir()) else None


def _score_rootfs(path):
    " Higher = more likely a real root filesystem. """
    p = Path(path)
    score = 0
    for marker, pts in [
        ("etc", 3), ("bin", 2), ("sbin", 2), ("usr", 1), ("lib", 1),
        ("etc/inittab", 4), ("etc/init.d", 4), ("etc/rc.d", 3),
        ("lib/firmware", 1), ("www", 1), ("overlay", 1),
    ]:
        if (p / marker).exists():
            score += pts
    # count executables as a weak signal
    try:
        n = sum(1 for _ in p.rglob("*") if _.is_file())
        score += min(n // 200, 5)
    except OSError:
        pass
    return score


def _binwalk_fallback(image_path, workdir):
    outdir = Path(workdir) / "binwalk-out"
    outdir.mkdir(parents=True, exist_ok=True)
    r = _run(["binwalk", "-e", "-C", str(outdir), str(image_path)], timeout=600)
    candidates = []
    for d in outdir.rglob("*"):
        if d.is_dir() and ((d / "etc").exists() or (d / "bin").exists()):
            candidates.append(d)
    return candidates


def extract_firmware(image_path, workdir):
    """Extract a firmware image. Returns dict:
    {image, sha256, rootfs_candidates: [{path, score, method}], primary_rootfs}
    """
    image_path = Path(image_path)
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    result = {"image": str(image_path), "sha256": sha256_file(image_path),
              "rootfs_candidates": [], "primary_rootfs": None}

    # Case 1: directory input = already extracted
    if image_path.is_dir():
        result["rootfs_candidates"].append(
            {"path": str(image_path), "score": _score_rootfs(image_path), "method": "directory"})
        result["primary_rootfs"] = str(image_path)
        return result

    data = image_path.read_bytes()
    carved_sqfs = []

    # Case 2: direct filesystem magics in the image
    carved_sqfs += _carve_squashfs(data, workdir / "direct", "direct")
    # cramfs
    coff = 0
    while True:
        off = data.find(CRAMFS_MAGIC, coff)
        if off < 0:
            break
        if off >= 16:
            size = struct.unpack(">I", data[off - 4:off])[0] if off >= 4 else 0
            # cramfs superblock: magic at offset 16 of sb; size field at sb+4
            sb_start = off - 16
            if sb_start >= 0:
                fssize = struct.unpack(">I", data[sb_start + 4:sb_start + 8])[0]
                if 0 < fssize <= len(data) - sb_start:
                    p = Path(workdir) / "direct" / f"carved-cramfs-{sb_start:x}.cramfs"
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_bytes(data[sb_start:sb_start + fssize])
                    carved_sqfs.append(p)  # reuse unsquashfs path below w/ cramfs note
        coff = off + 16

    # Case 3: UBI streams
    runs = _find_ubi_runs(data)
    for base, stream in _ubi_streams(data, runs):
        tag = f"ubi-{base:x}"
        sub = workdir / "ubi" / tag
        sub.mkdir(parents=True, exist_ok=True)
        (sub / "stream.bin").write_bytes(stream)
        carved_sqfs += _carve_squashfs(stream, sub, tag)

    # Extract every carved squashfs
    extracted = []
    for sq in carved_sqfs:
        name = sq.stem
        dest = workdir / "rootfs" / name
        fs = _unsquashfs(sq, dest)
        if fs:
            extracted.append({"path": str(fs), "score": _score_rootfs(fs),
                              "method": f"squashfs:{sq.name}"})

    # cramfs carve outputs need cramfsck; handle separately
    for sq in list(carved_sqfs):
        if sq.suffix == ".cramfs":
            dest = workdir / "rootfs" / sq.stem
            dest.mkdir(parents=True, exist_ok=True)
            r = _run(["cramfsck", "-x", str(dest), str(sq)])
            if (dest / "etc").exists() or any(dest.iterdir()):
                extracted.append({"path": str(dest), "score": _score_rootfs(dest),
                                  "method": f"cramfs:{sq.name}"})

    # Case 4: binwalk fallback if nothing extracted
    if not extracted:
        for d in _binwalk_fallback(image_path, workdir):
            extracted.append({"path": str(d), "score": _score_rootfs(d),
                              "method": "binwalk"})

    extracted.sort(key=lambda c: -c["score"])
    result["rootfs_candidates"] = extracted
    if extracted:
        result["primary_rootfs"] = extracted[0]["path"]
    return result
