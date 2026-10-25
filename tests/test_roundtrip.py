#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_roundtrip.py - ExiFS end-to-end verification

Covers: mkfs -> VBR/CRC -> metadata files -> mkdir -> write (resident &
non-resident) -> read-back -> integrity -> unlink -> bitmap consistency ->
fsck clean -> deliberate corruption -> fsck detects & repairs.
"""
import os
import sys
import struct
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
from exifs_core import *  # noqa
import exifs_ref as R

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] %s" % name)
    else:
        FAIL += 1
        print("  [FAIL] %s %s" % (name, detail))


def run(img, *args, binary=False):
    script = os.path.join(HERE, "..", "tools", "exifs_ref.py")
    base = [sys.executable, script]
    if args and args[0] == "mkfs":
        # mkfs takes -o <image>, no positional image argument
        argv = base + list(args)
    else:
        # <cmd> <image> [args...]
        argv = base + list(args[:1]) + [img] + list(args[1:])
    r = subprocess.run(argv, capture_output=True, text=not binary)
    return r


def main():
    tmp = tempfile.mkdtemp(prefix="exifs_test_")
    img = os.path.join(tmp, "test.exifs")

    print("== 1. mkfs 64M / cluster 4096 ==")
    r = run(img, "mkfs", "-o", img, "-s", "64M", "-l", "ExiTest")
    check("mkfs exit 0", r.returncode == 0, r.stderr)
    check("image size 64M", os.path.getsize(img) == 64 * 1024 * 1024)

    print("== 2. VBR / superblock ==")
    with open(img, "rb") as f:
        vbr = f.read(512)
    try:
        info = parse_vbr(vbr)
        ok = True
    except Exception as e:
        ok = False
        info = {"err": str(e)}
    check("VBR parses + CRC64 valid", ok, info.get("err", ""))
    check("OEM name EXIFS", vbr[3:11] == b"EXIFS   ")
    check("boot sig 0xAA55",
          struct.unpack_from("<H", vbr, 0x1FE)[0] == 0xAA55)
    check("label ExiTest", info.get("label") == "ExiTest", info.get("label"))
    check("MFT records = 64", info.get("mft_records") == 64)
    lay = compute_layout(4096, 64 * 1024 * 1024)
    check("data_lcn matches layout", info.get("data_lcn") == lay["data_lcn"],
          "%s vs %s" % (info.get("data_lcn"), lay["data_lcn"]))

    print("== 3. metadata files ==")
    fs = R.ExiFS(img, read_only=True)
    names = {}
    for no in range(16):
        try:
            p = parse_record(bytes(fs.mft[no]))
            if p["flags"] & MRF_INUSE:
                for a in p["attrs"]:
                    if a["type"] == AT_FILE_NAME and not a["nonres"]:
                        names[index_key_name(a["value"])] = no
        except Exception:
            pass
    for expect in ["$MFT", "$MFTMirr", "$LogFile", "$Volume", "$AttrDef",
                   ".", "$Bitmap", "$Boot", "$BadClus", "$Secure", "$UpCase",
                   "$Extend"]:
        check("metadata file %s present" % expect, expect in names)
    check("root is directory",
          parse_record(bytes(fs.mft[FILE_ROOT]))["flags"] & MRF_DIRECTORY)

    print("== 4. mirror consistency ==")
    fs.f.seek(lay["mftmirr_lcn"] * 4096)
    mirr = fs.f.read(4096)
    check("$MFTMirr == first 4 MFT records",
          mirr == bytes(fs.mft[0]) + bytes(fs.mft[1]) + bytes(fs.mft[2]) +
          bytes(fs.mft[3]))
    fs.close()

    print("== 5. mkdir / write / read ==")
    r = run(img, "mkdir", "/docs")
    check("mkdir /docs", r.returncode == 0, r.stdout + r.stderr)
    small = b"hello ExiFS"
    r = run(img, "write", "/docs/hello.txt", "-")
    check("write via stdin", r.returncode == 0, r.stderr)
    with open(os.path.join(tmp, "big.bin"), "wb") as f:
        f.write(os.urandom(100000))  # spans many clusters
    r = run(img, "write", "/docs/big.bin", os.path.join(tmp, "big.bin"))
    check("write 100KB non-resident", r.returncode == 0, r.stderr)
    r = run(img, "cat", "/docs/big.bin", binary=True)
    got = r.stdout
    with open(os.path.join(tmp, "big.bin"), "rb") as f:
        want = f.read()
    check("100KB read-back byte-identical", got == want,
          "%d vs %d bytes" % (len(got), len(want)))

    print("== 6. directory listing ==")
    r = run(img, "ls", "/docs")
    check("ls shows hello.txt", "hello.txt" in r.stdout, r.stdout)
    check("ls shows big.bin", "big.bin" in r.stdout)
    r = run(img, "ls", "/")
    check("root lists docs", "docs" in r.stdout, r.stdout)

    print("== 7. unlink + bitmap ==")
    r = run(img, "rm", "/docs/big.bin")
    check("rm big.bin", r.returncode == 0, r.stderr)
    fs = R.ExiFS(img)
    fs._bm_load()
    total = info["total_sectors"] * 512 // fs.cluster
    used = sum(bin(fs.bitmap[c >> 3]).count("1") for c in range(0, 1))
    allocated = 0
    for no, rec in enumerate(fs.mft):
        if rec is None or not (struct.unpack_from("<H", rec, 0x16)[0] &
                               MRF_INUSE):
            continue
        try:
            p = parse_record(bytes(rec))
        except Exception:
            continue
        for a in p["attrs"]:
            if a["type"] == AT_DATA and a["nonres"]:
                for rr in a["runs"]:
                    if not rr["sparse"]:
                        allocated += rr["length"]
    # every allocated cluster must be marked in bitmap
    bad = 0
    for no, rec in enumerate(fs.mft):
        if rec is None or not (struct.unpack_from("<H", rec, 0x16)[0] &
                               MRF_INUSE):
            continue
        try:
            p = parse_record(bytes(rec))
        except Exception:
            continue
        for a in p["attrs"]:
            if a["type"] == AT_DATA and a["nonres"]:
                for rr in a["runs"]:
                    if rr["sparse"]:
                        continue
                    for j in range(rr["length"]):
                        c = rr["lcn"] + j
                        if not (fs.bitmap[c >> 3] & (1 << (c & 7))):
                            bad += 1
    check("all allocated clusters marked in bitmap", bad == 0,
          "%d unmarked" % bad)
    fs.close()

    print("== 8. fsck clean ==")
    r = run(img, "fsck")
    check("fsck reports clean", "CLEAN" in r.stdout, r.stdout)
    check("fsck exit 0", r.returncode == 0, str(r.returncode))

    print("== 9. corruption detection & repair ==")
    fs = R.ExiFS(img)
    fs._bm_load()
    # flip a free bit to simulate bitmap corruption
    fs.bitmap[10] ^= 0xFF
    fs._bm_flush()
    fs.close()
    r = run(img, "fsck")
    check("fsck detects bitmap mismatch", "mismatch" in r.stdout, r.stdout)
    check("fsck exit 4 (uncorrected)", r.returncode == 4, str(r.returncode))
    r = run(img, "fsck", "-p")
    check("fsck -p repairs", "FIXED" in r.stdout, r.stdout)
    r = run(img, "fsck")
    check("fsck clean after repair", "CLEAN" in r.stdout, r.stdout)

    print("== 10. VBR corruption detection ==")
    with open(img, "r+b") as f:
        f.seek(0x50)
        f.write(b"XXXX")
    r = run(img, "info")
    check("info fails on corrupted VBR", r.returncode != 0)

    print("")
    print("=================================")
    print("RESULT: %d passed, %d failed" % (PASS, FAIL))
    print("=================================")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
