#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exifs_core.py - ExiFS on-disk format primitives (reference implementation)

Mirrors include/exifs.h exactly. All integers little-endian.
"""
import struct

SECTOR_SIZE = 512
MFT_REC_SIZE = 1024
INDEX_REC_SIZE = 4096
VERSION = 0x0100
OEM_NAME = b"EXIFS   "
MAGIC_FILE = b"FILE"
MAGIC_INDX = b"INDX"
BOOT_SIG = 0xAA55
VOL_SERIAL = 0x58484346
EPOCH_DIFF = 11644473600  # seconds 1601->1970

# attribute types
AT_STD_INFO = 0x10
AT_ATTR_LIST = 0x20
AT_FILE_NAME = 0x30
AT_VOL_NAME = 0x60
AT_VOL_INFO = 0x70
AT_DATA = 0x80
AT_INDEX_ROOT = 0x90
AT_INDEX_ALLOC = 0xA0
AT_BITMAP = 0xB0
AT_END = 0xFFFFFFFF

# record flags
MRF_INUSE = 0x0001
MRF_DIRECTORY = 0x0002

# dos flags
DOS_READONLY = 0x1
DOS_HIDDEN = 0x2
DOS_SYSTEM = 0x4
DOS_ARCHIVE = 0x20
DOS_NORMAL = 0x80

# namespaces
NS_POSIX = 0
NS_WIN32 = 1
NS_DOS = 2
NS_WIN32DOS = 3

# metadata files
FILE_MFT = 0
FILE_MFTMIRR = 1
FILE_LOGFILE = 2
FILE_VOLUME = 3
FILE_ATTRDEF = 4
FILE_ROOT = 5
FILE_BITMAP = 6
FILE_BOOT = 7
FILE_BADCLUS = 8
FILE_SECURE = 9
FILE_UPCASE = 10
FILE_EXTEND = 11
FIRST_USER = 16

MFT_RECORDS = 64  # must match mkexifs.c
MFT_ZONE_RECORDS = 1024  # preallocated MFT zone (extends in place, v1.1)

# ---------------------------------------------------------------- crc64
def _make_table():
    tbl = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ (0xC96C5795D7870F42 if crc & 1 else 0)
        tbl.append(crc)
    return tbl

_CRC_TABLE = _make_table()

def crc64(data: bytes) -> int:
    crc = 0xFFFFFFFFFFFFFFFF
    for b in data:
        crc = _CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return (~crc) & 0xFFFFFFFFFFFFFFFF

# ---------------------------------------------------------------- fixup
def fixup_prepare(buf: bytearray, usa_off: int, usa_count: int) -> bool:
    """Prepare a record for writing: save sector tails, stamp USN."""
    if usa_count < 2 or usa_off + usa_count * 2 > len(buf):
        return False
    usn = struct.unpack_from("<H", buf, usa_off)[0] + 1
    if usn == 0:
        usn = 1
    struct.pack_into("<H", buf, usa_off, usn)
    for i in range(usa_count - 1):
        tail = (i + 1) * SECTOR_SIZE - 2
        orig = struct.unpack_from("<H", buf, tail)[0]
        struct.pack_into("<H", buf, usa_off + 2 + i * 2, orig)
        struct.pack_into("<H", buf, tail, usn)
    return True

def fixup_apply(buf: bytearray, usa_off: int, usa_count: int) -> bool:
    """Restore original sector tails after reading."""
    if usa_count < 2 or usa_off + usa_count * 2 > len(buf):
        return False
    usn = struct.unpack_from("<H", buf, usa_off)[0]
    for i in range(usa_count - 1):
        tail = (i + 1) * SECTOR_SIZE - 2
        if struct.unpack_from("<H", buf, tail)[0] != usn:
            return False
        orig = struct.unpack_from("<H", buf, usa_off + 2 + i * 2)[0]
        struct.pack_into("<H", buf, tail, orig)
    return True

# ---------------------------------------------------------------- runs
def run_encode(lcn: int, vcn: int, length: int, prev_lcn: int,
               sparse: bool = False) -> bytes:
    """Encode one run. Header byte FIRST, then length bytes, then the
    signed offset delta. (Never overwrite already-written bytes.)"""
    out = bytearray()
    lb = 1
    l = length
    while (l >> (8 * lb)) and lb < 8:
        lb += 1
    hdr = lb & 0x0F
    ob = 0
    u = 0
    if not sparse and lcn is not None:
        delta = lcn - prev_lcn
        u = delta & 0xFFFFFFFFFFFFFFFF
        ob = 1
        while ob < 8:
            bits = 8 * ob
            mask = (1 << bits) - 1
            sign = 1 << (bits - 1)
            if 0 <= delta <= mask and not (delta & sign):
                break
            if -mask <= delta < 0 and (u & mask) == (u & ((sign << 1) - 1)) \
               and (u & sign):
                break
            ob += 1
        hdr |= (ob << 4) & 0xF0
    out.append(hdr)
    for i in range(lb):
        out.append((length >> (8 * i)) & 0xFF)
    for i in range(ob):
        out.append((u >> (8 * i)) & 0xFF)
    return bytes(out)

def runs_encode(runs) -> bytes:
    """runs: list of (lcn, length) tuples; lcn None = sparse."""
    out = bytearray()
    prev = 0
    for lcn, length in runs:
        sparse = lcn is None
        out += run_encode(lcn if not sparse else 0, 0, length, prev, sparse)
        if not sparse:
            prev = lcn
    out.append(0)
    return bytes(out)

def runs_parse(data: bytes):
    """-> list of dicts {lcn, vcn, length, sparse}"""
    runs = []
    pos = 0
    prev = 0
    while pos < len(data):
        hdr = data[pos]
        if hdr == 0:
            break
        lb = hdr & 0x0F
        ob = (hdr >> 4) & 0x0F
        if lb == 0 or pos + 1 + lb > len(data):
            raise ValueError("bad run header")
        length = int.from_bytes(data[pos + 1:pos + 1 + lb], "little")
        pos += 1 + lb
        if ob == 0:
            runs.append({"lcn": None, "vcn": 0 if not runs else runs[-1]["vcn"] + runs[-1]["length"],
                         "length": length, "sparse": True})
        else:
            if pos + ob > len(data):
                raise ValueError("truncated run offset")
            u = int.from_bytes(data[pos:pos + ob], "little")
            pos += ob
            if u & (1 << (8 * ob - 1)):
                u -= (1 << (8 * ob))
            lcn = prev + u
            prev = lcn
            runs.append({"lcn": lcn,
                         "vcn": 0 if not runs else runs[-1]["vcn"] + runs[-1]["length"],
                         "length": length, "sparse": False})
    return runs

# ---------------------------------------------------------------- utf16
def utf8_to_utf16le(s: str) -> bytes:
    return s.encode("utf-16-le")

def utf16le_to_utf8(b: bytes) -> str:
    return b.decode("utf-16-le", errors="replace")

# ---------------------------------------------------------------- refs
def ref_make(rec_no: int, seq: int = 1) -> int:
    return ((seq & 0xFFFF) << 48) | (rec_no & 0xFFFFFFFFFFFF)

def ref_recno(ref: int) -> int:
    return ref & 0xFFFFFFFFFFFF

# ---------------------------------------------------------------- attrs
def build_std_info(dos_flags: int = DOS_NORMAL) -> bytes:
    now = (EPOCH_DIFF * 10000000)
    return struct.pack("<QQQQIIQ", now, now, now, now, dos_flags, 0, 0)

def build_file_name(parent_ref: int, name: str, ns: int = NS_POSIX,
                    real_size: int = 0, flags: int = MRF_INUSE) -> bytes:
    nm = utf8_to_utf16le(name)
    now = EPOCH_DIFF * 10000000
    head = struct.pack("<QQQQQQQIBB", parent_ref, now, now, now, now,
                       0, real_size, flags, len(name), ns)
    return head + nm

def build_attr(type_: int, value: bytes, flags: int = 0, name: str = "") -> bytes:
    """resident attribute"""
    name_b = utf8_to_utf16le(name)
    name_off = 0x18
    val_off = (name_off + len(name_b) + 7) & ~7
    total = (val_off + len(value) + 7) & ~7
    hdr = bytearray(total)
    # type, length, non_resident, name_len, name_off, flags, instance
    struct.pack_into("<IIBBHHH", hdr, 0, type_, total, 0,
                     len(name), name_off, flags, 0)
    struct.pack_into("<IHB", hdr, 0x10, len(value), val_off, 0)
    if name_b:
        hdr[name_off:name_off + len(name_b)] = name_b
    hdr[val_off:val_off + len(value)] = value
    return bytes(hdr)

def build_attr_nonres(type_: int, runs: bytes, alloc_size: int,
                      real_size: int, init_size: int) -> bytes:
    """non-resident attribute, single VCN extent (fragmentation-free)"""
    run_off = 0x48
    total = (run_off + len(runs) + 7) & ~7
    hdr = bytearray(total)
    struct.pack_into("<II", hdr, 0, type_, total)
    hdr[8] = 1  # non-resident
    struct.pack_into("<HH", hdr, 0x0C, 0, 0)      # flags, instance
    struct.pack_into("<QQ", hdr, 0x10, 0, 0)      # start/last vcn
    struct.pack_into("<H", hdr, 0x28, run_off)
    struct.pack_into("<QQQ", hdr, 0x30, alloc_size, real_size, init_size)
    hdr[run_off:run_off + len(runs)] = runs
    return bytes(hdr)

# ---------------------------------------------------------------- index
def build_index_root(entries=None, small: bool = True) -> bytes:
    """entries: list of (ref, key_bytes). Returns resident value.

    Layout: 0x00 type(4) collation(4) entry_size(4) clusters_per_rec(1)+pad(3)
            0x10 index header: entries_off(4) index_len(4) alloc_len(4) flags(4)
            0x20 entries (entries_off is relative to 0x10)
    """
    body = bytearray()
    for ref, key in (entries or []):
        e = struct.pack("<QHH", ref, len(key), 0x02) + key
        e += b"\x00" * ((-len(e)) % 8)
        body += e
    val = bytearray(0x20 + len(body))
    struct.pack_into("<III", val, 0, AT_FILE_NAME, 1, 0)
    val[0x0C] = 0  # clusters per index record
    struct.pack_into("<IIII", val, 0x10, 0x10, 0x10 + len(body),
                     0x10 + len(body), 1 if small else 0)
    val[0x20:0x20 + len(body)] = body
    return bytes(val)

def parse_index_root(val: bytes):
    """-> list of (ref, key_bytes)"""
    entries_off = struct.unpack_from("<I", val, 0x10)[0]
    idx_len = struct.unpack_from("<I", val, 0x14)[0]
    out = []
    p = 0x10 + entries_off
    end = 0x10 + idx_len
    while p + 12 <= end:
        ref, klen, eflags = struct.unpack_from("<QHH", val, p)
        if p + 12 + klen > end:
            break
        out.append((ref, val[p + 12:p + 12 + klen]))
        p += (12 + klen + 7) & ~7
    return out

# ---------------------------------------------------------------- B+tree (v1.1)
# entry tuple: (ref, key_bytes, flags)
#   flags bit0 (0x01) = sub-node pointer; ref low48 = child VCN (not MFT no)
#   flags bit1 (0x02) = last entry marker (informational)
ENTRY_PTR = 0x01
ENTRY_LAST = 0x02

INDX_USA_OFF = 0x28
INDX_USA_COUNT = 9            # 8 sectors + USN
INDX_ENTRIES_OFF = 0x28       # relative to index header at 0x18
INDX_NODE_CAP = 3900          # max serialized entry bytes per INDX node
ROOT_NODE_CAP = 700           # max serialized entry bytes in resident root


def _entries_body(entries) -> bytes:
    body = bytearray()
    for ref, key, ef in entries:
        e = struct.pack("<QHH", ref, len(key), ef) + key
        e += b"\x00" * ((-len(e)) % 8)
        body += e
    return bytes(body)


def entries_size(entries) -> int:
    return len(_entries_body(entries))


def key_cmp(a: bytes, b: bytes) -> int:
    """collation for FILE_NAME keys: name (UTF-16 code units) then namespace"""
    na, nsa = a[0x3C], a[0x3D]
    nb, nsb = b[0x3C], b[0x3D]
    name_a = a[0x3E:0x3E + na * 2]
    name_b = b[0x3E:0x3E + nb * 2]
    if name_a != name_b:
        return -1 if name_a < name_b else 1
    if nsa != nsb:
        return -1 if nsa < nsb else 1
    return 0


def sorted_insert(entries, entry):
    """insert (ref, key, flags) keeping key order; returns new list"""
    lo, hi = 0, len(entries)
    while lo < hi:
        mid = (lo + hi) // 2
        if key_cmp(entries[mid][1], entry[1]) <= 0:
            lo = mid + 1
        else:
            hi = mid
    return entries[:lo] + [entry] + entries[lo:]


def build_index_root_v2(entries, small: bool = True) -> bytes:
    """INDEX_ROOT value; entries: [(ref, key, flags)]"""
    body = _entries_body(entries)
    val = bytearray(0x20 + len(body))
    struct.pack_into("<III", val, 0, AT_FILE_NAME, 1, 0)
    val[0x0C] = 0                                   # clusters per record
    struct.pack_into("<IIII", val, 0x10, 0x10, 0x10 + len(body),
                     0x10 + len(body), 1 if small else 0)
    val[0x20:0x20 + len(body)] = body
    return bytes(val)


def parse_index_root_v2(val: bytes):
    """-> [(ref, key, flags)]"""
    entries_off = struct.unpack_from("<I", val, 0x10)[0]
    idx_len = struct.unpack_from("<I", val, 0x14)[0]
    out = []
    p = 0x10 + entries_off
    end = 0x10 + idx_len
    while p + 12 <= end:
        ref, klen, ef = struct.unpack_from("<QHH", val, p)
        if p + 12 + klen > end:
            break
        out.append((ref, val[p + 12:p + 12 + klen], ef))
        p += (12 + klen + 7) & ~7
    return out


def build_indx(vcn: int, entries) -> bytes:
    """4096B INDEX_ALLOCATION record (leaf or interior node)"""
    body = _entries_body(entries)
    rec = bytearray(INDEX_REC_SIZE)
    rec[0:4] = MAGIC_INDX
    struct.pack_into("<HH", rec, 0x04, INDX_USA_OFF, INDX_USA_COUNT)
    struct.pack_into("<Q", rec, 0x08, 0)              # lsn
    struct.pack_into("<Q", rec, 0x10, vcn)
    idx_len = INDX_ENTRIES_OFF + len(body)            # measured from 0x18
    struct.pack_into("<IIII", rec, 0x18, INDX_ENTRIES_OFF, idx_len,
                     idx_len, 0)
    rec[0x40:0x40 + len(body)] = body
    fixup_prepare(rec, INDX_USA_OFF, INDX_USA_COUNT)
    return bytes(rec)


def parse_indx(rec: bytes):
    """-> [(ref, key, flags)]; raises on bad magic/fixup"""
    buf = bytearray(rec)
    if buf[0:4] != MAGIC_INDX:
        raise ValueError("bad INDX magic")
    if not fixup_apply(buf, INDX_USA_OFF, INDX_USA_COUNT):
        raise ValueError("INDX fixup failed")
    entries_off = struct.unpack_from("<I", buf, 0x18)[0]
    idx_len = struct.unpack_from("<I", buf, 0x1C)[0]
    out = []
    p = 0x18 + entries_off
    end = 0x18 + idx_len
    while p + 12 <= end:
        ref, klen, ef = struct.unpack_from("<QHH", buf, p)
        if p + 12 + klen > end:
            break
        out.append((ref, bytes(buf[p + 12:p + 12 + klen]), ef))
        p += (12 + klen + 7) & ~7
    return out

def index_key_name(key: bytes) -> str:
    nlen = key[0x3C]
    ns = key[0x3D]
    name = utf16le_to_utf8(key[0x3E:0x3E + nlen * 2])
    return name

# ---------------------------------------------------------------- record
def build_record(rec_no: int, flags: int, attrs: list) -> bytes:
    rec = bytearray(MFT_REC_SIZE)
    total = 56 + sum(len(a) for a in attrs) + 4
    if total > MFT_REC_SIZE:
        raise ValueError("record %d overflow: %d > %d bytes" %
                         (rec_no, total, MFT_REC_SIZE))
    rec[0:4] = MAGIC_FILE
    struct.pack_into("<HH", rec, 0x04, 48, 3)     # usa off/count
    struct.pack_into("<H", rec, 0x10, 1)          # sequence
    struct.pack_into("<H", rec, 0x12, 1)          # link count
    struct.pack_into("<H", rec, 0x14, 56)         # attr offset
    struct.pack_into("<H", rec, 0x16, flags)
    struct.pack_into("<I", rec, 0x1C, MFT_REC_SIZE)
    struct.pack_into("<H", rec, 0x28, 4)          # next attr id
    struct.pack_into("<I", rec, 0x2C, rec_no)
    off = 56
    for a in attrs:
        rec[off:off + len(a)] = a
        off += len(a)
    struct.pack_into("<I", rec, off, AT_END)
    off += 4
    used = (off + 7) & ~7
    struct.pack_into("<I", rec, 0x18, used)
    fixup_prepare(rec, 48, 3)
    return bytes(rec)

def parse_record(rec: bytes):
    """returns dict {rec_no, flags, attrs:[(type, header_dict, value_or_runs)]}"""
    buf = bytearray(rec)
    if buf[0:4] != MAGIC_FILE:
        raise ValueError("bad FILE magic")
    if not fixup_apply(buf, 48, 3):
        raise ValueError("fixup failed")
    flags = struct.unpack_from("<H", buf, 0x16)[0]
    used = struct.unpack_from("<I", buf, 0x18)[0]
    rec_no = struct.unpack_from("<I", buf, 0x2C)[0]
    attrs = []
    off = struct.unpack_from("<H", buf, 0x14)[0]
    while off + 24 <= used:
        type_ = struct.unpack_from("<I", buf, off)[0]
        if type_ == AT_END:
            break
        length = struct.unpack_from("<I", buf, off + 4)[0]
        nonres = buf[off + 8]
        if nonres:
            alloc = struct.unpack_from("<Q", buf, off + 0x30)[0]
            real = struct.unpack_from("<Q", buf, off + 0x38)[0]
            init = struct.unpack_from("<Q", buf, off + 0x40)[0]
            run_off = struct.unpack_from("<H", buf, off + 0x28)[0]
            runs = runs_parse(bytes(buf[off + run_off:off + length]))
            attrs.append({"type": type_, "nonres": True, "alloc": alloc,
                          "real": real, "init": init, "runs": runs,
                          "off": off, "len": length})
        else:
            vlen = struct.unpack_from("<I", buf, off + 0x10)[0]
            voff = struct.unpack_from("<H", buf, off + 0x14)[0]
            value = bytes(buf[off + voff:off + voff + vlen])
            attrs.append({"type": type_, "nonres": False, "value": value,
                          "off": off, "len": length})
        off += length
    return {"rec_no": rec_no, "flags": flags, "attrs": attrs,
            "used": used, "raw": bytes(buf)}

# ---------------------------------------------------------------- vbr
def build_vbr(cluster: int, total_bytes: int, mft_lcn: int, mftmirr_lcn: int,
              log_lcn: int, data_lcn: int, mft_records: int,
              label: str) -> bytes:
    v = bytearray(SECTOR_SIZE)
    v[0:3] = b"\xEB\x52\x90"
    v[3:11] = OEM_NAME
    struct.pack_into("<HBH", v, 0x0B, SECTOR_SIZE, cluster // SECTOR_SIZE, 0)
    struct.pack_into("<Q", v, 0x14, total_bytes // SECTOR_SIZE)
    struct.pack_into("<QQQQ", v, 0x1C, mft_lcn, mftmirr_lcn, log_lcn, data_lcn)
    struct.pack_into("<II", v, 0x3C, MFT_REC_SIZE, INDEX_REC_SIZE)
    struct.pack_into("<HH", v, 0x44, 0x0001, VERSION)
    struct.pack_into("<Q", v, 0x48, VOL_SERIAL)
    lb = label.encode("utf-8")[:63]
    v[0x50:0x50 + len(lb)] = lb
    for i in range(16):
        v[0x90 + i] = (i * 7 + 3) & 0xFF
    struct.pack_into("<Q", v, 0xA0, mft_records)
    struct.pack_into("<Q", v, 0xA8, crc64(bytes(v[:0xA8])))
    struct.pack_into("<H", v, 0x1FE, BOOT_SIG)
    return bytes(v)

def parse_vbr(v: bytes) -> dict:
    if v[3:11] != OEM_NAME:
        raise ValueError("not an ExiFS volume")
    if struct.unpack_from("<H", v, 0x1FE)[0] != BOOT_SIG:
        raise ValueError("bad boot signature")
    stored = struct.unpack_from("<Q", v, 0xA8)[0]
    if crc64(v[:0xA8]) != stored:
        raise ValueError("VBR CRC64 mismatch")
    bps = struct.unpack_from("<H", v, 0x0B)[0]
    spc = v[0x0D]
    return {
        "cluster": bps * spc,
        "total_sectors": struct.unpack_from("<Q", v, 0x14)[0],
        "mft_lcn": struct.unpack_from("<Q", v, 0x1C)[0],
        "mftmirr_lcn": struct.unpack_from("<Q", v, 0x24)[0],
        "log_lcn": struct.unpack_from("<Q", v, 0x2C)[0],
        "data_lcn": struct.unpack_from("<Q", v, 0x34)[0],
        "rec_size": struct.unpack_from("<I", v, 0x3C)[0],
        "mft_records": struct.unpack_from("<Q", v, 0xA0)[0],
        "label": v[0x50:0x90].split(b"\x00")[0].decode("utf-8", "replace"),
        "serial": struct.unpack_from("<Q", v, 0x48)[0],
    }

# ---------------------------------------------------------------- layout
def compute_layout(cluster: int, total_bytes: int):
    mft_clusters = (MFT_ZONE_RECORDS * MFT_REC_SIZE + cluster - 1) // cluster
    mft_lcn = 16
    mftmirr_lcn = mft_lcn + mft_clusters
    log_lcn = mftmirr_lcn + 1
    log_clusters = (128 * 1024 + cluster - 1) // cluster
    bitmap_lcn = log_lcn + log_clusters
    upcase_lcn = bitmap_lcn + 1
    upcase_clusters = (128 * 1024 + cluster - 1) // cluster
    data_lcn = upcase_lcn + upcase_clusters
    return {
        "mft_lcn": mft_lcn, "mft_clusters": mft_clusters,
        "mftmirr_lcn": mftmirr_lcn, "log_lcn": log_lcn,
        "log_clusters": log_clusters, "bitmap_lcn": bitmap_lcn,
        "upcase_lcn": upcase_lcn, "upcase_clusters": upcase_clusters,
        "data_lcn": data_lcn,
        "total_clus": total_bytes // cluster,
    }

ATTRDEFS = [
    ("$STANDARD_INFORMATION", AT_STD_INFO, 0x40, 48, 48),
    ("$ATTRIBUTE_LIST", AT_ATTR_LIST, 0x80, 0, 0),
    ("$FILE_NAME", AT_FILE_NAME, 0x42, 68, 0),
    ("$VOLUME_NAME", AT_VOL_NAME, 0x40, 2, 256),
    ("$VOLUME_INFORMATION", AT_VOL_INFO, 0x40, 16, 16),
    ("$DATA", AT_DATA, 0x00, 0, 0),
    ("$INDEX_ROOT", AT_INDEX_ROOT, 0x40, 32, 0),
    ("$INDEX_ALLOCATION", AT_INDEX_ALLOC, 0x00, 0, 0),
    ("$BITMAP", AT_BITMAP, 0x00, 0, 0),
]

def build_attrdef_table() -> bytes:
    out = bytearray()
    for name, t, f, mn, mx in ATTRDEFS:
        d = bytearray(64)
        nb = name.encode("utf-8")[:47]
        d[0:len(nb)] = nb
        struct.pack_into("<II", d, 48, t, f)
        struct.pack_into("<II", d, 56, mn, mx)
        out += d
    return bytes(out)
