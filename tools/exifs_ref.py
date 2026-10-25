#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exifs_ref.py - ExiFS reference implementation & CLI (read-write)

Usage:
  python exifs_ref.py mkfs  -o img.exifs [-s 64M] [-c 4096] [-l LABEL]
  python exifs_ref.py info  img.exifs
  python exifs_ref.py ls    img.exifs [path]
  python exifs_ref.py cat   img.exifs <path>
  python exifs_ref.py stat  img.exifs <path>
  python exifs_ref.py mkdir img.exifs <path>
  python exifs_ref.py write img.exifs <path> [file]   (file=- : stdin)
  python exifs_ref.py rm    img.exifs <path>
  python exifs_ref.py fsck  img.exifs [-p]

The same on-disk format is implemented in C (mkexifs / exifs_fuse / fsck.exifs);
images produced by either implementation are interchangeable.
"""
import os
import sys
import struct
import errno

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from exifs_core import *  # noqa


class ExiFS:
    def __init__(self, path, read_only=False):
        self.path = path
        self.f = open(path, "rb" if read_only else "r+b")
        vbr = self.f.read(SECTOR_SIZE)
        self.info = parse_vbr(vbr)
        self.cluster = self.info["cluster"]
        self.ro = read_only
        self.mft = [None] * self.info["mft_records"]
        self.bitmap = None
        self.dirty = set()
        self._load_all()
        self._bm_load()

    # ------------------------------------------------------------ raw io
    def _load_all(self):
        rec_size = self.info["rec_size"]
        self.f.seek(self.info["mft_lcn"] * self.cluster)
        data = self.f.read(rec_size * self.info["mft_records"])
        for i in range(self.info["mft_records"]):
            # store RAW on-disk bytes; parse_record() applies the fixup
            # exactly once, mirroring the C driver behaviour
            self.mft[i] = bytearray(data[i * rec_size:(i + 1) * rec_size])

    def _bm_load(self):
        rec = self.mft[FILE_BITMAP]
        p = parse_record(bytes(rec))
        for a in p["attrs"]:
            if a["type"] == AT_DATA and a["nonres"]:
                lcn = a["runs"][0]["lcn"]
                nbytes = a["runs"][0]["length"] * self.cluster
                self.bitmap = bytearray(self._pread(nbytes, lcn * self.cluster))
                return
        raise ValueError("no $Bitmap")

    def _pread(self, n, off):
        self.f.seek(off)
        return self.f.read(n)

    def _pwrite(self, data, off):
        self.f.seek(off)
        self.f.write(data)

    def _bm_flush(self):
        rec = self.mft[FILE_BITMAP]
        p = parse_record(bytes(rec))
        for a in p["attrs"]:
            if a["type"] == AT_DATA and a["nonres"]:
                lcn = a["runs"][0]["lcn"]
                self._pwrite(self.bitmap[:a["runs"][0]["length"] * self.cluster],
                             lcn * self.cluster)
                return

    def clus_alloc(self, count):
        """first-fit allocation from data region; returns list of lcns"""
        total = self.info["total_sectors"] * SECTOR_SIZE // self.cluster
        out = []
        c = self.info["data_lcn"]
        while c < total and len(out) < count:
            if not (self.bitmap[c >> 3] & (1 << (c & 7))):
                out.append(c)
                self.bitmap[c >> 3] |= 1 << (c & 7)
            c += 1
        if len(out) < count:
            raise ValueError("no space left on device")
        return out

    def clus_free(self, lcns):
        for c in lcns:
            self.bitmap[c >> 3] &= ~(1 << (c & 7))

    @staticmethod
    def _coalesce(lcns):
        """merge consecutive LCNs into extents [(lcn, count), ...]"""
        extents = []
        start = prev = lcns[0]
        for l in lcns[1:]:
            if l == prev + 1:
                prev = l
            else:
                extents.append((start, prev - start + 1))
                start = prev = l
        extents.append((start, prev - start + 1))
        return extents

    def free_count(self):
        total = self.info["total_sectors"] * SECTOR_SIZE // self.cluster
        n = 0
        for c in range(self.info["data_lcn"], total):
            if not (self.bitmap[c >> 3] & (1 << (c & 7))):
                n += 1
        return n

    # ------------------------------------------------------------ records
    def rec_mark_dirty(self, no):
        self.dirty.add(no)

    def rec_flush(self):
        rec_size = self.info["rec_size"]
        for no in sorted(self.dirty):
            self._pwrite(self.mft[no][:rec_size],
                         self.info["mft_lcn"] * self.cluster + no * rec_size)
        self.dirty.clear()

    def rec_find_free(self):
        for no in range(FIRST_USER, len(self.mft)):
            rec = self.mft[no]
            if rec is None or not (struct.unpack_from("<H", rec, 0x16)[0] &
                                   MRF_INUSE):
                return no
        self._mft_extend()
        return self.rec_find_free()

    def _mft_extend(self):
        """double the live MFT inside the preallocated zone (v1.1)"""
        zone = MFT_ZONE_RECORDS
        old = len(self.mft)
        if old >= zone:
            raise ValueError("MFT zone full (%d records); reformat with a "
                             "larger zone" % zone)
        new = min(zone, old * 2)
        rec_size = self.info["rec_size"]
        # write fresh free records into the reserved zone
        for no in range(old, new):
            self._pwrite(build_record(no, 0, []),
                         self.info["mft_lcn"] * self.cluster +
                         no * rec_size)
            self.mft.append(None)
            self.mft[no] = bytearray(self._pread(
                rec_size, self.info["mft_lcn"] * self.cluster + no * rec_size))
        # update $MFT record: real/init size = new * rec_size
        p0 = parse_record(bytes(self.mft[0]))
        new_attrs = []
        for a in p0["attrs"]:
            if a["type"] == AT_DATA and a["nonres"]:
                new_attrs.append(build_attr_nonres(
                    AT_DATA,
                    runs_encode([(r["lcn"], r["length"]) for r in a["runs"]]),
                    a["alloc"], new * rec_size, new * rec_size))
            elif a["nonres"]:
                new_attrs.append(build_attr_nonres(
                    a["type"],
                    runs_encode([(r["lcn"], r["length"]) for r in a["runs"]]),
                    a["alloc"], a["real"], a["init"]))
            else:
                new_attrs.append(build_attr(a["type"], a["value"]))
        self.mft[0] = bytearray(build_record(0, p0["flags"], new_attrs))
        self._pwrite(self.mft[0][:rec_size], self.info["mft_lcn"] *
                     self.cluster)
        # update VBR record count + CRC
        self.f.seek(0)
        vbr = bytearray(self.f.read(512))
        struct.pack_into("<Q", vbr, 0xA0, new)
        struct.pack_into("<Q", vbr, 0xA8, crc64(bytes(vbr[:0xA8])))
        self.f.seek(0)
        self.f.write(vbr)
        self.info["mft_records"] = new
        print("  [MFT extended: %d -> %d records]" % (old, new))

    # ------------------------------------------------------------ lookup
    def lookup(self, path):
        """-> record number"""
        if path in ("", "/"):
            return FILE_ROOT
        parts = [p for p in path.split("/") if p]
        cur = FILE_ROOT
        for part in parts:
            cur = self.dir_lookup(cur, part)
        return cur

    # ------------------------------------------------- B+tree dir ops (v1.1)
    def _dir_state(self, dir_no):
        """-> (root_entries, alloc_attr_or_None, parsed_record)"""
        p = parse_record(bytes(self.mft[dir_no]))
        root = alloc = None
        for a in p["attrs"]:
            if a["type"] == AT_INDEX_ROOT and not a["nonres"]:
                root = a
            elif a["type"] == AT_INDEX_ALLOC and a["nonres"]:
                alloc = a
        if root is None:
            raise ValueError("record %d has no INDEX_ROOT" % dir_no)
        return parse_index_root_v2(root["value"]), alloc, p

    def _dir_span(self):
        """clusters per INDX node"""
        return max(1, INDEX_REC_SIZE // self.cluster)

    def _dir_node_read(self, runs_parsed, vcn):
        span = self._dir_span()
        cvcn = vcn * span
        for r in runs_parsed:
            if r["vcn"] <= cvcn < r["vcn"] + r["length"]:
                lcn = r["lcn"] + (cvcn - r["vcn"])
                off = self.info["data_lcn"] * self.cluster + lcn * self.cluster
                data = self._pread(span * self.cluster, off)
                return parse_indx(data[:INDEX_REC_SIZE])
        raise ValueError("index node VCN %d not mapped" % vcn)

    def _dir_node_write(self, runs, vcn, entries):
        span = self._dir_span()
        lcn = runs[vcn][0]
        off = self.info["data_lcn"] * self.cluster + lcn * self.cluster
        self._pwrite(build_indx(vcn, entries), off)

    def _root_cap(self, prec, large):
        """max serialized entry bytes that fit in this record's INDEX_ROOT"""
        total = 56 + 4                      # record header + end marker
        for a in prec["attrs"]:
            if a["type"] == AT_INDEX_ROOT:
                continue
            total += a["len"]
        total += 24                         # INDEX_ROOT attr header
        if large:
            total += 72 + 64                # INDEX_ALLOCATION nonres attr
        return MFT_REC_SIZE - total - 16

    def _dir_store(self, dir_no, p, root_entries, runs):
        """persist INDEX_ROOT (+ INDEX_ALLOCATION when large)"""
        small = runs is None
        new_attrs = []
        for a in p["attrs"]:
            if a["type"] == AT_INDEX_ROOT and not a["nonres"]:
                new_attrs.append(build_attr(
                    AT_INDEX_ROOT,
                    build_index_root_v2(root_entries, small)))
            elif a["type"] == AT_INDEX_ALLOC:
                continue                    # re-added below when large
            elif a["nonres"]:
                new_attrs.append(build_attr_nonres(
                    a["type"],
                    runs_encode([(r["lcn"], r["length"]) for r in a["runs"]]),
                    a["alloc"], a["real"], a["init"]))
            else:
                new_attrs.append(build_attr(a["type"], a["value"]))
        if not small:
            nbytes = sum(l for _, l in runs) * self.cluster
            new_attrs.append(build_attr_nonres(
                AT_INDEX_ALLOC, runs_encode(runs), nbytes, nbytes, nbytes))
        self.mft[dir_no] = bytearray(build_record(dir_no, p["flags"],
                                                  new_attrs))
        self.rec_mark_dirty(dir_no)

    def _dir_descend(self, root_entries, runs_parsed, key):
        """walk pointers to the leaf that owns `key`
        returns (path, leaf_entries, leaf_id); path = [(node_id, entries)]"""
        node_entries = root_entries
        node_id = None
        path = []
        while True:
            ptrs = [e for e in node_entries if e[2] & ENTRY_PTR]
            if not ptrs:
                return path, node_entries, node_id
            chosen = None
            for e in ptrs:
                if key_cmp(e[1], key) <= 0:
                    chosen = e
            if chosen is None:
                chosen = ptrs[0]
            child_vcn = chosen[0] & 0xFFFFFFFFFFFF
            path.append((node_id, node_entries))
            node_id = child_vcn
            node_entries = self._dir_node_read(runs_parsed, child_vcn)

    def dir_insert(self, dir_no, ref, key):
        """insert (ref, key) into directory B+tree, splitting as needed"""
        root_entries, alloc, p = self._dir_state(dir_no)
        entry = (ref, key, ENTRY_LAST)
        if alloc is None:
            # ---- small index: try to keep everything resident
            cand = sorted_insert(root_entries, entry)
            if entries_size(cand) <= self._root_cap(p, False):
                self._dir_store(dir_no, p, cand, None)
                return
            # ---- convert to large index: one leaf, root keeps . .. + ptr
            span = self._dir_span()
            lcns = self.clus_alloc(span)
            runs = [(lcns[0], span)]
            # leaf gets user entries only; '.'/'..' stay in the root
            user = [e for e in root_entries
                    if index_key_name(e[1]) not in (".", "..")]
            leaf = sorted_insert(user, entry)
            self._dir_node_write(runs, 0, leaf)
            root = sorted_insert(
                [e for e in root_entries
                 if index_key_name(e[1]) in (".", "..")],
                (0, leaf[0][1], ENTRY_PTR))
            self._dir_store(dir_no, p, root, runs)
            return
        # ---- large index: descend, insert, split upward
        runs = [(r["lcn"], r["length"]) for r in alloc["runs"]]
        path, leaf_entries, leaf_id = self._dir_descend(
            root_entries, alloc["runs"], key)
        leaf_entries = sorted_insert(leaf_entries, entry)
        self._split_up(dir_no, p, path, leaf_id, leaf_entries, runs)

    def _split_up(self, dir_no, p, path, node_id, entries, runs):
        while True:
            cap = self._root_cap(p, True) if node_id is None else INDX_NODE_CAP
            if entries_size(entries) <= cap:
                if node_id is None:
                    self._dir_store(dir_no, p, entries, runs)
                else:
                    self._dir_node_write(runs, node_id, entries)
                    self._dir_store(dir_no, p, path[0][1], runs)
                return
            # ---- split node at midpoint
            # root keeps '.' and '..' forever: never split them away
            if node_id is None:
                n_data = sum(1 for e in entries if not (e[2] & ENTRY_PTR))
                mid = max(len(entries) // 2, n_data + 1)
            else:
                mid = len(entries) // 2
            if mid == 0 or mid >= len(entries):
                raise ValueError("cannot split node")
            left, right = entries[:mid], entries[mid:]
            new_vcn = len(runs)
            span = self._dir_span()
            lcns = self.clus_alloc(span)
            runs.append((lcns[0], span))
            self._dir_node_write(runs, new_vcn, right)
            ptr = (new_vcn, right[0][1], ENTRY_PTR)
            entries = left
            if node_id is None:
                new_root = sorted_insert(left, ptr)
                if entries_size(new_root) > self._root_cap(p, True):
                    raise OSError(errno.EDQUOT,
                                  "directory exceeds ExiFS v1.1 4-level "
                                  "tree limit (~680k entries)")
                self._dir_store(dir_no, p, new_root, runs)
                return
            self._dir_node_write(runs, node_id, left)
            parent_id, parent_entries = path.pop()
            parent_entries = sorted_insert(parent_entries, ptr)
            node_id, entries = parent_id, parent_entries

    def dir_lookup(self, dir_no, name):
        root_entries, alloc, p = self._dir_state(dir_no)
        for ref, key, ef in root_entries:
            if not (ef & ENTRY_PTR) and index_key_name(key) == name:
                return ref_recno(ref)
        if alloc is None:
            raise FileNotFoundError(path_str(name))
        probe = build_file_name(ref_make(dir_no), name)
        path, leaf_entries, leaf_id = self._dir_descend(
            root_entries, alloc["runs"], probe)
        for ref, key, ef in leaf_entries:
            if not (ef & ENTRY_PTR) and index_key_name(key) == name:
                return ref_recno(ref)
        raise FileNotFoundError(path_str(name))

    def listdir(self, dir_no):
        root_entries, alloc, p = self._dir_state(dir_no)
        out = []
        stack = [root_entries]
        while stack:
            entries = stack.pop()
            for ref, key, ef in entries:
                if ef & ENTRY_PTR:
                    if alloc is None:
                        raise ValueError("pointer entry in small index")
                    stack.append(self._dir_node_read(
                        alloc["runs"], ref & 0xFFFFFFFFFFFF))
                else:
                    nm = index_key_name(key)
                    if nm in (".", ".."):
                        continue
                    is_dir = bool(struct.unpack_from("<I", key, 0x38)[0] &
                                  MRF_DIRECTORY)
                    real = struct.unpack_from("<Q", key, 0x30)[0]
                    out.append((nm, is_dir, real))
        return sorted(out)

    # keep old name working
    def lookup_in(self, dir_no, name):
        return self.dir_lookup(dir_no, name)

    # ------------------------------------------------------------ read
    def read_file(self, no):
        """-> bytes of unnamed data stream"""
        p = parse_record(bytes(self.mft[no]))
        for a in p["attrs"]:
            if a["type"] == AT_DATA and not a["nonres"]:
                return a["value"]
            if a["type"] == AT_DATA and a["nonres"]:
                return self._read_runs(a)
        return b""

    def _read_runs(self, attr):
        out = bytearray()
        for r in attr["runs"]:
            n = r["length"] * self.cluster
            if r["sparse"]:
                out += b"\x00" * n
            else:
                off = self.info["data_lcn"] * self.cluster + r["lcn"] * self.cluster
                out += self._pread(n, off)
        return bytes(out[:attr["real"]])

    # ------------------------------------------------------------ write
    def create(self, path, data, is_dir=False):
        if "/" not in path:
            raise ValueError("path must be absolute (under /)")
        parent_path, name = path.rsplit("/", 1)
        if not name:
            raise ValueError("empty name")
        parent_no = self.lookup(parent_path)
        try:
            self.lookup_in(parent_no, name)
            raise FileExistsError(path)
        except FileNotFoundError:
            pass
        no = self.rec_find_free()
        flags = MRF_INUSE | (MRF_DIRECTORY if is_dir else 0)
        fn = build_file_name(ref_make(parent_no), name,
                             real_size=len(data), flags=flags)
        attrs = [build_attr(AT_STD_INFO, build_std_info()),
                 build_attr(AT_FILE_NAME, fn)]
        lcns = []
        if not is_dir and data:
            nclus = (len(data) + self.cluster - 1) // self.cluster
            lcns = self.clus_alloc(nclus)
            padded = data + b"\x00" * (nclus * self.cluster - len(data))
            # coalesce consecutive LCNs into extents (NTFS-style run lists)
            extents = self._coalesce(lcns)
            pos = 0
            for lcn, n in extents:
                self._pwrite(padded[pos * self.cluster:
                                    (pos + n) * self.cluster],
                             self.info["data_lcn"] * self.cluster +
                             lcn * self.cluster)
                pos += n
            runs = runs_encode(extents)
            attrs.append(build_attr_nonres(AT_DATA, runs,
                                           nclus * self.cluster,
                                           len(data), len(data)))
        elif is_dir:
            dot = build_file_name(ref_make(parent_no), ".", NS_POSIX, 0,
                                  MRF_INUSE | MRF_DIRECTORY)
            dotdot = build_file_name(ref_make(parent_no), "..", NS_POSIX, 0,
                                     MRF_INUSE | MRF_DIRECTORY)
            attrs.append(build_attr(AT_INDEX_ROOT, build_index_root_v2(
                [(ref_make(no), dot, ENTRY_LAST),
                 (ref_make(parent_no), dotdot, ENTRY_LAST)], small=True)))
        self.mft[no] = bytearray(build_record(no, flags, attrs))
        self.rec_mark_dirty(no)
        # insert into parent B+tree (splits automatically when needed)
        self.dir_insert(parent_no, ref_make(no), fn)
        return no

    def dir_remove(self, dir_no, name):
        """remove entry `name` from directory B+tree (no rebalance in v1.1)"""
        if name in (".", ".."):
            raise ValueError("cannot remove %s" % name)
        root_entries, alloc, p = self._dir_state(dir_no)
        probe = build_file_name(ref_make(dir_no), name)
        if alloc is None:
            new_entries = [e for e in root_entries
                           if index_key_name(e[1]) != name]
            if len(new_entries) == len(root_entries):
                raise FileNotFoundError(path_str(name))
            self._dir_store(dir_no, p, new_entries, None)
            return
        runs = [(r["lcn"], r["length"]) for r in alloc["runs"]]
        path, leaf_entries, leaf_id = self._dir_descend(
            root_entries, alloc["runs"], probe)
        new_leaf = [e for e in leaf_entries
                    if index_key_name(e[1]) != name]
        if len(new_leaf) == len(leaf_entries):
            raise FileNotFoundError(path_str(name))
        # always write back, even when the leaf becomes empty (no ghosts)
        self._dir_node_write(runs, leaf_id, new_leaf)

    # ------------------------------------------------------------ remove
    def remove(self, path):
        parent_path, name = path.rsplit("/", 1)
        parent_no = self.lookup(parent_path)
        no = self.dir_lookup(parent_no, name)
        p = parse_record(bytes(self.mft[no]))
        if p["flags"] & MRF_DIRECTORY and self.listdir(no):
            raise ValueError("directory not empty")
        # free clusters (data + index allocation) across whole extents
        for a in p["attrs"]:
            if a["nonres"] and a["type"] in (AT_DATA, AT_INDEX_ALLOC):
                for r in a["runs"]:
                    if not r["sparse"]:
                        self.clus_free(range(r["lcn"],
                                             r["lcn"] + r["length"]))
        # mark record free
        self.mft[no][0x16] &= ~MRF_INUSE & 0xFF
        self.rec_mark_dirty(no)
        # remove entry from parent B+tree
        self.dir_remove(parent_no, name)

    # ------------------------------------------------------------ sync
    def sync(self):
        if self.ro:
            return
        self.rec_flush()
        self._bm_flush()
        self.f.flush()
        os.fsync(self.f.fileno())

    def close(self):
        self.f.close()


def path_str(name):
    return name


# ================================================================ mkfs
def cmd_mkfs(args):
    image = None
    size = 64 * 1024 * 1024
    cluster = 4096
    label = "ExiFS"
    i = 0
    while i < len(args):
        if args[i] == "-o":
            image = args[i + 1]; i += 2
        elif args[i] == "-s":
            s = args[i + 1].upper()
            mult = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}.get(s[-1], 1)
            size = int(s.rstrip("KMG")) * mult; i += 2
        elif args[i] == "-c":
            cluster = int(args[i + 1]); i += 2
        elif args[i] == "-l":
            label = args[i + 1]; i += 2
        else:
            i += 1
    if not image:
        print("mkfs: missing -o"); return 2
    if size < 8 * 1024 * 1024:
        print("mkfs: size must be >= 8M"); return 2
    if cluster < 512 or cluster > 65536 or cluster & (cluster - 1):
        print("mkfs: cluster must be power of 2"); return 2

    lay = compute_layout(cluster, size)
    if lay["data_lcn"] >= lay["total_clus"]:
        print("mkfs: image too small for metadata"); return 2

    with open(image, "wb") as f:
        f.truncate(size)

    # ---- bitmap
    bm = bytearray((lay["total_clus"] + 7) // 8)
    for c in range(lay["data_lcn"]):
        bm[c >> 3] |= 1 << (c & 7)

    # ---- MFT records
    recs = [None] * MFT_RECORDS
    for r in range(16):
        if r >= 12:
            recs[r] = build_record(r, MRF_INUSE, [])
            continue
        names = {FILE_MFT: "$MFT", FILE_MFTMIRR: "$MFTMirr",
                 FILE_LOGFILE: "$LogFile", FILE_VOLUME: "$Volume",
                 FILE_ATTRDEF: "$AttrDef", FILE_ROOT: ".",
                 FILE_BITMAP: "$Bitmap", FILE_BOOT: "$Boot",
                 FILE_BADCLUS: "$BadClus", FILE_SECURE: "$Secure",
                 FILE_UPCASE: "$UpCase", FILE_EXTEND: "$Extend"}
        flags = MRF_INUSE
        if r == FILE_ROOT:
            flags |= MRF_DIRECTORY
        attrs = [build_attr(AT_STD_INFO, build_std_info()),
                 build_attr(AT_FILE_NAME,
                            build_file_name(ref_make(FILE_ROOT),
                                             names[r], real_size=0,
                                             flags=flags))]
        if r == FILE_MFT:
            runs = runs_encode([(lay["mft_lcn"], lay["mft_clusters"])])
            attrs.append(build_attr_nonres(AT_DATA, runs,
                                           lay["mft_clusters"] * cluster,
                                           MFT_RECORDS * MFT_REC_SIZE,
                                           MFT_RECORDS * MFT_REC_SIZE))
        elif r == FILE_MFTMIRR:
            runs = runs_encode([(lay["mftmirr_lcn"], 1)])
            attrs.append(build_attr_nonres(AT_DATA, runs, cluster, 4096, 4096))
        elif r == FILE_LOGFILE:
            runs = runs_encode([(lay["log_lcn"], lay["log_clusters"])])
            attrs.append(build_attr_nonres(AT_DATA, runs,
                                           lay["log_clusters"] * cluster,
                                           0, 0))
        elif r == FILE_VOLUME:
            attrs.append(build_attr(AT_VOL_NAME, utf8_to_utf16le(label)))
            attrs.append(build_attr(AT_VOL_INFO, struct.pack("<QBBHI",
                                                             0, 1, 0, 0x0001, 0)))
        elif r == FILE_ATTRDEF:
            attrs.append(build_attr(AT_DATA, build_attrdef_table()))
        elif r == FILE_ROOT:
            entries = [(ref_make(FILE_ROOT),
                        build_file_name(ref_make(FILE_ROOT), ".", NS_POSIX,
                                        0, MRF_INUSE | MRF_DIRECTORY),
                        ENTRY_LAST),
                       (ref_make(FILE_ROOT),
                        build_file_name(ref_make(FILE_ROOT), "..", NS_POSIX,
                                        0, MRF_INUSE | MRF_DIRECTORY),
                        ENTRY_LAST)]
            attrs.append(build_attr(AT_INDEX_ROOT,
                                    build_index_root_v2(entries)))
        elif r == FILE_BITMAP:
            runs = runs_encode([(lay["bitmap_lcn"], 1)])
            attrs.append(build_attr_nonres(AT_DATA, runs, cluster,
                                           len(bm), len(bm)))
        elif r == FILE_BOOT:
            runs = runs_encode([(0, 16)])
            attrs.append(build_attr_nonres(AT_DATA, runs, 16 * cluster,
                                           512, 512))
        elif r == FILE_BADCLUS:
            runs = runs_encode([(None, lay["total_clus"])])
            attrs.append(build_attr_nonres(AT_DATA, runs,
                                           lay["total_clus"] * cluster,
                                           lay["total_clus"] * cluster,
                                           lay["total_clus"] * cluster))
        elif r == FILE_SECURE:
            attrs.append(build_attr(AT_DATA, b""))
        elif r == FILE_UPCASE:
            runs = runs_encode([(lay["upcase_lcn"], lay["upcase_clusters"])])
            attrs.append(build_attr_nonres(AT_DATA, runs,
                                           lay["upcase_clusters"] * cluster,
                                           65536 * 2, 65536 * 2))
        recs[r] = build_record(r, flags, attrs)

    # records 16..63: free records (valid magic, not in use)
    for r in range(16, MFT_RECORDS):
        recs[r] = build_record(r, 0, [])

    with open(image, "r+b") as f:
        f.seek(lay["mft_lcn"] * cluster)
        for r in recs:
            f.write(r)
        f.seek(lay["mftmirr_lcn"] * cluster)
        for r in recs[:4]:
            f.write(r)
        f.seek(lay["upcase_lcn"] * cluster)
        uc = bytearray(65536 * 2)
        for c in range(65536):
            v = c - 32 if ord('a') <= c <= ord('z') else c
            struct.pack_into("<H", uc, c * 2, v)
        f.write(uc)
        f.seek(lay["bitmap_lcn"] * cluster)
        f.write(bm)
        vbr = build_vbr(cluster, size, lay["mft_lcn"], lay["mftmirr_lcn"],
                        lay["log_lcn"], lay["data_lcn"], MFT_RECORDS, label)
        f.seek(0)
        f.write(vbr)
        f.seek((size // SECTOR_SIZE - 1) * SECTOR_SIZE)
        f.write(vbr)

    print("ExiFS 1.0 formatted: %s" % image)
    print("  size          : %d bytes" % size)
    print("  cluster       : %d bytes" % cluster)
    print("  total clusters: %d" % lay["total_clus"])
    print("  MFT at LCN    : %d (%d records)" % (lay["mft_lcn"], MFT_RECORDS))
    print("  data at LCN   : %d" % lay["data_lcn"])
    print("  label         : %s" % label)
    return 0


# ================================================================ cmds
def cmd_info(fs, args):
    i = fs.info
    print("ExiFS volume: %s" % fs.path)
    print("  label        : %s" % i["label"])
    print("  version      : 1.0")
    print("  cluster size : %d" % fs.cluster)
    print("  total sectors: %d" % i["total_sectors"])
    print("  MFT records  : %d at LCN %d" % (i["mft_records"], i["mft_lcn"]))
    print("  data at LCN  : %d" % i["data_lcn"])
    fs._bm_load()
    print("  free clusters: %d (%.1f%%)" %
          (fs.free_count(),
           100.0 * fs.free_count() /
           (i["total_sectors"] * SECTOR_SIZE // fs.cluster)))
    return 0


def cmd_ls(fs, args):
    path = args[0] if args else "/"
    no = fs.lookup(path)
    p = parse_record(bytes(fs.mft[no]))
    if not (p["flags"] & MRF_DIRECTORY):
        print(path)
        return 0
    for name, is_dir, size in fs.listdir(no):
        if is_dir:
            print("  %-24s <DIR>" % name)
        else:
            print("  %-24s %d bytes" % (name, size))
    return 0


def cmd_cat(fs, args):
    if not args:
        print("cat: need path"); return 2
    no = fs.lookup(args[0])
    data = fs.read_file(no)
    sys.stdout.buffer.write(data)
    return 0


def cmd_stat(fs, args):
    no = fs.lookup(args[0])
    p = parse_record(bytes(fs.mft[no]))
    print("record : %d" % no)
    print("flags  : %s%s" % ("INUSE" if p["flags"] & MRF_INUSE else "FREE",
                             " DIRECTORY" if p["flags"] & MRF_DIRECTORY
                             else ""))
    for a in p["attrs"]:
        t = {AT_STD_INFO: "STD_INFO", AT_FILE_NAME: "FILE_NAME",
             AT_VOL_NAME: "VOL_NAME", AT_VOL_INFO: "VOL_INFO",
             AT_DATA: "DATA", AT_INDEX_ROOT: "INDEX_ROOT",
             AT_INDEX_ALLOC: "INDEX_ALLOC",
             AT_BITMAP: "BITMAP"}.get(a["type"], hex(a["type"]))
        if a["nonres"]:
            print("attr   : %-12s non-resident real=%d runs=%d" %
                  (t, a["real"], len(a["runs"])))
        else:
            print("attr   : %-12s resident len=%d" % (t, len(a["value"])))
    return 0


def cmd_mkdir(fs, args):
    if not args:
        print("mkdir: need path"); return 2
    fs.create(args[0], b"", is_dir=True)
    fs.sync()
    print("created directory: %s" % args[0])
    return 0


def cmd_write(fs, args):
    if len(args) < 2:
        print("write: need <path> <file|->"); return 2
    if args[1] == "-":
        data = sys.stdin.buffer.read()
    else:
        with open(args[1], "rb") as f:
            data = f.read()
    fs.create(args[0], data)
    fs.sync()
    print("wrote %d bytes to %s" % (len(data), args[0]))
    return 0


def cmd_rm(fs, args):
    if not args:
        print("rm: need path"); return 2
    fs.remove(args[0])
    fs.sync()
    print("removed: %s" % args[0])
    return 0


def cmd_fsck(fs, args):
    preen = "-p" in args
    errors = fixes = 0

    def E(msg):
        nonlocal errors
        errors += 1
        print("  [ERROR] %s" % msg)

    def F(msg):
        nonlocal fixes
        fixes += 1
        print("  [FIXED] %s" % msg)

    print("fsck: checking %s" % fs.path)
    # VBR
    try:
        fs.f.seek(0)
        v = fs.f.read(512)
        parse_vbr(v)
    except Exception as e:
        E("VBR: %s" % e)
        return 4
    # MFT records
    for no, rec in enumerate(fs.mft):
        if rec is None or bytes(rec[0:4]) != MAGIC_FILE:
            if no < 16:
                E("MFT[%d]: bad magic" % no)
            continue
        if not (struct.unpack_from("<H", rec, 0x16)[0] & MRF_INUSE):
            continue
        try:
            parse_record(bytes(rec))
        except Exception as e:
            E("MFT[%d]: %s" % (no, e))
    # bitmap
    fs._bm_load()
    computed = bytearray(len(fs.bitmap))
    for no, rec in enumerate(fs.mft):
        if rec is None or not (struct.unpack_from("<H", rec, 0x16)[0] &
                               MRF_INUSE):
            continue
        try:
            p = parse_record(bytes(rec))
        except Exception:
            continue
        for a in p["attrs"]:
            if a["nonres"] and a["type"] in (AT_DATA, AT_INDEX_ALLOC):
                for r in a["runs"]:
                    if r["sparse"]:
                        continue
                    for j in range(r["length"]):
                        c = r["lcn"] + j
                        if computed[c >> 3] & (1 << (c & 7)):
                            E("cluster %d double-allocated (MFT[%d])" % (c, no))
                        computed[c >> 3] |= 1 << (c & 7)
            # B+tree node integrity: every INDEX_ALLOCATION node must parse
            if a["type"] == AT_INDEX_ALLOC and a["nonres"]:
                span = max(1, INDEX_REC_SIZE // fs.cluster)
                for vi in range(a["real"] // INDEX_REC_SIZE):
                    try:
                        fs._dir_node_read(a["runs"], vi)
                    except Exception as e:
                        E("dir MFT[%d]: index node %d: %s" % (no, vi, e))
    # metadata region must be fully marked
    for c in range(fs.info["data_lcn"]):
        if not (computed[c >> 3] & (1 << (c & 7))):
            E("metadata cluster %d not marked allocated" % c)
            computed[c >> 3] |= 1 << (c & 7)
    if computed != fs.bitmap:
        diff = sum(1 for i in range(len(computed))
                   if computed[i] != fs.bitmap[i])
        E("bitmap mismatch (%d differing bytes)" % diff)
        if preen:
            fs.bitmap[:] = computed
            fs._bm_flush()
            F("bitmap rebuilt from MFT run lists")
    print("---- %d errors, %d fixed ----" % (errors, fixes))
    print("volume state: %s" % ("REPAIRED" if errors == fixes and errors
                                else ("CLEAN" if not errors else "DAMAGED")))
    return 0 if not (errors - fixes) else 4


USAGE = __doc__

def main(argv):
    if len(argv) < 3:
        print(USAGE)
        return 2
    cmd, image = argv[1], argv[2]
    if cmd == "mkfs":
        return cmd_mkfs(argv[2:])
    fs = ExiFS(image, read_only=(cmd in ("cat", "ls", "stat", "info")))
    if cmd == "info":
        return cmd_info(fs, argv[3:])
    if cmd == "ls":
        return cmd_ls(fs, argv[3:])
    if cmd == "cat":
        return cmd_cat(fs, argv[3:])
    if cmd == "stat":
        return cmd_stat(fs, argv[3:])
    if cmd == "mkdir":
        return cmd_mkdir(fs, argv[3:])
    if cmd == "write":
        return cmd_write(fs, argv[3:])
    if cmd == "rm":
        return cmd_rm(fs, argv[3:])
    if cmd == "fsck":
        return cmd_fsck(fs, argv[3:])
    print("unknown command: %s" % cmd)
    print(USAGE)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
