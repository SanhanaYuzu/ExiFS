#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_btree.py - ExiFS v1.1 多级 B+树目录测试 + 性能基准

覆盖: 600 文件强制叶子分裂 → 多级树 → 全量/随机查找 → 删除 →
      fsck(含 INDX 节点校验) → create/lookup 吞吐基准
"""
import os
import sys
import time
import struct
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


def main():
    tmp = tempfile.mkdtemp(prefix="exifs_btree_")
    img = os.path.join(tmp, "bulk.exifs")
    N = 600

    print("== 1. mkfs + 创建 %d 个文件（强制 B+树分裂）==" % N)
    rc = R.cmd_mkfs(["-o", img, "-s", "64M", "-l", "BTree"])
    check("mkfs", rc == 0)

    fs = R.ExiFS(img)
    t0 = time.time()
    names = ["file_%04d.dat" % i for i in range(N)]
    payload = b"ExiFS-btree-payload-%06d" % 0
    for i, nm in enumerate(names):
        data = ("content-of-%s" % nm).encode()
        fs.create("/bulk/" + nm if False else "/" + nm, data)
    fs.sync()
    t_create = time.time() - t0
    print("  创建耗时: %.2fs (%.0f files/s)" % (t_create, N / t_create))

    # 检查根目录已升级为大索引
    root_entries, alloc, p = fs._dir_state(FILE_ROOT)
    check("root 升级为 large index（有 INDEX_ALLOCATION）", alloc is not None)
    n_nodes = alloc["real"] // INDEX_REC_SIZE if alloc else 0
    check("生成了多个 INDX 节点（%d 个）" % n_nodes, n_nodes >= 2)
    n_ptr_root = sum(1 for e in root_entries if e[2] & ENTRY_PTR)
    print("  根指针数: %d, INDX 节点数: %d, 树层数: %d"
          % (n_ptr_root, n_nodes, 2 if n_nodes else 1))
    fs.close()

    print("== 2. 重新挂载后全量验证 ==")
    fs = R.ExiFS(img, read_only=True)
    listing = fs.listdir(FILE_ROOT)
    check("ls 返回 %d 个条目" % N, len(listing) == N,
          "got %d" % len(listing))
    ok = True
    for i in range(0, N, 7):  # 抽查 ~86 个
        nm = names[i]
        try:
            no = fs.dir_lookup(FILE_ROOT, nm)
            data = fs.read_file(no)
            if data != ("content-of-%s" % nm).encode():
                ok = False
                print("    内容不符: %s" % nm)
        except Exception as e:
            ok = False
            print("    查找失败: %s (%s)" % (nm, e))
    check("随机抽查查找+读内容全部正确", ok)
    fs.close()

    print("== 3. 边界名字（排序/碰撞）==")
    fs = R.ExiFS(img)
    edge = ["a.txt", "z.txt", "A.txt", "0.txt", "~tilde", "_under",
            "file_9999.dat", "zzzzzzzz", "aaa"]
    for nm in edge:
        fs.create("/" + nm, b"edge")
    fs.sync()
    ok = True
    for nm in edge:
        try:
            fs.dir_lookup(FILE_ROOT, nm)
        except Exception:
            ok = False
            print("    边界名查找失败: %s" % nm)
    check("边界名全部可查找", ok)
    check("ls 总数 = %d" % (N + len(edge)),
          len(fs.listdir(FILE_ROOT)) == N + len(edge))
    fs.close()

    print("== 4. fsck（含 INDX 节点校验）==")
    rc = R.cmd_fsck(R.ExiFS(img, read_only=True), [])
    # cmd_fsck 需要 ExiFS 实例；直接跑 CLI 更真实
    import subprocess
    r = subprocess.run([sys.executable,
                        os.path.join(HERE, "..", "tools", "exifs_ref.py"),
                        "fsck", img], capture_output=True, text=True)
    check("fsck CLEAN", "CLEAN" in r.stdout, r.stdout[-300:])
    check("fsck exit 0", r.returncode == 0, str(r.returncode))

    print("== 5. 删除 100 个后仍一致 ==")
    fs = R.ExiFS(img)
    for i in range(100):
        fs.remove("/" + names[i])
    fs.sync()
    remain = [nm for nm in names[100:]]
    ok = all_ok = True
    for nm in remain[::5]:
        try:
            fs.dir_lookup(FILE_ROOT, nm)
        except Exception:
            ok = False
    check("删除后剩余文件全部可查找", ok)
    gone = True
    for i in range(100):
        try:
            fs.dir_lookup(FILE_ROOT, names[i])
            gone = False
        except FileNotFoundError:
            pass
    check("已删除文件全部不可见", gone)
    check("ls 数量正确", len(fs.listdir(FILE_ROOT)) ==
          N + len(edge) - 100)
    fs.close()

    print("== 6. 性能基准 ==")
    fs = R.ExiFS(img)
    # lookup 延迟
    lat = []
    for rep in range(3):
        for i in range(0, 200, 4):
            nm = names[100 + i]
            t1 = time.perf_counter()
            fs.dir_lookup(FILE_ROOT, nm)
            lat.append((time.perf_counter() - t1) * 1e6)
    lat.sort()
    p50 = lat[len(lat) // 2]
    p99 = lat[int(len(lat) * 0.99)]
    print("  lookup 延迟: P50=%.1fus P99=%.1fus (n=%d)"
          % (p50, p99, len(lat)))
    check("lookup P99 < 500us", p99 < 500, "%.1fus" % p99)
    # create 吞吐（追加 200 个）
    t1 = time.time()
    for i in range(200):
        fs.create("/bench_%03d" % i, b"x" * 16)
    fs.sync()
    rate = 200 / (time.time() - t1)
    print("  create 吞吐: %.0f ops/s" % rate)
    check("create > 200 ops/s", rate > 200, "%.0f" % rate)
    # 顺序读吞吐
    no = fs.dir_lookup(FILE_ROOT, names[300])
    big = os.urandom(1024 * 1024)  # 1MB
    fs.create("/bigfile", big)
    fs.sync()
    t1 = time.time()
    got = fs.read_file(fs.dir_lookup(FILE_ROOT, "bigfile"))
    dt = time.time() - t1
    check("1MB 读回一致", got == big)
    print("  1MB 读吞吐: %.1f MB/s (Python 参考实现)" % (1.0 / dt))
    fs.close()

    print("")
    print("=================================")
    print("RESULT: %d passed, %d failed" % (PASS, FAIL))
    print("=================================")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
