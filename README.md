# ExiFS — 自研文件系统 (Exi File System)

版本 1.1 · 设计思想对标 NTFS：**一切皆文件、元数据即数据、B+树目录、位图分配、预写日志**。
性能架构见 [docs/PERF.md](docs/PERF.md)（如何达到 NTFS 级性能 + ExiOS 内核集成设计）。

纯自研 on-disk 格式，无任何微软代码/规范抄袭；完整规范见 [docs/SPEC.md](docs/SPEC.md)。

## 特性

| 特性 | 说明 |
|---|---|
| MFT 主文件表 | 每条记录 1024B，属性化元数据（与 NTFS 同构子集） |
| MFT 动态扩展 | 1024 条记录预留区，64→128→256→512→1024 就地倍增，不搬迁 |
| 属性系统 | 常驻/非常驻、run list 数据段、稀疏段支持 |
| **多级 B+树目录** | INDEX_ROOT + INDEX_ALLOCATION，中点分裂、指针冒泡，四层约 55 万文件/目录 |
| Extent 合并 | 分配时合并连续簇为单 run，元数据随文件大小亚线性增长 |
| Fixup 机制 | 每 512B 扇区尾字节 USN 校验，防撕裂写 |
| 位图分配 | $Bitmap 每簇 1 位，first-fit |
| 元数据文件 | $MFT / $MFTMirr / $LogFile / $Volume / $AttrDef / $Bitmap / $Boot / $BadClus / $Secure / $UpCase / $Extend |
| 崩溃恢复基础 | $LogFile WAL 区预留（重放逻辑 v1.2） |
| CRC64 | VBR 超级块 ECMA-182 校验和 |

## 目录结构

```
ExiFS/
├── include/exifs.h        # 磁盘格式结构体 + 常量 + 助手函数声明
├── src/
│   ├── exifs_util.c       # CRC64 / fixup / run list / UTF 转换
│   ├── mkexifs.c          # 格式化工具（mkfs）
│   ├── fsck.exifs.c       # 一致性检查与修复（含 INDX 节点校验）
│   └── exifs_fuse.c       # FUSE3 只读挂载驱动（B+树遍历）
├── tools/
│   ├── exifs_core.py      # Python 参考实现：格式原语（与 C 逐字节一致）
│   └── exifs_ref.py       # Python 参考 CLI：mkfs/ls/cat/write/mkdir/rm/fsck
├── tests/
│   ├── test_roundtrip.py  # 端到端测试（38 项断言，全过）
│   └── test_btree.py      # B+树大目录测试 + 性能基准（15 项，全过）
└── docs/
    ├── SPEC.md            # 完整磁盘格式规范
    └── PERF.md            # NTFS 级性能架构 + ExiOS 内核集成设计
```

## 快速开始（Python 参考版，Windows 直接可用）

```bash
# 格式化
python tools/exifs_ref.py mkfs -o disk.exifs -s 64M -c 4096 -l ExiFS

# 查看
python tools/exifs_ref.py info disk.exifs
python tools/exifs_ref.py ls   disk.exifs /
python tools/exifs_ref.py cat  disk.exifs /hello.txt

# 写入
mkdir "dir"        # python tools/exifs_ref.py mkdir disk.exifs /dir
python tools/exifs_ref.py write disk.exifs /dir/a.bin big.bin
echo hi | python tools/exifs_ref.py write disk.exifs /dir/a.txt -

# 删除与检查
python tools/exifs_ref.py rm   disk.exifs /dir/a.bin
python tools/exifs_ref.py fsck disk.exifs -p
```

运行测试：`python tests/test_roundtrip.py`（38/38）、`python tests/test_btree.py`（15/15）

实测基准（Python 参考实现，非优化目标）：create ≈1600 ops/s，
lookup P99 ≈192μs（600 文件目录，3 层树），1MB 顺序读 ≈524 MB/s。

## 构建 C 工具（Linux / WSL / MinGW）

```bash
make            # 生成 mkexifs / fsck.exifs / exifs_fuse
make test       # 运行 Python 测试套件
```

- `mkexifs -o disk.exifs -s 64M -c 4096 -l ExiFS`
- `fsck.exifs -p disk.exifs`
- `./exifs_fuse disk.exifs /mnt`（需要 libfuse3；Windows 可用 WinFsp 方案扩展）

C 与 Python 实现**共享同一 on-disk 格式**，任一侧 mkfs 的镜像另一侧可读。

## 与 NTFS 的关键差异

| 维度 | NTFS | ExiFS |
|---|---|---|
| 定位 | 闭源商业 | 开源自研、规范透明 |
| 大小写 | Win32 不敏感 | POSIX namespace 可配置敏感 |
| 属性 | 13+ 内置 | 同构子集，无 EFS/压缩内置 |
| 目标 | 通用生产 | 学习研究 + 可嵌入轻量自研格式 |

## 路线图

- v1.1 ✅：多级 B+树、MFT 就地扩展、extent 合并、大目录测试
- v1.2：$LogFile 组提交与重放、页缓存/延迟分配、CRC32C、无锁读路径
- v2.0：ExiOS 自研内核 + ExiFS 内核态驱动 + 从 ExiFS 分区自举（设计见 PERF.md）

©XHCGROUP - ALLRIGHTSRESERVED
GITHUB SanhanaYuzu
BASED ON AGPL 3.0 OPEN SOURCE LICENSE
XHCGROUP - NO BOUNDS OF IMAGINATIONS