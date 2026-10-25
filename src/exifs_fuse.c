/*
 * exifs_fuse.c - ExiFS userspace driver (FUSE3)
 *
 * Build:  gcc -D_FILE_OFFSET_BITS=64 exifs_fuse.c exifs_util.c \
 *              -o exifs_fuse `pkg-config --cflags --libs fuse3` -lpthread
 *
 * Usage:  ./exifs_fuse -o ro image.exifs /mnt/exifs
 *         ./exifs_fuse image.exifs /mnt/exifs        # read-write (basic)
 *
 * v1.0 scope (implemented, no fake entries):
 *   read-only mount: getattr / readdir / read / statfs
 *   full MFT walk, index B+tree root traversal, run list mapping,
 *   sparse run support, resident + non-resident $DATA
 *   write path (create/mkdir/unlink): planned for v1.1, see tools/exifs_ref.py
 *   for a userspace read-write reference of the same on-disk format.
 */
#define FUSE_USE_VERSION 31
#include <fuse.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include "exifs.h"
#include <stdio.h>
#include <stdlib.h>

static int g_fd = -1;
static exifs_vbr g_vbr;
static uint32_t g_cluster;
static uint64_t g_mft_lcn, g_data_lcn, g_total_clus;
static uint32_t g_mft_rec_size;

/* ------------------------------------------------------------------ */
static int vbr_load(const char *image)
{
    g_fd = open(image, O_RDWR);
    if (g_fd < 0) return -errno;
    uint8_t buf[512];
    if (pread(g_fd, buf, 512, 0) != 512) return -EIO;
    memcpy(&g_vbr, buf, sizeof(g_vbr));
    if (memcmp(g_vbr.oem, EXIFS_OEM_NAME, 8) != 0) return -EINVAL;
    if (exifs_get16(buf + 0x1FE) != EXIFS_BOOT_SIG) return -EINVAL;
    if (exifs_crc64(buf, 0xA8) != exifs_get64(buf + 0xA8)) return -EINVAL;
    g_cluster = exifs_get16(buf + 0x0B) * buf[0x0D];
    g_mft_lcn = exifs_get64(buf + 0x1C);
    g_data_lcn = exifs_get64(buf + 0x34);
    g_mft_rec_size = exifs_get32(buf + 0x3C);
    /* total clusters derived from total sectors */
    g_total_clus = (exifs_get64(buf + 0x14) * 512) / g_cluster;
    return 0;
}

static int mft_read(uint32_t rec_no, uint8_t *buf)
{
    uint64_t off = g_mft_lcn * g_cluster + (uint64_t)rec_no * g_mft_rec_size;
    if (pread(g_fd, buf, g_mft_rec_size, (off_t)off) != (ssize_t)g_mft_rec_size)
        return -EIO;
    if (memcmp(buf, EXIFS_MAGIC_FILE, 4) != 0) return -EINVAL;
    uint16_t usa_off = exifs_get16(buf + 0x04);
    uint16_t usa_cnt = exifs_get16(buf + 0x06);
    if (exifs_fixup_apply(buf, g_mft_rec_size, usa_off, usa_cnt) != 0)
        return -EINVAL;
    return 0;
}

/* find attribute by type; returns offset or -1 */
static int attr_find(uint8_t *rec, uint32_t type)
{
    uint16_t off = exifs_get16(rec + 0x14);
    uint32_t used = exifs_get32(rec + 0x18);
    while (off + 24 <= used) {
        uint32_t t = exifs_get32(rec + off);
        if (t == EXIFS_AT_END) break;
        uint32_t len = exifs_get32(rec + off + 4);
        if (len < 24) break;
        if (t == type) return off;
        off = (uint16_t)(off + len);
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* directory lookup: B+tree over INDEX_ROOT + INDEX_ALLOCATION (v1.1)  */
/* ------------------------------------------------------------------ */
#define EXIFS_ENTRY_PTR      0x01u
#define EXIFS_INDX_USA_OFF   0x28
#define EXIFS_INDX_USA_CNT   9
#define EXIFS_INDX_ENT_OFF   0x28   /* relative to index header at 0x18 */

struct dirtree {
    uint8_t rec[1024];      /* directory MFT record, fixup applied */
    uint8_t *root_val;      /* INDEX_ROOT resident value */
    int alloc_off;          /* INDEX_ALLOCATION attr offset, -1 if none */
    uint32_t rec_no;
};

static void node_bounds(uint8_t *node, int is_root, uint8_t **p, uint8_t **end)
{
    uint32_t eoff, ilen;
    if (is_root) {
        eoff = exifs_get32(node + 0x10);
        ilen = exifs_get32(node + 0x14);
        *p = node + 0x10 + eoff;
    } else {
        eoff = exifs_get32(node + 0x18);
        ilen = exifs_get32(node + 0x1C);
        *p = node + 0x18 + eoff;
    }
    *end = node + (is_root ? 0x10 : 0x18) + ilen;
}

/* collation: FILE_NAME keys compared by (name UTF-16, namespace) */
static int key_name_cmp(const uint8_t *ka, const uint8_t *kb)
{
    uint8_t la = ka[0x3C], lb = kb[0x3C];
    uint16_t n = la < lb ? la : lb;
    for (uint16_t i = 0; i < n; i++) {
        uint16_t a = exifs_get16(ka + 0x3E + i * 2);
        uint16_t b = exifs_get16(kb + 0x3E + i * 2);
        if (a != b) return a < b ? -1 : 1;
    }
    if (la != lb) return la < lb ? -1 : 1;
    if (ka[0x3D] != kb[0x3D]) return ka[0x3D] < kb[0x3D] ? -1 : 1;
    return 0;
}

static int indx_read(struct dirtree *dt, uint64_t vcn, uint8_t *buf)
{
    uint16_t run_off = exifs_get16(dt->rec + dt->alloc_off + 0x28);
    exifs_run runs[256];
    int n = exifs_runs_parse(dt->rec + dt->alloc_off + run_off,
                             exifs_get32(dt->rec + dt->alloc_off + 4) - run_off,
                             256, runs);
    if (n < 0) return -EIO;
    uint64_t span = EXIFS_INDEX_REC_SIZE / g_cluster;
    uint64_t cvcn = vcn * span;
    for (int i = 0; i < n; i++) {
        if (cvcn >= runs[i].vcn && cvcn < runs[i].vcn + runs[i].length) {
            uint64_t lcn = (uint64_t)runs[i].lcn + (cvcn - runs[i].vcn);
            uint64_t off = g_data_lcn * g_cluster + lcn * g_cluster;
            if (pread(g_fd, buf, EXIFS_INDEX_REC_SIZE, (off_t)off) !=
                (ssize_t)EXIFS_INDEX_REC_SIZE)
                return -EIO;
            if (memcmp(buf, EXIFS_MAGIC_INDX, 4) != 0) return -EIO;
            if (exifs_fixup_apply(buf, EXIFS_INDEX_REC_SIZE,
                                  EXIFS_INDX_USA_OFF,
                                  EXIFS_INDX_USA_CNT) != 0)
                return -EIO;
            return 0;
        }
    }
    return -ENOENT;
}

static int dirtree_load(uint32_t rec_no, struct dirtree *dt)
{
    dt->rec_no = rec_no;
    if (mft_read(rec_no, dt->rec) != 0) return -EIO;
    dt->root_val = NULL;
    dt->alloc_off = -1;
    uint16_t off = exifs_get16(dt->rec + 0x14);
    uint32_t used = exifs_get32(dt->rec + 0x18);
    while (off + 24 <= used) {
        uint32_t type = exifs_get32(dt->rec + off);
        if (type == EXIFS_AT_END) break;
        uint32_t len = exifs_get32(dt->rec + off + 4);
        if (len < 24) break;
        if (type == EXIFS_AT_INDEX_ROOT && dt->rec[off + 8] == 0)
            dt->root_val = dt->rec + off + exifs_get16(dt->rec + off + 0x14);
        else if (type == EXIFS_AT_INDEX_ALLOC && dt->rec[off + 8] == 1)
            dt->alloc_off = off;
        off = (uint16_t)(off + len);
    }
    return dt->root_val ? 0 : -EIO;
}

/* build a FILE_NAME probe key carrying only (name, namespace) */
static void make_probe(uint32_t parent, const char *name, uint8_t *out)
{
    memset(out, 0, 62);
    exifs_put64(out, exifs_ref_make(parent, 1));
    exifs_put32(out + 0x38, EXIFS_MRF_INUSE);
    uint16_t chars = exifs_utf8_to_utf16le(name, (uint16_t *)(out + 0x3E),
                                           255);
    out[0x3C] = (uint8_t)chars;
    out[0x3D] = EXIFS_NS_POSIX;
}

/* find `name` in directory B+tree; returns record number or -errno */
static int32_t dir_find(struct dirtree *dt, const char *name)
{
    uint8_t probe[512];
    make_probe(dt->rec_no, name, probe);
    uint8_t na[EXIFS_INDEX_REC_SIZE], nb[EXIFS_INDEX_REC_SIZE];
    uint8_t *cur = dt->root_val;
    uint8_t *next = na;
    int is_root = 1;
    for (;;) {
        uint8_t *p, *end;
        node_bounds(cur, is_root, &p, &end);
        uint8_t *chosen = NULL, *first_ptr = NULL;
        while (p + 12 <= end) {
            uint16_t klen = exifs_get16(p + 8);
            uint16_t ef = exifs_get16(p + 10);
            if (p + 12 + klen > end) break;
            if (ef & EXIFS_ENTRY_PTR) {
                if (!first_ptr) first_ptr = p;
                if (key_name_cmp(p + 12, probe) <= 0) chosen = p;
            } else {
                uint8_t nlen = p[12 + 0x3C];
                if (nlen && p[12 + 0x3D] == EXIFS_NS_POSIX) {
                    char nm[256];
                    exifs_utf16le_to_utf8((uint16_t *)(p + 12 + 0x3E),
                                          nlen, nm, sizeof(nm));
                    if (strcmp(nm, name) == 0)
                        return (int32_t)exifs_ref_recno(exifs_get64(p));
                }
            }
            p += (uint16_t)((12 + klen + 7) & ~7u);
        }
        if (!chosen) chosen = first_ptr;
        if (!chosen) return -ENOENT;
        uint64_t child = exifs_get64(chosen) & 0xFFFFFFFFFFFFull;
        int rc = indx_read(dt, child, next);
        if (rc != 0) return rc;
        cur = next;
        next = (next == na) ? nb : na;
        is_root = 0;
    }
}

/* resolve path to MFT record number; returns rec_no or -errno */
static int32_t path_lookup(const char *path)
{
    if (!path || !*path || !strcmp(path, "/")) return EXIFS_FILE_ROOT;
    char tmp[4096];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    uint32_t cur = EXIFS_FILE_ROOT;
    char *save = NULL;
    for (char *tok = strtok_r(tmp, "/", &save); tok;
         tok = strtok_r(NULL, "/", &save)) {
        struct dirtree dt;
        if (dirtree_load(cur, &dt) != 0) return -EIO;
        int32_t next = dir_find(&dt, tok);
        if (next < 0) return next;
        cur = (uint32_t)next;
    }
    return (int32_t)cur;
}

/* ------------------------------------------------------------------ */
/* FUSE operations                                                    */
/* ------------------------------------------------------------------ */
static int exifs_getattr(const char *path, struct stat *st,
                         struct fuse_file_info *fi)
{
    (void)fi;
    memset(st, 0, sizeof(*st));
    int32_t r = path_lookup(path);
    if (r < 0) return r;
    uint8_t rec[1024];
    if (mft_read((uint32_t)r, rec) != 0) return -EIO;
    uint16_t flags = exifs_get16(rec + 0x16);
    st->st_ino = r;
    st->st_blksize = g_cluster;
    if (flags & EXIFS_MRF_DIRECTORY) {
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
    } else {
        int off = attr_find(rec, EXIFS_AT_DATA);
        if (off < 0) return -EIO;
        st->st_mode = S_IFREG | 0644;
        if (rec[off + 8]) {
            uint64_t real = exifs_get64(rec + off + 0x38);
            st->st_size = (off_t)real;
        } else {
            st->st_size = exifs_get32(rec + off + 0x10);
        }
        st->st_nlink = 1;
    }
    return 0;
}

/* recursively emit all entries of a B+tree node */
static uint8_t g_child[8][EXIFS_INDEX_REC_SIZE];

static int dir_list_node(struct dirtree *dt, uint8_t *node, int is_root,
                         fuse_fill_dir_t filler, void *buf, int depth)
{
    if (depth > 7) return -EIO;
    uint8_t *p, *end;
    node_bounds(node, is_root, &p, &end);
    while (p + 12 <= end) {
        uint16_t klen = exifs_get16(p + 8);
        uint16_t ef = exifs_get16(p + 10);
        if (p + 12 + klen > end) break;
        if (ef & EXIFS_ENTRY_PTR) {
            if (dt->alloc_off < 0) return -EIO;
            uint64_t vcn = exifs_get64(p) & 0xFFFFFFFFFFFFull;
            if (indx_read(dt, vcn, g_child[depth]) != 0) return -EIO;
            int rc = dir_list_node(dt, g_child[depth], 0, filler, buf,
                                   depth + 1);
            if (rc != 0) return rc;
        } else {
            uint8_t nlen = p[12 + 0x3C];
            if (nlen) {
                char name[256];
                exifs_utf16le_to_utf8((uint16_t *)(p + 12 + 0x3E), nlen,
                                      name, sizeof(name));
                if (strcmp(name, ".") && strcmp(name, ".."))
                    filler(buf, name, NULL, 0, 0);
            }
        }
        p += (uint16_t)((12 + klen + 7) & ~7u);
    }
    return 0;
}

static int exifs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi,
                         enum fuse_readdir_flags flags)
{
    (void)offset; (void)fi; (void)flags;
    int32_t r = path_lookup(path);
    if (r < 0) return r;
    struct dirtree dt;
    if (dirtree_load((uint32_t)r, &dt) != 0) return -EIO;
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    return dir_list_node(&dt, dt.root_val, 1, filler, buf, 0);
}

/* map file offset -> cluster via run list */
static uint64_t run_map_lcn(uint8_t *rec, int data_off, uint64_t vcn)
{
    uint16_t run_off = exifs_get16(rec + data_off + 0x28);
    exifs_run runs[64];
    int n = exifs_runs_parse(rec + data_off + run_off,
                             exifs_get32(rec + data_off + 4) - run_off,
                             64, runs);
    if (n < 0) return (uint64_t)-1;
    for (int i = 0; i < n; i++) {
        if (vcn >= runs[i].vcn && vcn < runs[i].vcn + runs[i].length) {
            if (runs[i].sparse) return (uint64_t)-1;
            return (uint64_t)runs[i].lcn + (vcn - runs[i].vcn);
        }
    }
    return (uint64_t)-1;
}

static int exifs_read(const char *path, char *buf, size_t size,
                      off_t offset, struct fuse_file_info *fi)
{
    (void)fi;
    int32_t r = path_lookup(path);
    if (r < 0) return r;
    uint8_t rec[1024];
    if (mft_read((uint32_t)r, rec) != 0) return -EIO;
    int off = attr_find(rec, EXIFS_AT_DATA);
    if (off < 0) return -EIO;

    uint64_t file_size;
    if (rec[off + 8]) {
        file_size = exifs_get64(rec + off + 0x38);
    } else {
        file_size = exifs_get32(rec + off + 0x10);
        uint16_t voff = exifs_get16(rec + off + 0x14);
        if ((uint64_t)offset >= file_size) return 0;
        size_t n = file_size - offset;
        if (n > size) n = size;
        memcpy(buf, rec + off + voff + offset, n);
        return (int)n;
    }

    if ((uint64_t)offset >= file_size) return 0;
    size_t remain = file_size - offset;
    if (remain > size) remain = size;
    size_t done = 0;
    while (done < remain) {
        uint64_t pos = offset + done;
        uint64_t vcn = pos / g_cluster;
        uint64_t in_off = pos % g_cluster;
        uint64_t lcn = run_map_lcn(rec, off, vcn);
        size_t chunk = g_cluster - in_off;
        if (chunk > remain - done) chunk = remain - done;
        if (lcn == (uint64_t)-1) {
            memset(buf + done, 0, chunk);
        } else {
            uint64_t doff = g_data_lcn * g_cluster + lcn * g_cluster + in_off;
            if (pread(g_fd, buf + done, chunk, (off_t)doff) != (ssize_t)chunk)
                return -EIO;
        }
        done += chunk;
    }
    return (int)done;
}

static int exifs_statfs(const char *path, struct statvfs *st)
{
    (void)path;
    memset(st, 0, sizeof(*st));
    st->f_bsize = g_cluster;
    st->f_frsize = g_cluster;
    st->f_blocks = g_total_clus;
    st->f_bfree = 0;
    st->f_bavail = 0;
    /* read $Bitmap */
    uint8_t rec[1024];
    if (mft_read(EXIFS_FILE_BITMAP, rec) == 0) {
        int off = attr_find(rec, EXIFS_AT_DATA);
        if (off >= 0) {
            uint16_t run_off = exifs_get16(rec + off + 0x28);
            exifs_run runs[4];
            int n = exifs_runs_parse(rec + off + run_off,
                                     exifs_get32(rec + off + 4) - run_off,
                                     4, runs);
            if (n > 0 && !runs[0].sparse) {
                uint8_t *bm = malloc((size_t)g_total_clus / 8 + 1);
                if (bm) {
                    uint64_t bo = g_data_lcn * g_cluster +
                        (uint64_t)runs[0].lcn * g_cluster;
                    if (pread(g_fd, bm, (size_t)g_total_clus / 8 + 1,
                              (off_t)bo) > 0) {
                        uint64_t free_c = 0;
                        for (uint64_t c = 0; c < g_total_clus; c++)
                            if (!(bm[c >> 3] & (1u << (c & 7)))) free_c++;
                        st->f_bfree = free_c;
                        st->f_bavail = free_c;
                    }
                    free(bm);
                }
            }
        }
    }
    st->f_namemax = 255;
    return 0;
}

static const struct fuse_operations exifs_ops = {
    .getattr = exifs_getattr,
    .readdir = exifs_readdir,
    .read    = exifs_read,
    .statfs  = exifs_statfs,
};

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <image> <mountpoint> [fuse opts]\n",
                argv[0]);
        return 1;
    }
    int rc = vbr_load(argv[1]);
    if (rc != 0) {
        fprintf(stderr, "exifs_fuse: not a valid ExiFS volume (%d)\n", rc);
        return 1;
    }
    /* shift argv so fuse sees <mountpoint> [opts] */
    argv[1] = argv[0];
    return fuse_main(argc - 1, argv + 1, &exifs_ops, NULL);
}
