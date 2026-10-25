/*
 * mkexifs.c - ExiFS formatter (mkfs equivalent)
 *
 * Usage: mkexifs -o <image> [-s <size>] [-c <cluster>] [-l <label>]
 *   -s  64M / 512K / 2G ...   (default 64M, min 8M)
 *   -c  512..65536, power of 2 (default 4096)
 *   -l  volume label (UTF-8, <= 63 chars)
 */
#include "exifs.h"
#include <stdio.h>
#include <stdlib.h>

#define MFT_RECORDS      64u    /* live MFT records at format time */
#define MFT_ZONE_RECORDS 1024u  /* preallocated zone (extends in place) */

/* ------------------------------------------------------------------ */
static FILE *g_img;
static uint64_t g_total_sectors;
static uint32_t g_cluster;          /* bytes per cluster */
static uint32_t g_sectors_per_clus;
static uint64_t g_total_clus;

static uint64_t g_mft_lcn, g_mft_clusters;
static uint64_t g_mftmirr_lcn, g_log_lcn, g_log_clusters;
static uint64_t g_bitmap_lcn, g_upcase_lcn, g_upcase_clusters, g_data_lcn;

static uint8_t *g_bitmap;           /* cluster bitmap in memory */

static void die(const char *msg)
{
    fprintf(stderr, "mkexifs: %s\n", msg);
    exit(1);
}

static void write_at(uint64_t off, const void *buf, size_t len)
{
    if (fseek(g_img, (long)off, SEEK_SET) != 0) die("seek failed");
    if (fwrite(buf, 1, len, g_img) != len) die("write failed");
}

static void read_at(uint64_t off, void *buf, size_t len)
{
    if (fseek(g_img, (long)off, SEEK_SET) != 0) die("seek failed");
    if (fread(buf, 1, len, g_img) != len) die("read failed");
}

static uint64_t clus_off(uint64_t lcn)
{
    return lcn * g_cluster;
}

static void bm_set(uint64_t lcn)
{
    g_bitmap[lcn >> 3] |= (uint8_t)(1u << (lcn & 7));
}

/* ------------------------------------------------------------------ */
/* MFT record builders                                                */
/* ------------------------------------------------------------------ */
static void rec_init(uint8_t *rec, uint32_t rec_no, uint16_t flags)
{
    memset(rec, 0, EXIFS_MFT_REC_SIZE);
    memcpy(rec, EXIFS_MAGIC_FILE, 4);
    exifs_put16(rec + 0x04, 48);            /* usa_off */
    exifs_put16(rec + 0x06, 3);             /* usa_count: 2 sectors + USN */
    exifs_put16(rec + 0x10, 1);             /* sequence */
    exifs_put16(rec + 0x12, 1);             /* link count */
    exifs_put16(rec + 0x14, 56);            /* attr_off */
    exifs_put16(rec + 0x16, flags);
    exifs_put32(rec + 0x18, EXIFS_MFT_REC_SIZE);
    exifs_put32(rec + 0x1C, EXIFS_MFT_REC_SIZE);
    exifs_put16(rec + 0x28, 4);             /* next attr id */
    exifs_put32(rec + 0x2C, rec_no);
}

static void rec_finish(uint8_t *rec, uint16_t used)
{
    exifs_put32(rec + 0x18, used);
    /* end marker */
    exifs_put32(rec + used, EXIFS_AT_END);
    used += 4;
    memset(rec + used, 0, EXIFS_MFT_REC_SIZE - used);
    exifs_fixup_prepare(rec, EXIFS_MFT_REC_SIZE, 48, 3);
}

/* returns offset just past the attribute */
static uint16_t add_res_attr(uint8_t *rec, uint16_t off, uint32_t type,
                             uint16_t aflags, const void *value,
                             uint32_t value_len)
{
    uint16_t name_off = 0x18;
    uint16_t val_off = (uint16_t)((name_off + 7) & ~7u);
    uint32_t total = (uint32_t)((val_off + value_len + 7) & ~7u);
    if ((uint32_t)off + total + 4 > EXIFS_MFT_REC_SIZE)
        die("MFT record overflow in mkexifs");
    exifs_attr_res h;
    memset(&h, 0, sizeof(h));
    h.type = type;
    h.non_resident = 0;
    h.flags = aflags;
    h.value_len = value_len;
    uint16_t name_off = 0x18;
    uint16_t val_off = (uint16_t)((name_off + 7) & ~7u);
    h.value_off = val_off;
    h.length = (uint32_t)((val_off + value_len + 7) & ~7u);
    memcpy(rec + off, &h, sizeof(h));
    if (value && value_len)
        memcpy(rec + off + val_off, value, value_len);
    exifs_put32(rec + off + 4, h.length);
    exifs_put16(rec + off + 0x14, val_off);
    return (uint16_t)(off + h.length);
}

static uint16_t add_nonres_attr(uint8_t *rec, uint16_t off, uint32_t type,
                                uint64_t alloc_size, uint64_t real_size,
                                uint64_t init_size, const uint8_t *runs,
                                size_t run_len)
{
    uint32_t total = (uint32_t)((0x48 + run_len + 7) & ~7u);
    if ((uint32_t)off + total + 4 > EXIFS_MFT_REC_SIZE)
        die("MFT record overflow in mkexifs");
    exifs_attr_res h;
    memset(&h, 0, sizeof(h));
    h.type = type;
    h.non_resident = 1;
    exifs_put32(rec + off, type);
    exifs_put32(rec + off + 4, 0);            /* patched below */
    rec[off + 8] = 1;
    exifs_put16(rec + off + 0x0C, 0);
    exifs_put16(rec + off + 0x0E, 0);
    exifs_put64(rec + off + 0x10, 0);         /* start_vcn */
    exifs_put64(rec + off + 0x18, 0);         /* last_vcn (patched) */
    exifs_put16(rec + off + 0x28, 0x40);      /* run_off */
    exifs_put64(rec + off + 0x30, alloc_size);
    exifs_put64(rec + off + 0x38, real_size);
    exifs_put64(rec + off + 0x40, init_size);
    memcpy(rec + off + 0x40 + 0, runs, run_len);
    (void)h;
    uint32_t total = (uint32_t)(0x48 + run_len);
    total = (total + 7) & ~7u;
    exifs_put32(rec + off + 4, total);
    return (uint16_t)(off + total);
}

/* standard information + file name, common to every record */
static uint16_t add_std_and_name(uint8_t *rec, uint16_t off, uint32_t rec_no,
                                 const char *name, uint8_t ns)
{
    uint64_t now = exifs_time_from_unix(0);
    exifs_std_info si;
    memset(&si, 0, sizeof(si));
    si.ctime = si.mtime = si.rtime = si.atime = now;
    si.dos_flags = EXIFS_DOS_NORMAL;
    off = add_res_attr(rec, off, EXIFS_AT_STD_INFO, 0, &si, sizeof(si));

    uint8_t fn[256];
    uint16_t fn_len;
    exifs_file_name f;
    memset(&f, 0, sizeof(f));
    f.parent_ref = exifs_ref_make(EXIFS_FILE_ROOT, 1);
    f.ctime = f.mtime = f.rtime = f.atime = now;
    f.flags = EXIFS_MRF_INUSE;
    uint16_t chars = (uint16_t)exifs_utf8_to_utf16le(name,
        (uint16_t *)(fn + sizeof(f)), (sizeof(fn) - sizeof(f)) / 2);
    f.name_len = (uint8_t)chars;
    f.namespace = ns;
    memcpy(fn, &f, sizeof(f));
    fn_len = (uint16_t)(sizeof(f) + chars * 2);
    off = add_res_attr(rec, off, EXIFS_AT_FILE_NAME, 0, fn, fn_len);
    return off;
}

/* index entry: 12B header + FILE_NAME key */
static uint16_t index_entry(uint8_t *buf, uint64_t ref, const char *name,
                            uint16_t flags, uint8_t ns)
{
    exifs_index_entry e;
    memset(&e, 0, sizeof(e));
    e.file_ref = ref;
    e.flags = flags;

    uint8_t key[256];
    exifs_file_name f;
    memset(&f, 0, sizeof(f));
    f.parent_ref = exifs_ref_make(EXIFS_FILE_ROOT, 1);
    f.ctime = f.mtime = f.rtime = f.atime = exifs_time_from_unix(0);
    f.alloc_size = 0;
    f.real_size = 0;
    f.flags = EXIFS_MRF_INUSE | EXIFS_MRF_DIRECTORY;
    uint16_t chars = (uint16_t)exifs_utf8_to_utf16le(name,
        (uint16_t *)(key + sizeof(f)), (sizeof(key) - sizeof(f)) / 2);
    f.name_len = (uint8_t)chars;
    f.namespace = ns;
    memcpy(key, &f, sizeof(f));
    uint16_t key_len = (uint16_t)(sizeof(f) + chars * 2);
    e.key_len = key_len;
    memcpy(buf, &e, sizeof(e));
    memcpy(buf + sizeof(e), key, key_len);
    return (uint16_t)(sizeof(e) + key_len);
}

static uint16_t add_index_root(uint8_t *rec, uint16_t off)
{
    uint8_t val[1024];
    exifs_index_root ir;
    memset(&ir, 0, sizeof(ir));
    ir.indexed_type = EXIFS_AT_FILE_NAME;
    ir.collation = 1;
    ir.entry_size = 0;
    ir.clusters_per_rec = 0;
    ir.entries_off = 0x10;
    ir.flags = 1;                      /* small index */
    memcpy(val, &ir, sizeof(ir));

    /* entries start at 0x10 + entries_off = 0x20 */
    uint8_t *entries = val + 0x10 + ir.entries_off;
    uint16_t e = 0;
    e += index_entry(entries + e, exifs_ref_make(EXIFS_FILE_ROOT, 1), ".", 0x02, EXIFS_NS_POSIX);
    e += index_entry(entries + e, exifs_ref_make(EXIFS_FILE_ROOT, 1), "..", 0x02, EXIFS_NS_POSIX);
    uint16_t idx_len = (uint16_t)(0x10 + e);
    exifs_put32(val + 0x14, idx_len);
    exifs_put32(val + 0x18, idx_len);
    return add_res_attr(rec, off, EXIFS_AT_INDEX_ROOT, 0, val,
                        (uint32_t)(0x20 + e));
}

/* ------------------------------------------------------------------ */
static uint8_t *g_mft;   /* MFT_RECORDS * 1024 */

/* returns encoded run-list length (including 0x00 terminator) */
static size_t build_runs_for_range(uint8_t *runs, uint64_t lcn_start,
                                   uint64_t clusters, int sparse)
{
    size_t n = (size_t)exifs_run_encode(runs, sparse ? 0 : (int64_t)lcn_start,
                                        0, clusters, 0, sparse);
    runs[n] = 0;
    return n + 1;
}

int main(int argc, char **argv)
{
    const char *image = NULL, *label = "ExiFS";
    uint64_t size = 64ull * 1024 * 1024;
    uint32_t cluster = 4096;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-o") && i + 1 < argc) image = argv[++i];
        else if (!strcmp(argv[i], "-s") && i + 1 < argc) {
            char *s = argv[++i];
            size = strtoull(s, &s, 10);
            if (*s == 'K' || *s == 'k') size *= 1024;
            else if (*s == 'M' || *s == 'm') size *= 1024 * 1024;
            else if (*s == 'G' || *s == 'g') size *= 1024ull * 1024 * 1024;
        } else if (!strcmp(argv[i], "-c") && i + 1 < argc) {
            cluster = (uint32_t)strtoul(argv[++i], NULL, 10);
        } else if (!strcmp(argv[i], "-l") && i + 1 < argc) {
            label = argv[++i];
        } else {
            fprintf(stderr, "usage: %s -o img [-s 64M] [-c 4096] [-l label]\n",
                    argv[0]);
            return 1;
        }
    }
    if (!image) die("missing -o <image>");
    if (size < 8ull * 1024 * 1024) die("size must be >= 8M");
    if (cluster < 512 || cluster > 65536 || (cluster & (cluster - 1)))
        die("cluster must be power of 2 in [512,65536]");
    if (strlen(label) > 63) die("label too long");

    g_cluster = cluster;
    g_sectors_per_clus = cluster / EXIFS_SECTOR_SIZE;
    g_total_sectors = size / EXIFS_SECTOR_SIZE;
    g_total_clus = size / cluster;

    /* ---- layout ---- */
    g_mft_lcn = 16;
    g_mft_clusters = (MFT_ZONE_RECORDS * EXIFS_MFT_REC_SIZE + cluster - 1) / cluster;
    g_mftmirr_lcn = g_mft_lcn + g_mft_clusters;
    g_log_lcn = g_mftmirr_lcn + 1;
    g_log_clusters = (128 * 1024 + cluster - 1) / cluster;
    g_bitmap_lcn = g_log_lcn + g_log_clusters;
    g_upcase_lcn = g_bitmap_lcn + 1;
    g_upcase_clusters = (128 * 1024 + cluster - 1) / cluster;
    g_data_lcn = g_upcase_lcn + g_upcase_clusters;
    if (g_data_lcn >= g_total_clus) die("image too small for metadata");

    g_img = fopen(image, "w+b");
    if (!g_img) die("cannot create image");
    if (fseek(g_img, (long)size - 1, SEEK_SET) != 0) die("truncate failed");
    if (fputc(0, g_img) == EOF) die("truncate failed");

    g_bitmap = calloc(1, (size_t)((g_total_clus + 7) / 8));
    if (!g_bitmap) die("oom");
    for (uint64_t c = 0; c < g_data_lcn; c++) bm_set(c);

    /* ---- build MFT ---- */
    g_mft = calloc(MFT_RECORDS, EXIFS_MFT_REC_SIZE);
    if (!g_mft) die("oom");
    uint8_t runs[512];

    for (uint32_t r = 0; r < 16; r++) {
        uint8_t *rec = g_mft + (size_t)r * EXIFS_MFT_REC_SIZE;
        uint16_t off = 56;
        if (r >= 12) {                 /* reserved empty records */
            rec_init(rec, r, EXIFS_MRF_INUSE);
            rec_finish(rec, off);
            continue;
        }
        const char *name = NULL;
        uint16_t flags = EXIFS_MRF_INUSE;
        switch (r) {
        case EXIFS_FILE_ROOT: name = "."; flags |= EXIFS_MRF_DIRECTORY; break;
        case EXIFS_FILE_MFT: name = "$MFT"; break;
        case EXIFS_FILE_MFTMIRR: name = "$MFTMirr"; break;
        case EXIFS_FILE_LOGFILE: name = "$LogFile"; break;
        case EXIFS_FILE_VOLUME: name = "$Volume"; break;
        case EXIFS_FILE_ATTRDEF: name = "$AttrDef"; break;
        case EXIFS_FILE_BITMAP: name = "$Bitmap"; break;
        case EXIFS_FILE_BOOT: name = "$Boot"; break;
        case EXIFS_FILE_BADCLUS: name = "$BadClus"; break;
        case EXIFS_FILE_SECURE: name = "$Secure"; break;
        case EXIFS_FILE_UPCASE: name = "$UpCase"; break;
        case EXIFS_FILE_EXTEND: name = "$Extend"; break;
        }
        rec_init(rec, r, flags);
        off = add_std_and_name(rec, off, r, name, EXIFS_NS_POSIX);

        switch (r) {
        case EXIFS_FILE_MFT: {
            size_t rl = build_runs_for_range(runs, g_mft_lcn, g_mft_clusters, 0);
            off = add_nonres_attr(rec, off, EXIFS_AT_DATA,
                                  g_mft_clusters * g_cluster,
                                  MFT_RECORDS * EXIFS_MFT_REC_SIZE,
                                  MFT_RECORDS * EXIFS_MFT_REC_SIZE,
                                  runs, rl);
            break;
        }
        case EXIFS_FILE_MFTMIRR: {
            size_t rl = build_runs_for_range(runs, g_mftmirr_lcn, 1, 0);
            off = add_nonres_attr(rec, off, EXIFS_AT_DATA,
                                  g_cluster, 4096, 4096, runs, rl);
            break;
        }
        case EXIFS_FILE_LOGFILE: {
            size_t rl = build_runs_for_range(runs, g_log_lcn, g_log_clusters, 0);
            off = add_nonres_attr(rec, off, EXIFS_AT_DATA,
                                  g_log_clusters * g_cluster, 0, 0, runs, rl);
            break;
        }
        case EXIFS_FILE_VOLUME: {
            char utf16[128];
            uint16_t chars = (uint16_t)exifs_utf8_to_utf16le(label,
                (uint16_t *)utf16, 64);
            off = add_res_attr(rec, off, EXIFS_AT_VOL_NAME, 0, utf16,
                               chars * 2);
            exifs_vol_info vi;
            memset(&vi, 0, sizeof(vi));
            vi.major = EXIFS_VERSION_MAJOR;
            vi.minor = EXIFS_VERSION_MINOR;
            vi.flags = EXIFS_VF_DIRTY;      /* cleared on clean unmount */
            off = add_res_attr(rec, off, EXIFS_AT_VOL_INFO, 0, &vi, sizeof(vi));
            break;
        }
        case EXIFS_FILE_ATTRDEF: {
            static const struct { const char *n; uint32_t t; uint32_t f;
                                  uint64_t mn, mx; } defs[] = {
                {"$STANDARD_INFORMATION", EXIFS_AT_STD_INFO, 0x40, 48, 48},
                {"$ATTRIBUTE_LIST", EXIFS_AT_ATTR_LIST, 0x80, 0, 0},
                {"$FILE_NAME", EXIFS_AT_FILE_NAME, 0x42, 68, 0},
                {"$VOLUME_NAME", EXIFS_AT_VOL_NAME, 0x40, 2, 256},
                {"$VOLUME_INFORMATION", EXIFS_AT_VOL_INFO, 0x40, 16, 16},
                {"$DATA", EXIFS_AT_DATA, 0x00, 0, 0},
                {"$INDEX_ROOT", EXIFS_AT_INDEX_ROOT, 0x40, 32, 0},
                {"$INDEX_ALLOCATION", EXIFS_AT_INDEX_ALLOC, 0x00, 0, 0},
                {"$BITMAP", EXIFS_AT_BITMAP, 0x00, 0, 0},
            };
            uint8_t tbl[2048];
            uint32_t tl = 0;
            for (size_t i = 0; i < sizeof(defs) / sizeof(defs[0]); i++) {
                exifs_attrdef d;
                memset(&d, 0, sizeof(d));
                strncpy(d.name, defs[i].n, 47);
                exifs_put32(&d.type, defs[i].t);
                exifs_put32(&d.flags, defs[i].f);
                exifs_put64(&d.min_size, defs[i].mn);
                exifs_put64(&d.max_size, defs[i].mx);
                memcpy(tbl + tl, &d, sizeof(d));
                tl += sizeof(d);
            }
            off = add_res_attr(rec, off, EXIFS_AT_DATA, 0, tbl, tl);
            break;
        }
        case EXIFS_FILE_ROOT:
            off = add_index_root(rec, off);
            break;
        case EXIFS_FILE_BITMAP: {
            size_t rl = build_runs_for_range(runs, g_bitmap_lcn, 1, 0);
            off = add_nonres_attr(rec, off, EXIFS_AT_DATA, g_cluster,
                                  (g_total_clus + 7) / 8,
                                  (g_total_clus + 7) / 8, runs, rl);
            break;
        }
        case EXIFS_FILE_BOOT: {
            size_t rl = build_runs_for_range(runs, 0, 16, 0);
            off = add_nonres_attr(rec, off, EXIFS_AT_DATA, 16 * g_cluster,
                                  512, 512, runs, rl);
            break;
        }
        case EXIFS_FILE_BADCLUS: {
            size_t rl = build_runs_for_range(runs, 0, g_total_clus, 1);
            off = add_nonres_attr(rec, off, EXIFS_AT_DATA,
                                  g_total_clus * g_cluster,
                                  g_total_clus * g_cluster,
                                  g_total_clus * g_cluster, runs, rl);
            break;
        }
        case EXIFS_FILE_SECURE:
            off = add_res_attr(rec, off, EXIFS_AT_DATA, 0, NULL, 0);
            break;
        case EXIFS_FILE_UPCASE: {
            size_t rl = build_runs_for_range(runs, g_upcase_lcn, g_upcase_clusters, 0);
            off = add_nonres_attr(rec, off, EXIFS_AT_DATA,
                                  g_upcase_clusters * g_cluster,
                                  65536 * 2, 65536 * 2, runs, rl);
            break;
        }
        default:
            break;
        }
        rec_finish(rec, off);
    }

    /* write MFT */
    write_at(clus_off(g_mft_lcn), g_mft, MFT_RECORDS * EXIFS_MFT_REC_SIZE);
    /* mirror: first 4 records */
    write_at(clus_off(g_mftmirr_lcn), g_mft, 4096);

    /* ---- $UpCase ---- */
    {
        uint16_t *uc = malloc(65536 * 2);
        if (!uc) die("oom");
        for (uint32_t c = 0; c < 65536; c++) {
            uint16_t v = (uint16_t)c;
            if (c >= 'a' && c <= 'z') v = (uint16_t)(c - 32);
            uc[c] = v;
        }
        write_at(clus_off(g_upcase_lcn), uc, 65536 * 2);
        free(uc);
    }

    /* ---- $Bitmap ---- */
    write_at(clus_off(g_bitmap_lcn), g_bitmap, (size_t)((g_total_clus + 7) / 8));

    /* ---- VBR ---- */
    {
        uint8_t vbr[512];
        memset(vbr, 0, sizeof(vbr));
        vbr[0] = 0xEB; vbr[1] = 0x52; vbr[2] = 0x90;
        memcpy(vbr + 3, EXIFS_OEM_NAME, 8);
        exifs_put16(vbr + 0x0B, EXIFS_SECTOR_SIZE);
        vbr[0x0D] = (uint8_t)g_sectors_per_clus;
        exifs_put16(vbr + 0x0E, 0);
        exifs_put64(vbr + 0x14, g_total_sectors);
        exifs_put64(vbr + 0x1C, g_mft_lcn);
        exifs_put64(vbr + 0x24, g_mftmirr_lcn);
        exifs_put64(vbr + 0x2C, g_log_lcn);
        exifs_put64(vbr + 0x34, g_data_lcn);
        exifs_put32(vbr + 0x3C, EXIFS_MFT_REC_SIZE);
        exifs_put32(vbr + 0x40, EXIFS_INDEX_REC_SIZE);
        exifs_put16(vbr + 0x44, EXIFS_VF_DIRTY);
        exifs_put16(vbr + 0x46, EXIFS_VERSION);
        exifs_put64(vbr + 0x48, EXIFS_VOL_SERIAL);
        strncpy((char *)vbr + 0x50, label, 63);
        for (int i = 0; i < 16; i++) vbr[0x90 + i] = (uint8_t)(i * 7 + 3);
        exifs_put64(vbr + 0xA0, MFT_RECORDS);
        exifs_put64(vbr + 0xA8, exifs_crc64(vbr, 0xA8));
        exifs_put16(vbr + 0x1FE, EXIFS_BOOT_SIG);
        write_at(0, vbr, 512);
        /* backup at last sector */
        write_at((uint64_t)(g_total_sectors - 1) * EXIFS_SECTOR_SIZE, vbr, 512);
    }

    printf("ExiFS 1.0 formatted successfully.\n");
    printf("  image          : %s (%llu bytes)\n", image,
           (unsigned long long)size);
    printf("  cluster size   : %u bytes (%u sectors)\n", g_cluster,
           g_sectors_per_clus);
    printf("  total clusters : %llu\n", (unsigned long long)g_total_clus);
    printf("  MFT at cluster %llu (%llu clusters, %u records)\n",
           (unsigned long long)g_mft_lcn, (unsigned long long)g_mft_clusters,
           MFT_RECORDS);
    printf("  mirror / log   : %llu / %llu\n",
           (unsigned long long)g_mftmirr_lcn, (unsigned long long)g_log_lcn);
    printf("  data region    : cluster %llu\n", (unsigned long long)g_data_lcn);
    printf("  volume label   : %s\n", label);

    fclose(g_img);
    return 0;
}
