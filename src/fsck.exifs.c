/*
 * fsck.exifs - ExiFS consistency checker & repairer
 *
 * Build: gcc fsck.exifs.c exifs_util.c -o fsck.exifs
 *
 * Usage: fsck.exifs [-n] [-p] image
 *   -n  read-only (no repairs even with -p implied off)
 *   -p  preen: auto-repair what is safely repairable (bitmap rebuild)
 *
 * Checks performed:
 *   1. VBR magic / boot signature / CRC64
 *   2. backup VBR matches primary
 *   3. MFT record magic + fixup (update sequence) validity
 *   4. attribute header sanity (length bounds, end marker)
 *   5. non-resident run lists: LCN in range, no overlap between files
 *   6. cluster bitmap matches allocated runs (repaired with -p)
 *   7. directory index entries reference in-use records
 *
 * Exit codes: 0 = clean, 4 = uncorrected errors, 8 = operational error
 */
#include "exifs.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>

#define MAX_RECORDS 65536u

static int g_fd;
static exifs_vbr g_vbr;
static uint32_t g_cluster, g_rec_size;
static uint64_t g_mft_lcn, g_data_lcn, g_total_clus, g_mft_records;
static uint8_t *g_mft;              /* all MFT records, fixups applied */
static uint8_t *g_bm_computed;      /* bitmap computed from runs */
static uint8_t *g_bm_disk;          /* bitmap as stored on disk */
static int g_errors, g_fixes, g_preen;

static void err(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    g_errors++;
}

static void fix(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf(" [FIXED]\n");
    g_fixes++;
}

static int vbr_check(void)
{
    uint8_t buf[512], bak[512];
    if (pread(g_fd, buf, 512, 0) != 512) { err("cannot read VBR"); return -1; }
    memcpy(&g_vbr, buf, sizeof(g_vbr));
    if (memcmp(g_vbr.oem, EXIFS_OEM_NAME, 8) != 0) {
        err("VBR: bad OEM name (not an ExiFS volume)");
        return -1;
    }
    if (exifs_get16(buf + 0x1FE) != EXIFS_BOOT_SIG) {
        err("VBR: bad boot signature 0x%04X", exifs_get16(buf + 0x1FE));
    }
    uint64_t c = exifs_crc64(buf, 0xA8);
    if (c != exifs_get64(buf + 0xA8)) {
        err("VBR: CRC64 mismatch (stored %016llX, computed %016llX)",
            (unsigned long long)exifs_get64(buf + 0xA8),
            (unsigned long long)c);
    }
    uint64_t last = (exifs_get64(buf + 0x14) - 1) * 512;
    if (pread(g_fd, bak, 512, (off_t)last) != 512 ||
        memcmp(buf, bak, 512) != 0)
        err("VBR: backup copy at sector %llu differs",
            (unsigned long long)(last / 512));
    return 0;
}

static int mft_load(void)
{
    g_cluster = (uint32_t)(exifs_get16((uint8_t *)&g_vbr + 0x0B) *
               ((uint8_t *)&g_vbr)[0x0D]);
    g_rec_size = exifs_get32((uint8_t *)&g_vbr + 0x3C);
    g_mft_lcn = exifs_get64((uint8_t *)&g_vbr + 0x1C);
    g_data_lcn = exifs_get64((uint8_t *)&g_vbr + 0x34);
    g_mft_records = exifs_get64((uint8_t *)&g_vbr + 0xA0);
    g_total_clus = (exifs_get64((uint8_t *)&g_vbr + 0x14) * 512) / g_cluster;
    if (g_mft_records == 0 || g_mft_records > MAX_RECORDS) {
        err("VBR: implausible MFT record count %llu",
            (unsigned long long)g_mft_records);
        return -1;
    }
    g_mft = malloc((size_t)g_mft_records * g_rec_size);
    if (!g_mft) { err("out of memory"); return -1; }
    uint64_t off = g_mft_lcn * g_cluster;
    if (pread(g_fd, g_mft, (size_t)(g_mft_records * g_rec_size),
              (off_t)off) != (ssize_t)(g_mft_records * g_rec_size)) {
        err("cannot read MFT at cluster %llu",
            (unsigned long long)g_mft_lcn);
        return -1;
    }
    for (uint64_t r = 0; r < g_mft_records; r++) {
        uint8_t *rec = g_mft + r * g_rec_size;
        if (memcmp(rec, EXIFS_MAGIC_FILE, 4) != 0) {
            err("MFT[%llu]: bad magic", (unsigned long long)r);
            continue;
        }
        if (exifs_fixup_apply(rec, g_rec_size, exifs_get16(rec + 0x04),
                              exifs_get16(rec + 0x06)) != 0)
            err("MFT[%llu]: fixup check failed", (unsigned long long)r);
    }
    return 0;
}

/* mark runs into computed bitmap; returns 0 ok */
static int mark_runs(uint64_t rec_no, uint16_t attr_off, uint32_t attr_len)
{
    uint8_t *rec = g_mft + rec_no * g_rec_size;
    uint16_t run_off = exifs_get16(rec + attr_off + 0x28);
    uint32_t rl = attr_len - run_off;
    exifs_run runs[256];
    int n = exifs_runs_parse(rec + attr_off + run_off, rl, 256, runs);
    if (n < 0) {
        err("MFT[%llu]: malformed run list", (unsigned long long)rec_no);
        return -1;
    }
    for (int i = 0; i < n; i++) {
        if (runs[i].sparse) continue;
        if (runs[i].lcn < 0 ||
            runs[i].lcn + runs[i].length > (int64_t)g_total_clus) {
            err("MFT[%llu]: run out of volume range (LCN %lld + %llu)",
                (unsigned long long)rec_no, (long long)runs[i].lcn,
                (unsigned long long)runs[i].length);
            continue;
        }
        for (uint64_t j = 0; j < runs[i].length; j++) {
            uint64_t c = (uint64_t)runs[i].lcn + j;
            if (g_bm_computed[c >> 3] & (1u << (c & 7))) {
                err("MFT[%llu]: cluster %llu double-allocated",
                    (unsigned long long)rec_no, (unsigned long long)c);
            }
            g_bm_computed[c >> 3] |= (uint8_t)(1u << (c & 7));
        }
    }
    return 0;
}

static void check_records(void)
{
    for (uint64_t r = 0; r < g_mft_records; r++) {
        uint8_t *rec = g_mft + r * g_rec_size;
        if (memcmp(rec, EXIFS_MAGIC_FILE, 4) != 0) continue;
        uint16_t flags = exifs_get16(rec + 0x16);
        if (!(flags & EXIFS_MRF_INUSE)) continue;
        uint32_t used = exifs_get32(rec + 0x18);
        if (used > g_rec_size) {
            err("MFT[%llu]: used size %u > record size", 
                (unsigned long long)r, used);
            continue;
        }
        uint16_t off = exifs_get16(rec + 0x14);
        while (off + 24 <= used) {
            uint32_t type = exifs_get32(rec + off);
            if (type == EXIFS_AT_END) break;
            uint32_t len = exifs_get32(rec + off + 4);
            if (len < 24 || off + len > used) {
                err("MFT[%llu]: attribute length %u invalid at 0x%X",
                    (unsigned long long)r, len, off);
                break;
            }
            if ((type == EXIFS_AT_DATA || type == EXIFS_AT_INDEX_ALLOC) &&
                rec[off + 8] == 1)
                mark_runs(r, off, len);
            off = (uint16_t)(off + len);
        }
    }
}

static void check_bitmap(void)
{
    size_t bm_bytes = (size_t)((g_total_clus + 7) / 8);
    g_bm_computed = calloc(1, bm_bytes);
    g_bm_disk = calloc(1, bm_bytes);
    if (!g_bm_computed || !g_bm_disk) { err("oom"); return; }

    check_records();

    /* load on-disk $Bitmap via record 6 */
    uint8_t *rec = g_mft + EXIFS_FILE_BITMAP * g_rec_size;
    uint16_t off = exifs_get16(rec + 0x14);
    uint32_t used = exifs_get32(rec + 0x18);
    uint64_t bm_lcn = 0; uint32_t bm_len = 0;
    while (off + 24 <= used) {
        uint32_t type = exifs_get32(rec + off);
        if (type == EXIFS_AT_END) break;
        uint32_t len = exifs_get32(rec + off + 4);
        if (type == EXIFS_AT_DATA && rec[off + 8] == 1) {
            uint16_t run_off = exifs_get16(rec + off + 0x28);
            exifs_run runs[4];
            int n = exifs_runs_parse(rec + off + run_off, len - run_off,
                                     4, runs);
            if (n > 0 && !runs[0].sparse) {
                bm_lcn = (uint64_t)runs[0].lcn;
                bm_len = (uint32_t)(runs[0].length * g_cluster);
            }
        }
        off = (uint16_t)(off + len);
    }
    if (!bm_lcn) { err("$Bitmap: no run list found"); return; }
    uint32_t rd = bm_bytes < bm_len ? (uint32_t)bm_bytes : bm_len;
    if (pread(g_fd, g_bm_disk, rd, (off_t)(bm_lcn * g_cluster)) !=
        (ssize_t)rd) {
        err("$Bitmap: read failed");
        return;
    }
    if (memcmp(g_bm_disk, g_bm_computed, bm_bytes) != 0) {
        uint64_t diff = 0;
        for (uint64_t c = 0; c < g_total_clus; c++)
            if ((g_bm_disk[c >> 3] ^ g_bm_computed[c >> 3]) &
                (1u << (c & 7))) diff++;
        err("$Bitmap: %llu clusters differ from allocated runs",
            (unsigned long long)diff);
        if (g_preen) {
            if (pwrite(g_fd, g_bm_computed, rd, (off_t)(bm_lcn * g_cluster))
                == (ssize_t)rd)
                fix("$Bitmap rebuilt from MFT run lists");
        }
    }
}

static void check_dirs(void)
{
    for (uint64_t r = 0; r < g_mft_records; r++) {
        uint8_t *rec = g_mft + r * g_rec_size;
        if (memcmp(rec, EXIFS_MAGIC_FILE, 4) != 0) continue;
        uint16_t flags = exifs_get16(rec + 0x16);
        if (!(flags & EXIFS_MRF_INUSE) || !(flags & EXIFS_MRF_DIRECTORY))
            continue;
        uint16_t off = exifs_get16(rec + 0x14);
        uint32_t used = exifs_get32(rec + 0x18);
        while (off + 24 <= used) {
            uint32_t type = exifs_get32(rec + off);
            if (type == EXIFS_AT_END) break;
            uint32_t len = exifs_get32(rec + off + 4);
            if (type == EXIFS_AT_INDEX_ROOT && rec[off + 8] == 0) {
                uint32_t val_off = exifs_get16(rec + off + 0x14);
                uint8_t *val = rec + off + val_off;
                uint32_t entries_off = exifs_get32(val + 0x10);
                uint32_t idx_len = exifs_get32(val + 0x14);
                uint8_t *p = val + 0x10 + entries_off;
                uint8_t *end = val + 0x10 + idx_len;
                while (p + 12 <= end) {
                    uint64_t ref = exifs_get64(p);
                    uint16_t klen = exifs_get16(p + 8);
                    if (p + 12 + klen > end) break;
                    uint32_t target = exifs_ref_recno(ref);
                    if (target >= g_mft_records ||
                        memcmp(g_mft + target * g_rec_size,
                               EXIFS_MAGIC_FILE, 4) != 0 ||
                        !(exifs_get16(g_mft + target * g_rec_size + 0x16) &
                          EXIFS_MRF_INUSE))
                        err("dir MFT[%llu]: index entry references dead "
                            "record %u", (unsigned long long)r, target);
                    p += (uint16_t)((12 + klen + 7) & ~7u);
                }
            }
            off = (uint16_t)(off + len);
        }
    }
}

/* ------------------------------------------------------------------ */
/* B+tree node validation (v1.1)                                      */
/* ------------------------------------------------------------------ */
static void check_index_nodes(void)
{
    uint8_t node[EXIFS_INDEX_REC_SIZE];
    for (uint64_t r = 0; r < g_mft_records; r++) {
        uint8_t *rec = g_mft + r * g_rec_size;
        if (memcmp(rec, EXIFS_MAGIC_FILE, 4) != 0) continue;
        if (!(exifs_get16(rec + 0x16) & EXIFS_MRF_INUSE)) continue;
        uint16_t off = exifs_get16(rec + 0x14);
        uint32_t used = exifs_get32(rec + 0x18);
        while (off + 24 <= used) {
            uint32_t type = exifs_get32(rec + off);
            if (type == EXIFS_AT_END) break;
            uint32_t len = exifs_get32(rec + off + 4);
            if (len < 24 || off + len > used) break;
            if (type == EXIFS_AT_INDEX_ALLOC && rec[off + 8] == 1) {
                uint16_t run_off = exifs_get16(rec + off + 0x28);
                exifs_run runs[256];
                int n = exifs_runs_parse(rec + off + run_off,
                                         len - run_off, 256, runs);
                if (n < 0) {
                    err("MFT[%llu]: INDEX_ALLOCATION run list malformed",
                        (unsigned long long)r);
                } else {
                    uint64_t nodes = exifs_get64(rec + off + 0x38) /
                        EXIFS_INDEX_REC_SIZE;
                    for (uint64_t v = 0; v < nodes; v++) {
                        uint64_t span = EXIFS_INDEX_REC_SIZE / g_cluster;
                        uint64_t cvcn = v * span, lcn = 0;
                        int found = 0;
                        for (int i = 0; i < n; i++) {
                            if (cvcn >= runs[i].vcn &&
                                cvcn < runs[i].vcn + runs[i].length) {
                                lcn = (uint64_t)runs[i].lcn +
                                    (cvcn - runs[i].vcn);
                                found = 1;
                                break;
                            }
                        }
                        if (!found) {
                            err("dir MFT[%llu]: index node VCN %llu "
                                "unmapped", (unsigned long long)r,
                                (unsigned long long)v);
                            continue;
                        }
                        uint64_t off64 = g_data_lcn * g_cluster +
                            lcn * g_cluster;
                        if (pread(g_fd, node, EXIFS_INDEX_REC_SIZE,
                                  (off_t)off64) !=
                            (ssize_t)EXIFS_INDEX_REC_SIZE) {
                            err("dir MFT[%llu]: cannot read index node %llu",
                                (unsigned long long)r,
                                (unsigned long long)v);
                            continue;
                        }
                        if (memcmp(node, EXIFS_MAGIC_INDX, 4) != 0) {
                            err("dir MFT[%llu]: index node %llu bad magic",
                                (unsigned long long)r,
                                (unsigned long long)v);
                            continue;
                        }
                        if (exifs_fixup_apply(node, EXIFS_INDEX_REC_SIZE,
                                              exifs_get16(node + 0x04),
                                              exifs_get16(node + 0x06)) != 0)
                            err("dir MFT[%llu]: index node %llu fixup "
                                "failed", (unsigned long long)r,
                                (unsigned long long)v);
                    }
                }
            }
            off = (uint16_t)(off + len);
        }
    }
}

int main(int argc, char **argv)
{
    const char *image = NULL;
    g_preen = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-p")) g_preen = 1;
        else if (!strcmp(argv[i], "-n")) g_preen = 0;
        else if (argv[i][0] != '-') image = argv[i];
        else { fprintf(stderr, "usage: %s [-n] [-p] image\n", argv[0]);
               return 8; }
    }
    if (!image) { fprintf(stderr, "usage: %s [-n] [-p] image\n", argv[0]);
                  return 8; }
    g_fd = open(image, g_preen ? O_RDWR : O_RDONLY);
    if (g_fd < 0) { perror("open"); return 8; }

    printf("fsck.exifs: checking %s\n", image);
    if (vbr_check() != 0) return 8;
    if (mft_load() != 0) return 8;
    check_bitmap();
    check_dirs();
    check_index_nodes();

    printf("---- %d errors, %d fixed ----\n", g_errors, g_fixes);
    if (g_errors) printf("volume state: %s\n",
        g_fixes == g_errors ? "REPAIRED" : "DAMAGED");
    else printf("volume state: CLEAN\n");
    close(g_fd);
    return g_errors - g_fixes > 0 ? 4 : 0;
}
