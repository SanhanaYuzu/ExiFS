/*
 * exifs.h - ExiFS (Exi File System) on-disk format & core helpers
 * Version: 1.0
 *
 * ExiFS is a self-developed file system inspired by NTFS design:
 *   - Master File Table (MFT) with attribute-based metadata
 *   - B+tree directory indexes ($INDEX_ROOT / $INDEX_ALLOCATION)
 *   - Cluster allocation bitmap ($Bitmap)
 *   - Write-ahead log ($LogFile) for crash recovery
 *   - Reserved metadata files ($MFT, $MFTMirr, $Volume, $Boot, ...)
 *
 * All multi-byte integers on disk are little-endian.
 * All timestamps are 100ns intervals since 1601-01-01 UTC.
 */
#ifndef EXIFS_H
#define EXIFS_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Version                                                            */
/* ------------------------------------------------------------------ */
#define EXIFS_VERSION_MAJOR   1
#define EXIFS_VERSION_MINOR   0
#define EXIFS_VERSION         ((EXIFS_VERSION_MAJOR << 8) | EXIFS_VERSION_MINOR)

/* ------------------------------------------------------------------ */
/* Signatures                                                         */
/* ------------------------------------------------------------------ */
#define EXIFS_OEM_NAME        "EXIFS   "   /* 8 bytes, at VBR+3        */
#define EXIFS_MAGIC_FILE      "FILE"       /* MFT record               */
#define EXIFS_MAGIC_INDX      "INDX"       /* index allocation record  */
#define EXIFS_MAGIC_LOG       "EXILOG  "   /* log record               */
#define EXIFS_MAGIC_RCRD      "RCRD"       /* log record payload       */
#define EXIFS_BOOT_SIG        0xAA55u      /* at VBR+0x1FE             */

/* ------------------------------------------------------------------ */
/* Geometry constants                                                 */
/* ------------------------------------------------------------------ */
#define EXIFS_SECTOR_SIZE     512u
#define EXIFS_MFT_REC_SIZE    1024u        /* default MFT record size  */
#define EXIFS_INDEX_REC_SIZE  4096u        /* default index record     */
#define EXIFS_FIRST_USER      16           /* first user file number   */
#define EXIFS_VOL_SERIAL      0x58484346u  /* "XHCF" default serial   */

/* ------------------------------------------------------------------ */
/* Volume flags (VBR.state)                                           */
/* ------------------------------------------------------------------ */
#define EXIFS_VF_DIRTY        0x0001u
#define EXIFS_VF_MOUNTED      0x0002u

/* MFT record flags */
#define EXIFS_MRF_INUSE       0x0001u
#define EXIFS_MRF_DIRECTORY   0x0002u

/* Attribute flags */
#define EXIFS_AF_COMPRESSED   0x0001u
#define EXIFS_AF_ENCRYPTED    0x4000u
#define EXIFS_AF_SPARSE       0x8000u

/* DOS file flags (standard information) */
#define EXIFS_DOS_READONLY    0x00000001u
#define EXIFS_DOS_HIDDEN      0x00000002u
#define EXIFS_DOS_SYSTEM      0x00000004u
#define EXIFS_DOS_ARCHIVE     0x00000020u
#define EXIFS_DOS_DEVICE      0x00000040u
#define EXIFS_DOS_NORMAL      0x00000080u
#define EXIFS_DOS_TEMP        0x00000100u
#define EXIFS_DOS_SPARSE      0x00000200u
#define EXIFS_DOS_REPARSE     0x00000400u
#define EXIFS_DOS_COMPRESSED  0x00000800u
#define EXIFS_DOS_OFFLINE     0x00001000u
#define EXIFS_DOS_ENCRYPTED   0x00004000u

/* File name namespaces */
#define EXIFS_NS_POSIX        0u   /* case sensitive, all chars      */
#define EXIFS_NS_WIN32        1u   /* Win32 long names               */
#define EXIFS_NS_DOS          2u   /* 8.3 short name                 */
#define EXIFS_NS_WIN32DOS     3u   /* long + short                   */

/* ------------------------------------------------------------------ */
/* Attribute types                                                    */
/* ------------------------------------------------------------------ */
#define EXIFS_AT_UNUSED       0x00
#define EXIFS_AT_STD_INFO     0x10   /* $STANDARD_INFORMATION         */
#define EXIFS_AT_ATTR_LIST    0x20   /* $ATTRIBUTE_LIST               */
#define EXIFS_AT_FILE_NAME    0x30   /* $FILE_NAME                    */
#define EXIFS_AT_OBJECT_ID    0x40   /* $OBJECT_ID                    */
#define EXIFS_AT_SECURITY     0x50   /* $SECURITY_DESCRIPTOR          */
#define EXIFS_AT_VOL_NAME     0x60   /* $VOLUME_NAME                  */
#define EXIFS_AT_VOL_INFO     0x70   /* $VOLUME_INFORMATION           */
#define EXIFS_AT_DATA         0x80   /* $DATA                         */
#define EXIFS_AT_INDEX_ROOT   0x90   /* $INDEX_ROOT                   */
#define EXIFS_AT_INDEX_ALLOC  0xA0   /* $INDEX_ALLOCATION             */
#define EXIFS_AT_BITMAP       0xB0   /* $BITMAP                       */
#define EXIFS_AT_REPARSE      0xC0   /* $REPARSE_POINT                */
#define EXIFS_AT_EA_INFO      0xD0   /* $EA_INFORMATION               */
#define EXIFS_AT_EA           0xE0   /* $EA                           */
#define EXIFS_AT_LOGGED       0x100  /* $LOGGED_UTILITY_STREAM        */
#define EXIFS_AT_END          0xFFFFFFFFu

/* ------------------------------------------------------------------ */
/* Reserved metadata file numbers                                     */
/* ------------------------------------------------------------------ */
#define EXIFS_FILE_MFT        0
#define EXIFS_FILE_MFTMIRR    1
#define EXIFS_FILE_LOGFILE    2
#define EXIFS_FILE_VOLUME     3
#define EXIFS_FILE_ATTRDEF    4
#define EXIFS_FILE_ROOT       5
#define EXIFS_FILE_BITMAP     6
#define EXIFS_FILE_BOOT       7
#define EXIFS_FILE_BADCLUS    8
#define EXIFS_FILE_SECURE     9
#define EXIFS_FILE_UPCASE     10
#define EXIFS_FILE_EXTEND     11
/* 12..15 reserved for future use */

/* ------------------------------------------------------------------ */
/* On-disk structures (all packed, little-endian fields)              */
/* ------------------------------------------------------------------ */
#pragma pack(push, 1)

/* Volume Boot Record / Super Block - 512 bytes */
typedef struct {
    uint8_t  jmp[3];            /* 0x00  EB 52 90                     */
    char     oem[8];           /* 0x03  "EXIFS   "                   */
    uint16_t bytes_per_sector;  /* 0x0B  must be 512                  */
    uint8_t  sectors_per_cluster; /* 0x0D power of 2                 */
    uint16_t reserved_sectors;  /* 0x0E                               */
    uint32_t reserved1;         /* 0x10                               */
    uint64_t total_sectors;     /* 0x14                               */
    uint64_t mft_lcn;           /* 0x1C  MFT start cluster            */
    uint64_t mftmirr_lcn;       /* 0x24  MFT mirror start cluster     */
    uint64_t log_lcn;           /* 0x2C  log start cluster            */
    uint64_t data_lcn;          /* 0x34  data region start cluster    */
    uint32_t mft_record_size;   /* 0x3C  bytes per MFT record         */
    uint32_t index_record_size; /* 0x40  bytes per index record       */
    uint16_t state;             /* 0x44  volume flags                 */
    uint16_t version;           /* 0x46  0x0100 = 1.0                 */
    uint64_t serial;            /* 0x48  volume serial number         */
    char     label[64];         /* 0x50  UTF-8 volume label           */
    uint8_t  uuid[16];          /* 0x90  volume UUID (GUID)           */
    uint64_t mft_records;       /* 0xA0  total MFT records            */
    uint64_t checksum;          /* 0xA8  CRC64 of bytes 0..0xA7       */
    uint8_t  reserved2[0x150];  /* 0xB0  zero                         */
    uint16_t boot_sig;          /* 0x1FE 0xAA55                       */
} exifs_vbr;                    /* 512 bytes total                    */

/* MFT record header */
typedef struct {
    char     magic[4];          /* 0x00  "FILE"                       */
    uint16_t usa_off;           /* 0x04  offset to fixup array        */
    uint16_t usa_count;         /* 0x06  entries incl. USN itself     */
    uint64_t lsn;               /* 0x08  $LogFile sequence number     */
    uint16_t sequence;          /* 0x10  record sequence number       */
    uint16_t link_count;        /* 0x12  hard link count              */
    uint16_t attr_off;          /* 0x14  offset of first attribute    */
    uint16_t flags;             /* 0x16  EXIFS_MRF_*                  */
    uint32_t used_size;         /* 0x18  bytes used in record         */
    uint32_t alloc_size;        /* 0x1C  bytes allocated              */
    uint64_t base_ref;          /* 0x20  base record ref (extensions) */
    uint16_t next_attr_id;      /* 0x28                               */
    uint16_t reserved;          /* 0x2A                               */
    uint32_t rec_number;        /* 0x2C  MFT record number            */
} exifs_mft_rec;                /* 0x30 = 48 bytes                    */

/* Attribute header - resident part */
typedef struct {
    uint32_t type;              /* 0x00  EXIFS_AT_*                   */
    uint32_t length;            /* 0x04  total attribute length       */
    uint8_t  non_resident;      /* 0x08  0 = resident, 1 = non-res    */
    uint8_t  name_len;          /* 0x09  name length in UTF-16 chars  */
    uint16_t name_off;          /* 0x0A  offset to name               */
    uint16_t flags;             /* 0x0C  EXIFS_AF_*                   */
    uint16_t instance;          /* 0x0E  instance tag                 */
    uint32_t value_len;         /* 0x10  resident value length        */
    uint16_t value_off;         /* 0x14  offset to value              */
    uint8_t  indexed;           /* 0x16                               */
    uint8_t  reserved;          /* 0x17                               */
} exifs_attr_res;               /* 0x18 = 24 bytes                    */

/* Attribute header - non-resident extension */
typedef struct {
    uint64_t start_vcn;         /* 0x18                               */
    uint64_t last_vcn;          /* 0x20                               */
    uint16_t run_off;           /* 0x28  offset to run list           */
    uint16_t comp_unit;         /* 0x2A  compression unit             */
    uint32_t reserved;          /* 0x2C                               */
    uint64_t alloc_size;        /* 0x30  allocated bytes              */
    uint64_t real_size;         /* 0x38  real (initialized) size      */
    uint64_t init_size;         /* 0x40  initialized size             */
} exifs_attr_nonres;            /* 0x48 = 72 bytes total header       */

/* $STANDARD_INFORMATION value */
typedef struct {
    uint64_t ctime;             /* creation time                      */
    uint64_t mtime;             /* modification time                  */
    uint64_t rtime;             /* MFT modification time              */
    uint64_t atime;             /* access time                        */
    uint32_t dos_flags;         /* EXIFS_DOS_*                        */
    uint32_t reserved;          /* 0                                  */
    uint64_t usn;               /* update sequence number             */
} exifs_std_info;               /* 48 bytes                           */

/* $FILE_NAME value */
typedef struct {
    uint64_t parent_ref;        /* parent directory (MFT ref)         */
    uint64_t ctime;             /* 0x08                               */
    uint64_t mtime;             /* 0x10                               */
    uint64_t rtime;             /* 0x18                               */
    uint64_t atime;             /* 0x20                               */
    uint64_t alloc_size;        /* 0x28                               */
    uint64_t real_size;         /* 0x30                               */
    uint32_t flags;             /* 0x38  EXIFS_MRF_*                  */
    uint8_t  name_len;          /* 0x3C  in UTF-16 chars              */
    uint8_t  namespace;         /* 0x3D  EXIFS_NS_*                   */
    /* UTF-16LE name follows */
} exifs_file_name;              /* 0x3E = 62 bytes + name             */

/* $VOLUME_INFORMATION value */
typedef struct {
    uint64_t reserved;          /* 0x00                               */
    uint8_t  major;             /* 0x08                               */
    uint8_t  minor;             /* 0x09                               */
    uint16_t flags;             /* 0x0A  0x1 dirty 0x2 mounted...     */
    uint32_t reserved2;         /* 0x0C                               */
} exifs_vol_info;               /* 0x10 = 16 bytes                    */

/* Index root value (resident directory) */
typedef struct {
    uint32_t indexed_type;      /* 0x00  EXIFS_AT_FILE_NAME           */
    uint32_t collation;         /* 0x04  1 = filename collation       */
    uint32_t entry_size;        /* 0x08  bytes per entry (alloc)      */
    uint8_t  clusters_per_rec;  /* 0x0C                               */
    uint8_t  reserved[3];       /* 0x0D                               */
    /* index header */
    uint32_t entries_off;       /* 0x10  offset of entries (from 0x10)*/
    uint32_t index_len;         /* 0x14  total index length           */
    uint32_t alloc_len;         /* 0x18  allocated length             */
    uint32_t flags;             /* 0x1C  0x01 = small (resident)      */
    /* entries follow at 0x10 + entries_off */
} exifs_index_root;             /* 0x20 = 32 bytes                    */

/* Index entry */
typedef struct {
    uint64_t file_ref;          /* MFT reference (low48 = number)     */
    uint16_t key_len;           /* key length in bytes                */
    uint16_t flags;             /* 0x01 = has sub-node, 0x02 = last   */
    /* key follows (FILE_NAME value) */
} exifs_index_entry;            /* 12 bytes + key                     */

/* Index allocation record (INDX) */
typedef struct {
    char     magic[4];          /* 0x00  "INDX"                       */
    uint16_t usa_off;           /* 0x04                               */
    uint16_t usa_count;         /* 0x06                               */
    uint64_t lsn;               /* 0x08                               */
    uint64_t vcn;               /* 0x10  VCN of this record           */
    /* index header (same layout as index root tail) */
    uint32_t entries_off;       /* 0x18  from 0x18                    */
    uint32_t index_len;         /* 0x1C                               */
    uint32_t alloc_len;         /* 0x20                               */
    uint32_t flags;             /* 0x24  0x01 = small (resident)      */
    /* entries follow at 0x18 + entries_off */
} exifs_indx_rec;               /* 0x28 = 40 bytes                    */

/* Log record header */
typedef struct {
    char     magic[8];          /* "EXILOG  "                         */
    uint64_t lsn;               /* this record's LSN                  */
    uint64_t prev_lsn;          /* previous record's LSN (0 = start)  */
    uint32_t type;              /* 1=start 2=commit 3=redo 4=undo      */
    uint32_t data_len;          /* bytes of data following            */
    uint64_t checksum;          /* CRC64 of header[0..0x20)+data      */
    /* data follows */
} exifs_log_rec;                /* 40 bytes                           */

/* Attribute definition entry ($AttrDef table, 64 bytes each) */
typedef struct {
    char     name[48];          /* UTF-8 name, e.g. "$STANDARD_INFO"  */
    uint32_t type;              /* attribute type                     */
    uint32_t flags;             /* 0x02 = indexed, 0x40 = resident... */
    uint32_t min_size;          /* 0                                  */
    uint32_t max_size;          /* 0 = unlimited                      */
} exifs_attrdef;                /* 64 bytes                           */

#pragma pack(pop)

/* ------------------------------------------------------------------ */
/* Little-endian helpers                                              */
/* ------------------------------------------------------------------ */
static inline uint16_t exifs_get16(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint16_t)(b[0] | ((uint16_t)b[1] << 8));
}
static inline uint32_t exifs_get32(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}
static inline uint64_t exifs_get64(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint64_t)exifs_get32(b) | ((uint64_t)exifs_get32(b + 4) << 32);
}
static inline void exifs_put16(void *p, uint16_t v) {
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)(v); b[1] = (uint8_t)(v >> 8);
}
static inline void exifs_put32(void *p, uint32_t v) {
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)(v); b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16); b[3] = (uint8_t)(v >> 24);
}
static inline void exifs_put64(void *p, uint64_t v) {
    uint8_t *b = (uint8_t *)p;
    exifs_put32(b, (uint32_t)v);
    exifs_put32(b + 4, (uint32_t)(v >> 32));
}

/* CRC-64/ECMA-182 (reflected poly 0xC96C5795D7870F42, init/xorout ~0) */
uint64_t exifs_crc64(const void *data, size_t len);

/* MFT reference helpers: low 48 bits = record number, high 16 = sequence */
static inline uint64_t exifs_ref_make(uint32_t rec_no, uint16_t seq) {
    return ((uint64_t)seq << 48) | (rec_no & 0xFFFFFFFFFFFFull);
}
static inline uint32_t exifs_ref_recno(uint64_t ref) {
    return (uint32_t)(ref & 0xFFFFFFFFFFFFull);
}
static inline uint16_t exifs_ref_seq(uint64_t ref) {
    return (uint16_t)(ref >> 48);
}

/* Windows epoch: 1601-01-01 -> 1970-01-01 = 11644473600 seconds */
#define EXIFS_EPOCH_DIFF 11644473600LL

static inline uint64_t exifs_time_from_unix(int64_t unix_ns_100) {
    return (uint64_t)((unix_ns_100 / 100) + EXIFS_EPOCH_DIFF * 10000000LL);
}

/* ------------------------------------------------------------------ */
/* Fixup (update sequence) array helpers                              */
/* usa[0] = USN; usa[i] = original value of last 2 bytes of sector i  */
/* ------------------------------------------------------------------ */
int exifs_fixup_apply(uint8_t *buf, size_t size, uint16_t usa_off,
                      uint16_t usa_count);
int exifs_fixup_prepare(uint8_t *buf, size_t size, uint16_t usa_off,
                        uint16_t usa_count);

/* ------------------------------------------------------------------ */
/* Run list parsing                                                   */
/* ------------------------------------------------------------------ */
typedef struct {
    int64_t  lcn;          /* physical cluster; -1 = sparse */
    uint64_t vcn;          /* virtual cluster number        */
    uint64_t length;       /* clusters in run              */
    int      sparse;
} exifs_run;

/* Parse run list; returns count of runs (up to max), -1 on error. */
int exifs_runs_parse(const uint8_t *runs, size_t max_len, size_t max_runs,
                     exifs_run *out);

/* Encode one run into buf; returns bytes written. */
int exifs_run_encode(uint8_t *buf, int64_t lcn, uint64_t vcn,
                     uint64_t length, int64_t prev_lcn, int sparse);

/* ------------------------------------------------------------------ */
/* UTF-16LE <-> UTF-8 conversion (minimal, BMP only + surrogate pairs) */
/* ------------------------------------------------------------------ */
size_t exifs_utf8_to_utf16le(const char *src, uint16_t *dst, size_t dst_chars);
size_t exifs_utf16le_to_utf8(const uint16_t *src, size_t src_chars,
                             char *dst, size_t dst_bytes);

#ifdef __cplusplus
}
#endif

#endif /* EXIFS_H */
