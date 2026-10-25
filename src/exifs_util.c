/*
 * exifs_util.c - ExiFS core helpers implementation
 */
#include "exifs.h"
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/* CRC-64/ECMA-182 (reflected, poly 0xC96C5795D7870F42)               */
/* ------------------------------------------------------------------ */
static uint64_t crc_table[256];
static int crc_table_ready = 0;

static void crc64_init(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint64_t crc = i;
        for (int b = 0; b < 8; b++)
            crc = (crc >> 1) ^ (0xC96C5795D7870F42ull & (uint64_t)(-(int64_t)(crc & 1)));
        crc_table[i] = crc;
    }
    crc_table_ready = 1;
}

uint64_t exifs_crc64(const void *data, size_t len)
{
    if (!crc_table_ready) crc64_init();
    const uint8_t *p = (const uint8_t *)data;
    uint64_t crc = ~0ull;
    for (size_t i = 0; i < len; i++)
        crc = crc_table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

/* ------------------------------------------------------------------ */
/* Fixup array                                                        */
/* ------------------------------------------------------------------ */
int exifs_fixup_apply(uint8_t *buf, size_t size, uint16_t usa_off,
                      uint16_t usa_count)
{
    if (usa_count < 2 || usa_off + (size_t)usa_count * 2 > size)
        return -1;
    uint16_t usn = exifs_get16(buf + usa_off);
    size_t sectors = (size_t)usa_count - 1;
    if (sectors * EXIFS_SECTOR_SIZE > size)
        return -1;
    for (size_t i = 0; i < sectors; i++) {
        uint8_t *tail = buf + (i + 1) * EXIFS_SECTOR_SIZE - 2;
        if (exifs_get16(tail) != usn)
            return -1;
        uint16_t orig = exifs_get16(buf + usa_off + 2 + i * 2);
        exifs_put16(tail, orig);
    }
    return 0;
}

int exifs_fixup_prepare(uint8_t *buf, size_t size, uint16_t usa_off,
                        uint16_t usa_count)
{
    if (usa_count < 2 || usa_off + (size_t)usa_count * 2 > size)
        return -1;
    uint16_t usn = (uint16_t)(exifs_get16(buf + usa_off) + 1);
    if (usn == 0) usn = 1;
    exifs_put16(buf + usa_off, usn);
    size_t sectors = (size_t)usa_count - 1;
    if (sectors * EXIFS_SECTOR_SIZE > size)
        return -1;
    for (size_t i = 0; i < sectors; i++) {
        uint8_t *tail = buf + (i + 1) * EXIFS_SECTOR_SIZE - 2;
        uint16_t orig = exifs_get16(tail);
        exifs_put16(buf + usa_off + 2 + i * 2, orig);
        exifs_put16(tail, usn);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Run list encode/decode                                             */
/* ------------------------------------------------------------------ */
int exifs_run_encode(uint8_t *buf, int64_t lcn, uint64_t vcn,
                     uint64_t length, int64_t prev_lcn, int sparse)
{
    uint64_t l = length;
    int lbytes = 1;
    while ((l >> (8 * lbytes)) && lbytes < 8) lbytes++;
    uint8_t hdr = (uint8_t)(lbytes & 0x0F);
    int obytes = 0;
    uint64_t u = 0;
    if (!sparse && lcn >= 0) {
        int64_t delta = lcn - prev_lcn;
        u = (uint64_t)delta;
        obytes = 1;
        while (obytes < 8) {
            uint64_t mask = (obytes == 8) ? ~0ull :
                (~0ull) >> (64 - 8 * obytes);
            uint64_t sign_bit = 1ull << (8 * obytes - 1);
            if (delta >= 0) {
                if (((uint64_t)delta & ~mask) == 0 &&
                    !((uint64_t)delta & sign_bit))
                    break;
            } else {
                if ((u & ~mask) == 0 && (u & sign_bit))
                    break;
            }
            obytes++;
        }
        hdr |= (uint8_t)((obytes << 4) & 0xF0);
    }
    /* header byte first, then length bytes, then signed offset */
    uint8_t *b = buf;
    *b++ = hdr;
    for (int i = 0; i < lbytes; i++)
        *b++ = (uint8_t)(length >> (8 * i));
    for (int i = 0; i < obytes; i++)
        *b++ = (uint8_t)(u >> (8 * i));
    return (int)(b - buf);
}

int exifs_runs_parse(const uint8_t *runs, size_t max_len, size_t max_runs,
                     exifs_run *out)
{
    size_t pos = 0, n = 0;
    int64_t prev = 0;
    while (pos < max_len) {
        uint8_t hdr = runs[pos];
        if (hdr == 0) break;
        int lbytes = hdr & 0x0F;
        int obytes = (hdr >> 4) & 0x0F;
        if (lbytes == 0 || pos + 1 + lbytes > max_len) return -1;
        uint64_t length = 0;
        for (int i = 0; i < lbytes; i++)
            length |= (uint64_t)runs[pos + 1 + i] << (8 * i);
        pos += 1 + lbytes;
        if (n >= max_runs) return -1;
        out[n].length = length;
        if (obytes == 0) {
            out[n].sparse = 1;
            out[n].lcn = -1;
        } else {
            if (pos + obytes > max_len) return -1;
            uint64_t u = 0;
            for (int i = 0; i < obytes; i++)
                u |= (uint64_t)runs[pos + i] << (8 * i);
            /* sign extend */
            if (u & (1ull << (8 * obytes - 1))) {
                uint64_t mask = (obytes == 8) ? 0ull : (~0ull) << (8 * obytes);
                u |= mask;
            }
            int64_t delta = (int64_t)u;
            out[n].sparse = 0;
            out[n].lcn = prev + delta;
            prev = out[n].lcn;
        }
        out[n].vcn = (n == 0) ? 0 : (out[n - 1].vcn + out[n - 1].length);
        pos += obytes;
        n++;
    }
    return (int)n;
}

/* ------------------------------------------------------------------ */
/* UTF-16LE <-> UTF-8 (handles surrogate pairs)                       */
/* ------------------------------------------------------------------ */
size_t exifs_utf8_to_utf16le(const char *src, uint16_t *dst, size_t dst_chars)
{
    size_t n = 0;
    const uint8_t *s = (const uint8_t *)src;
    while (*s && n < dst_chars) {
        uint32_t cp;
        if (*s < 0x80) { cp = *s++; }
        else if ((*s & 0xE0) == 0xC0 && (s[1] & 0xC0) == 0x80) {
            cp = ((uint32_t)(*s & 0x1F) << 6) | (s[1] & 0x3F); s += 2;
        } else if ((*s & 0xF0) == 0xE0 && (s[1] & 0xC0) == 0x80 &&
                   (s[2] & 0xC0) == 0x80) {
            cp = ((uint32_t)(*s & 0x0F) << 12) | ((uint32_t)(s[1] & 0x3F) << 6)
                 | (s[2] & 0x3F); s += 3;
        } else if ((*s & 0xF8) == 0xF0 && (s[1] & 0xC0) == 0x80 &&
                   (s[2] & 0xC0) == 0x80 && (s[3] & 0xC0) == 0x80) {
            cp = ((uint32_t)(*s & 0x07) << 18) | ((uint32_t)(s[1] & 0x3F) << 12)
                 | ((uint32_t)(s[2] & 0x3F) << 6) | (s[3] & 0x3F); s += 4;
        } else { cp = '?'; s++; }
        if (cp < 0x10000) {
            dst[n++] = (uint16_t)cp;
        } else if (n + 1 < dst_chars) {
            cp -= 0x10000;
            dst[n++] = (uint16_t)(0xD800 + (cp >> 10));
            dst[n++] = (uint16_t)(0xDC00 + (cp & 0x3FF));
        } else break;
    }
    return n;
}

size_t exifs_utf16le_to_utf8(const uint16_t *src, size_t src_chars,
                             char *dst, size_t dst_bytes)
{
    size_t n = 0;
    for (size_t i = 0; i < src_chars && n + 4 < dst_bytes; i++) {
        uint32_t cp = src[i];
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < src_chars &&
            src[i + 1] >= 0xDC00 && src[i + 1] <= 0xDFFF) {
            cp = 0x10000 + ((cp - 0xD800) << 10) + (src[i + 1] - 0xDC00);
            i++;
        }
        if (cp < 0x80) {
            dst[n++] = (char)cp;
        } else if (cp < 0x800) {
            dst[n++] = (char)(0xC0 | (cp >> 6));
            dst[n++] = (char)(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            dst[n++] = (char)(0xE0 | (cp >> 12));
            dst[n++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            dst[n++] = (char)(0x80 | (cp & 0x3F));
        } else {
            dst[n++] = (char)(0xF0 | (cp >> 18));
            dst[n++] = (char)(0x80 | ((cp >> 12) & 0x3F));
            dst[n++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            dst[n++] = (char)(0x80 | (cp & 0x3F));
        }
    }
    dst[n] = '\0';
    return n;
}
