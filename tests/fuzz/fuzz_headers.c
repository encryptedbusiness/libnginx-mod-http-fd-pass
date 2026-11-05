/*
 * libFuzzer target for the pure header/framing helpers.
 *
 * Build (clang required):
 *   clang -std=c11 -g -O1 -fsanitize=fuzzer,address,undefined \
 *         -I../src fuzz_headers.c ../src/fd_pass_core.c -o fuzz_headers
 *   ./fuzz_headers -max_total_time=60
 *
 * Two framings:
 *   - default: a sequence of (nlen, name, vlen, value) with small lengths
 *   - 0xFF: one header whose value_len is an 8-byte little-endian integer
 *     that may be SIZE_MAX. The value pointer only covers the bytes that
 *     follow. Lengths in the allocation-wrap window are passed through and
 *     must be rejected without a read past those bytes.
 */
#include "fd_pass_core.h"

#include <stdint.h>
#include <stdlib.h>

#define MAX_H 16
#define MAX_NAME 64
#define MAX_VALUE 256

static void
check_output(const unsigned char *out, size_t out_len)
{
    size_t i, nuls = 0;

    for (i = 0; i < out_len; i++) {
        if (out[i] == '\r' || out[i] == '\n') {
            abort();
        }
        if (out[i] == '\0') {
            nuls++;
        }
    }
    if (out_len && out[out_len - 1] != '\0') {
        abort();
    }
    if (nuls % 2 != 0) {
        abort();
    }
}

static void
call_build(const fdp_header_t *h, size_t n, const fdp_header_opts_t *o)
{
    unsigned char *out = NULL;
    size_t         out_len = 0;
    char           err[64];

    if (fdp_build_headers(h, n, o, &out, &out_len, err, sizeof(err)) == FDP_OK) {
        check_output(out, out_len);
        free(out);
    }
}

/* Every input tries one length that used to wrap the allocator. */
static void
probe_overflow(const uint8_t *data, size_t size, const fdp_header_opts_t *o)
{
    fdp_header_t   h;
    unsigned char *out = NULL;
    size_t         out_len = 0;
    char           err[64];

    if (size == 0) {
        return;
    }
    h.name = (const unsigned char *) "A";
    h.name_len = 1;
    h.value = data;
    h.value_len = (size_t) -1 - 7;
    if (fdp_build_headers(&h, 1, o, &out, &out_len, err, sizeof(err)) == FDP_OK) {
        abort();
    }
}

static void
hostile_frame(const uint8_t *data, size_t size, const fdp_header_opts_t *o)
{
    fdp_header_t h;
    size_t       pos = 1, nlen, actual, i;
    uint64_t     vlen = 0;

    if (size < 1 + 1 + 8) {
        return;
    }
    nlen = data[pos++];
    if (nlen > FDP_MAX_NAME || pos + nlen + 8 > size) {
        return;
    }
    h.name = data + pos;
    h.name_len = nlen;
    pos += nlen;
    for (i = 0; i < 8; i++) {
        vlen |= (uint64_t) data[pos + i] << (8 * i);
    }
    pos += 8;
    actual = size - pos;
    h.value = data + pos;

    if (vlen > (uint64_t) (size_t) -1) {
        h.value_len = (size_t) -1;
    } else if ((size_t) vlen > actual) {
        size_t overhead = 7 + nlen;

        /* Only the wrap window is allowed to declare more bytes than we
         * hold. A moderate lie would be an out-of-contract read. */
        if (nlen > 0 && overhead < (size_t) -1
            && (size_t) vlen > (size_t) -1 - overhead)
        {
            h.value_len = (size_t) vlen;
        } else {
            h.value_len = actual > MAX_VALUE ? MAX_VALUE : actual;
        }
    } else {
        h.value_len = (size_t) vlen;
    }

    {
        unsigned char *out = NULL;
        size_t         out_len = 0;
        char           err[64];
        int            rc;

        rc = fdp_build_headers(&h, 1, o, &out, &out_len, err, sizeof(err));
        if ((size_t) vlen > actual && h.value_len == (size_t) vlen && rc == FDP_OK) {
            abort();
        }
        if (rc == FDP_OK) {
            check_output(out, out_len);
            free(out);
        }
    }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fdp_header_t h[MAX_H];
    size_t       n = 0, pos = 0;
    fdp_header_opts_t o;

    o.combine_duplicates = 1;
    o.allow_underscore = 0;
    o.reject_duplicate_critical = 1;

    probe_overflow(data, size, &o);

    if (size > 0 && data[0] == 0xFF) {
        hostile_frame(data, size, &o);
        return 0;
    }

    while (pos < size && n < MAX_H) {
        size_t nlen, vlen;

        nlen = data[pos++];
        if (nlen > MAX_NAME || pos + nlen > size) {
            break;
        }
        h[n].name = data + pos;
        h[n].name_len = nlen;
        pos += nlen;

        if (pos >= size) {
            break;
        }
        vlen = data[pos++];
        if (vlen > MAX_VALUE || pos + vlen > size) {
            break;
        }
        h[n].value = data + pos;
        h[n].value_len = vlen;
        pos += vlen;
        n++;
    }

    call_build(h, n, &o);
    return 0;
}
