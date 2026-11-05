/*
 * fd_pass_core.c - pure C helpers for the nginx fd_pass module.
 */
#include "fd_pass_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int
fdp_lower(int c)
{
    return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

static int
fdp_ci_eq(const unsigned char *a, size_t al, const unsigned char *b, size_t bl)
{
    size_t i;

    if (al != bl) {
        return 0;
    }
    for (i = 0; i < al; i++) {
        if (fdp_lower(a[i]) != fdp_lower(b[i])) {
            return 0;
        }
    }
    return 1;
}

int
fdp_validate_component(const unsigned char *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (p[i] == '\0' || p[i] == '\r' || p[i] == '\n') {
            return FDP_ERR_INJECTION;
        }
    }
    return FDP_OK;
}

int
fdp_add_size(size_t *a, size_t b)
{
    if (*a > (size_t) -1 - b) {
        return FDP_ERR_OVERFLOW;
    }
    *a += b;
    return FDP_OK;
}

int
fdp_mul_size(size_t *a, size_t b)
{
    if (*a != 0 && b > (size_t) -1 / *a) {
        return FDP_ERR_OVERFLOW;
    }
    *a *= b;
    return FDP_OK;
}

/* Record is "HTTP_" + name + NUL + payload + NUL. Every add is checked
 * on its own so a huge payload cannot wrap the sum before the test. */
static int
fdp_add_record(size_t *total, size_t name_len, size_t payload)
{
    size_t rec = 0;

    if (fdp_add_size(&rec, 5) != FDP_OK
        || fdp_add_size(&rec, name_len) != FDP_OK
        || fdp_add_size(&rec, 1) != FDP_OK
        || fdp_add_size(&rec, payload) != FDP_OK
        || fdp_add_size(&rec, 1) != FDP_OK
        || fdp_add_size(total, rec) != FDP_OK)
    {
        return FDP_ERR_OVERFLOW;
    }
    return FDP_OK;
}

static int
fdp_emit(unsigned char *buf, size_t total, size_t *pos,
         const void *src, size_t n)
{
    size_t next = *pos;

    if (fdp_add_size(&next, n) != FDP_OK || next > total) {
        return FDP_ERR_OVERFLOW;
    }
    if (n != 0) {
        memcpy(buf + *pos, src, n);
    }
    *pos = next;
    return FDP_OK;
}

int
fdp_netstring_prefix(size_t payload_len, char *out, size_t out_len)
{
    int n;

    n = snprintf(out, out_len, "%zu:", payload_len);
    if (n < 0 || (size_t) n >= out_len) {
        return FDP_ERR_TOO_LONG;
    }
    return n;
}

int
fdp_prefix_span(const unsigned char *start, const unsigned char *pos,
                const unsigned char *last, const unsigned char *end,
                size_t *len)
{
    if (len == NULL || start == NULL || pos == NULL
        || last == NULL || end == NULL)
    {
        return FDP_ERR_OVERFLOW;
    }
    if (start > end || pos < start || last > end || pos > last) {
        return FDP_ERR_OVERFLOW;
    }
    *len = (size_t) (last - pos);
    return FDP_OK;
}

int
fdp_iov_total(const fdp_iov_t *iov, size_t count, size_t *total)
{
    size_t i, sum = 0;

    if (total == NULL) {
        return FDP_ERR_OVERFLOW;
    }
    for (i = 0; i < count; i++) {
        if (fdp_add_size(&sum, iov[i].len) != FDP_OK) {
            return FDP_ERR_OVERFLOW;
        }
    }
    *total = sum;
    return FDP_OK;
}

int
fdp_iov_advance(const fdp_iov_t *iov, size_t count,
                size_t *index, size_t *offset, size_t sent)
{
    if (sent == 0) {
        if (*index < count && *offset > iov[*index].len) {
            return FDP_ERR_OVERFLOW;
        }
        return FDP_OK;
    }

    while (sent > 0) {
        size_t avail;

        if (*index >= count || *offset > iov[*index].len) {
            return FDP_ERR_OVERFLOW;
        }
        avail = iov[*index].len - *offset;
        if (sent < avail) {
            *offset += sent;
            return FDP_OK;
        }
        sent -= avail;
        (*index)++;
        *offset = 0;
    }
    return FDP_OK;
}

int
fdp_send_prepare(const fdp_send_state_t *st, const fdp_iov_t *iov, size_t count,
                 int *include_cmsg, int *done)
{
    if (st == NULL || include_cmsg == NULL || done == NULL) {
        return FDP_ERR_OVERFLOW;
    }
    if (st->index > count) {
        return FDP_ERR_OVERFLOW;
    }
    if (st->index == count) {
        *include_cmsg = 0;
        *done = 1;
        return FDP_OK;
    }
    if (iov == NULL || st->offset > iov[st->index].len) {
        return FDP_ERR_OVERFLOW;
    }
    *done = 0;
    *include_cmsg = st->fd_pending ? 1 : 0;
    return FDP_OK;
}

int
fdp_send_advance(fdp_send_state_t *st, const fdp_iov_t *iov, size_t count,
                 size_t accepted)
{
    if (st == NULL) {
        return FDP_ERR_OVERFLOW;
    }
    if (accepted > 0 && st->fd_pending) {
        st->fd_pending = 0;
    }
    return fdp_iov_advance(iov, count, &st->index, &st->offset, accepted);
}

static int
fdp_normalize(const unsigned char *name, size_t n,
              unsigned char *out, size_t out_len, size_t *norm_len)
{
    size_t i;

    if (n + 5 > out_len) {
        return FDP_ERR_TOO_LONG;
    }
    memcpy(out, "HTTP_", 5);
    for (i = 0; i < n; i++) {
        unsigned char c = name[i];
        if (c == '-') {
            c = '_';
        } else if (c >= 'a' && c <= 'z') {
            c = (unsigned char) (c - ('a' - 'A'));
        }
        out[5 + i] = c;
    }
    *norm_len = 5 + n;
    return FDP_OK;
}

typedef struct {
    const unsigned char *name;
    size_t               name_len;
    size_t               count;
    size_t               value_total;
    unsigned char        norm[FDP_MAX_NAME + 5];
    size_t               norm_len;
    int                  cookie;
} fdp_group_t;

static int
fdp_is_critical(const unsigned char *name, size_t n)
{
    static const char *critical[] = {
        "host", "content-length", "transfer-encoding",
        "sec-websocket-key", "sec-websocket-version", "origin",
        NULL
    };
    int i;

    for (i = 0; critical[i]; i++) {
        size_t cl = strlen(critical[i]);
        if (n == cl && fdp_ci_eq(name, n, (const unsigned char *) critical[i], cl)) {
            return 1;
        }
    }
    return 0;
}

int
fdp_build_headers(const fdp_header_t *h, size_t n,
                  const fdp_header_opts_t *o,
                  unsigned char **out, size_t *out_len,
                  char *err, size_t err_len)
{
    fdp_group_t *g;
    size_t       i, j, ng = 0, total = 0, pos;
    unsigned char *buf;
    const char   *sep;
    size_t        sep_len;

    if (err && err_len) {
        err[0] = '\0';
    }
    *out = NULL;
    *out_len = 0;

    if (n == 0) {
        buf = malloc(1);
        if (buf == NULL) {
            return FDP_ERR_OOM;
        }
        *out = buf;
        *out_len = 0;
        return FDP_OK;
    }

    if (o == NULL || h == NULL) {
        return FDP_ERR_INJECTION;
    }

    g = calloc(n, sizeof(*g));
    if (g == NULL) {
        return FDP_ERR_OOM;
    }

    for (i = 0; i < n; i++) {
        unsigned char norm[FDP_MAX_NAME + 5];
        size_t        norm_len, scratch = 0;
        int           rc, found = -1;

        /* Length checks happen before any read of the value bytes. A lying
         * value_len near SIZE_MAX must not walk off the caller's buffer. */
        if (h[i].name_len == 0 || h[i].name_len > FDP_MAX_NAME) {
            free(g);
            return FDP_ERR_TOO_LONG;
        }
        if (h[i].name == NULL) {
            free(g);
            return FDP_ERR_INJECTION;
        }
        if (fdp_add_record(&scratch, h[i].name_len, h[i].value_len) != FDP_OK) {
            free(g);
            return FDP_ERR_OVERFLOW;
        }
        if (fdp_validate_component(h[i].name, h[i].name_len) != FDP_OK) {
            free(g);
            if (err && err_len) snprintf(err, err_len, "control byte in header");
            return FDP_ERR_INJECTION;
        }
        for (j = 0; j < h[i].name_len; j++) {
            if (h[i].name[j] == '_' && !o->allow_underscore) {
                free(g);
                if (err && err_len) snprintf(err, err_len, "underscore in header name");
                return FDP_ERR_UNDERSCORE;
            }
        }
        rc = fdp_normalize(h[i].name, h[i].name_len, norm, sizeof(norm), &norm_len);
        if (rc != FDP_OK) {
            free(g);
            return rc;
        }

        for (j = 0; j < ng; j++) {
            if (fdp_ci_eq(g[j].name, g[j].name_len, h[i].name, h[i].name_len)) {
                found = (int) j;
                break;
            }
        }
        if (found >= 0) {
            if (!o->combine_duplicates) {
                free(g);
                if (err && err_len) snprintf(err, err_len, "duplicate header");
                return FDP_ERR_DUPLICATE;
            }
            g[found].count++;
            if (fdp_add_size(&g[found].value_total, h[i].value_len) != FDP_OK) {
                free(g);
                return FDP_ERR_OVERFLOW;
            }
            continue;
        }

        /* A distinct original name that normalizes to an existing SCGI name
         * (X-Foo vs X_Foo) is an ambiguity a backend cannot resolve. */
        for (j = 0; j < ng; j++) {
            if (g[j].norm_len == norm_len
                && memcmp(g[j].norm, norm, norm_len) == 0)
            {
                free(g);
                if (err && err_len) snprintf(err, err_len, "header name collision");
                return FDP_ERR_HEADER_COLLISION;
            }
        }

        g[ng].name = h[i].name;
        g[ng].name_len = h[i].name_len;
        g[ng].count = 1;
        g[ng].value_total = h[i].value_len;
        memcpy(g[ng].norm, norm, norm_len);
        g[ng].norm_len = norm_len;
        g[ng].cookie = (h[i].name_len == 6
                        && fdp_ci_eq(h[i].name, 6, (const unsigned char *) "cookie", 6));
        ng++;
    }

    if (o->reject_duplicate_critical) {
        for (j = 0; j < ng; j++) {
            if (g[j].count > 1 && fdp_is_critical(g[j].name, g[j].name_len)) {
                free(g);
                if (err && err_len) snprintf(err, err_len, "duplicate critical header");
                return FDP_ERR_DUPLICATE;
            }
        }
    }

    for (j = 0; j < ng; j++) {
        size_t combined = g[j].value_total;

        sep = g[j].cookie ? "; " : ", ";
        sep_len = 2;
        if (g[j].count > 1) {
            size_t extra = g[j].count - 1;

            if (fdp_mul_size(&extra, sep_len) != FDP_OK
                || fdp_add_size(&combined, extra) != FDP_OK
                || fdp_add_record(&total, g[j].name_len, combined) != FDP_OK)
            {
                free(g);
                return FDP_ERR_OVERFLOW;
            }
        } else if (fdp_add_record(&total, g[j].name_len, combined) != FDP_OK) {
            free(g);
            return FDP_ERR_OVERFLOW;
        }
    }

    /* Values are scanned only after every length has been shown to fit. */
    for (i = 0; i < n; i++) {
        if (h[i].value_len != 0 && h[i].value == NULL) {
            free(g);
            return FDP_ERR_INJECTION;
        }
        if (fdp_validate_component(h[i].value, h[i].value_len) != FDP_OK) {
            free(g);
            if (err && err_len) snprintf(err, err_len, "control byte in header");
            return FDP_ERR_INJECTION;
        }
    }

    buf = malloc(total ? total : 1);
    if (buf == NULL) {
        free(g);
        return FDP_ERR_OOM;
    }

    pos = 0;
    for (j = 0; j < ng; j++) {
        size_t k;
        int    first = 1;
        unsigned char nul = 0;
        unsigned char folded[FDP_MAX_NAME];

        if (fdp_emit(buf, total, &pos, "HTTP_", 5) != FDP_OK) {
            goto overflow;
        }
        for (k = 0; k < g[j].name_len; k++) {
            unsigned char c = g[j].name[k];
            if (c == '-') {
                c = '_';
            } else if (c >= 'a' && c <= 'z') {
                c = (unsigned char) (c - ('a' - 'A'));
            }
            folded[k] = c;
        }
        if (fdp_emit(buf, total, &pos, folded, g[j].name_len) != FDP_OK
            || fdp_emit(buf, total, &pos, &nul, 1) != FDP_OK)
        {
            goto overflow;
        }

        sep = g[j].cookie ? "; " : ", ";
        sep_len = 2;
        for (i = 0; i < n; i++) {
            if (!fdp_ci_eq(g[j].name, g[j].name_len, h[i].name, h[i].name_len)) {
                continue;
            }
            if (!first) {
                if (fdp_emit(buf, total, &pos, sep, sep_len) != FDP_OK) {
                    goto overflow;
                }
            }
            if (h[i].value_len
                && fdp_emit(buf, total, &pos, h[i].value, h[i].value_len) != FDP_OK)
            {
                goto overflow;
            }
            first = 0;
        }
        if (fdp_emit(buf, total, &pos, &nul, 1) != FDP_OK) {
            goto overflow;
        }
    }

    if (pos != total) {
        goto overflow;
    }

    free(g);
    *out = buf;
    *out_len = pos;
    return FDP_OK;

overflow:
    free(buf);
    free(g);
    return FDP_ERR_OVERFLOW;
}
