/*
 * fd_pass_core.h - pure C helpers for the nginx fd_pass module.
 *
 * This file deliberately has no nginx dependency so it can be unit-tested and
 * fuzzed. The module converts its header list into fdp_header_t and calls in.
 */
#ifndef FD_PASS_CORE_H
#define FD_PASS_CORE_H

#include <stddef.h>

#define FDP_OK                       0
#define FDP_ERR_OOM                 -1
#define FDP_ERR_HEADER_COLLISION    -2
#define FDP_ERR_UNDERSCORE          -3
#define FDP_ERR_DUPLICATE           -4
#define FDP_ERR_OVERFLOW            -5
#define FDP_ERR_INJECTION           -6
#define FDP_ERR_TOO_LONG            -7

#define FDP_MAX_NAME 256
#define FDP_IOSIZE   24

typedef struct {
    const unsigned char  *name;
    size_t                name_len;
    const unsigned char  *value;
    size_t                value_len;
} fdp_header_t;

typedef struct {
    int combine_duplicates;        /* 1 = combine, 0 = reject duplicates */
    int allow_underscore;          /* 0 = reject names containing '_' */
    int reject_duplicate_critical; /* 1 = reject duplicate singleton headers */
} fdp_header_opts_t;

typedef struct {
    unsigned char  *base;
    size_t          len;
} fdp_iov_t;

/* Build "HTTP_NAME\0v1, v2\0..." with no trailing comma. On success *out is
 * malloc'd and must be free()d. Returns FDP_OK or a negative FDP_ERR_*. */
int fdp_build_headers(const fdp_header_t *h, size_t n,
                      const fdp_header_opts_t *o,
                      unsigned char **out, size_t *out_len,
                      char *err, size_t err_len);

/* Checked size add. Returns FDP_OK or FDP_ERR_OVERFLOW. */
int fdp_add_size(size_t *a, size_t b);

/* Checked multiply. On overflow *a is left unchanged. */
int fdp_mul_size(size_t *a, size_t b);

/* Write "<payload_len>:" into out. Returns the number of bytes or
 * FDP_ERR_OVERFLOW / FDP_ERR_TOO_LONG. */
int fdp_netstring_prefix(size_t payload_len, char *out, size_t out_len);

/* Validate that a component contains no NUL, CR or LF. */
int fdp_validate_component(const unsigned char *p, size_t n);

/* Both pointers must lie in [start, end], with pos <= last.
 * *len is last - pos. Anything else is FDP_ERR_OVERFLOW. */
int fdp_prefix_span(const unsigned char *start, const unsigned char *pos,
                    const unsigned char *last, const unsigned char *end,
                    size_t *len);

/* iovec helpers. Totals and cursors fail closed instead of wrapping. */
int  fdp_iov_total(const fdp_iov_t *iov, size_t count, size_t *total);
int  fdp_iov_advance(const fdp_iov_t *iov, size_t count,
                     size_t *index, size_t *offset, size_t sent);

/* SCM_RIGHTS retry cursor. include_cmsg is set only while fd_pending is
 * still set and there is data left. A positive advance clears fd_pending
 * so a short write cannot attach the fd twice. */
typedef struct {
    size_t index;
    size_t offset;
    int    fd_pending;
} fdp_send_state_t;

int fdp_send_prepare(const fdp_send_state_t *st,
                     const fdp_iov_t *iov, size_t count,
                     int *include_cmsg, int *done);
int fdp_send_advance(fdp_send_state_t *st,
                     const fdp_iov_t *iov, size_t count,
                     size_t accepted);

#endif /* FD_PASS_CORE_H */
