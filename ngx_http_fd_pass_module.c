/*
 * Copyright (C) Bridge Technologies Co AS
 *
 * Hardened fork: protocol v2 prefix handoff, body rejection, header merging,
 * aligned SCM_RIGHTS, async connect/send with retries, full-kTLS requirement.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_http.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "fd_pass_core.h"

#define NGX_HTTP_FD_PASS_MAX_IOV 6

#define NGX_HTTP_FD_PASS_STATE_INIT      0
#define NGX_HTTP_FD_PASS_STATE_CONNECT   1
#define NGX_HTTP_FD_PASS_STATE_SEND      2
#define NGX_HTTP_FD_PASS_STATE_ATTACHED  3
#define NGX_HTTP_FD_PASS_STATE_FAILED    4

static char *ngx_http_fd_pass_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_fd_pass_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static void *ngx_http_fd_pass_create_loc_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_fd_pass_handler(ngx_http_request_t *r);

typedef struct {
    ngx_addr_t      *socket_addr;
    ngx_flag_t       prefix_forward;
    ngx_flag_t       reject_body;
    ngx_flag_t       combine_headers;
    ngx_flag_t       allow_underscore;
    ngx_flag_t       reject_duplicate_critical;
    ngx_flag_t       require_full_ktls;
    ngx_flag_t       require_upgrade;
    size_t           max_prefix;
    ngx_msec_t       connect_timeout;
    ngx_msec_t       send_timeout;
    ngx_int_t        peer_uid;
    ngx_int_t        peer_gid;
} ngx_http_fd_pass_loc_conf_t;

static ngx_command_t ngx_http_fd_pass_commands[] = {

    { ngx_string("fd_pass"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_fd_pass_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("fd_pass_prefix"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fd_pass_loc_conf_t, prefix_forward),
      NULL },

    { ngx_string("fd_pass_reject_body"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fd_pass_loc_conf_t, reject_body),
      NULL },

    { ngx_string("fd_pass_combine_headers"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fd_pass_loc_conf_t, combine_headers),
      NULL },

    { ngx_string("fd_pass_allow_underscore_headers"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fd_pass_loc_conf_t, allow_underscore),
      NULL },

    { ngx_string("fd_pass_reject_duplicate_critical"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fd_pass_loc_conf_t, reject_duplicate_critical),
      NULL },

    { ngx_string("fd_pass_require_full_ktls"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fd_pass_loc_conf_t, require_full_ktls),
      NULL },

    { ngx_string("fd_pass_require_upgrade"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fd_pass_loc_conf_t, require_upgrade),
      NULL },

    { ngx_string("fd_pass_max_prefix"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fd_pass_loc_conf_t, max_prefix),
      NULL },

    { ngx_string("fd_pass_connect_timeout"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fd_pass_loc_conf_t, connect_timeout),
      NULL },

    { ngx_string("fd_pass_send_timeout"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fd_pass_loc_conf_t, send_timeout),
      NULL },

    { ngx_string("fd_pass_peer_uid"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fd_pass_loc_conf_t, peer_uid),
      NULL },

    { ngx_string("fd_pass_peer_gid"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fd_pass_loc_conf_t, peer_gid),
      NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_fd_pass_module_ctx = {
    NULL,                                /* preconfiguration */
    NULL,                                /* postconfiguration */
    NULL,                                /* create main configuration */
    NULL,                                /* init main configuration */
    NULL,                                /* create server configuration */
    NULL,                                /* merge server configuration */
    ngx_http_fd_pass_create_loc_conf,    /* create location configuration */
    ngx_http_fd_pass_merge_loc_conf      /* merge location configuration */
};

ngx_module_t ngx_http_fd_pass_module = {
    NGX_MODULE_V1,
    &ngx_http_fd_pass_module_ctx,
    ngx_http_fd_pass_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

typedef struct {
    ngx_peer_connection_t  peer;

    ngx_uint_t             state;
    unsigned               async:1;
    unsigned               fd_pending:1;
    unsigned               fd_sent:1;
    unsigned               done:1;

    struct iovec           iov[NGX_HTTP_FD_PASS_MAX_IOV];
    ngx_uint_t             iov_count;
    ngx_uint_t             iov_index;
    size_t                 iov_offset;

    union {
        struct cmsghdr     hdr;
        u_char             buf[CMSG_SPACE(sizeof(int))];
    } control;

    u_char                *lenbuf;
    size_t                 lenbuf_len;
    u_char                *server;
    size_t                 server_len;
    u_char                *headers;
    size_t                 headers_len;
    u_char                 comma;

    u_char                *prefix;
    size_t                 prefix_len;
} ngx_http_fd_pass_ctx_t;

static void ngx_http_fd_pass_connect_handler(ngx_event_t *wev);
static void ngx_http_fd_pass_send_handler(ngx_event_t *wev);
static ngx_int_t ngx_http_fd_pass_start(ngx_http_request_t *r);
static ngx_int_t ngx_http_fd_pass_build(ngx_http_request_t *r,
    ngx_http_fd_pass_ctx_t *ctx);
static ngx_int_t ngx_http_fd_pass_send(ngx_http_request_t *r,
    ngx_http_fd_pass_ctx_t *ctx);
static void ngx_http_fd_pass_attach(ngx_http_request_t *r);
static void ngx_http_fd_pass_cleanup(ngx_http_request_t *r);
static void ngx_http_fd_pass_fail(ngx_http_request_t *r, ngx_int_t status);
static void ngx_http_fd_pass_pool_cleanup(void *data);

static ngx_int_t
ngx_http_fd_pass_send(ngx_http_request_t *r, ngx_http_fd_pass_ctx_t *ctx)
{
    ssize_t        n;
    struct msghdr  msg;
    struct iovec   local[NGX_HTTP_FD_PASS_MAX_IOV];
    fdp_iov_t      view[NGX_HTTP_FD_PASS_MAX_IOV];
    ngx_uint_t     i, j, idx;
    size_t         off;

    if (ctx->iov_count > NGX_HTTP_FD_PASS_MAX_IOV) {
        return NGX_ERROR;
    }

    for (i = 0; i < ctx->iov_count; i++) {
        view[i].base = ctx->iov[i].iov_base;
        view[i].len = ctx->iov[i].iov_len;
    }

    for ( ;; ) {
        fdp_send_state_t  st;
        int               include_cmsg, done, was_pending, rc;

        st.index = ctx->iov_index;
        st.offset = ctx->iov_offset;
        st.fd_pending = ctx->fd_pending ? 1 : 0;

        if (fdp_send_prepare(&st, view, ctx->iov_count,
                             &include_cmsg, &done) != FDP_OK)
        {
            return NGX_ERROR;
        }
        if (done) {
            return NGX_OK;
        }

        j = 0;
        idx = (ngx_uint_t) st.index;
        off = st.offset;

        for (i = 0; idx < ctx->iov_count
                    && i < NGX_HTTP_FD_PASS_MAX_IOV; i++, idx++)
        {
            local[i].iov_base = ctx->iov[idx].iov_base;
            local[i].iov_len = ctx->iov[idx].iov_len;
            if (i == 0 && off) {
                if (off > local[i].iov_len) {
                    return NGX_ERROR;
                }
                local[i].iov_base = (u_char *) local[i].iov_base + off;
                local[i].iov_len -= off;
            }
            j++;
        }

        if (j == 0) {
            return NGX_OK;
        }

        ngx_memzero(&msg, sizeof(msg));
        msg.msg_iov = local;
        msg.msg_iovlen = j;

        if (include_cmsg) {
            msg.msg_control = ctx->control.buf;
            msg.msg_controllen = sizeof(ctx->control.buf);
        }

        n = sendmsg(ctx->peer.connection->fd, &msg, MSG_NOSIGNAL);

        if (n > 0) {
            was_pending = st.fd_pending;
            rc = fdp_send_advance(&st, view, ctx->iov_count, (size_t) n);
            /* The fd rides with the first accepted byte. Remember that
             * even if the cursor then rejects a short count, so a later
             * error does not write an HTTP response onto this socket. */
            if (was_pending && !st.fd_pending) {
                ctx->fd_sent = 1;
            }
            ctx->iov_index = (ngx_uint_t) st.index;
            ctx->iov_offset = st.offset;
            ctx->fd_pending = st.fd_pending ? 1 : 0;
            if (rc != FDP_OK) {
                return NGX_ERROR;
            }
            continue;
        }

        if (n == -1 && ngx_socket_errno == NGX_EINTR) {
            continue;
        }

        if (n == -1
            && (ngx_socket_errno == NGX_EAGAIN
                || ngx_socket_errno == EWOULDBLOCK))
        {
            return NGX_AGAIN;
        }

        if (n == 0) {
            return NGX_AGAIN;
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_socket_errno,
                      "fd_pass: sendmsg failed");
        return NGX_ERROR;
    }
}

static void
ngx_http_fd_pass_arm_send(ngx_http_request_t *r,
    ngx_http_fd_pass_ctx_t *ctx)
{
    ngx_http_fd_pass_loc_conf_t  *flcf;
    ngx_connection_t             *peer = ctx->peer.connection;

    flcf = ngx_http_get_module_loc_conf(r, ngx_http_fd_pass_module);

    peer->data = r;
    peer->write->handler = ngx_http_fd_pass_send_handler;

    if (!peer->write->timer_set) {
        ngx_add_timer(peer->write, flcf->send_timeout);
    }

    if (ngx_handle_write_event(peer->write, 0) != NGX_OK) {
        ngx_http_fd_pass_fail(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
}

static ngx_int_t
ngx_http_fd_pass_start(ngx_http_request_t *r)
{
    ngx_int_t                 rc;
    ngx_http_fd_pass_ctx_t   *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_fd_pass_module);
    if (ctx == NULL || ctx->done) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_fd_pass_build(r, ctx);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_fd_pass_send(r, ctx);
    if (rc == NGX_OK) {
        ngx_http_fd_pass_attach(r);
        ctx->state = NGX_HTTP_FD_PASS_STATE_ATTACHED;
        return NGX_DONE;
    }

    if (rc == NGX_AGAIN) {
        ctx->state = NGX_HTTP_FD_PASS_STATE_SEND;
        ngx_http_fd_pass_arm_send(r, ctx);
        return NGX_AGAIN;
    }

    return NGX_HTTP_BAD_GATEWAY;
}

static void
ngx_http_fd_pass_attach(ngx_http_request_t *r)
{
    r->keepalive = 0;

    if (r->connection->ssl) {
        /* The backend owns the write path. Do not let nginx emit a
         * close_notify or any other byte on the client socket. */
        SSL_set_quiet_shutdown(r->connection->ssl->connection, 1);
    }
}

static void
ngx_http_fd_pass_cleanup(ngx_http_request_t *r)
{
    ngx_http_fd_pass_ctx_t  *ctx;
    ngx_connection_t        *peer;

    ctx = ngx_http_get_module_ctx(r, ngx_http_fd_pass_module);
    if (ctx == NULL) {
        return;
    }

    ngx_http_set_ctx(r, NULL, ngx_http_fd_pass_module);
    ctx->done = 1;

    peer = ctx->peer.connection;
    if (peer == NULL) {
        return;
    }

    ctx->peer.connection = NULL;

    if (peer->write->timer_set) {
        ngx_del_timer(peer->write);
    }
    if (peer->read->timer_set) {
        ngx_del_timer(peer->read);
    }
    if (peer->write->handler == ngx_http_fd_pass_send_handler
        || peer->write->handler == ngx_http_fd_pass_connect_handler)
    {
        peer->write->handler = ngx_http_empty_handler;
    }

    ngx_close_connection(peer);
}

static void
ngx_http_fd_pass_pool_cleanup(void *data)
{
    ngx_http_fd_pass_cleanup((ngx_http_request_t *) data);
}

static void
ngx_http_fd_pass_fail(ngx_http_request_t *r, ngx_int_t status)
{
    ngx_http_fd_pass_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_fd_pass_module);
    if (ctx != NULL && ctx->fd_sent) {
        /* SCM_RIGHTS already left. An error page or close_notify would
         * land on the socket the backend now owns. */
        if (r->connection->ssl != NULL
            && r->connection->ssl->connection != NULL)
        {
            SSL_set_quiet_shutdown(r->connection->ssl->connection, 1);
        }
        r->keepalive = 0;
        ctx->state = NGX_HTTP_FD_PASS_STATE_FAILED;
        ngx_http_fd_pass_cleanup(r);
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    if (ctx != NULL) {
        ctx->state = NGX_HTTP_FD_PASS_STATE_FAILED;
    }

    ngx_http_fd_pass_cleanup(r);
    ngx_http_finalize_request(r, status);
}

static void
ngx_http_fd_pass_connect_handler(ngx_event_t *wev)
{
    int                       err;
    socklen_t                 len;
    ngx_int_t                 rc;
    ngx_connection_t        *peer;
    ngx_http_request_t      *r;
    ngx_http_fd_pass_ctx_t  *ctx;

    peer = wev->data;
    r = peer->data;

    ctx = ngx_http_get_module_ctx(r, ngx_http_fd_pass_module);
    if (ctx == NULL || ctx->done
        || ctx->state != NGX_HTTP_FD_PASS_STATE_CONNECT)
    {
        return;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_ETIMEDOUT,
                      "fd_pass: backend connect timed out");
        ngx_http_fd_pass_fail(r, NGX_HTTP_GATEWAY_TIME_OUT);
        return;
    }

    if (wev->error) {
        ngx_http_fd_pass_fail(r, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    err = 0;
    len = sizeof(err);
    if (getsockopt(peer->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len) != 0
        || err != 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                      "fd_pass: backend connect failed");
        ngx_http_fd_pass_fail(r, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    rc = ngx_http_fd_pass_start(r);

    if (rc == NGX_DONE) {
        ctx->state = NGX_HTTP_FD_PASS_STATE_ATTACHED;
        ngx_http_finalize_request(r, NGX_DONE);

    } else if (rc != NGX_AGAIN) {
        ngx_http_fd_pass_fail(r, rc);
    }
}

static void
ngx_http_fd_pass_send_handler(ngx_event_t *wev)
{
    ngx_int_t                    rc;
    ngx_connection_t            *peer;
    ngx_http_request_t          *r;
    ngx_http_fd_pass_ctx_t      *ctx;
    ngx_http_fd_pass_loc_conf_t *flcf;

    peer = wev->data;
    r = peer->data;

    ctx = ngx_http_get_module_ctx(r, ngx_http_fd_pass_module);
    if (ctx == NULL || ctx->done || ctx->state != NGX_HTTP_FD_PASS_STATE_SEND) {
        return;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_ETIMEDOUT,
                      "fd_pass: backend send timed out");
        ngx_http_fd_pass_fail(r, NGX_HTTP_GATEWAY_TIME_OUT);
        return;
    }

    if (wev->error) {
        ngx_http_fd_pass_fail(r, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    rc = ngx_http_fd_pass_send(r, ctx);

    if (rc == NGX_OK) {
        ngx_http_fd_pass_attach(r);
        ctx->state = NGX_HTTP_FD_PASS_STATE_ATTACHED;
        ngx_http_finalize_request(r, NGX_DONE);
        return;
    }

    if (rc == NGX_AGAIN) {
        flcf = ngx_http_get_module_loc_conf(r, ngx_http_fd_pass_module);
        ngx_add_timer(wev, flcf->send_timeout);
        if (ngx_handle_write_event(wev, 0) != NGX_OK) {
            ngx_http_fd_pass_fail(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
        return;
    }

    ngx_http_fd_pass_fail(r, NGX_HTTP_BAD_GATEWAY);
}

static ngx_int_t
ngx_http_fd_pass_peer_check(ngx_http_request_t *r,
    ngx_http_fd_pass_ctx_t *ctx, ngx_http_fd_pass_loc_conf_t *flcf)
{
#if (NGX_LINUX)
    struct ucred  uc;
    socklen_t     len;

    if (flcf->peer_uid < 0 && flcf->peer_gid < 0) {
        return NGX_OK;
    }

    ngx_memzero(&uc, sizeof(uc));
    len = sizeof(uc);

    if (getsockopt(ctx->peer.connection->fd, SOL_SOCKET, SO_PEERCRED,
                   (void *) &uc, &len) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_socket_errno,
                      "fd_pass: getsockopt(SO_PEERCRED) failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if ((flcf->peer_uid >= 0 && uc.uid != (uid_t) flcf->peer_uid)
        || (flcf->peer_gid >= 0 && uc.gid != (gid_t) flcf->peer_gid))
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "fd_pass: backend peer credentials rejected "
                      "uid=%ui gid=%ui",
                      (ngx_uint_t) uc.uid, (ngx_uint_t) uc.gid);
        return NGX_HTTP_FORBIDDEN;
    }
#else
    (void) ctx;

    if (flcf->peer_uid >= 0 || flcf->peer_gid >= 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "fd_pass: peer credentials are not supported "
                      "on this platform");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
#endif
    return NGX_OK;
}

static ngx_int_t
ngx_http_fd_pass_build(ngx_http_request_t *r, ngx_http_fd_pass_ctx_t *ctx)
{
    u_char                       *p, *end;
    size_t                        server_len, payload, nheaders, i;
    ngx_int_t                     rc;
    ngx_flag_t                    ktls_rx;
    ngx_list_part_t              *part;
    ngx_table_elt_t              *h;
    fdp_header_t                 *ha;
    fdp_header_opts_t             opts;
    unsigned char                *hb;
    size_t                        hlen;
    char                          err[64];
    ngx_http_fd_pass_loc_conf_t  *flcf;

    flcf = ngx_http_get_module_loc_conf(r, ngx_http_fd_pass_module);

    if (ctx->peer.connection == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_fd_pass_peer_check(r, ctx, flcf);
    if (rc != NGX_OK) {
        return rc;
    }

    ktls_rx = 0;

    if (r->connection->ssl) {
        SSL  *ssl = r->connection->ssl->connection;
        BIO  *bio = SSL_get_wbio(ssl);

        if (bio == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "fd_pass: SSL_get_wbio returned NULL");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (BIO_get_ktls_send(bio) != 1) {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                          "fd_pass: enabling kTLS");
            SSL_set_options(ssl, SSL_OP_ENABLE_KTLS);

            if (BIO_get_ktls_send(bio) != 1) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "fd_pass: kTLS could not be enabled");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        ktls_rx = BIO_get_ktls_recv(bio);

        if (ktls_rx != 0 && ktls_rx != 1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "fd_pass: BIO_get_ktls_recv returned %i", ktls_rx);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (ktls_rx != 1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "fd_pass: kTLS RX is not armed (TLS 1.3 full "
                          "handover requires OpenSSL 3.2+); refusing handoff");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (!flcf->require_full_ktls) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "fd_pass: fd_pass_require_full_ktls is off; this "
                          "build still refuses TX-only handoff");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* server variables */
    server_len = 1024;
    if (fdp_add_size(&server_len, r->unparsed_uri.len) != FDP_OK
        || fdp_add_size(&server_len, r->args.len) != FDP_OK)
    {
        return NGX_HTTP_REQUEST_URI_TOO_LARGE;
    }

    ctx->server = ngx_palloc(r->pool, server_len);
    if (ctx->server == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ctx->server;
    end = ctx->server + server_len;

    p = ngx_slprintf(p, end, "CONTENT_LENGTH%Z0%Z");
    p = ngx_slprintf(p, end, "SCGI%Z1+fd_pass%Z");
    p = ngx_slprintf(p, end, "FD_PASS_PROTOCOL%Z2%Z");
    p = ngx_slprintf(p, end, "FD_PASS_PREFIX_LEN%Z%uz%Z", ctx->prefix_len);
    p = ngx_slprintf(p, end, "FD_PASS_BODY_LEN%Z0%Z");

    if (r->connection->ssl) {
        p = ngx_slprintf(p, end, "HTTPS%Zon%Z");
        p = ngx_slprintf(p, end, "KTLS_RX%Z1%Z");
    }

    if (r->connection->addr_text.data) {
        p = ngx_slprintf(p, end, "REMOTE_ADDR%Z%V%Z",
                         &r->connection->addr_text);
        p = ngx_slprintf(p, end, "REMOTE_PORT%Z%ui%Z",
                         ngx_inet_get_port(r->connection->sockaddr));
    }

    p = ngx_slprintf(p, end, "REQUEST_METHOD%Z%V%Z", &r->main->method_name);
    p = ngx_slprintf(p, end, "REQUEST_URI%Z%V%Z", &r->unparsed_uri);

    {
        u_char     addr[NGX_SOCKADDR_STRLEN];
        ngx_str_t  server_addr = { .len = sizeof(addr), .data = addr };

        if (ngx_connection_local_sockaddr(r->connection, &server_addr, 0)
            == NGX_OK)
        {
            p = ngx_slprintf(p, end, "SERVER_ADDR%Z%V%Z", &server_addr);
            p = ngx_slprintf(p, end, "SERVER_PORT%Z%ui%Z",
                             ngx_inet_get_port(r->connection->local_sockaddr));
        }
    }

    p = ngx_slprintf(p, end, "QUERY_STRING%Z%V%Z", &r->args);

    if (p >= end) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "fd_pass: server variable buffer exhausted");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->server_len = p - ctx->server;

    /* headers */
    nheaders = 0;
    for (part = &r->headers_in.headers.part; part; part = part->next) {
        nheaders += part->nelts;
    }

    if (nheaders > (size_t) -1 / sizeof(fdp_header_t)) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ha = ngx_palloc(r->pool, nheaders * sizeof(fdp_header_t) + 1);
    if (ha == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    i = 0;
    for (part = &r->headers_in.headers.part; part; part = part->next) {
        h = part->elts;
        for (ngx_uint_t k = 0; k < part->nelts; k++) {
            ha[i].name = h[k].key.data;
            ha[i].name_len = h[k].key.len;
            ha[i].value = h[k].value.data;
            ha[i].value_len = h[k].value.len;
            i++;
        }
    }

    opts.combine_duplicates = flcf->combine_headers ? 1 : 0;
    opts.allow_underscore = flcf->allow_underscore ? 1 : 0;
    opts.reject_duplicate_critical = flcf->reject_duplicate_critical ? 1 : 0;

    hb = NULL;
    hlen = 0;
    rc = fdp_build_headers(ha, nheaders, &opts, &hb, &hlen, err, sizeof(err));

    if (rc != FDP_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "fd_pass: header build rejected: %s", err);
        switch (rc) {
        case FDP_ERR_HEADER_COLLISION:
        case FDP_ERR_UNDERSCORE:
        case FDP_ERR_DUPLICATE:
        case FDP_ERR_INJECTION:
        case FDP_ERR_TOO_LONG:
            return NGX_HTTP_BAD_REQUEST;
        default:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    ctx->headers = ngx_palloc(r->pool, hlen ? hlen : 1);
    if (ctx->headers == NULL) {
        free(hb);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(ctx->headers, hb, hlen);
    free(hb);
    ctx->headers_len = hlen;

    /* netstring length covers server vars + header pairs, not the comma and
     * not the prefix/body trailer. */
    payload = ctx->server_len;
    if (fdp_add_size(&payload, ctx->headers_len) != FDP_OK) {
        return NGX_HTTP_REQUEST_URI_TOO_LARGE;
    }

    ctx->lenbuf = ngx_palloc(r->pool, FDP_IOSIZE);
    if (ctx->lenbuf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = fdp_netstring_prefix(payload, (char *) ctx->lenbuf, FDP_IOSIZE);
    if (rc < 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ctx->lenbuf_len = (size_t) rc;

    /* iovecs */
    ctx->comma = ',';
    ctx->iov_count = 0;

    ctx->iov[ctx->iov_count].iov_base = ctx->lenbuf;
    ctx->iov[ctx->iov_count].iov_len = ctx->lenbuf_len;
    ctx->iov_count++;

    ctx->iov[ctx->iov_count].iov_base = ctx->server;
    ctx->iov[ctx->iov_count].iov_len = ctx->server_len;
    ctx->iov_count++;

    ctx->iov[ctx->iov_count].iov_base = ctx->headers;
    ctx->iov[ctx->iov_count].iov_len = ctx->headers_len;
    ctx->iov_count++;

    ctx->iov[ctx->iov_count].iov_base = &ctx->comma;
    ctx->iov[ctx->iov_count].iov_len = 1;
    ctx->iov_count++;

    if (ctx->prefix_len) {
        ctx->iov[ctx->iov_count].iov_base = ctx->prefix;
        ctx->iov[ctx->iov_count].iov_len = ctx->prefix_len;
        ctx->iov_count++;
    }

    ctx->iov_index = 0;
    ctx->iov_offset = 0;

    ngx_memzero(&ctx->control, sizeof(ctx->control));
    ctx->control.hdr.cmsg_len = CMSG_LEN(sizeof(int));
    ctx->control.hdr.cmsg_level = SOL_SOCKET;
    ctx->control.hdr.cmsg_type = SCM_RIGHTS;

    {
        int fd = r->connection->fd;
        ngx_memcpy(CMSG_DATA(&ctx->control.hdr), &fd, sizeof(fd));
    }

    ctx->fd_pending = 1;

    return NGX_OK;
}

static ngx_int_t
ngx_http_fd_pass_handler(ngx_http_request_t *r)
{
    ngx_int_t                     rc;
    ngx_connection_t             *c = r->connection;
    ngx_http_fd_pass_ctx_t       *ctx;
    ngx_http_fd_pass_loc_conf_t  *flcf;
    ngx_pool_cleanup_t           *cln;

    if (r != r->main) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "fd_pass: refusing to hand off a subrequest");
        return NGX_HTTP_BAD_REQUEST;
    }

    if (r->http_version != NGX_HTTP_VERSION_11) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "fd_pass: unsupported HTTP protocol %V "
                      "(HTTP/1.1 is required)", &r->http_protocol);
        return NGX_HTTP_VERSION_NOT_SUPPORTED;
    }

    flcf = ngx_http_get_module_loc_conf(r, ngx_http_fd_pass_module);
    if (flcf == NULL || flcf->socket_addr == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "fd_pass: no backend socket configured");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (flcf->require_upgrade && r->headers_in.upgrade == NULL) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "fd_pass: request is not an upgrade");
        return NGX_HTTP_BAD_REQUEST;
    }

    if (flcf->reject_body) {
        if (r->headers_in.content_length_n > 0
            || r->headers_in.chunked
            || r->headers_in.expect)
        {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "fd_pass: refusing a request with a body");
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    if (fdp_validate_component(r->main->method_name.data,
                               r->main->method_name.len) != FDP_OK
        || fdp_validate_component(r->unparsed_uri.data,
                                  r->unparsed_uri.len) != FDP_OK
        || fdp_validate_component(r->args.data, r->args.len) != FDP_OK)
    {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "fd_pass: control byte in request component");
        return NGX_HTTP_BAD_REQUEST;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r->header_in) {
        size_t span = 0;

        if (fdp_prefix_span(r->header_in->start, r->header_in->pos,
                            r->header_in->last, r->header_in->end,
                            &span) != FDP_OK)
        {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "fd_pass: header_in span is outside its buffer");
            return NGX_HTTP_BAD_REQUEST;
        }
        if (span > flcf->max_prefix) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "fd_pass: trailing bytes exceed fd_pass_max_prefix");
            return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
        }
        if (span && !flcf->prefix_forward) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "fd_pass: %uz trailing byte(s) after the request head; "
                          "set fd_pass_prefix on to forward them",
                          span);
            return NGX_HTTP_BAD_REQUEST;
        }
        if (span) {
            ctx->prefix = ngx_palloc(r->pool, span);
            if (ctx->prefix == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            ngx_memcpy(ctx->prefix, r->header_in->pos, span);
            ctx->prefix_len = span;
        }
    }

    ngx_http_set_ctx(r, ctx, ngx_http_fd_pass_module);

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        ngx_http_set_ctx(r, NULL, ngx_http_fd_pass_module);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    cln->handler = ngx_http_fd_pass_pool_cleanup;
    cln->data = r;

    ctx->peer.sockaddr = flcf->socket_addr->sockaddr;
    ctx->peer.socklen = flcf->socket_addr->socklen;
    ctx->peer.name = &flcf->socket_addr->name;
    ctx->peer.log_error = NGX_ERROR_ERR;
    ctx->peer.log = c->log;
    ctx->peer.get = ngx_event_get_peer;
    ctx->peer.data = r;

    rc = ngx_event_connect_peer(&ctx->peer);

    if (rc == NGX_ERROR || rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "fd_pass: failed to connect to backend socket");
        ngx_http_set_ctx(r, NULL, ngx_http_fd_pass_module);
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }

    if (rc == NGX_AGAIN) {
        ctx->state = NGX_HTTP_FD_PASS_STATE_CONNECT;
        ctx->peer.connection->data = r;
        ctx->peer.connection->write->handler = ngx_http_fd_pass_connect_handler;

        ngx_add_timer(ctx->peer.connection->write, flcf->connect_timeout);

        if (ngx_handle_write_event(ctx->peer.connection->write, 0) != NGX_OK) {
            ngx_http_fd_pass_cleanup(r);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ctx->async = 1;
        r->main->count++;
        return NGX_DONE;
    }

    rc = ngx_http_fd_pass_start(r);

    if (rc == NGX_AGAIN) {
        ctx->async = 1;
        r->main->count++;
        return NGX_DONE;
    }

    return rc;
}

static void *
ngx_http_fd_pass_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_fd_pass_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL) {
        return NULL;
    }

    conf->prefix_forward = NGX_CONF_UNSET;
    conf->reject_body = NGX_CONF_UNSET;
    conf->combine_headers = NGX_CONF_UNSET;
    conf->allow_underscore = NGX_CONF_UNSET;
    conf->reject_duplicate_critical = NGX_CONF_UNSET;
    conf->require_full_ktls = NGX_CONF_UNSET;
    conf->require_upgrade = NGX_CONF_UNSET;
    conf->max_prefix = NGX_CONF_UNSET_SIZE;
    conf->connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->send_timeout = NGX_CONF_UNSET_MSEC;
    conf->peer_uid = NGX_CONF_UNSET;
    conf->peer_gid = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_fd_pass_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                    *value = cf->args->elts;
    ngx_http_core_loc_conf_t     *clcf;
    ngx_http_fd_pass_loc_conf_t  *flcf = conf;
    ngx_url_t                     u;

    if (flcf->socket_addr) {
        return "is duplicate";
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    if (clcf->handler && clcf->handler != ngx_http_fd_pass_handler) {
        return "conflicts with an existing content handler in this location";
    }

    ngx_memzero(&u, sizeof(u));
    u.url = value[1];
    u.no_resolve = 1;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        return u.err;
    }

    if (u.family != AF_UNIX || u.naddrs != 1) {
        return "is not a UNIX domain socket";
    }

    flcf->socket_addr = &u.addrs[0];
    clcf->handler = ngx_http_fd_pass_handler;

    return NGX_CONF_OK;
}

static char *
ngx_http_fd_pass_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_core_loc_conf_t     *clcf;
    ngx_http_fd_pass_loc_conf_t  *conf = child;
    ngx_http_fd_pass_loc_conf_t  *prev = parent;

    ngx_conf_merge_ptr_value(conf->socket_addr, prev->socket_addr, NULL);
    ngx_conf_merge_value(conf->prefix_forward, prev->prefix_forward, 0);
    ngx_conf_merge_value(conf->reject_body, prev->reject_body, 1);
    ngx_conf_merge_value(conf->combine_headers, prev->combine_headers, 1);
    ngx_conf_merge_value(conf->allow_underscore, prev->allow_underscore, 0);
    ngx_conf_merge_value(conf->reject_duplicate_critical,
                         prev->reject_duplicate_critical, 1);
    ngx_conf_merge_value(conf->require_full_ktls, prev->require_full_ktls, 1);
    ngx_conf_merge_value(conf->require_upgrade, prev->require_upgrade, 0);
    ngx_conf_merge_size_value(conf->max_prefix, prev->max_prefix,
                              1024 * 1024);
    ngx_conf_merge_msec_value(conf->connect_timeout, prev->connect_timeout,
                              10000);
    ngx_conf_merge_msec_value(conf->send_timeout, prev->send_timeout, 10000);
    ngx_conf_merge_value(conf->peer_uid, prev->peer_uid, -1);
    ngx_conf_merge_value(conf->peer_gid, prev->peer_gid, -1);

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    if (clcf->handler == ngx_http_fd_pass_handler) {
        clcf->lingering_close = NGX_HTTP_LINGERING_OFF;
    }

    return NGX_CONF_OK;
}
