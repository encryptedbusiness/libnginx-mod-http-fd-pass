# MODULE_AUDIT_v2 — hardened fork

Module: `encryptedbusiness/libnginx-mod-http-fd-pass` (fork of
`knneth/libnginx-mod-http-fd-pass@58ec887`).
Baseline audit: `MODULE_AUDIT.md` (v1). This is the re-audit after the hardening
work.

## Verdict

**No critical or high findings remain in the default build.** Every v1 critical
and high finding is fixed or removed; the remaining items are medium/low and
are accepted with rationale below. The protocol-v2 prefix handoff is covered by
unit tests, a live pipelined probe (plaintext and TLS), and fuzzing.

Severity totals after hardening: **0 critical, 0 high, 4 medium (accepted), 3 low
(accepted)**. The TX-only partial-handover path is not built by default and is
not claimed.

## v1 finding disposition

| id | v1 severity | status | evidence |
| --- | --- | --- | --- |
| C1 trailing bytes dropped | critical | **fixed** | `FD_PASS_PREFIX_LEN` + trailer; N3 and TLS pipelined pass |
| H1 body misrepresented | high | **fixed (reject)** | `fd_pass_reject_body on` default; 400; probe `plain-body` |
| H2 header ambiguity/duplicates | high | **fixed** | combine duplicates, reject `-`/`_` collision and underscores; probes `plain-dup`, `plain-underscore`; unit tests |
| H3 TX-only lifetime/UAF | high | **removed** | full kTLS required; TX-only not built by default |
| M1 CMSG alignment | medium | **fixed** | aligned union + `memcpy`; `-Wcast-align`; unit test |
| M2 short sendmsg/EAGAIN | medium | **fixed** | async iov state machine; fd sent once; unit test + short-send probe |
| M3 `NGX_AGAIN` connect | medium | **fixed** | connect handler + timeout |
| M4 negative `BIO_get_ktls_recv` | medium | **fixed** | only 0/1 accepted; `SSL_get_wbio` guarded |
| M5 unchecked cleanup alloc | medium | **fixed** | NULL check |
| M6 relay starvation | medium | **removed** | TX-only removed |
| M7 peer-read truncation | medium | **removed** | TX-only removed |
| M8 no timeouts | medium | **fixed** | `fd_pass_connect_timeout`, `fd_pass_send_timeout` |
| M9 unauthenticated UDS | medium | **mitigated** | `fd_pass_peer_uid/gid` (module) + `-peer-uid/-gid` (receiver); default deployment guidance 0660 |
| M10 TLS close_notify/KeyUpdate | medium | **accepted** | inherent to full handoff; documented in `THREAT_MODEL.md` |
| M11 `if`/merge NULL deref | medium | **fixed** | merge `socket_addr`, guard NULL, reject handler conflict |
| L1 netstring prefix off-by-one | low | **fixed** | `FDP_IOSIZE` 24, checked `snprintf` |
| L2 size overflow | low | **fixed** | `fdp_add_size` checked adds |
| L3 NUL/CR/LF injection | low | **fixed** | component validation + header fuzz invariant |
| L4 duplicate query | low | **accepted** | protocol compatibility; documented |
| L5 non-standard SCGI marker | low | **accepted** | `FD_PASS_PROTOCOL=2` added |
| L6 misleading `ngx_pfree` | low | **fixed** | removed |
| L7 debug log sensitivity | low | **fixed in prototype** | receiver debug is opt-in; production should redact |
| L8 no tests/CI/fuzz | low | **fixed** | `tests/unit`, `tests/fuzz`, CI workflows |
| L9 503 vs 502/504 | low | **accepted** | documented |
| L10 cleanup signature cast | low | **fixed** | `void (*)(void *)` wrapper |
| L11 connection pool ownership | low | **accepted** | close order documented; ASAN run |

## New findings introduced or still present

| id | sev | finding | disposition |
| --- | --- | --- | --- |
| N-A | medium | Async handoff keeps the request alive with `r->main->count++` and finalizes with `NGX_DONE`. This is the standard nginx pattern but is subtle. | Unit + live short-send test; `-DNGX_DEBUG` log check for "request count is zero" |
| N-B | medium | TLS 1.3 `KeyUpdate` and `close_notify` cannot be processed after handoff (no OpenSSL state). | Accepted, documented; require WS Close before FIN |
| N-C | medium | Peer authentication is opt-in; default receiver socket in the prototype is 0666. | Documented; production uses 0660 + `-peer-uid/-gid` |
| N-D | medium | `FD_PASS_PROTOCOL=2` is a wire extension; a stock SCGI backend that ignores it will misparse the trailer if `fd_pass_prefix on`. | Default `fd_pass_prefix off` (reject), so stock backends are safe |
| N-E | low | Body forwarding is intentionally not implemented; bodies are rejected. | Documented; safe default |
| N-F | low | TX-only partial handover (OpenSSL 3.0/3.1, TLS 1.3) is not supported. | Documented; use OpenSSL 3.2+ |
| N-G | low | `fd_pass_require_upgrade` is off by default (generic module). | Documented; enable for WebSocket-only locations |

## What was verified

- Pipelined frame after the request head is delivered on plaintext and TLS
  (`plain-pipelined`, `tls-pipelined`): `frame_received=true`, `echo_valid=true`.
- Duplicate critical header → `400`; underscore/collision → `400`; body → `400`.
- 10,000 TLS connections: `KTLS_RX=1` on all, `getsockopt(SOL_TLS, TLS_TX/RX)=0`
  on all, 0 client errors.
- Unit tests (ASAN/UBSAN) for normalization, merging, collision, injection,
  netstring framing, checked arithmetic, iov advance.
- libFuzzer target for the pure builder with the invariant that output contains
  no CR/LF and the declared framing matches.

## Follow-up pass (hostile lengths)

A later pass aimed at buffer overflows and the CVE shapes below. The
`SIZE_MAX - 7` header length is not reachable through nginx's header buffers.
It is reachable through `fdp_build_headers`, and the unfixed function aborted
under AddressSanitizer: `fdp_validate_component` trusted `value_len` and read
past a one-byte value (`fd_pass_core.c` stack-buffer-overflow). The same length
then wrapped `5 + name_len + 1 + value_len + 1` before `fdp_add_size` saw it,
so `malloc` was undersized for the later `memcpy` (CVE-2013-2028 /
CVE-2026-42945: the copy and the length disagree).

Fixed in `src/fd_pass_core.c`:

- Record size is added one term at a time, including `(count - 1) * sep_len`
  via `fdp_mul_size`. A length that cannot fit is rejected before any value
  byte is read. Each `memcpy` is checked against the allocation.
- `fdp_iov_total` / `fdp_iov_advance` fail on wrap instead of subtracting
  through zero (CVE-2017-7529).
- `fdp_prefix_span` refuses a `header_in` tail whose pointers are not inside
  `[start, end]` (CVE-2026-42946: pointer subtraction across buffers). The
  module copies that tail into the request pool.
- `fdp_send_prepare` / `fdp_send_advance` are what the module's `sendmsg` loop
  calls. A short write attaches `SCM_RIGHTS` on the first accepted byte only.
- After that byte, `fd_sent` makes `ngx_http_fd_pass_fail` finalize with
  `NGX_ERROR` and `SSL_set_quiet_shutdown`. No 502/504 body.
- Subrequests are rejected. `fd_pass_peer_uid` / `fd_pass_peer_gid` fail closed
  where `SO_PEERCRED` does not exist.

CVE map, and what this module does about each:

- **CVE-2013-2028** (chunked stack overflow) and **CVE-2026-42945** (undersized
  buffer, then a copy). Length math is checked before the copy. Bodies,
  `Transfer-Encoding`, and `Expect` still return 400.
- **CVE-2017-7529** (unsigned subtraction underflow) and **CVE-2026-42946**
  (SCGI/uwsgi cross-buffer length). Prefix bytes use `fdp_prefix_span`. iov
  cursors refuse `offset > len`.
- **CVE-2021-23017** (one-byte overwrite). Netstring length stays a checked
  `snprintf` into `FDP_IOSIZE` (24). `SIZE_MAX` fits; a buffer of exactly the
  digit count does not.
- **Request smuggling via leftover bytes.** Still rejected unless
  `fd_pass_prefix on`. The new hole was writing an error page after the fd
  had already been passed. That path is quiet now.
- **`underscores_in_headers` / CGI name confusion.** Unchanged policy, with
  tests for `Host`/`host` and `X-Foo`/`X_foo`.
- **SCM_RIGHTS short write** (a second ancillary message delivers a second
  fd). The tested stepper clears `fd_pending` after the first `n > 0`.
- **CVE-2021-0920** (kernel `SCM_RIGHTS` garbage collection). Not fixable
  here. This module does not `MSG_PEEK` the unix socket.

`make -C tests/unit check` (ASAN/UBSAN) covers the wrap, the duplicate
`SIZE_MAX/2` sum, the iov underflow, the prefix span, and the one-fd retry.
The fuzzer probes `value_len = SIZE_MAX - 7` on every input.

## Residual risk statement

The default build is safe for the measured WebSocket-over-HTTP/1.1 and
WebSocket-over-TLS-1.3-with-full-kTLS paths. It is not a generic SCGI server:
the backend must implement protocol 2 (`FD_PASS_PREFIX_LEN` / trailer) when
`fd_pass_prefix` is enabled. The TLS post-handoff limitations are architectural,
not bugs; protocols that cannot tolerate a missing `close_notify` or KeyUpdate
should not use full FD handoff.
