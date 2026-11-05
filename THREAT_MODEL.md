# Threat model — nginx fd_pass handoff

## Assets

- The client's TLS session (traffic keys live in the kernel after kTLS).
- The client socket file descriptor and its byte stream.
- The backend process and the Unix-domain control socket.
- Headers, cookies and authorization data forwarded as SCGI variables.

## Trust boundaries

1. **Remote client → nginx**: untrusted HTTP/1.1 and TLS. nginx parses and
   validates the request; the module re-validates control bytes and headers.
2. **nginx worker → backend UDS**: nginx is the only intended writer. The socket
   is a capability to inject a client fd and headers, so it must be protected.
3. **Backend → kernel kTLS**: the backend writes plaintext; the kernel encrypts.
4. **Local process in the same namespace**: can connect to the UDS unless the
   socket mode and `SO_PEERCRED` restrict it.

## Adversaries and mitigations

| adversary | capability | mitigation |
| --- | --- | --- |
| remote client | send arbitrary headers, pipelined bytes, bodies, duplicate headers | reject bodies; combine/reject duplicate and `-`/`_`-ambiguous headers; validate control bytes; forward trailing bytes explicitly, never implicitly |
| remote client | coalesce the upgrade and early frames | protocol-v2 prefix trailer; N3 test |
| remote client | stall the handshake / backend | nginx handshake timeout; module connect/send timeouts |
| local process | connect to the fd_pass UDS and inject a fake handoff | `fd_pass_peer_uid/gid`, `SO_PEERCRED`, socket mode 0660 + group |
| compromised backend | already owns the client fd and plaintext | out of scope; the handoff is the capability |
| network attacker | observe/modify TLS | kTLS; TLS 1.3 only in the tested profile |

## Known architectural limitations

- **No TLS `close_notify` after handoff.** nginx closes its copy and the backend
  has no SSL object; the client sees a FIN. Protocols must use an application
  close (WebSocket Close) and treat truncation as a risk.
- **No TLS 1.3 `KeyUpdate` after handoff.** The kernel kTLS path does not have
  the userspace state machine to process a KeyUpdate. Clients that rotate keys
  mid-connection may break.
- **TX-only partial handover** (OpenSSL 3.0/3.1, TLS 1.3) is not built. It
  requires keeping nginx in the read path and was judged too fragile to keep.
- **No HTTP response after SCM_RIGHTS.** Once `sendmsg` has accepted a byte,
  the client fd belongs to the backend. A later backend error closes the
  client socket quietly (`NGX_ERROR`, TLS quiet shutdown). nginx must not
  write a 502/504 body or a `close_notify` onto that socket.

## Operational requirements

- Run `fd_pass_prefix on` only with a protocol-2 backend.
- Keep `fd_pass_reject_body on` unless the backend explicitly implements body
  handling.
- Use `fd_pass_peer_uid/gid` and a 0660 socket owned by a shared group.
- Do not enable `fd_pass_allow_underscore_headers`.
- Build with OpenSSL 3.2+ and `ssl_conf_command Options KTLS`.
