# Changelog

## v2.0.0-fdpass-ext (hardening fork)

- Forward `r->header_in` trailing bytes as a protocol-v2 trailer
  (`FD_PASS_PROTOCOL=2`, `FD_PASS_PREFIX_LEN`); reject them with `400` when
  `fd_pass_prefix` is off (default).
- Reject non-empty request bodies (`fd_pass_reject_body on`).
- Combine duplicate headers; reject `-`/`_` collisions and underscore names.
- Align the `SCM_RIGHTS` control buffer and send the fd exactly once across
  short writes.
- Complete `NGX_AGAIN` connects; add connect/send timeouts.
- Require full kTLS for TLS handoff; remove the TX-only path.
- Add `SO_PEERCRED` verification, checked arithmetic, NULL guards, and merge
  fixes.
- Add unit tests, a libFuzzer target, fault-injection shims, and CI.
- Add `MODULE_AUDIT_v2.md` and `THREAT_MODEL.md`.
