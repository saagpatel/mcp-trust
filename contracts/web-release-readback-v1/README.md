# WebReleaseReadbackV1

`WebReleaseReadbackV1` is a bounded, read-only verification contract for web
release candidates. It standardizes the generic part of preview and deployed
route readback while leaving deployment authority and product policy with each
consumer.

The reference verifier accepts an explicit origin and route-sentinel manifest,
then emits one JSON receipt on stdout. It supports status, required and
forbidden sentinels, exact UTF-8 bytes, SHA-256 body digests, per-route timeouts,
bounded bodies, and GET or HEAD routes. It rejects mutation methods before any
network request.

The capability boundary is structural:

- no deploy, alias, DNS, promotion, rollback, or provider API exists;
- no credential, custom header, token, environment proxy, or output-file input
  exists;
- non-loopback targets require HTTPS;
- redirects are off by default and can only be enabled within the target
  origin;
- POST, PUT, PATCH, DELETE, CONNECT, and TRACE are always denied.

Consumers must keep domain-specific checks in parallel until their new receipt
proves equivalent coverage. In particular, a status or sentinel match cannot
replace application-specific API validation, badge semantics, public-data
guards, release lineage checks, or an operator decision to alias or promote.

Compatibility is additive within `1.x`: new optional receipt fields or reason
codes may be added, while existing meanings and the safe-method boundary stay
stable. A new network method, credential surface, required manifest field, or
changed assertion meaning requires a new major contract.

Rollback is consumer-local: stop invoking the shared verifier and retain the
consumer's prior release checks. The verifier never owns a deployment to roll
back.
