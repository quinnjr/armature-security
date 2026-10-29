# Changelog — `armature-security`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

## [0.6.0] - 2026-10-29

### Changed

- Requires `armature-core` 0.12 (was `0.11`).

## [0.5.0] - 2026-10-17

### Security

- **CORS regex origins are anchored.** `CorsConfig::allow_origin_regex` compiles the pattern as `^(?:pattern)$`; previously it was a substring match, so the documented `https://.*\.example\.com` admitted `https://a.example.com.attacker.net` with credentials. The opaque origin `null` is never allowed by an allowlist or pattern. The doc example now uses a single-label pattern (`https://[a-z0-9-]+\.example\.com`). Re-check existing patterns: one that relied on substring matching (for example no scheme) now needs to match the whole origin.
- **Request signing MACs raw bytes over an unambiguous canonical form** (`ARMATURE-HMAC-SHA256-V1`, length-prefixed method and path, `hex(sha256(body))`, timestamp). Binary bodies are no longer collapsed by lossy UTF-8 conversion and `:` in a field can no longer shift bytes between fields.
- **Request-signing secrets must be at least 32 bytes** (`MIN_SECRET_LEN`); shorter ones are rejected with `SigningError::WeakSecret`.
- **`RequestSigningMiddleware` no longer skips `/health/*` and `/metrics/*` by default**; exemptions are explicit via `skip_path`.
- **Stricter default CSP**: adds `frame-ancestors 'none'`, `base-uri 'none'`, `form-action 'self'`, keeps `object-src 'none'`, drops `'unsafe-inline'` from `style-src` and `https:` from `img-src`.
- **CSP directive names and values are validated**: values containing `;`, `,`, whitespace or control characters (CR/LF) are rejected (`CspError`). A policy that bypasses validation by writing the public `csp` field directly is replaced by `default-src 'none'` rather than emitted.
- **`SecurityMiddleware::apply` no longer overwrites handler-set headers**: each security header is only added when the response does not already carry it under any letter case (previously it overwrote same-case headers and duplicated differently cased ones). `hide_powered_by` removes every spelling of `X-Powered-By`.

### Added

- `csrf` module: `CsrfMiddleware`, `CsrfProtection`, `CsrfConfig`, `CsrfToken` — signed double-submit CSRF protection (HMAC of a random `__Host-` `SameSite=Strict` `HttpOnly` `Secure` cookie nonce, optionally bound to a session/principal via `CsrfConfig::bind_to`), constant-time comparison, safe methods exempt, segment-matched exempt paths, token accepted from the `X-CSRF-Token` header or the `_csrf` form field.
- `SecurityMiddleware` emits `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin` and a restrictive `Permissions-Policy` by default (`new()` and `default()`); configure with `with_coop`, `with_corp`, `with_permissions_policy` (pass `None` to disable). New `cross_origin` and `permissions_policy` modules.
- `CspConfig::frame_ancestors`, `base_uri`, `form_action`, `validate`.
- `RequestSigner`, `RequestVerifier` and `CsrfConfig` implement a redacting `Debug`.

### Changed

- **Breaking:** `RequestSigner::new`, `RequestVerifier::new` and `RequestSigningMiddleware::new` return `Result<_, SigningError>` and take `impl AsRef<[u8]>`. Migration: add `?`/`.unwrap()` and use a ≥32-byte secret.
- **Breaking:** `RequestSigner::sign` and `RequestVerifier::verify` take the body as `&[u8]`, and signatures use the new canonical form. Migration: pass `body.as_bytes()`; clients must re-implement signing per the module docs.
- **Breaking:** `RequestSigningMiddleware` has no default skip paths. Migration: call `.skip_path("/health")` etc. for endpoints that must stay unsigned.
- **Breaking:** `CspConfig::to_header_value` returns `Result<String, CspError>` and `SecurityMiddleware::with_csp` returns `Result<Self, CspError>`. Migration: add `?`/`.unwrap()`.
- **Breaking:** `SecurityMiddleware` gained public fields `cross_origin_opener_policy`, `cross_origin_resource_policy`, `permissions_policy`. Migration: struct literals must set them (or start from `new()`/`default()`).
- CSP directives are emitted in name order (deterministic header).

## [0.4.0] - 2026-09-15

### Changed

- **Breaking:** requires `armature-core` 0.10 (was `0.9`); its types appear in this crate's API, so the requirement change is breaking here and the minor moves. Part of the `armature-core` 0.10 release train.
- Dependencies bumped to their latest releases: `regex` 1.12 → 1.13, `tokio` 1.52 → 1.53.

## [0.3.0] - 2026-08-05

### Changed

- **Requires `armature-core` 0.9 (breaking).** The requirement moved `0.8` →
  `0.9`. `armature-core 0.9.0` itself moves `armature-h1` across a breaking
  0.x boundary; because `armature-core` types appear in this crate's own
  public API, the requirement change is breaking here too and the minor moves
  with it. Under Cargo's 0.x caret rules the 0.8 and 0.9 types are distinct
  and do not unify, so a consumer holding an `armature-core 0.8` type cannot
  pass it to this crate. Part of the `armature-core 0.9.0` release train; see
  `armature-core`'s CHANGELOG for the publish order.

## [0.2.1] - 2026-08-04

### Fixed

- Requirements on sibling armature crates name a minor instead of `0`. Under
  Cargo's 0.x rules `version = "0"` matches any release ever made, and edition
  2024 selects the MSRV-aware resolver, so a consumer declaring an older
  `rust-version` was handed the oldest version satisfying it — resolving
  `armature-core = "0"` on Rust 1.89 produced `armature-core 0.2.3` while an
  explicit `armature-core = "0.8"` elsewhere in the same graph pulled 0.8.2.
  Two copies of core, and a build failing on symbols the older one lacks. Each
  0.x minor in this family is a breaking change, so the requirement now names
  one. No API change.
