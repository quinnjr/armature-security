//! Request Signing with HMAC
//!
//! Provides HMAC-based request signing and verification for API security.
//!
//! # Features
//!
//! - HMAC-SHA256 request signing over the raw body bytes
//! - Unambiguous canonical form (see below)
//! - Timestamp-based freshness window (see below)
//! - Signature verification middleware
//!
//! # Canonical form
//!
//! The MAC covers the following string, with every variable-length field
//! length-prefixed so no two distinct requests share a canonical form:
//!
//! ```text
//! ARMATURE-HMAC-SHA256-V1\n
//! <len(method)>:<method>\n
//! <len(path)>:<path>\n
//! <hex(sha256(body))>\n
//! <timestamp>
//! ```
//!
//! The body enters as the SHA-256 of its exact bytes, so binary payloads are
//! covered byte-for-byte (no lossy UTF-8 conversion) and a field separator
//! inside the body cannot shift bytes into another field.
//!
//! # Secrets
//!
//! Secrets shorter than [`MIN_SECRET_LEN`] bytes are rejected: a short HMAC
//! key can be brute-forced offline from a single captured signature.
//!
//! # Replay protection
//!
//! The timestamp check bounds how long a captured signature stays useful — it
//! is a *freshness* window, not full replay protection. Without a nonce store
//! an attacker who captures a signed request can replay it verbatim until the
//! window closes. Pair this with an idempotency or nonce store if you need
//! exactly-once semantics.
//!
//! # Usage
//!
//! ```
//! use armature_security::request_signing::*;
//! use std::time::{SystemTime, UNIX_EPOCH};
//!
//! # fn main() -> Result<(), SigningError> {
//! let secret = "0123456789abcdef0123456789abcdef"; // >= 32 bytes
//! let timestamp = SystemTime::now()
//!     .duration_since(UNIX_EPOCH)
//!     .unwrap()
//!     .as_secs();
//!
//! // Generate signature
//! let signer = RequestSigner::new(secret)?;
//! let signature = signer.sign("POST", "/api/users", b"request body", timestamp);
//!
//! // Verify signature
//! let verifier = RequestVerifier::new(secret)?;
//! assert!(verifier.verify("POST", "/api/users", b"request body", timestamp, &signature)?);
//! # Ok(())
//! # }
//! ```

use armature_core::{Error, HttpRequest, HttpResponse, Middleware};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Minimum accepted HMAC secret length, in bytes.
///
/// 32 bytes matches the SHA-256 block-size guidance for HMAC keys and puts an
/// offline brute force of the key out of reach.
pub const MIN_SECRET_LEN: usize = 32;

/// Domain-separation tag that starts every canonical string.
const CANONICAL_VERSION: &str = "ARMATURE-HMAC-SHA256-V1";

/// Request signing errors
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Missing signature header")]
    MissingSignature,

    #[error("Missing timestamp header")]
    MissingTimestamp,

    #[error("Invalid timestamp")]
    InvalidTimestamp,

    #[error("Request expired (replay attack?)")]
    RequestExpired,

    #[error("Timestamp is too far in the future")]
    TimestampInFuture,

    /// The configured secret is shorter than [`MIN_SECRET_LEN`] bytes.
    #[error("Signing secret must be at least {MIN_SECRET_LEN} bytes (got {0})")]
    WeakSecret(usize),
}

/// Tolerance for a client clock running ahead of ours.
///
/// Without an upper bound the freshness window is one-sided: a signature minted
/// with a timestamp years in the future never ages out of it.
const MAX_CLOCK_SKEW_SECONDS: u64 = 60;

/// Validate and copy a secret.
fn checked_secret(secret: impl AsRef<[u8]>) -> Result<Vec<u8>, SigningError> {
    let secret = secret.as_ref();
    if secret.len() < MIN_SECRET_LEN {
        return Err(SigningError::WeakSecret(secret.len()));
    }
    Ok(secret.to_vec())
}

/// Build the canonical string the MAC covers. See the module docs.
fn canonical_message(method: &str, path: &str, body: &[u8], timestamp: u64) -> String {
    let body_hash = hex::encode(Sha256::digest(body));
    format!(
        "{CANONICAL_VERSION}\n{}:{method}\n{}:{path}\n{body_hash}\n{timestamp}",
        method.len(),
        path.len(),
    )
}

/// Request signer
///
/// Generates HMAC-SHA256 signatures for requests.
#[derive(Clone)]
pub struct RequestSigner {
    secret: Vec<u8>,
}

impl std::fmt::Debug for RequestSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestSigner")
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl RequestSigner {
    /// Create a new request signer
    ///
    /// # Errors
    ///
    /// [`SigningError::WeakSecret`] if `secret` is shorter than
    /// [`MIN_SECRET_LEN`] bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use armature_security::request_signing::RequestSigner;
    ///
    /// let signer = RequestSigner::new("0123456789abcdef0123456789abcdef").unwrap();
    /// assert!(RequestSigner::new("short").is_err());
    /// ```
    pub fn new(secret: impl AsRef<[u8]>) -> Result<Self, SigningError> {
        Ok(Self {
            secret: checked_secret(secret)?,
        })
    }

    /// Sign a request
    ///
    /// # Arguments
    ///
    /// * `method` - HTTP method
    /// * `path` - Request target (path and query string)
    /// * `body` - Exact request body bytes
    /// * `timestamp` - Unix timestamp
    ///
    /// # Examples
    ///
    /// ```
    /// use armature_security::request_signing::RequestSigner;
    ///
    /// let signer = RequestSigner::new("0123456789abcdef0123456789abcdef").unwrap();
    /// let signature = signer.sign("POST", "/api/users", b"request body", 1702468800);
    /// assert_eq!(signature.len(), 64);
    /// ```
    pub fn sign(&self, method: &str, path: &str, body: &[u8], timestamp: u64) -> String {
        let message = canonical_message(method, path, body, timestamp);
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts any key length");
        mac.update(message.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}

/// Request verifier
///
/// Verifies HMAC-SHA256 signatures on incoming requests.
pub struct RequestVerifier {
    signer: RequestSigner,
    max_age_seconds: u64,
}

impl std::fmt::Debug for RequestVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestVerifier")
            .field("secret", &"[REDACTED]")
            .field("max_age_seconds", &self.max_age_seconds)
            .finish()
    }
}

impl RequestVerifier {
    /// Create a new request verifier
    ///
    /// # Arguments
    ///
    /// * `secret` - Shared secret for HMAC, at least [`MIN_SECRET_LEN`] bytes
    ///
    /// # Errors
    ///
    /// [`SigningError::WeakSecret`] if the secret is too short.
    ///
    /// # Examples
    ///
    /// ```
    /// use armature_security::request_signing::RequestVerifier;
    ///
    /// let verifier = RequestVerifier::new("0123456789abcdef0123456789abcdef").unwrap();
    /// ```
    pub fn new(secret: impl AsRef<[u8]>) -> Result<Self, SigningError> {
        Ok(Self {
            signer: RequestSigner::new(secret)?,
            max_age_seconds: 300, // 5 minutes default
        })
    }

    /// Set maximum age for requests (replay protection)
    ///
    /// # Examples
    ///
    /// ```
    /// use armature_security::request_signing::RequestVerifier;
    ///
    /// let verifier = RequestVerifier::new("0123456789abcdef0123456789abcdef")
    ///     .unwrap()
    ///     .with_max_age(600); // 10 minutes
    /// ```
    pub fn with_max_age(mut self, seconds: u64) -> Self {
        self.max_age_seconds = seconds;
        self
    }

    /// Verify a signed request
    ///
    /// # Arguments
    ///
    /// * `method` - HTTP method
    /// * `path` - Request target (path and query string)
    /// * `body` - Exact request body bytes
    /// * `timestamp` - Unix timestamp from request
    /// * `signature` - HMAC signature from request
    ///
    /// # Examples
    ///
    /// ```
    /// use armature_security::request_signing::RequestVerifier;
    ///
    /// # fn example() -> Result<(), armature_security::request_signing::SigningError> {
    /// let verifier = RequestVerifier::new("0123456789abcdef0123456789abcdef")?;
    /// let is_valid = verifier.verify(
    ///     "POST",
    ///     "/api/users",
    ///     b"request body",
    ///     1702468800,
    ///     "expected-signature"
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn verify(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        timestamp: u64,
        signature: &str,
    ) -> Result<bool, SigningError> {
        // Bound the timestamp on both sides: too old is a stale replay, too far
        // ahead is a signature minted to outlive the window entirely.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SigningError::InvalidTimestamp)?
            .as_secs();

        if timestamp > now.saturating_add(MAX_CLOCK_SKEW_SECONDS) {
            return Err(SigningError::TimestampInFuture);
        }

        let age = now.saturating_sub(timestamp);
        if age > self.max_age_seconds {
            return Err(SigningError::RequestExpired);
        }

        let expected = self.signer.sign(method, path, body, timestamp);

        // Constant-time comparison
        Ok(armature_core::crypto::constant_time_eq(
            signature.as_bytes(),
            expected.as_bytes(),
        ))
    }

    /// Verify request from HttpRequest
    pub fn verify_request(&self, request: &HttpRequest) -> Result<bool, SigningError> {
        let signature = request
            .headers
            .get("X-Signature")
            .ok_or(SigningError::MissingSignature)?;

        let timestamp_str = request
            .headers
            .get("X-Timestamp")
            .ok_or(SigningError::MissingTimestamp)?;

        let timestamp: u64 = timestamp_str
            .parse()
            .map_err(|_| SigningError::InvalidTimestamp)?;

        // `body_ref()` is the zero-copy view of the request's `Bytes` body; the
        // signature must cover exactly the bytes the handler will see.
        //
        // Sign over the raw target (query string included) so query parameters
        // are covered by the signature.
        self.verify(
            request.method_str(),
            &request.path,
            request.body_ref(),
            timestamp,
            signature,
        )
    }
}

/// Request signing middleware
///
/// Automatically verifies HMAC signatures on incoming requests. Every path is
/// verified unless it is explicitly exempted with
/// [`skip_path`](Self::skip_path); nothing is skipped by default.
pub struct RequestSigningMiddleware {
    verifier: RequestVerifier,
    skip_paths: Vec<String>,
}

impl RequestSigningMiddleware {
    /// Create new request signing middleware
    ///
    /// # Errors
    ///
    /// [`SigningError::WeakSecret`] if the secret is shorter than
    /// [`MIN_SECRET_LEN`] bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use armature_security::request_signing::RequestSigningMiddleware;
    ///
    /// let middleware = RequestSigningMiddleware::new("0123456789abcdef0123456789abcdef")
    ///     .unwrap()
    ///     // Opt specific, side-effect-free endpoints out of verification.
    ///     .skip_path("/health");
    /// ```
    pub fn new(secret: impl AsRef<[u8]>) -> Result<Self, SigningError> {
        Ok(Self {
            verifier: RequestVerifier::new(secret)?,
            skip_paths: Vec::new(),
        })
    }

    /// Set maximum age for signed requests
    pub fn with_max_age(mut self, seconds: u64) -> Self {
        self.verifier = self.verifier.with_max_age(seconds);
        self
    }

    /// Exempt a path, and every path below it, from signature verification.
    ///
    /// The exemption covers `path` itself and anything under `path/`, so only
    /// exempt subtrees whose every route is safe to serve unsigned.
    pub fn skip_path(mut self, path: impl Into<String>) -> Self {
        self.skip_paths.push(path.into());
        self
    }

    /// Check if path should be skipped
    ///
    /// Matched on whole segments of the routing path. A `starts_with` test over
    /// the raw target would make `/healthcheck-admin`, `/health../admin` and
    /// `/metrics/../v1/transfer` all skip signature verification, so a prefix
    /// only counts when the next character is a separator, and any path
    /// carrying a dot segment is verified rather than skipped.
    fn should_skip(&self, path: &str) -> bool {
        if path.split('/').any(|seg| seg == "." || seg == "..") {
            return false;
        }

        self.skip_paths.iter().any(|p| {
            p == path
                || path
                    .strip_prefix(p.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
        })
    }
}

#[async_trait::async_trait]
impl Middleware for RequestSigningMiddleware {
    async fn handle(
        &self,
        request: HttpRequest,
        next: armature_core::middleware::Next,
    ) -> Result<HttpResponse, Error> {
        // Skip explicitly exempted paths. Decided on the routing path, never
        // the raw target: a query string must not be able to steer the skip
        // decision.
        if !self.should_skip(request.path_only()) {
            // Verify signature
            match self.verifier.verify_request(&request) {
                Ok(true) => {
                    // Signature valid, proceed
                }
                Ok(false) => {
                    return Err(Error::Unauthorized("Invalid signature".to_string()));
                }
                Err(SigningError::RequestExpired) => {
                    return Err(Error::BadRequest("Request expired".to_string()));
                }
                Err(SigningError::TimestampInFuture) => {
                    return Err(Error::BadRequest(
                        "Request timestamp is in the future".to_string(),
                    ));
                }
                Err(SigningError::MissingSignature) => {
                    return Err(Error::BadRequest("Missing X-Signature header".to_string()));
                }
                Err(SigningError::MissingTimestamp) => {
                    return Err(Error::BadRequest("Missing X-Timestamp header".to_string()));
                }
                Err(e) => {
                    return Err(Error::BadRequest(format!(
                        "Signature verification failed: {}",
                        e
                    )));
                }
            }
        }

        next(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn test_sign_request() {
        let signer = RequestSigner::new(SECRET).unwrap();
        let sig = signer.sign("POST", "/api/users", b"body", 1702468800);
        assert!(!sig.is_empty());
        assert_eq!(sig.len(), 64); // SHA256 hex = 64 chars
    }

    #[test]
    fn test_verify_request() {
        let signer = RequestSigner::new(SECRET).unwrap();
        let verifier = RequestVerifier::new(SECRET).unwrap();

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let signature = signer.sign("POST", "/api/test", b"test body", timestamp);

        assert!(
            verifier
                .verify("POST", "/api/test", b"test body", timestamp, &signature)
                .unwrap()
        );
    }

    #[test]
    fn test_verify_wrong_signature() {
        let verifier = RequestVerifier::new(SECRET).unwrap();

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let result = verifier.verify(
            "POST",
            "/api/test",
            b"test body",
            timestamp,
            "wrong-signature",
        );

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_expired_request() {
        let verifier = RequestVerifier::new(SECRET).unwrap().with_max_age(10);

        // Timestamp from 1 hour ago
        let old_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3600;

        let result = verifier.verify("POST", "/api/test", b"body", old_timestamp, "signature");

        assert!(matches!(result, Err(SigningError::RequestExpired)));
    }

    #[test]
    fn test_verify_future_timestamp_rejected() {
        let verifier = RequestVerifier::new(SECRET).unwrap().with_max_age(10);

        // A far-future timestamp used to be clamped to age 0 by the saturating
        // subtraction, making the signature valid forever.
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 315_360_000; // ~10 years

        let result = verifier.verify("POST", "/api/test", b"body", future, "signature");

        assert!(matches!(result, Err(SigningError::TimestampInFuture)));
    }

    #[test]
    fn test_small_clock_skew_is_tolerated() {
        let signer = RequestSigner::new(SECRET).unwrap();
        let verifier = RequestVerifier::new(SECRET).unwrap();

        let slightly_ahead = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 5;
        let signature = signer.sign("POST", "/api/test", b"body", slightly_ahead);

        assert!(
            verifier
                .verify("POST", "/api/test", b"body", slightly_ahead, &signature)
                .unwrap()
        );
    }

    #[test]
    fn nothing_is_skipped_by_default() {
        // `/health/*` and `/metrics/*` used to be exempt out of the box, so any
        // route mounted under them (say `/metrics/admin/reset`) was reachable
        // unsigned without the operator ever opting in.
        let middleware = RequestSigningMiddleware::new(SECRET).unwrap();

        assert!(!middleware.should_skip("/health"));
        assert!(!middleware.should_skip("/health/live"));
        assert!(!middleware.should_skip("/metrics"));
        assert!(!middleware.should_skip("/metrics/admin/reset"));
    }

    #[test]
    fn test_should_skip_matches_whole_segments_only() {
        let middleware = RequestSigningMiddleware::new(SECRET)
            .unwrap()
            .skip_path("/health")
            .skip_path("/metrics");

        assert!(middleware.should_skip("/health"));
        assert!(middleware.should_skip("/health/live"));
        assert!(middleware.should_skip("/metrics"));

        // Bypass attempts: prefix-but-not-segment, and traversal.
        assert!(!middleware.should_skip("/healthcheck-admin"));
        assert!(!middleware.should_skip("/healthz"));
        assert!(!middleware.should_skip("/health../admin"));
        assert!(!middleware.should_skip("/metrics/../v1/transfer"));
        assert!(!middleware.should_skip("/metrics/./../admin"));
        assert!(!middleware.should_skip("/api/health"));
    }

    #[test]
    fn short_secrets_are_rejected() {
        assert!(matches!(
            RequestSigner::new(""),
            Err(SigningError::WeakSecret(0))
        ));
        assert!(matches!(
            RequestVerifier::new("secret"),
            Err(SigningError::WeakSecret(6))
        ));
        assert!(RequestSigningMiddleware::new(&SECRET[..31]).is_err());
        assert!(RequestSigner::new(SECRET).is_ok());
    }

    #[test]
    fn binary_bodies_are_not_malleable() {
        // Two different invalid-UTF-8 bodies used to collapse to the same
        // U+FFFD replacement string, so a signature over one verified the
        // other.
        let signer = RequestSigner::new(SECRET).unwrap();
        let a = signer.sign("POST", "/upload", &[0xff, 0x00], 1_700_000_000);
        let b = signer.sign("POST", "/upload", &[0xfe, 0x00], 1_700_000_000);
        assert_ne!(a, b);
        assert_eq!(
            String::from_utf8_lossy(&[0xff, 0x00]),
            String::from_utf8_lossy(&[0xfe, 0x00])
        );
    }

    #[test]
    fn field_boundaries_are_unambiguous() {
        // With `method:path:body:ts` these two produced the same MAC input
        // ("POST:/a:b:c:1").
        let signer = RequestSigner::new(SECRET).unwrap();
        assert_ne!(
            signer.sign("POST", "/a:b", b"c", 1),
            signer.sign("POST", "/a", b"b:c", 1)
        );
        assert_ne!(
            signer.sign("POST", "/a\nb", b"", 1),
            signer.sign("POST\n/a", "b", b"", 1)
        );
    }

    #[test]
    fn debug_redacts_secret() {
        let signer = RequestSigner::new(SECRET).unwrap();
        let verifier = RequestVerifier::new(SECRET).unwrap();
        assert!(!format!("{signer:?}").contains(SECRET));
        assert!(!format!("{verifier:?}").contains(SECRET));
    }

    #[test]
    fn test_verify_request_with_zero_copy_body() {
        // Regression test: the production HTTP server stores incoming bodies
        // via `HttpRequest::set_body_bytes` (zero-copy). `verify_request` must
        // sign over that payload, otherwise every real signed request fails
        // verification.
        let signer = RequestSigner::new(SECRET).unwrap();
        let verifier = RequestVerifier::new(SECRET).unwrap();

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = "{\"test\":\"data\"}";
        let signature = signer.sign("POST", "/api/secure", body.as_bytes(), timestamp);

        let mut request = HttpRequest::new("POST", "/api/secure".to_string());
        request.headers.insert("X-Signature", signature);
        request.headers.insert("X-Timestamp", timestamp.to_string());
        // Simulate the real server path: the body arrives as zero-copy Bytes.
        request.set_body_bytes(bytes::Bytes::from_static(body.as_bytes()));
        assert_eq!(request.body_slice(), body.as_bytes());

        assert!(verifier.verify_request(&request).unwrap());
    }

    #[test]
    fn sign_is_real_hmac_sha256() {
        // Reference value computed independently via Python's hmac module:
        // body = hashlib.sha256(b"test body").hexdigest()
        // msg = f"ARMATURE-HMAC-SHA256-V1\n4:POST\n9:/api/test\n{body}\n1700000000"
        // hmac.new(SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()
        let signer = RequestSigner::new(SECRET).unwrap();
        let sig = signer.sign("POST", "/api/test", b"test body", 1700000000);
        assert_eq!(
            sig,
            "ddf697d537b760042522c60cde5901d7709797ad3fd9e9a4afc6280f8ecde5e7"
        );
    }

    #[test]
    fn test_constant_time_eq() {
        use armature_core::crypto::constant_time_eq;
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
