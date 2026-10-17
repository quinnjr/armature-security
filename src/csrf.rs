//! Cross-Site Request Forgery (CSRF) protection
//!
//! Implements the *signed double-submit cookie* pattern:
//!
//! 1. A random 256-bit nonce is stored in a `SameSite=Strict`, `HttpOnly`,
//!    `Secure` cookie (`__Host-` prefixed by default, so a sibling subdomain
//!    cannot plant one).
//! 2. The token the page submits is `HMAC-SHA256(secret, nonce ‖ binding)`,
//!    where `binding` is an optional session or principal identifier. The
//!    server renders it into forms (`_csrf` field) or hands it to scripts,
//!    which send it back in the `X-CSRF-Token` header.
//! 3. On every state-changing request (anything but `GET`, `HEAD`, `OPTIONS`,
//!    `TRACE`) the server recomputes the MAC from the cookie and compares it in
//!    constant time with the submitted token.
//!
//! A cross-site attacker can make the browser *send* the cookie but can read
//! neither it nor the page that carries the token, and without the server
//! secret cannot mint a token for a cookie it planted. Binding the token to the
//! session means a token leaked from one session is useless in another.
//!
//! # Usage
//!
//! ```
//! use armature_security::csrf::{CsrfConfig, CsrfMiddleware, CsrfToken};
//!
//! # fn main() -> Result<(), armature_security::csrf::CsrfError> {
//! let csrf = CsrfMiddleware::new(
//!     CsrfConfig::new("0123456789abcdef0123456789abcdef")?
//!         // Machine-to-machine endpoints authenticated by other means.
//!         .exempt_path("/webhooks"),
//! );
//! // Handlers read the token for the current request from the
//! // `CsrfToken` request extension and embed it in their forms:
//! //   <input type="hidden" name="_csrf" value="{token}">
//! # let _ = csrf;
//! # Ok(())
//! # }
//! ```

use armature_core::{Error, HttpRequest, HttpResponse, Middleware};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;

/// Minimum accepted secret length, in bytes.
pub const MIN_SECRET_LEN: usize = 32;

/// Nonce length in bytes (hex-encoded in the cookie).
const NONCE_LEN: usize = 32;

/// Domain-separation tag for the MAC input.
const MAC_CONTEXT: &str = "armature-csrf-v1";

/// CSRF configuration and verification errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CsrfError {
    /// The secret is shorter than [`MIN_SECRET_LEN`] bytes.
    #[error("CSRF secret must be at least {MIN_SECRET_LEN} bytes (got {0})")]
    WeakSecret(usize),

    /// A `__Host-` cookie must be `Secure`.
    #[error("cookie name {0:?} uses the __Host- prefix, which requires Secure")]
    HostPrefixRequiresSecure(String),

    /// The cookie name is not a valid cookie token.
    #[error("invalid CSRF cookie name {0:?}")]
    InvalidCookieName(String),

    /// The CSRF cookie is missing or malformed.
    #[error("missing CSRF cookie")]
    MissingCookie,

    /// No token was submitted in the header or form field.
    #[error("missing CSRF token")]
    MissingToken,

    /// The submitted token does not match the cookie and binding.
    #[error("invalid CSRF token")]
    InvalidToken,
}

/// `SameSite` attribute for the CSRF cookie
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    /// Never sent on cross-site requests (default).
    Strict,
    /// Sent on top-level cross-site navigations (`GET` links).
    Lax,
}

impl SameSite {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Strict => "Strict",
            Self::Lax => "Lax",
        }
    }
}

/// Resolves the session or principal a token is bound to.
pub type BindingResolver = Arc<dyn Fn(&HttpRequest) -> Option<String> + Send + Sync>;

/// CSRF configuration
#[derive(Clone)]
pub struct CsrfConfig {
    secret: Vec<u8>,
    cookie_name: String,
    header_name: String,
    form_field: String,
    same_site: SameSite,
    secure: bool,
    exempt_paths: Vec<String>,
    binding: Option<BindingResolver>,
}

impl std::fmt::Debug for CsrfConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CsrfConfig")
            .field("secret", &"[REDACTED]")
            .field("cookie_name", &self.cookie_name)
            .field("header_name", &self.header_name)
            .field("form_field", &self.form_field)
            .field("same_site", &self.same_site)
            .field("secure", &self.secure)
            .field("exempt_paths", &self.exempt_paths)
            .field("binding", &self.binding.is_some())
            .finish()
    }
}

impl CsrfConfig {
    /// Create a configuration with secure defaults: cookie
    /// `__Host-armature-csrf` (`Secure; HttpOnly; SameSite=Strict; Path=/`),
    /// header `X-CSRF-Token`, form field `_csrf`, no exempt paths, no session
    /// binding.
    ///
    /// # Errors
    ///
    /// [`CsrfError::WeakSecret`] if `secret` is shorter than
    /// [`MIN_SECRET_LEN`] bytes.
    pub fn new(secret: impl AsRef<[u8]>) -> Result<Self, CsrfError> {
        let secret = secret.as_ref();
        if secret.len() < MIN_SECRET_LEN {
            return Err(CsrfError::WeakSecret(secret.len()));
        }
        Ok(Self {
            secret: secret.to_vec(),
            cookie_name: "__Host-armature-csrf".to_string(),
            header_name: "X-CSRF-Token".to_string(),
            form_field: "_csrf".to_string(),
            same_site: SameSite::Strict,
            secure: true,
            exempt_paths: Vec::new(),
            binding: None,
        })
    }

    /// Set the cookie name.
    ///
    /// # Errors
    ///
    /// [`CsrfError::InvalidCookieName`] for a name that is not an RFC 6265
    /// token, [`CsrfError::HostPrefixRequiresSecure`] for a `__Host-` name on a
    /// non-`Secure` configuration.
    pub fn cookie_name(mut self, name: impl Into<String>) -> Result<Self, CsrfError> {
        let name = name.into();
        let valid = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
        if !valid {
            return Err(CsrfError::InvalidCookieName(name));
        }
        self.cookie_name = name;
        self.check_prefix()?;
        Ok(self)
    }

    /// Set the request header carrying the token.
    pub fn header_name(mut self, name: impl Into<String>) -> Self {
        self.header_name = name.into();
        self
    }

    /// Set the form field carrying the token.
    pub fn form_field(mut self, name: impl Into<String>) -> Self {
        self.form_field = name.into();
        self
    }

    /// Set the cookie's `SameSite` attribute.
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = same_site;
        self
    }

    /// Mark the cookie `Secure` (default `true`). Plain-HTTP development needs
    /// `false` *and* a cookie name without the `__Host-` prefix.
    ///
    /// # Errors
    ///
    /// [`CsrfError::HostPrefixRequiresSecure`] when turning `Secure` off while
    /// the cookie name keeps the `__Host-` prefix.
    pub fn secure(mut self, secure: bool) -> Result<Self, CsrfError> {
        self.secure = secure;
        self.check_prefix()?;
        Ok(self)
    }

    /// Exempt a path and everything below it from verification (for example
    /// webhook receivers authenticated by signature). Matching is per whole
    /// segment and a path containing `.`/`..` segments is never exempt.
    pub fn exempt_path(mut self, path: impl Into<String>) -> Self {
        self.exempt_paths.push(path.into());
        self
    }

    /// Bind tokens to a session or principal identifier read from the request
    /// (for example the session id, or the verified user id). A token minted
    /// for one binding does not verify under another.
    pub fn bind_to<F>(mut self, resolver: F) -> Self
    where
        F: Fn(&HttpRequest) -> Option<String> + Send + Sync + 'static,
    {
        self.binding = Some(Arc::new(resolver));
        self
    }

    fn check_prefix(&self) -> Result<(), CsrfError> {
        if self.cookie_name.starts_with("__Host-") && !self.secure {
            return Err(CsrfError::HostPrefixRequiresSecure(
                self.cookie_name.clone(),
            ));
        }
        Ok(())
    }
}

/// The CSRF token for the current request, inserted as a request extension
/// by [`CsrfMiddleware`] so handlers can render it into forms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsrfToken(pub String);

impl CsrfToken {
    /// The token string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stateless CSRF token issuing and verification.
///
/// Use this directly when a component renders its own forms (see
/// [`issue`](Self::issue) and [`verify`](Self::verify)); use
/// [`CsrfMiddleware`] to protect a whole application.
#[derive(Debug, Clone)]
pub struct CsrfProtection {
    config: CsrfConfig,
}

/// Result of [`CsrfProtection::issue`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedToken {
    /// Token to embed in the form or hand to the client script.
    pub token: String,
    /// `Set-Cookie` value to add to the response when the request carried no
    /// usable CSRF cookie (push it onto [`HttpResponse::cookies`]).
    pub set_cookie: Option<String>,
}

impl CsrfProtection {
    /// Create from a configuration.
    pub fn new(config: CsrfConfig) -> Self {
        Self { config }
    }

    /// The configuration.
    pub fn config(&self) -> &CsrfConfig {
        &self.config
    }

    /// The binding for `request` from the configured resolver (empty when
    /// none is configured or it yields nothing).
    pub fn binding_for(&self, request: &HttpRequest) -> String {
        self.config
            .binding
            .as_ref()
            .and_then(|resolve| resolve(request))
            .unwrap_or_default()
    }

    /// Compute the token for a cookie nonce and binding.
    pub fn token_for(&self, nonce: &str, binding: &str) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.config.secret).expect("HMAC accepts any key length");
        // Length-prefixed so nonce/binding boundaries are unambiguous.
        mac.update(
            format!(
                "{MAC_CONTEXT}\n{}:{nonce}\n{}:{binding}",
                nonce.len(),
                binding.len()
            )
            .as_bytes(),
        );
        hex::encode(mac.finalize().into_bytes())
    }

    /// The well-formed CSRF cookie nonce on `request`, if any.
    pub fn cookie_nonce(&self, request: &HttpRequest) -> Option<String> {
        let header = request.headers.get("cookie")?;
        header
            .split(';')
            .filter_map(|pair| pair.trim().split_once('='))
            .find(|(name, _)| *name == self.config.cookie_name)
            .map(|(_, value)| value.trim().to_string())
            .filter(|v| v.len() == NONCE_LEN * 2 && v.bytes().all(|b| b.is_ascii_hexdigit()))
    }

    /// Build the `Set-Cookie` value for `nonce`.
    pub fn set_cookie_value(&self, nonce: &str) -> String {
        let mut cookie = format!(
            "{}={}; Path=/; HttpOnly; SameSite={}",
            self.config.cookie_name,
            nonce,
            self.config.same_site.as_str()
        );
        if self.config.secure {
            cookie.push_str("; Secure");
        }
        cookie
    }

    /// Generate a fresh random nonce.
    pub fn new_nonce() -> String {
        let mut bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut bytes).expect("OS random number generator unavailable");
        hex::encode(bytes)
    }

    /// Issue a token for `request`, bound to `binding`, reusing the request's
    /// CSRF cookie or minting a new one (returned in
    /// [`IssuedToken::set_cookie`]).
    pub fn issue(&self, request: &HttpRequest, binding: &str) -> IssuedToken {
        match self.cookie_nonce(request) {
            Some(nonce) => IssuedToken {
                token: self.token_for(&nonce, binding),
                set_cookie: None,
            },
            None => {
                let nonce = Self::new_nonce();
                IssuedToken {
                    token: self.token_for(&nonce, binding),
                    set_cookie: Some(self.set_cookie_value(&nonce)),
                }
            }
        }
    }

    /// The token the client submitted: the configured header, else the form
    /// field of an `application/x-www-form-urlencoded` body.
    pub fn submitted_token(&self, request: &HttpRequest) -> Option<String> {
        if let Some(token) = request.headers.get(&self.config.header_name) {
            return Some(token.trim().to_string());
        }
        let is_form = request.headers.get("content-type").is_some_and(|ct| {
            ct.split(';').next().is_some_and(|m| {
                m.trim()
                    .eq_ignore_ascii_case("application/x-www-form-urlencoded")
            })
        });
        if !is_form {
            return None;
        }
        url_form_value(request.body_ref(), &self.config.form_field)
    }

    /// Verify a state-changing request against `binding`.
    ///
    /// # Errors
    ///
    /// [`CsrfError::MissingCookie`], [`CsrfError::MissingToken`] or
    /// [`CsrfError::InvalidToken`].
    pub fn verify(&self, request: &HttpRequest, binding: &str) -> Result<(), CsrfError> {
        let nonce = self.cookie_nonce(request).ok_or(CsrfError::MissingCookie)?;
        let submitted = self
            .submitted_token(request)
            .ok_or(CsrfError::MissingToken)?;
        let expected = self.token_for(&nonce, binding);
        if armature_core::crypto::constant_time_eq(submitted.as_bytes(), expected.as_bytes()) {
            Ok(())
        } else {
            Err(CsrfError::InvalidToken)
        }
    }

    /// Whether `path` is exempt from verification.
    pub fn is_exempt(&self, path: &str) -> bool {
        if path.split('/').any(|seg| seg == "." || seg == "..") {
            return false;
        }
        self.config.exempt_paths.iter().any(|p| {
            p == path
                || path
                    .strip_prefix(p.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
        })
    }
}

/// Whether `method` is safe (exempt from CSRF verification).
pub fn is_safe_method(method: &str) -> bool {
    ["GET", "HEAD", "OPTIONS", "TRACE"]
        .iter()
        .any(|m| m.eq_ignore_ascii_case(method))
}

/// Find `field` in an `application/x-www-form-urlencoded` body.
fn url_form_value(body: &[u8], field: &str) -> Option<String> {
    let body = std::str::from_utf8(body).ok()?;
    body.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        (percent_decode(name)? == field).then(|| percent_decode(value))?
    })
}

fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = input.get(i + 1..i + 3)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 2;
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// CSRF protection middleware
///
/// - Safe methods pass through; the request gets a [`CsrfToken`] extension
///   and, if it had no CSRF cookie, the response sets one.
/// - Every other method must carry a token (header or form field) matching
///   the cookie and binding, or the request is rejected with `403`.
/// - Paths registered with [`CsrfConfig::exempt_path`] are not checked.
pub struct CsrfMiddleware {
    protection: CsrfProtection,
}

impl CsrfMiddleware {
    /// Create the middleware.
    pub fn new(config: CsrfConfig) -> Self {
        Self {
            protection: CsrfProtection::new(config),
        }
    }

    /// The underlying token issuer/verifier.
    pub fn protection(&self) -> &CsrfProtection {
        &self.protection
    }
}

#[async_trait::async_trait]
impl Middleware for CsrfMiddleware {
    async fn handle(
        &self,
        mut request: HttpRequest,
        next: armature_core::middleware::Next,
    ) -> Result<HttpResponse, Error> {
        let binding = self.protection.binding_for(&request);

        if !is_safe_method(request.method_str()) && !self.protection.is_exempt(request.path_only())
        {
            self.protection
                .verify(&request, &binding)
                .map_err(|e| Error::Forbidden(format!("CSRF check failed: {e}")))?;
        }

        let issued = self.protection.issue(&request, &binding);
        request.insert_extension(CsrfToken(issued.token));

        let mut response = next(request).await?;
        if let Some(cookie) = issued.set_cookie {
            response.cookies.push(cookie);
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn protection() -> CsrfProtection {
        CsrfProtection::new(CsrfConfig::new(SECRET).unwrap())
    }

    fn with_cookie(method: &str, nonce: &str) -> HttpRequest {
        let mut req = HttpRequest::new(method, "/transfer".to_string());
        req.headers
            .insert("cookie", format!("other=1; __Host-armature-csrf={nonce}"));
        req
    }

    #[test]
    fn weak_secret_rejected() {
        assert!(matches!(
            CsrfConfig::new("short"),
            Err(CsrfError::WeakSecret(5))
        ));
    }

    #[test]
    fn host_prefix_requires_secure() {
        let config = CsrfConfig::new(SECRET).unwrap();
        assert!(config.clone().secure(false).is_err());
        assert!(config.cookie_name("csrf").unwrap().secure(false).is_ok());
    }

    #[test]
    fn cookie_attributes_are_strict() {
        let cookie = protection().set_cookie_value("ab");
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.starts_with("__Host-armature-csrf="));
        assert!(cookie.contains("Path=/"));
    }

    #[test]
    fn header_token_round_trips() {
        let p = protection();
        let nonce = CsrfProtection::new_nonce();
        let mut req = with_cookie("POST", &nonce);
        req.headers.insert("X-CSRF-Token", p.token_for(&nonce, ""));
        assert_eq!(p.verify(&req, ""), Ok(()));
    }

    #[test]
    fn form_token_round_trips() {
        let p = protection();
        let nonce = CsrfProtection::new_nonce();
        let mut req = with_cookie("POST", &nonce);
        req.headers
            .insert("content-type", "application/x-www-form-urlencoded");
        req.body =
            armature_core::Bytes::from(format!("amount=10&_csrf={}", p.token_for(&nonce, "")));
        assert_eq!(p.verify(&req, ""), Ok(()));
    }

    #[test]
    fn missing_or_forged_tokens_fail() {
        let p = protection();
        let nonce = CsrfProtection::new_nonce();

        let req = with_cookie("POST", &nonce);
        assert_eq!(p.verify(&req, ""), Err(CsrfError::MissingToken));

        let mut req = HttpRequest::new("POST", "/transfer".to_string());
        req.headers.insert("X-CSRF-Token", p.token_for(&nonce, ""));
        assert_eq!(p.verify(&req, ""), Err(CsrfError::MissingCookie));

        // Naive double submit (token == cookie) is not accepted: the token
        // must be the server's MAC.
        let mut req = with_cookie("POST", &nonce);
        req.headers.insert("X-CSRF-Token", nonce.clone());
        assert_eq!(p.verify(&req, ""), Err(CsrfError::InvalidToken));
    }

    #[test]
    fn token_is_bound_to_session() {
        let p = protection();
        let nonce = CsrfProtection::new_nonce();
        let mut req = with_cookie("POST", &nonce);
        req.headers
            .insert("X-CSRF-Token", p.token_for(&nonce, "session-a"));
        assert_eq!(p.verify(&req, "session-a"), Ok(()));
        assert_eq!(p.verify(&req, "session-b"), Err(CsrfError::InvalidToken));
    }

    #[test]
    fn token_from_other_secret_fails() {
        let other =
            CsrfProtection::new(CsrfConfig::new("fedcba9876543210fedcba9876543210").unwrap());
        let nonce = CsrfProtection::new_nonce();
        let mut req = with_cookie("POST", &nonce);
        req.headers
            .insert("X-CSRF-Token", other.token_for(&nonce, ""));
        assert_eq!(protection().verify(&req, ""), Err(CsrfError::InvalidToken));
    }

    #[test]
    fn exempt_paths_match_whole_segments() {
        let p = CsrfProtection::new(CsrfConfig::new(SECRET).unwrap().exempt_path("/webhooks"));
        assert!(p.is_exempt("/webhooks"));
        assert!(p.is_exempt("/webhooks/stripe"));
        assert!(!p.is_exempt("/webhooksx"));
        assert!(!p.is_exempt("/webhooks/../admin"));
        assert!(!p.is_exempt("/admin"));
    }

    #[test]
    fn safe_methods() {
        assert!(is_safe_method("GET"));
        assert!(is_safe_method("head"));
        assert!(!is_safe_method("POST"));
        assert!(!is_safe_method("DELETE"));
    }

    #[test]
    fn debug_redacts_secret() {
        let config = CsrfConfig::new(SECRET).unwrap();
        assert!(!format!("{config:?}").contains(SECRET));
    }

    fn ok_next() -> armature_core::middleware::Next {
        Box::new(|req: HttpRequest| {
            Box::pin(async move {
                let token = req
                    .extension::<CsrfToken>()
                    .map(|t| t.0.clone())
                    .unwrap_or_default();
                Ok(HttpResponse::ok().with_body(token.into_bytes()))
            })
        })
    }

    #[tokio::test]
    async fn middleware_issues_cookie_and_token_on_get() {
        let mw = CsrfMiddleware::new(CsrfConfig::new(SECRET).unwrap());
        let req = HttpRequest::new("GET", "/form".to_string());
        let resp = mw.handle(req, ok_next()).await.unwrap();
        assert_eq!(resp.cookies.len(), 1);
        let cookie = &resp.cookies[0];
        let nonce = cookie
            .strip_prefix("__Host-armature-csrf=")
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        assert_eq!(resp.body_string(), mw.protection().token_for(nonce, ""));
    }

    #[tokio::test]
    async fn middleware_rejects_unprotected_post() {
        let mw = CsrfMiddleware::new(CsrfConfig::new(SECRET).unwrap());
        let req = HttpRequest::new("POST", "/transfer".to_string());
        let err = mw.handle(req, ok_next()).await.unwrap_err();
        assert!(matches!(err, Error::Forbidden(_)));
    }

    #[tokio::test]
    async fn middleware_accepts_valid_post_and_exempt_paths() {
        let mw = CsrfMiddleware::new(
            CsrfConfig::new(SECRET)
                .unwrap()
                .exempt_path("/webhooks")
                .bind_to(|req| req.headers.get("x-session").map(str::to_string)),
        );
        let nonce = CsrfProtection::new_nonce();
        let mut req = with_cookie("POST", &nonce);
        req.headers.insert("x-session", "s1");
        req.headers
            .insert("X-CSRF-Token", mw.protection().token_for(&nonce, "s1"));
        assert!(mw.handle(req, ok_next()).await.is_ok());

        let req = HttpRequest::new("POST", "/webhooks/stripe".to_string());
        assert!(mw.handle(req, ok_next()).await.is_ok());
    }
}
