//! Security middleware for Armature - inspired by Helmet for Express.js
//!
//! This module provides a comprehensive set of security headers and protections
//! to help secure your Armature applications against common web vulnerabilities.
//!
//! ## Features
//!
//! - 🛡️ **Content Security Policy** - Prevent XSS attacks
//! - 🔒 **HSTS** - Force HTTPS connections
//! - 🚫 **Frame Guard** - Prevent clickjacking
//! - 🎭 **XSS Filter** - Browser XSS protection
//! - 📝 **Content Type Options** - Prevent MIME sniffing
//! - 🌐 **Referrer Policy** - Control referrer information
//! - 🔐 **11 Security Headers** - Comprehensive protection
//!
//! ## Quick Start - Default Security
//!
//! ```
//! use armature_security::SecurityMiddleware;
//!
//! // Use default security settings (recommended for most apps)
//! let security = SecurityMiddleware::default();
//!
//! // Apply to a response
//! let mut response = armature_core::HttpResponse::ok();
//! let response = security.apply(response);
//!
//! // Now response has all default security headers
//! assert!(response.headers.contains_key("X-Frame-Options"));
//! assert!(response.headers.contains_key("X-Content-Type-Options"));
//! ```
//!
//! ## Custom Configuration
//!
//! ```
//! use armature_security::SecurityMiddleware;
//! use armature_security::hsts::HstsConfig;
//! use armature_security::frame_guard::FrameGuard;
//! use armature_security::referrer_policy::ReferrerPolicy;
//!
//! let security = SecurityMiddleware::new()
//!     .with_hsts(HstsConfig::new(31536000).include_subdomains(true))
//!     .with_frame_guard(FrameGuard::Deny)
//!     .with_referrer_policy(ReferrerPolicy::StrictOrigin)
//!     .hide_powered_by(true);
//!
//! let response = security.apply(armature_core::HttpResponse::ok());
//! assert_eq!(response.headers.get("X-Frame-Options"), Some(&"DENY".to_string()));
//! ```
//!
//! ## Content Security Policy
//!
//! ```
//! use armature_security::SecurityMiddleware;
//! use armature_security::content_security_policy::CspConfig;
//!
//! let csp = CspConfig::new()
//!     .default_src(vec!["'self'".to_string()])
//!     .script_src(vec!["'self'".to_string(), "'unsafe-inline'".to_string()])
//!     .style_src(vec!["'self'".to_string(), "https://fonts.googleapis.com".to_string()]);
//!
//! // Directive values are validated: `;`, `,`, whitespace and CR/LF are rejected.
//! let security = SecurityMiddleware::new().with_csp(csp).unwrap();
//! let response = security.apply(armature_core::HttpResponse::ok());
//!
//! assert!(response.headers.contains_key("Content-Security-Policy"));
//! ```
//!
//! ## Handler-set headers win
//!
//! [`SecurityMiddleware::apply`] only fills in a security header the response
//! does not already carry (compared case-insensitively), so a handler that sets
//! its own, stricter or route-specific, policy keeps it.
//!
//! ```
//! use armature_security::SecurityMiddleware;
//!
//! let mut response = armature_core::HttpResponse::ok();
//! response
//!     .headers
//!     .insert("x-frame-options".to_string(), "SAMEORIGIN".to_string());
//! let response = SecurityMiddleware::default().apply(response);
//!
//! assert_eq!(response.headers.get("x-frame-options"), Some(&"SAMEORIGIN".to_string()));
//! assert!(!response.headers.contains_key("X-Frame-Options"));
//! ```
//!
//! ## HSTS (HTTP Strict Transport Security)
//!
//! ```
//! use armature_security::SecurityMiddleware;
//! use armature_security::hsts::HstsConfig;
//!
//! // HSTS for 1 year with subdomains
//! let hsts = HstsConfig::new(31536000)
//!     .include_subdomains(true)
//!     .preload(true);
//!
//! let security = SecurityMiddleware::new().with_hsts(hsts);
//! let response = security.apply(armature_core::HttpResponse::ok());
//!
//! let hsts_header = response.headers.get("Strict-Transport-Security").unwrap();
//! assert!(hsts_header.contains("max-age=31536000"));
//! assert!(hsts_header.contains("includeSubDomains"));
//! ```
//!
//! ## Frame Guard (Clickjacking Protection)
//!
//! ```
//! use armature_security::SecurityMiddleware;
//! use armature_security::frame_guard::FrameGuard;
//!
//! // Deny all framing
//! let security = SecurityMiddleware::new()
//!     .with_frame_guard(FrameGuard::Deny);
//!
//! let response = security.apply(armature_core::HttpResponse::ok());
//! assert_eq!(response.headers.get("X-Frame-Options"), Some(&"DENY".to_string()));
//!
//! // Allow framing from same origin
//! let security = SecurityMiddleware::new()
//!     .with_frame_guard(FrameGuard::SameOrigin);
//!
//! let response = security.apply(armature_core::HttpResponse::ok());
//! assert_eq!(response.headers.get("X-Frame-Options"), Some(&"SAMEORIGIN".to_string()));
//! ```

pub mod content_security_policy;
pub mod content_type_options;
pub mod cors;
pub mod cross_origin;
pub mod csrf;
pub mod dns_prefetch_control;
pub mod download_options;
pub mod expect_ct;
pub mod frame_guard;
pub mod hsts;
pub mod permissions_policy;
pub mod permitted_cross_domain_policies;
pub mod powered_by;
pub mod referrer_policy;
pub mod request_signing;
pub mod xss_filter;

use armature_core::HttpResponse;

/// Main security middleware that combines all security features
#[derive(Debug, Clone)]
pub struct SecurityMiddleware {
    /// Content Security Policy configuration
    pub csp: Option<content_security_policy::CspConfig>,

    /// DNS Prefetch Control
    pub dns_prefetch_control: dns_prefetch_control::DnsPrefetchControl,

    /// Expect-CT configuration
    #[allow(deprecated)]
    pub expect_ct: Option<expect_ct::ExpectCtConfig>,

    /// Frame Guard (X-Frame-Options)
    pub frame_guard: frame_guard::FrameGuard,

    /// HSTS (Strict-Transport-Security)
    pub hsts: Option<hsts::HstsConfig>,

    /// Hide X-Powered-By header
    pub hide_powered_by: bool,

    /// Referrer Policy
    pub referrer_policy: referrer_policy::ReferrerPolicy,

    /// X-XSS-Protection
    pub xss_filter: xss_filter::XssFilter,

    /// X-Content-Type-Options
    pub content_type_options: content_type_options::ContentTypeOptions,

    /// X-Download-Options
    pub download_options: download_options::DownloadOptions,

    /// X-Permitted-Cross-Domain-Policies
    pub permitted_cross_domain_policies:
        permitted_cross_domain_policies::PermittedCrossDomainPolicies,

    /// Cross-Origin-Opener-Policy (`None` = not sent)
    pub cross_origin_opener_policy: Option<cross_origin::CrossOriginOpenerPolicy>,

    /// Cross-Origin-Resource-Policy (`None` = not sent)
    pub cross_origin_resource_policy: Option<cross_origin::CrossOriginResourcePolicy>,

    /// Permissions-Policy (`None` = not sent)
    pub permissions_policy: Option<permissions_policy::PermissionsPolicy>,
}

/// Header value sent when a [`content_security_policy::CspConfig`] that fails
/// validation reaches [`SecurityMiddleware::apply`] (only possible by writing
/// the public `csp` field directly): block everything rather than emit an
/// injectable policy or none at all.
const FAIL_CLOSED_CSP: &str = "default-src 'none'; frame-ancestors 'none'";

/// Insert `name: value` unless the response already has `name` under any
/// letter case.
fn set_if_absent(response: &mut HttpResponse, name: &str, value: String) {
    let present = response
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case(name));
    if !present {
        response.headers.insert(name.to_string(), value);
    }
}

/// Remove every spelling of `name` from the response headers.
fn remove_all_cases(response: &mut HttpResponse, name: &str) {
    let keys: Vec<String> = response
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(k, _)| k.clone())
        .collect();
    for key in keys {
        response.headers.remove(&key);
    }
}

impl SecurityMiddleware {
    /// Create a new security middleware with the always-safe headers enabled
    ///
    /// `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
    /// `X-Content-Type-Options: nosniff`, `X-Download-Options: noopen`,
    /// `X-Permitted-Cross-Domain-Policies: none`,
    /// `Cross-Origin-Opener-Policy: same-origin`,
    /// `Cross-Origin-Resource-Policy: same-origin` and a restrictive
    /// `Permissions-Policy` are on. Relax COOP/CORP with
    /// [`with_coop`](Self::with_coop) / [`with_corp`](Self::with_corp) if the
    /// application relies on cross-origin popups or serves embeddable assets.
    /// The headers that need per-deployment tuning — CSP, HSTS and Expect-CT —
    /// are off until configured, as is the legacy XSS auditor.
    pub fn new() -> Self {
        Self {
            csp: None,
            dns_prefetch_control: dns_prefetch_control::DnsPrefetchControl::Off,
            expect_ct: None,
            frame_guard: frame_guard::FrameGuard::Deny,
            hsts: None,
            hide_powered_by: false,
            referrer_policy: referrer_policy::ReferrerPolicy::NoReferrer,
            // Modern browsers have removed the legacy XSS auditor (it could itself introduce
            // vulnerabilities), so it is disabled by default in line with Helmet's current
            // recommendation. Prefer a strong Content-Security-Policy instead.
            xss_filter: xss_filter::XssFilter::Disabled,
            content_type_options: content_type_options::ContentTypeOptions::NoSniff,
            download_options: download_options::DownloadOptions::NoOpen,
            permitted_cross_domain_policies:
                permitted_cross_domain_policies::PermittedCrossDomainPolicies::None,
            cross_origin_opener_policy: Some(cross_origin::CrossOriginOpenerPolicy::SameOrigin),
            cross_origin_resource_policy: Some(cross_origin::CrossOriginResourcePolicy::SameOrigin),
            permissions_policy: Some(permissions_policy::PermissionsPolicy::restrictive()),
        }
    }

    /// Enable Content Security Policy
    ///
    /// # Errors
    ///
    /// [`content_security_policy::CspError`] if a directive name or value
    /// could inject into the header (`;`, `,`, whitespace, CR/LF).
    pub fn with_csp(
        mut self,
        config: content_security_policy::CspConfig,
    ) -> Result<Self, content_security_policy::CspError> {
        config.validate()?;
        self.csp = Some(config);
        Ok(self)
    }

    /// Set or disable (`None`) `Cross-Origin-Opener-Policy`
    pub fn with_coop(mut self, policy: Option<cross_origin::CrossOriginOpenerPolicy>) -> Self {
        self.cross_origin_opener_policy = policy;
        self
    }

    /// Set or disable (`None`) `Cross-Origin-Resource-Policy`
    pub fn with_corp(mut self, policy: Option<cross_origin::CrossOriginResourcePolicy>) -> Self {
        self.cross_origin_resource_policy = policy;
        self
    }

    /// Set or disable (`None`) `Permissions-Policy`
    pub fn with_permissions_policy(
        mut self,
        policy: Option<permissions_policy::PermissionsPolicy>,
    ) -> Self {
        self.permissions_policy = policy;
        self
    }

    /// Enable DNS Prefetch Control
    pub fn with_dns_prefetch_control(
        mut self,
        control: dns_prefetch_control::DnsPrefetchControl,
    ) -> Self {
        self.dns_prefetch_control = control;
        self
    }

    /// Enable Expect-CT
    #[allow(deprecated)]
    pub fn with_expect_ct(mut self, config: expect_ct::ExpectCtConfig) -> Self {
        self.expect_ct = Some(config);
        self
    }

    /// Set Frame Guard policy
    pub fn with_frame_guard(mut self, guard: frame_guard::FrameGuard) -> Self {
        self.frame_guard = guard;
        self
    }

    /// Enable HSTS
    pub fn with_hsts(mut self, config: hsts::HstsConfig) -> Self {
        self.hsts = Some(config);
        self
    }

    /// Hide X-Powered-By header
    pub fn hide_powered_by(mut self, hide: bool) -> Self {
        self.hide_powered_by = hide;
        self
    }

    /// Set Referrer Policy
    pub fn with_referrer_policy(mut self, policy: referrer_policy::ReferrerPolicy) -> Self {
        self.referrer_policy = policy;
        self
    }

    /// Set XSS Filter
    pub fn with_xss_filter(mut self, filter: xss_filter::XssFilter) -> Self {
        self.xss_filter = filter;
        self
    }

    /// Apply security headers to a response
    ///
    /// A header the response already carries — under any letter case — is
    /// left as the handler set it; only missing headers are added.
    pub fn apply(&self, mut response: HttpResponse) -> HttpResponse {
        // Content Security Policy
        if let Some(ref csp) = self.csp {
            let header_name = if csp.report_only {
                "Content-Security-Policy-Report-Only"
            } else {
                "Content-Security-Policy"
            };
            let value = csp
                .to_header_value()
                .unwrap_or_else(|_| FAIL_CLOSED_CSP.to_string());
            set_if_absent(&mut response, header_name, value);
        }

        set_if_absent(
            &mut response,
            "X-DNS-Prefetch-Control",
            self.dns_prefetch_control.to_header_value(),
        );

        if let Some(ref expect_ct) = self.expect_ct {
            set_if_absent(&mut response, "Expect-CT", expect_ct.to_header_value());
        }

        set_if_absent(
            &mut response,
            "X-Frame-Options",
            self.frame_guard.to_header_value(),
        );

        if let Some(ref hsts) = self.hsts {
            set_if_absent(
                &mut response,
                "Strict-Transport-Security",
                hsts.to_header_value(),
            );
        }

        set_if_absent(
            &mut response,
            "Referrer-Policy",
            self.referrer_policy.to_header_value(),
        );

        set_if_absent(
            &mut response,
            "X-XSS-Protection",
            self.xss_filter.to_header_value(),
        );

        set_if_absent(
            &mut response,
            "X-Content-Type-Options",
            self.content_type_options.to_header_value(),
        );

        set_if_absent(
            &mut response,
            "X-Download-Options",
            self.download_options.to_header_value(),
        );

        set_if_absent(
            &mut response,
            "X-Permitted-Cross-Domain-Policies",
            self.permitted_cross_domain_policies.to_header_value(),
        );

        if let Some(coop) = self.cross_origin_opener_policy {
            set_if_absent(
                &mut response,
                "Cross-Origin-Opener-Policy",
                coop.to_header_value(),
            );
        }

        if let Some(corp) = self.cross_origin_resource_policy {
            set_if_absent(
                &mut response,
                "Cross-Origin-Resource-Policy",
                corp.to_header_value(),
            );
        }

        if let Some(ref policy) = self.permissions_policy
            && !policy.is_empty()
        {
            set_if_absent(
                &mut response,
                "Permissions-Policy",
                policy.to_header_value(),
            );
        }

        // Remove X-Powered-By (every spelling) if requested
        if self.hide_powered_by {
            remove_all_cases(&mut response, "X-Powered-By");
        }

        response
    }

    /// Convenience method to enable all common security features (recommended defaults)
    ///
    /// Note: Expect-CT is intentionally *not* enabled here. The `Expect-CT` header is
    /// deprecated and has been removed from all major browsers (since ~2023), so it is a
    /// no-op in practice; use it explicitly via [`Self::with_expect_ct`] only if you have a
    /// specific legacy requirement.
    pub fn enable_all(max_age_seconds: u64) -> Self {
        Self {
            csp: Some(content_security_policy::CspConfig::default()),
            dns_prefetch_control: dns_prefetch_control::DnsPrefetchControl::Off,
            expect_ct: None,
            frame_guard: frame_guard::FrameGuard::Deny,
            hsts: Some(hsts::HstsConfig::new(max_age_seconds)),
            hide_powered_by: true,
            referrer_policy: referrer_policy::ReferrerPolicy::NoReferrer,
            // See `new()` for why this defaults to `Disabled`.
            xss_filter: xss_filter::XssFilter::Disabled,
            content_type_options: content_type_options::ContentTypeOptions::NoSniff,
            download_options: download_options::DownloadOptions::NoOpen,
            permitted_cross_domain_policies:
                permitted_cross_domain_policies::PermittedCrossDomainPolicies::None,
            cross_origin_opener_policy: Some(cross_origin::CrossOriginOpenerPolicy::SameOrigin),
            cross_origin_resource_policy: Some(cross_origin::CrossOriginResourcePolicy::SameOrigin),
            permissions_policy: Some(permissions_policy::PermissionsPolicy::restrictive()),
        }
    }
}

impl Default for SecurityMiddleware {
    fn default() -> Self {
        Self::enable_all(31536000) // 1 year
    }
}

/// Prelude for common imports.
///
/// ```
/// use armature_security::prelude::*;
/// ```
pub mod prelude {
    pub use crate::SecurityMiddleware;
    pub use crate::content_security_policy::CspConfig;
    pub use crate::cors::CorsConfig;
    pub use crate::csrf::{CsrfConfig, CsrfMiddleware, CsrfProtection};
    pub use crate::frame_guard::FrameGuard;
    pub use crate::hsts::HstsConfig;
    pub use crate::referrer_policy::ReferrerPolicy;
    pub use crate::request_signing::{RequestSigner, RequestSigningMiddleware, RequestVerifier};
}

/// Implement the core Middleware trait for SecurityMiddleware
/// This allows it to be used in a MiddlewareChain
#[async_trait::async_trait]
impl armature_core::Middleware for SecurityMiddleware {
    async fn handle(
        &self,
        req: armature_core::HttpRequest,
        next: Box<
            dyn FnOnce(
                    armature_core::HttpRequest,
                ) -> std::pin::Pin<
                    Box<
                        dyn std::future::Future<
                                Output = Result<armature_core::HttpResponse, armature_core::Error>,
                            > + Send,
                    >,
                > + Send,
        >,
    ) -> Result<armature_core::HttpResponse, armature_core::Error> {
        // Call the next handler first
        let response = next(req).await?;
        // Apply security headers to the response
        Ok(self.apply(response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_middleware_new() {
        let middleware = SecurityMiddleware::new();
        assert!(middleware.csp.is_none());
        assert!(!middleware.hide_powered_by);
    }

    #[test]
    fn test_security_middleware_default() {
        let middleware = SecurityMiddleware::default();
        assert!(middleware.csp.is_some());
        assert!(middleware.hsts.is_some());
        assert!(middleware.hide_powered_by);
    }

    #[test]
    fn test_security_middleware_apply() {
        let middleware = SecurityMiddleware::default();
        let response = HttpResponse::ok();
        let secured = middleware.apply(response);

        assert!(secured.headers.contains_key("X-Frame-Options"));
        assert!(secured.headers.contains_key("X-Content-Type-Options"));
        assert!(secured.headers.contains_key("X-XSS-Protection"));
        assert!(secured.headers.contains_key("Strict-Transport-Security"));
        assert!(secured.headers.contains_key("Content-Security-Policy"));
    }

    #[test]
    fn test_xss_filter_defaults_to_disabled() {
        // Modern browsers dropped the legacy XSS auditor; both `new()` and the
        // recommended `enable_all`/`Default` configuration should disable it ("0")
        // rather than opting into the deprecated, sometimes-exploitable filter ("1").
        assert_eq!(
            SecurityMiddleware::new().xss_filter,
            xss_filter::XssFilter::Disabled
        );
        assert_eq!(
            SecurityMiddleware::default().xss_filter,
            xss_filter::XssFilter::Disabled
        );

        let secured = SecurityMiddleware::default().apply(HttpResponse::ok());
        assert_eq!(
            secured.headers.get("X-XSS-Protection"),
            Some(&"0".to_string())
        );
    }

    #[test]
    fn test_enable_all_does_not_enable_expect_ct() {
        // Expect-CT is deprecated and removed from browsers; the recommended defaults
        // should not send it.
        let middleware = SecurityMiddleware::default();
        assert!(middleware.expect_ct.is_none());

        let secured = middleware.apply(HttpResponse::ok());
        assert!(!secured.headers.contains_key("Expect-CT"));
    }

    #[test]
    fn test_csp_header_name_depends_on_report_only() {
        // Enforcing CSP uses the standard header name.
        let enforcing = SecurityMiddleware::new()
            .with_csp(content_security_policy::CspConfig::default())
            .unwrap();
        let secured = enforcing.apply(HttpResponse::ok());
        assert!(secured.headers.contains_key("Content-Security-Policy"));
        assert!(
            !secured
                .headers
                .contains_key("Content-Security-Policy-Report-Only")
        );

        // report_only(true) must emit the header under the Report-Only name instead.
        let report_only = SecurityMiddleware::new()
            .with_csp(content_security_policy::CspConfig::default().report_only(true))
            .unwrap();
        let secured = report_only.apply(HttpResponse::ok());
        assert!(
            secured
                .headers
                .contains_key("Content-Security-Policy-Report-Only")
        );
        assert!(!secured.headers.contains_key("Content-Security-Policy"));
    }

    #[test]
    fn test_hide_powered_by() {
        let middleware = SecurityMiddleware::new().hide_powered_by(true);
        let mut response = HttpResponse::ok();
        response
            .headers
            .insert("X-Powered-By".to_string(), "Armature".to_string());

        let secured = middleware.apply(response);
        assert!(!secured.headers.contains_key("X-Powered-By"));
    }

    #[test]
    fn test_custom_configuration() {
        let middleware = SecurityMiddleware::new()
            .with_frame_guard(frame_guard::FrameGuard::SameOrigin)
            .with_referrer_policy(referrer_policy::ReferrerPolicy::StrictOriginWhenCrossOrigin)
            .hide_powered_by(true);

        let response = HttpResponse::ok();
        let secured = middleware.apply(response);

        assert_eq!(
            secured.headers.get("X-Frame-Options"),
            Some(&"SAMEORIGIN".to_string())
        );
        assert_eq!(
            secured.headers.get("Referrer-Policy"),
            Some(&"strict-origin-when-cross-origin".to_string())
        );
    }

    #[test]
    fn default_emits_isolation_headers() {
        let secured = SecurityMiddleware::default().apply(HttpResponse::ok());
        assert_eq!(
            secured.headers.get("Cross-Origin-Opener-Policy"),
            Some(&"same-origin".to_string())
        );
        assert_eq!(
            secured.headers.get("Cross-Origin-Resource-Policy"),
            Some(&"same-origin".to_string())
        );
        assert!(
            secured
                .headers
                .get("Permissions-Policy")
                .unwrap()
                .contains("camera=()")
        );
    }

    #[test]
    fn isolation_headers_are_configurable() {
        let secured = SecurityMiddleware::default()
            .with_coop(Some(
                cross_origin::CrossOriginOpenerPolicy::SameOriginAllowPopups,
            ))
            .with_corp(None)
            .with_permissions_policy(None)
            .apply(HttpResponse::ok());
        assert_eq!(
            secured.headers.get("Cross-Origin-Opener-Policy"),
            Some(&"same-origin-allow-popups".to_string())
        );
        assert!(!secured.headers.contains_key("Cross-Origin-Resource-Policy"));
        assert!(!secured.headers.contains_key("Permissions-Policy"));
    }

    #[test]
    fn apply_does_not_clobber_handler_headers() {
        // A handler that sets its own (possibly route-specific) policy, in any
        // letter case, must keep it; the middleware used to overwrite it and,
        // for a different case, emit a conflicting duplicate.
        let mut response = HttpResponse::ok();
        response.headers.insert(
            "content-security-policy".to_string(),
            "default-src 'none'".to_string(),
        );
        response
            .headers
            .insert("X-Frame-Options".to_string(), "SAMEORIGIN".to_string());

        let secured = SecurityMiddleware::default().apply(response);

        assert_eq!(
            secured.headers.get("content-security-policy"),
            Some(&"default-src 'none'".to_string())
        );
        assert!(!secured.headers.contains_key("Content-Security-Policy"));
        assert_eq!(
            secured.headers.get("X-Frame-Options"),
            Some(&"SAMEORIGIN".to_string())
        );
    }

    #[test]
    fn with_csp_rejects_injection() {
        let csp = content_security_policy::CspConfig::new()
            .script_src(vec!["'self'; script-src *".to_string()]);
        assert!(SecurityMiddleware::new().with_csp(csp).is_err());
    }

    #[test]
    fn invalid_csp_set_directly_fails_closed() {
        let mut middleware = SecurityMiddleware::new();
        middleware.csp = Some(
            content_security_policy::CspConfig::new()
                .script_src(vec!["*\r\nSet-Cookie: a=b".to_string()]),
        );
        let secured = middleware.apply(HttpResponse::ok());
        assert_eq!(
            secured.headers.get("Content-Security-Policy"),
            Some(&FAIL_CLOSED_CSP.to_string())
        );
    }

    #[test]
    fn hide_powered_by_is_case_insensitive() {
        let mut response = HttpResponse::ok();
        response
            .headers
            .insert("x-powered-by".to_string(), "Armature".to_string());
        let secured = SecurityMiddleware::new()
            .hide_powered_by(true)
            .apply(response);
        assert!(!secured.headers.contains_key("x-powered-by"));
    }
}
