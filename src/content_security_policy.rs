//! Content Security Policy (CSP) configuration
//!
//! CSP helps prevent XSS attacks by declaring which dynamic resources are allowed to load.
//!
//! Directive names and source values are validated before they are rendered
//! into the header: a value carrying `;` or `,` would start a new directive or
//! a second policy, and CR/LF would split the header, so such values are
//! rejected with [`CspError`] instead of being emitted.

use std::collections::HashMap;

/// A CSP directive name or value that cannot be emitted safely.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CspError {
    /// The directive name is empty or contains characters outside
    /// `[A-Za-z0-9-]`.
    #[error("invalid CSP directive name: {0:?}")]
    InvalidDirectiveName(String),

    /// A source value is empty or contains `;`, `,`, whitespace or a control
    /// character (including CR and LF).
    #[error("invalid value {value:?} for CSP directive {directive}")]
    InvalidValue {
        /// Directive the value was given for.
        directive: String,
        /// The rejected value.
        value: String,
    },
}

/// Content Security Policy configuration
#[derive(Debug, Clone)]
pub struct CspConfig {
    /// CSP directives
    ///
    /// Entries inserted here directly are validated when the policy is
    /// rendered ([`to_header_value`](Self::to_header_value)) or installed
    /// ([`SecurityMiddleware::with_csp`](crate::SecurityMiddleware::with_csp)).
    pub directives: HashMap<String, Vec<String>>,

    /// Report violations only (doesn't enforce)
    pub report_only: bool,
}

impl CspConfig {
    /// Create a new CSP configuration
    pub fn new() -> Self {
        Self {
            directives: HashMap::new(),
            report_only: false,
        }
    }

    /// Add a directive
    ///
    /// The values are not checked here so the builder can be chained; an
    /// invalid name or value is reported by [`validate`](Self::validate),
    /// which every rendering path runs.
    pub fn directive(mut self, name: impl Into<String>, values: Vec<String>) -> Self {
        self.directives.insert(name.into(), values);
        self
    }

    /// Set default-src directive
    pub fn default_src(self, sources: Vec<String>) -> Self {
        self.directive("default-src", sources)
    }

    /// Set script-src directive
    pub fn script_src(self, sources: Vec<String>) -> Self {
        self.directive("script-src", sources)
    }

    /// Set style-src directive
    pub fn style_src(self, sources: Vec<String>) -> Self {
        self.directive("style-src", sources)
    }

    /// Set img-src directive
    pub fn img_src(self, sources: Vec<String>) -> Self {
        self.directive("img-src", sources)
    }

    /// Set connect-src directive
    pub fn connect_src(self, sources: Vec<String>) -> Self {
        self.directive("connect-src", sources)
    }

    /// Set font-src directive
    pub fn font_src(self, sources: Vec<String>) -> Self {
        self.directive("font-src", sources)
    }

    /// Set object-src directive
    pub fn object_src(self, sources: Vec<String>) -> Self {
        self.directive("object-src", sources)
    }

    /// Set media-src directive
    pub fn media_src(self, sources: Vec<String>) -> Self {
        self.directive("media-src", sources)
    }

    /// Set frame-src directive
    pub fn frame_src(self, sources: Vec<String>) -> Self {
        self.directive("frame-src", sources)
    }

    /// Set frame-ancestors directive (who may embed this page)
    pub fn frame_ancestors(self, sources: Vec<String>) -> Self {
        self.directive("frame-ancestors", sources)
    }

    /// Set base-uri directive
    pub fn base_uri(self, sources: Vec<String>) -> Self {
        self.directive("base-uri", sources)
    }

    /// Set form-action directive
    pub fn form_action(self, sources: Vec<String>) -> Self {
        self.directive("form-action", sources)
    }

    /// Enable report-only mode
    pub fn report_only(mut self, enabled: bool) -> Self {
        self.report_only = enabled;
        self
    }

    /// Check every directive name and value.
    ///
    /// # Errors
    ///
    /// [`CspError`] for the first name or value that could inject a new
    /// directive, a second policy, or a header line.
    ///
    /// ```
    /// use armature_security::content_security_policy::CspConfig;
    ///
    /// let bad = CspConfig::new().script_src(vec!["'self'; script-src *".to_string()]);
    /// assert!(bad.validate().is_err());
    /// assert!(CspConfig::default().validate().is_ok());
    /// ```
    pub fn validate(&self) -> Result<(), CspError> {
        for (name, values) in &self.directives {
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return Err(CspError::InvalidDirectiveName(name.clone()));
            }
            for value in values {
                let bad = value.is_empty()
                    || value
                        .chars()
                        .any(|c| c == ';' || c == ',' || c.is_whitespace() || c.is_control());
                if bad {
                    return Err(CspError::InvalidValue {
                        directive: name.clone(),
                        value: value.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Convert to header value
    ///
    /// Directives are emitted in name order so the header is deterministic.
    ///
    /// # Errors
    ///
    /// See [`validate`](Self::validate).
    pub fn to_header_value(&self) -> Result<String, CspError> {
        self.validate()?;

        let mut names: Vec<&String> = self.directives.keys().collect();
        names.sort();

        let parts: Vec<String> = names
            .into_iter()
            .map(|directive| {
                let values = &self.directives[directive];
                if values.is_empty() {
                    directive.clone()
                } else {
                    format!("{} {}", directive, values.join(" "))
                }
            })
            .collect();

        Ok(parts.join("; "))
    }
}

impl Default for CspConfig {
    /// A strict baseline: same-origin resources only, no plugins, no
    /// framing, no `<base>` rewriting, forms post back to this origin only.
    /// Inline styles and arbitrary HTTPS images are *not* allowed; add them
    /// explicitly if the application needs them.
    fn default() -> Self {
        let own = || vec!["'self'".to_string()];
        let none = || vec!["'none'".to_string()];
        Self::new()
            .default_src(own())
            .script_src(own())
            .style_src(own())
            .img_src(vec!["'self'".to_string(), "data:".to_string()])
            .font_src(own())
            .connect_src(own())
            .object_src(none())
            .frame_ancestors(none())
            .base_uri(none())
            .form_action(own())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csp_default() {
        let csp = CspConfig::default();
        let header = csp.to_header_value().unwrap();

        assert!(header.contains("default-src 'self'"));
        assert!(header.contains("script-src 'self'"));
        assert!(header.contains("object-src 'none'"));
    }

    #[test]
    fn default_policy_is_strict() {
        let header = CspConfig::default().to_header_value().unwrap();

        assert!(header.contains("frame-ancestors 'none'"));
        assert!(header.contains("base-uri 'none'"));
        assert!(header.contains("form-action 'self'"));
        assert!(header.contains("object-src 'none'"));
        assert!(!header.contains("'unsafe-inline'"));
        assert!(header.contains("img-src 'self' data:"));
        assert!(!header.contains("https:"));
    }

    #[test]
    fn test_csp_custom() {
        let csp = CspConfig::new()
            .default_src(vec!["'self'".to_string()])
            .script_src(vec![
                "'self'".to_string(),
                "https://cdn.example.com".to_string(),
            ]);

        let header = csp.to_header_value().unwrap();
        assert!(header.contains("script-src 'self' https://cdn.example.com"));
    }

    #[test]
    fn injection_characters_are_rejected() {
        for value in [
            "'self'; script-src *",
            "'self', script-src *",
            "'self'\r\nSet-Cookie: x=y",
            "'self'\nfoo",
            "a b",
            "",
        ] {
            let csp = CspConfig::new().script_src(vec![value.to_string()]);
            assert!(
                matches!(csp.to_header_value(), Err(CspError::InvalidValue { .. })),
                "{value:?} must be rejected"
            );
        }

        let csp = CspConfig::new().directive("script-src;", vec!["'self'".to_string()]);
        assert!(matches!(
            csp.validate(),
            Err(CspError::InvalidDirectiveName(_))
        ));
    }

    #[test]
    fn valueless_directive_renders_alone() {
        let csp = CspConfig::new().directive("upgrade-insecure-requests", vec![]);
        assert_eq!(csp.to_header_value().unwrap(), "upgrade-insecure-requests");
    }

    #[test]
    fn test_csp_report_only() {
        let csp = CspConfig::default().report_only(true);
        assert!(csp.report_only);
    }
}
