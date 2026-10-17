//! Cross-origin isolation headers
//!
//! - `Cross-Origin-Opener-Policy` (COOP) severs the `window.opener` link with
//!   cross-origin documents, closing XS-Leaks and tab-nabbing channels.
//! - `Cross-Origin-Resource-Policy` (CORP) stops other origins from loading
//!   this response as a subresource (Spectre-style side channels, hotlinking).

/// `Cross-Origin-Opener-Policy` values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossOriginOpenerPolicy {
    /// Isolate the browsing context from every cross-origin document.
    SameOrigin,
    /// Like `SameOrigin`, but popups this page opens keep their opener
    /// (needed by some OAuth / payment popup flows).
    SameOriginAllowPopups,
    /// No isolation.
    UnsafeNone,
}

impl CrossOriginOpenerPolicy {
    /// Header value
    pub fn to_header_value(&self) -> String {
        match self {
            Self::SameOrigin => "same-origin",
            Self::SameOriginAllowPopups => "same-origin-allow-popups",
            Self::UnsafeNone => "unsafe-none",
        }
        .to_string()
    }
}

/// `Cross-Origin-Resource-Policy` values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossOriginResourcePolicy {
    /// Only this origin may load the resource.
    SameOrigin,
    /// Any origin on the same site may load the resource.
    SameSite,
    /// Any origin may load the resource (public CDN assets).
    CrossOrigin,
}

impl CrossOriginResourcePolicy {
    /// Header value
    pub fn to_header_value(&self) -> String {
        match self {
            Self::SameOrigin => "same-origin",
            Self::SameSite => "same-site",
            Self::CrossOrigin => "cross-origin",
        }
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values() {
        assert_eq!(
            CrossOriginOpenerPolicy::SameOrigin.to_header_value(),
            "same-origin"
        );
        assert_eq!(
            CrossOriginResourcePolicy::SameSite.to_header_value(),
            "same-site"
        );
    }
}
