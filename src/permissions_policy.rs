//! `Permissions-Policy`
//!
//! Disables powerful browser features (camera, microphone, geolocation, ...)
//! for this document and everything it embeds, so an injected script or a
//! third-party iframe cannot prompt for them.

/// `Permissions-Policy` configuration
///
/// Each feature maps to an allowlist; an empty allowlist (`feature=()`)
/// disables the feature everywhere.
///
/// ```
/// use armature_security::permissions_policy::PermissionsPolicy;
///
/// let policy = PermissionsPolicy::restrictive().allow_self("fullscreen");
/// let value = policy.to_header_value();
/// assert!(value.contains("camera=()"));
/// assert!(value.contains("fullscreen=(self)"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PermissionsPolicy {
    features: Vec<(String, Vec<String>)>,
}

/// Features [`PermissionsPolicy::restrictive`] disables.
const RESTRICTED_FEATURES: &[&str] = &[
    "accelerometer",
    "autoplay",
    "camera",
    "display-capture",
    "encrypted-media",
    "fullscreen",
    "geolocation",
    "gyroscope",
    "hid",
    "magnetometer",
    "microphone",
    "midi",
    "payment",
    "picture-in-picture",
    "publickey-credentials-get",
    "screen-wake-lock",
    "serial",
    "usb",
    "xr-spatial-tracking",
];

impl PermissionsPolicy {
    /// An empty policy (emits nothing until features are added).
    pub fn new() -> Self {
        Self::default()
    }

    /// Disable every commonly abused powerful feature.
    pub fn restrictive() -> Self {
        let mut policy = Self::new();
        for feature in RESTRICTED_FEATURES {
            policy = policy.deny(feature);
        }
        policy
    }

    fn set(mut self, feature: &str, allowlist: Vec<String>) -> Self {
        let feature = feature.to_ascii_lowercase();
        // Only token characters survive, so a feature name cannot inject a
        // second member or break the header line.
        let feature: String = feature
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        if feature.is_empty() {
            return self;
        }
        self.features.retain(|(f, _)| *f != feature);
        self.features.push((feature, allowlist));
        self
    }

    /// Disable `feature` everywhere (`feature=()`).
    pub fn deny(self, feature: &str) -> Self {
        self.set(feature, Vec::new())
    }

    /// Allow `feature` for this origin only (`feature=(self)`).
    pub fn allow_self(self, feature: &str) -> Self {
        self.set(feature, vec!["self".to_string()])
    }

    /// Header value
    pub fn to_header_value(&self) -> String {
        self.features
            .iter()
            .map(|(feature, allow)| format!("{}=({})", feature, allow.join(" ")))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Whether the policy has no members.
    pub fn is_empty(&self) -> bool {
        self.features.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restrictive_denies_camera_and_mic() {
        let value = PermissionsPolicy::restrictive().to_header_value();
        assert!(value.contains("camera=()"));
        assert!(value.contains("microphone=()"));
        assert!(value.contains("geolocation=()"));
    }

    #[test]
    fn feature_names_cannot_inject() {
        let value = PermissionsPolicy::new()
            .deny("camera=*, geolocation")
            .to_header_value();
        assert!(!value.contains(','));
        assert!(!value.contains('*'));
    }

    #[test]
    fn later_setting_replaces_earlier() {
        let value = PermissionsPolicy::restrictive()
            .allow_self("camera")
            .to_header_value();
        assert!(value.contains("camera=(self)"));
        assert!(!value.contains("camera=()"));
    }
}
