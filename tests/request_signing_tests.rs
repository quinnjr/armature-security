//! Request Signing Integration Tests

use armature_core::HttpRequest;
use armature_security::request_signing::{RequestSigner, RequestVerifier, SigningError};
use std::time::{SystemTime, UNIX_EPOCH};

const SECRET: &str = "0123456789abcdef0123456789abcdef";
const OTHER_SECRET: &str = "fedcba9876543210fedcba9876543210";

#[test]
fn test_sign_and_verify() {
    let signer = RequestSigner::new(SECRET).unwrap();
    let verifier = RequestVerifier::new(SECRET).unwrap();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let signature = signer.sign("POST", "/api/users", b"request body", timestamp);

    // Should verify successfully
    let result = verifier.verify("POST", "/api/users", b"request body", timestamp, &signature);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_verify_wrong_method() {
    let signer = RequestSigner::new(SECRET).unwrap();
    let verifier = RequestVerifier::new(SECRET).unwrap();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Sign with POST
    let signature = signer.sign("POST", "/api/users", b"body", timestamp);

    // Try to verify with GET
    let result = verifier.verify("GET", "/api/users", b"body", timestamp, &signature);
    assert!(result.is_ok());
    assert!(!result.unwrap()); // Should be false
}

#[test]
fn test_verify_wrong_path() {
    let signer = RequestSigner::new(SECRET).unwrap();
    let verifier = RequestVerifier::new(SECRET).unwrap();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let signature = signer.sign("POST", "/api/users", b"body", timestamp);

    // Try different path
    let result = verifier.verify("POST", "/api/posts", b"body", timestamp, &signature);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_verify_wrong_body() {
    let signer = RequestSigner::new(SECRET).unwrap();
    let verifier = RequestVerifier::new(SECRET).unwrap();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let signature = signer.sign("POST", "/api/users", b"original body", timestamp);

    // Try different body
    let result = verifier.verify(
        "POST",
        "/api/users",
        b"modified body",
        timestamp,
        &signature,
    );
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_verify_wrong_secret() {
    let signer = RequestSigner::new(SECRET).unwrap();
    let verifier = RequestVerifier::new(OTHER_SECRET).unwrap();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let signature = signer.sign("POST", "/api/users", b"body", timestamp);

    let result = verifier.verify("POST", "/api/users", b"body", timestamp, &signature);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_verify_expired_request() {
    let signer = RequestSigner::new(SECRET).unwrap();
    let verifier = RequestVerifier::new(SECRET).unwrap().with_max_age(10); // 10 seconds

    // Create old timestamp (1 hour ago)
    let old_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 3600;

    let signature = signer.sign("POST", "/api/users", b"body", old_timestamp);

    let result = verifier.verify("POST", "/api/users", b"body", old_timestamp, &signature);
    assert!(matches!(result, Err(SigningError::RequestExpired)));
}

#[test]
fn test_verify_request_within_window() {
    let signer = RequestSigner::new(SECRET).unwrap();
    let verifier = RequestVerifier::new(SECRET).unwrap().with_max_age(300); // 5 minutes

    // Recent timestamp (1 minute ago)
    let recent_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 60;

    let signature = signer.sign("POST", "/api/users", b"body", recent_timestamp);

    let result = verifier.verify("POST", "/api/users", b"body", recent_timestamp, &signature);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_verify_http_request() {
    let signer = RequestSigner::new(SECRET).unwrap();
    let verifier = RequestVerifier::new(SECRET).unwrap();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let body = "test body";
    let signature = signer.sign("POST", "/api/test", body.as_bytes(), timestamp);

    let mut request = HttpRequest::new("POST", "/api/test".to_string());
    request.body = armature_core::Bytes::copy_from_slice(body.as_bytes());
    request.headers.insert("X-Signature", signature);
    request.headers.insert("X-Timestamp", timestamp.to_string());

    let result = verifier.verify_request(&request);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_verify_request_missing_signature() {
    let verifier = RequestVerifier::new(SECRET).unwrap();

    let request = HttpRequest::new("POST", "/api/test".to_string());

    let result = verifier.verify_request(&request);
    assert!(matches!(result, Err(SigningError::MissingSignature)));
}

#[test]
fn test_verify_request_missing_timestamp() {
    let verifier = RequestVerifier::new(SECRET).unwrap();

    let mut request = HttpRequest::new("POST", "/api/test".to_string());
    request
        .headers
        .insert("X-Signature", "signature".to_string());

    let result = verifier.verify_request(&request);
    assert!(matches!(result, Err(SigningError::MissingTimestamp)));
}

#[test]
fn test_verify_request_invalid_timestamp() {
    let verifier = RequestVerifier::new(SECRET).unwrap();

    let mut request = HttpRequest::new("POST", "/api/test".to_string());
    request
        .headers
        .insert("X-Signature", "signature".to_string());
    request
        .headers
        .insert("X-Timestamp", "not-a-number".to_string());

    let result = verifier.verify_request(&request);
    assert!(matches!(result, Err(SigningError::InvalidTimestamp)));
}

#[test]
fn test_signature_consistency() {
    let signer = RequestSigner::new(SECRET).unwrap();

    let sig1 = signer.sign("POST", "/api/test", b"body", 1702468800);
    let sig2 = signer.sign("POST", "/api/test", b"body", 1702468800);

    // Same inputs should produce same signature
    assert_eq!(sig1, sig2);
}

#[test]
fn test_signature_hex_format() {
    let signer = RequestSigner::new(SECRET).unwrap();
    let signature = signer.sign("POST", "/api/test", b"body", 1702468800);

    // SHA256 hex should be 64 characters
    assert_eq!(signature.len(), 64);

    // Should only contain hex characters
    assert!(signature.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_different_timestamps_different_signatures() {
    let signer = RequestSigner::new(SECRET).unwrap();

    let sig1 = signer.sign("POST", "/api/test", b"body", 1702468800);
    let sig2 = signer.sign("POST", "/api/test", b"body", 1702468801);

    // Different timestamps should produce different signatures
    assert_ne!(sig1, sig2);
}

#[test]
fn test_max_age_configuration() {
    let verifier1 = RequestVerifier::new(SECRET).unwrap().with_max_age(300);
    let verifier2 = RequestVerifier::new(SECRET).unwrap().with_max_age(600);

    // Check that different max ages are respected
    let old_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 400;

    let signer = RequestSigner::new(SECRET).unwrap();
    let signature = signer.sign("POST", "/api/test", b"body", old_timestamp);

    // Should fail with 300s max age
    let result1 = verifier1.verify("POST", "/api/test", b"body", old_timestamp, &signature);
    assert!(matches!(result1, Err(SigningError::RequestExpired)));

    // Should succeed with 600s max age
    let result2 = verifier2.verify("POST", "/api/test", b"body", old_timestamp, &signature);
    assert!(result2.is_ok());
    assert!(result2.unwrap());
}
