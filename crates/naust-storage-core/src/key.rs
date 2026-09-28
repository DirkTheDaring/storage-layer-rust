//! Relative hierarchical object key representation.

use std::borrow::Borrow;
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

use crate::error::ObjectKeyError;

/// A validated, lossless relative object key.
///
/// # Invariants
/// - Relative path hierarchy using single `/` separators (e.g. `blobs/sha256/abc`).
/// - Non-empty string.
/// - No leading or trailing `/` separators.
/// - No repeated separators (`//`) and thus no empty segments.
/// - No `.` or `..` path segments.
/// - No backslashes (`\\`), NUL bytes (`\\0`), or ASCII/Unicode control characters.
/// - No Unix absolute paths, Windows drive prefixes (e.g. `C:`), or UNC syntax (e.g. `//`, `\\\\`).
/// - Byte-for-byte preservation with zero silent normalization (no trimming, case folding,
///   separator substitution, percent-decoding, or Unicode canonicalization).
///
/// # Contract Gate O-03
/// In Slice 2A, maximum key length validation is intentionally deferred to contract gate O-03.
/// This omission is provisional; no completeness claim is made.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObjectKey(Box<str>);

impl ObjectKey {
    /// Validates and parses an object key from a string slice.
    ///
    /// The input must strictly obey relative hierarchical key syntax rules without
    /// silent normalization or transformation.
    pub fn parse(s: &str) -> Result<Self, ObjectKeyError> {
        if s.is_empty() {
            return Err(ObjectKeyError::Empty);
        }

        // UNC prefixes: \\ or //
        if s.starts_with("//") || s.starts_with("\\\\") {
            return Err(ObjectKeyError::UncPrefix);
        }

        // Windows drive prefix: ASCII letter followed by ':'
        let bytes = s.as_bytes();
        if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            return Err(ObjectKeyError::WindowsDrivePrefix);
        }

        // NUL bytes
        if s.contains('\0') {
            return Err(ObjectKeyError::NulByte);
        }

        // Backslashes
        if s.contains('\\') {
            return Err(ObjectKeyError::Backslash);
        }

        // Control characters
        if s.chars().any(|c| c.is_control()) {
            return Err(ObjectKeyError::ControlCharacter);
        }

        // Leading slash (Unix absolute paths)
        if s.starts_with('/') {
            return Err(ObjectKeyError::LeadingSlash);
        }

        // Trailing slash
        if s.ends_with('/') {
            return Err(ObjectKeyError::TrailingSlash);
        }

        // Segment-level validation: repeated separators, dot, and dot-dot segments
        for segment in s.split('/') {
            if segment.is_empty() {
                return Err(ObjectKeyError::RepeatedSeparator);
            }
            if segment == "." {
                return Err(ObjectKeyError::DotSegment);
            }
            if segment == ".." {
                return Err(ObjectKeyError::DotDotSegment);
            }
        }

        // Preserves input byte-for-byte without normalization
        Ok(Self(s.to_string().into_boxed_str()))
    }

    /// Returns the raw string slice representation of the key.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ObjectKey").field(&self.as_str()).finish()
    }
}

impl fmt::Display for ObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Deref for ObjectKey {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl AsRef<str> for ObjectKey {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for ObjectKey {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl TryFrom<&str> for ObjectKey {
    type Error = ObjectKeyError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl TryFrom<String> for ObjectKey {
    type Error = ObjectKeyError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl FromStr for ObjectKey {
    type Err = ObjectKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_key_valid_hierarchical_keys_accepted_and_preserved() {
        let valid_keys = [
            "blobs/sha256/abc",
            "uploads/session-1/chunk-0",
            "repos/acme/widget/tags/latest",
            "single-segment",
            "a/b/c/d/e/f",
        ];

        for raw in valid_keys {
            let key = ObjectKey::parse(raw).expect("valid key must parse successfully");
            assert_eq!(key.as_str(), raw);
            assert_eq!(key.to_string(), raw);
        }
    }

    #[test]
    fn test_object_key_rejects_empty() {
        let err = ObjectKey::parse("").expect_err("empty key must fail");
        assert_eq!(err, ObjectKeyError::Empty);
    }

    #[test]
    fn test_object_key_rejects_leading_slash() {
        let err = ObjectKey::parse("/blobs/sha256/abc").expect_err("leading slash must fail");
        assert_eq!(err, ObjectKeyError::LeadingSlash);

        let err_root = ObjectKey::parse("/").expect_err("root slash must fail");
        assert_eq!(err_root, ObjectKeyError::LeadingSlash);
    }

    #[test]
    fn test_object_key_rejects_trailing_slash() {
        let err = ObjectKey::parse("blobs/sha256/abc/").expect_err("trailing slash must fail");
        assert_eq!(err, ObjectKeyError::TrailingSlash);
    }

    #[test]
    fn test_object_key_rejects_repeated_separator() {
        let samples = ["blobs//sha256/abc", "a///b", "uploads/session//chunk"];

        for sample in samples {
            let err = ObjectKey::parse(sample).expect_err("repeated separator must fail");
            assert_eq!(err, ObjectKeyError::RepeatedSeparator);
        }
    }

    #[test]
    fn test_object_key_rejects_dot_segment() {
        let samples = [".", "./blobs", "blobs/./sha256", "blobs/sha256/."];

        for sample in samples {
            let err = ObjectKey::parse(sample).expect_err("dot segment must fail");
            assert_eq!(err, ObjectKeyError::DotSegment);
        }
    }

    #[test]
    fn test_object_key_rejects_dot_dot_segment() {
        let samples = ["..", "../blobs", "blobs/../sha256", "blobs/sha256/.."];

        for sample in samples {
            let err = ObjectKey::parse(sample).expect_err("dot dot segment must fail");
            assert_eq!(err, ObjectKeyError::DotDotSegment);
        }
    }

    #[test]
    fn test_object_key_rejects_backslash() {
        let samples = ["blobs\\sha256\\abc", "foo/bar\\baz", "trailing\\"];

        for sample in samples {
            let err = ObjectKey::parse(sample).expect_err("backslash must fail");
            assert_eq!(err, ObjectKeyError::Backslash);
        }
    }

    #[test]
    fn test_object_key_rejects_nul_byte() {
        let sample = "blobs/sha256\0abc";
        let err = ObjectKey::parse(sample).expect_err("nul byte must fail");
        assert_eq!(err, ObjectKeyError::NulByte);
    }

    #[test]
    fn test_object_key_rejects_control_character() {
        let samples = [
            "blobs/sha256/\nabc",
            "blobs/\tabc",
            "uploads/\u{001F}chunk",
            "repos/\u{007F}tag",
        ];

        for sample in samples {
            let err = ObjectKey::parse(sample).expect_err("control character must fail");
            assert_eq!(err, ObjectKeyError::ControlCharacter);
        }
    }

    #[test]
    fn test_object_key_rejects_windows_drive_prefix() {
        let samples = ["C:/blobs/sha256/abc", "c:/uploads/1", "D:foo/bar", "z:key"];

        for sample in samples {
            let err = ObjectKey::parse(sample).expect_err("Windows drive prefix must fail");
            assert_eq!(err, ObjectKeyError::WindowsDrivePrefix);
        }
    }

    #[test]
    fn test_object_key_rejects_unc_prefix() {
        let samples = ["//server/share/file", "\\\\server\\share\\file"];

        for sample in samples {
            let err = ObjectKey::parse(sample).expect_err("UNC prefix must fail");
            assert_eq!(err, ObjectKeyError::UncPrefix);
        }
    }

    #[test]
    fn test_object_key_preserves_whitespace_and_unicode_without_normalization() {
        let key_str = "repos/acme/my widget/tags/v1.0.0-β/résumé";
        let key = ObjectKey::parse(key_str).expect("valid key with spaces and unicode must parse");
        assert_eq!(key.as_str(), key_str);
        assert_eq!(key.to_string(), key_str);
        assert_eq!(key.as_bytes(), key_str.as_bytes());
    }

    #[test]
    fn test_object_key_try_from_and_from_str_consistency() {
        let valid = "blobs/sha256/test-key-123";
        let key_from_str: ObjectKey = valid.parse().unwrap();
        let key_try_from = ObjectKey::try_from(valid).unwrap();
        assert_eq!(key_from_str, key_try_from);

        let invalid = "/leading/slash";
        let err_from_str: Result<ObjectKey, _> = invalid.parse();
        let err_try_from = ObjectKey::try_from(invalid);
        assert_eq!(err_from_str.unwrap_err(), err_try_from.unwrap_err());
    }

    #[test]
    fn test_object_key_display_and_as_str_byte_for_byte_identity() {
        let raw = "uploads/session-abc-123/part-42";
        let key = ObjectKey::parse(raw).unwrap();
        assert_eq!(key.as_str(), raw);
        assert_eq!(format!("{key}"), raw);
        assert_eq!(&*key, raw);
    }
}
