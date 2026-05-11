use thiserror::Error;

use crate::error::ZapshootError;

/// A docker image reference.  In MVP1 only `Digest` is supported -- callers must
/// always pin by `@sha256:<64-hex>`.  Tag-only and repo-only references are
/// rejected at parse time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageRef {
    Digest { repo: String, sha256_hex: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ImageRefError {
    #[error("not_digest")]
    NotDigest,
    #[error("digest_malformed")]
    DigestMalformed,
    #[error("repo_charset")]
    RepoCharset,
    #[error("repo_too_long")]
    RepoTooLong,
}

impl From<ImageRefError> for ZapshootError {
    fn from(e: ImageRefError) -> Self {
        match e {
            ImageRefError::NotDigest => ZapshootError::ImageRefNotDigest,
            ImageRefError::DigestMalformed => ZapshootError::ImageRefDigestMalformed,
            ImageRefError::RepoCharset => ZapshootError::ImageRefRepoCharset,
            ImageRefError::RepoTooLong => ZapshootError::ImageRefRepoTooLong,
        }
    }
}

impl ImageRef {
    /// Parse a string into an `ImageRef::Digest`.  Returns `Err(NotDigest)` for
    /// any tag-only or repo-only reference; `Err(DigestMalformed)` if the digest
    /// is not exactly 64 lowercase hex chars; `Err(RepoCharset)` if the repo
    /// contains shell metacharacters or other unsafe characters; `Err(RepoTooLong)`
    /// if the repo exceeds 255 characters.
    pub fn parse(s: &str) -> Result<ImageRef, ImageRefError> {
        let (repo, digest) = s.split_once("@sha256:").ok_or(ImageRefError::NotDigest)?;

        if repo.is_empty() {
            return Err(ImageRefError::RepoCharset);
        }
        if repo.len() > 255 {
            return Err(ImageRefError::RepoTooLong);
        }
        if !is_safe_repo(repo) {
            return Err(ImageRefError::RepoCharset);
        }
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(ImageRefError::DigestMalformed);
        }

        Ok(ImageRef::Digest {
            repo: repo.to_string(),
            sha256_hex: digest.to_string(),
        })
    }

    pub fn repo(&self) -> &str {
        let ImageRef::Digest { repo, .. } = self;
        repo
    }

    pub fn sha256_hex(&self) -> &str {
        let ImageRef::Digest { sha256_hex, .. } = self;
        sha256_hex
    }

    pub fn as_canonical_string(&self) -> String {
        let ImageRef::Digest { repo, sha256_hex } = self;
        format!("{repo}@sha256:{sha256_hex}")
    }
}

/// Validate the docker repository portion of an image reference.
///
/// A repo is one or more path components separated by `/`.  An optional first
/// component may be a registry hostname with an optional `:<port>` suffix.
/// Each component must:
/// - start and end with a lowercase ASCII alphanumeric;
/// - contain only lowercase ASCII alphanumerics, `.`, `_`, or `-` in between;
/// - not start with `.`, `-`, `_`.
///
/// Uppercase, whitespace, shell metacharacters, and leading `--` are all
/// rejected -- this defends against argv-smuggling into a future `docker run`
/// argv (CWE-88) and against image references that confuse downstream parsers.
fn is_safe_repo(repo: &str) -> bool {
    if repo.is_empty() || repo.starts_with('/') || repo.ends_with('/') {
        return false;
    }
    for component in repo.split('/') {
        if !is_safe_component(component) {
            return false;
        }
    }
    true
}

fn is_safe_component(c: &str) -> bool {
    if c.is_empty() {
        return false;
    }
    let bytes = c.as_bytes();
    let first = bytes[0];
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    let last = bytes[bytes.len() - 1];
    if !last.is_ascii_lowercase() && !last.is_ascii_digit() {
        // The hostname:port case allows `:` as last only if a port follows -- handled
        // below by treating the colon-suffix as a special form.
        if let Some((host, port)) = c.rsplit_once(':') {
            return is_safe_component(host)
                && !port.is_empty()
                && port.bytes().all(|b| b.is_ascii_digit());
        }
        return false;
    }
    for &b in bytes {
        let ok = b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || b == b'.'
            || b == b'_'
            || b == b'-'
            || b == b':';
        if !ok {
            return false;
        }
    }
    true
}
