use crate::cli::BumpImageArgs;
use crate::types::{ImageDigest, ImageRef};
use crate::{DastSpikeError, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

const DEFAULT_PIN_FILE: &str = "references/zap-image-pin.toml";

#[derive(Debug, Clone, Deserialize)]
pub struct ZapImagePin {
    pub upstream: ImagePinSection,
    pub ours: ImagePinSection,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImagePinSection {
    pub image: String,
    pub digest: String,
    #[serde(default)]
    pub checked_at: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

impl ZapImagePin {
    pub fn load_default() -> Result<Self> {
        Self::load(Path::new(DEFAULT_PIN_FILE))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)?;
        let pin: Self = toml::from_str(&text)?;
        pin.validate()?;
        Ok(pin)
    }

    pub fn validate(&self) -> Result<()> {
        ImageDigest::try_from(self.upstream.digest.as_str()).map_err(DastSpikeError::Usage)?;
        ImageDigest::try_from(self.ours.digest.as_str()).map_err(DastSpikeError::Usage)?;
        Ok(())
    }

    pub fn our_digest(&self) -> Result<ImageDigest> {
        ImageDigest::try_from(self.ours.digest.as_str()).map_err(DastSpikeError::Usage)
    }

    pub fn upstream_digest(&self) -> Result<ImageDigest> {
        ImageDigest::try_from(self.upstream.digest.as_str()).map_err(DastSpikeError::Usage)
    }
}

pub fn resolve_digest(cli_image: Option<&str>) -> Result<ImageDigest> {
    if let Some(value) = cli_image {
        ImageDigest::try_from(value).map_err(DastSpikeError::Usage)
    } else {
        ZapImagePin::load_default()?.our_digest()
    }
}

/// Resolve a full image reference from the optional `--image` CLI input and
/// the pin file fallback.
///
/// Accepts either form on the CLI:
/// * `sha256:<hex>` — bare digest; the canonical repo is used at render time.
/// * `<repo>@sha256:<hex>` — full reference; the provided repo is preserved
///   verbatim (used by CI for local-build / mirror flows where the image is
///   not at the canonical GHCR coordinate).
///
/// When `cli_image` is `None`, falls back to the pin file's `[ours].digest`
/// (bare digest form), which combines with the canonical repo at render time.
pub fn resolve_image_ref(cli_image: Option<&str>) -> Result<ImageRef> {
    if let Some(value) = cli_image {
        ImageRef::try_from(value).map_err(DastSpikeError::Usage)
    } else {
        let digest = ZapImagePin::load_default()?.our_digest()?;
        Ok(ImageRef::from_digest(digest))
    }
}

pub fn run_bump_image(args: BumpImageArgs) -> Result<()> {
    let pin = ZapImagePin::load(&args.pin_file)?;
    if args.check {
        println!(
            "zap upstream pin ok: {}@{}",
            pin.upstream.image, pin.upstream.digest
        );
        println!(
            "dast-spike image pin ok: {}@{}",
            pin.ours.image, pin.ours.digest
        );
        return Ok(());
    }

    if args.no_pr {
        println!("validated image pins in {}", args.pin_file.display());
        Ok(())
    } else {
        Err(DastSpikeError::Usage(
            "opening an image-bump PR is not implemented in the local runner; use --check or --no-pr"
                .to_string(),
        ))
    }
}
