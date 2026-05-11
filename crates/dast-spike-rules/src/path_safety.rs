use crate::{Result, RulesError};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

pub fn validate_path_for_write(root: &Path, relative: &Path) -> Result<PathBuf> {
    if relative.is_absolute() {
        return Err(RulesError::Validation(format!(
            "write path must be relative: {}",
            relative.display()
        )));
    }

    let mut out = PathBuf::from(root);
    for component in relative.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            _ => {
                return Err(RulesError::Validation(format!(
                    "write path contains unsafe component: {}",
                    relative.display()
                )));
            }
        }
    }

    let mut cursor = PathBuf::from(root);
    for component in relative.components() {
        let Component::Normal(part) = component else {
            continue;
        };
        cursor.push(part);
        if cursor == out {
            if let Ok(meta) = fs::symlink_metadata(&cursor) {
                if meta.file_type().is_symlink() {
                    return Err(RulesError::Validation(format!(
                        "{} is a symlink - refusing to write",
                        cursor.display()
                    )));
                }
            }
            break;
        }
        match fs::symlink_metadata(&cursor) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(RulesError::Validation(format!(
                    "{} is a symlink - refusing to write",
                    cursor.display()
                )));
            }
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                return Err(RulesError::Validation(format!(
                    "{} exists but is not a directory",
                    cursor.display()
                )));
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&cursor)?;
            }
            Err(err) => return Err(err.into()),
        }
    }

    Ok(out)
}

pub fn safe_write(root: &Path, relative: &Path, contents: &[u8]) -> Result<PathBuf> {
    let path = validate_path_for_write(root, relative)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Ok(meta) = fs::symlink_metadata(&path) {
        if meta.file_type().is_symlink() {
            return Err(RulesError::Validation(format!(
                "{} is a symlink - refusing to write",
                path.display()
            )));
        }
    }

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)?;
    file.write_all(contents)?;
    file.flush()?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_parent_components() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = validate_path_for_write(dir.path(), Path::new("../escape")).unwrap_err();
        assert!(err.to_string().contains("unsafe component"));
    }
}
