use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use exn_anyhow::into_anyhow;
use globset::{Candidate, Glob, GlobSet};
use type_crawler::{Env, EnvOptions, Language, ParseOptions, TypeCrawler, WordSize};
use walkdir::WalkDir;

use crate::{
    list::UnsafeList,
    traits::{TryAsSafe, UnsafeString},
    types::Bool32,
};

pub struct SafeTypeSyncOptions {
    project_path: PathBuf,
    includes: Vec<String>,
    files: Vec<String>,
    languages: Vec<Language>,
    short_enums: bool,
    signed_char: bool,
}

pub fn get_type_sync_yaml(options: SafeTypeSyncOptions) -> Result<String> {
    let env = Env::new(EnvOptions {
        word_size: WordSize::Size32,
        short_enums: options.short_enums,
        signed_char: options.signed_char,
    });
    // Disable libclang crash recovery to avoid overriding signal handlers in the JVM
    std::env::set_var("LIBCLANG_DISABLE_CRASH_RECOVERY", "1");
    let mut type_crawler = TypeCrawler::new(env).map_err(into_anyhow)?;

    let mut builder = GlobSet::builder();
    for include_glob in options.includes {
        // If `include_glob` is relative, it gets appended to `project_path`
        // If it is absolute, then it replaces `project_path` entirely
        let glob_as_path = options.project_path.join(&include_glob);
        let glob_str = glob_as_path.to_string_lossy();
        let glob = Glob::new(&glob_str).context("Invalid glob pattern in `includes`")?;
        builder.add(glob);
    }
    let includes_globset = builder.build().context("Failed to build globset for `includes`")?;

    let mut builder = GlobSet::builder();
    for file_glob in options.files {
        let glob_as_path = options.project_path.join(&file_glob);
        let glob_str = glob_as_path.to_string_lossy();
        let glob = Glob::new(&glob_str).context("Invalid glob pattern in `files`")?;
        builder.add(glob);
    }
    let files_globset = builder.build().context("Failed to build globset for `files`")?;

    let mut files_globset_matches = Vec::new();
    let mut files_to_process = Vec::new();
    for entry in WalkDir::new(options.project_path).sort_by_file_name().follow_links(true) {
        let entry = entry?;
        let path = entry.path();
        let candidate = Candidate::new(path);

        if includes_globset.is_match_candidate(&candidate) {
            type_crawler.add_include_path(path).map_err(into_anyhow)?;
        }

        if path.is_file() {
            files_globset.matches_candidate_into(&candidate, &mut files_globset_matches);
            if let Some(index) = files_globset_matches.first() {
                let language = *options
                    .languages
                    .get(*index)
                    .ok_or_else(|| anyhow!("Not enough languages passed to `get_type_sync_yaml`"))?;
                files_to_process.push((path.to_path_buf(), language));
            }
        }
    }

    for (path, language) in files_to_process {
        type_crawler
            .parse_file_with_options(&path, ParseOptions { language })
            .map_err(into_anyhow)
            .with_context(|| format!("while parsing file {}", path.display()))?;
    }

    let types = type_crawler.into_types();
    Ok(serde_saphyr::to_string_with_options(&types, serde_saphyr::SerializerOptions {
        empty_as_braces: false, // bug in serde-saphyr fails to indent empty lists when preceded by an enum struct variant
        ..Default::default()
    })?)
}

#[repr(C)]
#[derive(Clone)]
pub struct TypeSyncOptions {
    project_path: UnsafeString,
    includes: UnsafeList<UnsafeString>,
    files: UnsafeList<UnsafeString>,
    languages: UnsafeList<Language>,
    short_enums: Bool32,
    signed_char: Bool32,
}

impl TryAsSafe for TypeSyncOptions {
    type SafeType = SafeTypeSyncOptions;

    unsafe fn try_as_safe(&self) -> Result<Self::SafeType> {
        let project_path = PathBuf::from(self.project_path.try_as_safe()?);
        let includes = self.includes.try_as_safe()?.into_iter().collect();
        let files = self.files.try_as_safe()?.into_iter().collect();
        let languages = self.languages.try_as_safe()?.into_iter().collect();
        let short_enums = self.short_enums.clone().into();
        let signed_char = self.signed_char.clone().into();
        Ok(SafeTypeSyncOptions { project_path, includes, files, languages, short_enums, signed_char })
    }
}

impl TryAsSafe for Language {
    type SafeType = Language;

    unsafe fn try_as_safe(&self) -> Result<Self::SafeType> {
        Ok(*self)
    }
}
