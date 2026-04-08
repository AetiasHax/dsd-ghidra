use std::path::PathBuf;

use anyhow::{Context, Result};
use exn_anyhow::into_anyhow;
use type_crawler::{Env, EnvOptions, TypeCrawler, WordSize};
use walkdir::WalkDir;

use crate::{
    list::UnsafeList,
    traits::{TryAsSafe, UnsafeString},
    types::Bool32,
};

pub struct SafeTypeSyncOptions {
    includes: Vec<PathBuf>,
    excludes: Vec<PathBuf>,
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
    for include in &options.includes {
        type_crawler.add_include_path(include).map_err(into_anyhow)?;
    }
    for include in &options.includes {
        for entry in WalkDir::new(include)
            .sort_by_file_name()
            .follow_links(true)
            .into_iter()
            .filter_entry(|entry| !options.excludes.iter().any(|exclude| entry.path().starts_with(exclude)))
        {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            type_crawler
                .parse_file(path)
                .map_err(into_anyhow)
                .with_context(|| format!("while parsing file {}", path.display()))?;
        }
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
    includes: UnsafeList<UnsafeString>,
    excludes: UnsafeList<UnsafeString>,
    short_enums: Bool32,
    signed_char: Bool32,
}

impl TryAsSafe for TypeSyncOptions {
    type SafeType = SafeTypeSyncOptions;

    unsafe fn try_as_safe(&self) -> Result<Self::SafeType> {
        let includes = self.includes.try_as_safe()?.into_iter().map(PathBuf::from).collect();
        let excludes = self.excludes.try_as_safe()?.into_iter().map(PathBuf::from).collect();
        let short_enums = self.short_enums.clone().into();
        let signed_char = self.signed_char.clone().into();
        Ok(SafeTypeSyncOptions { includes, excludes, short_enums, signed_char })
    }
}
