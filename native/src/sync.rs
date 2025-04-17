use std::path::Path;

use anyhow::{Context, Result};
use ds_decomp::config::{
    config::{Config, ConfigModule},
    delinks::Delinks,
    module::{Module, ModuleKind, OverlayModuleOptions},
    relocations::{RelocationKind, RelocationModule, Relocations},
    section::{Section, SectionKind},
    symbol::{SymData, SymbolKind, SymbolMap},
};
use ds_rom::rom::{raw::AutoloadKind, Rom, RomLoadOptions};
use unarm::arm;

use crate::{
    list::UnsafeList,
    traits::{TryIntoSafe, TryIntoUnsafe, UnsafeString},
    types::Bool32,
};

pub struct SafeDsdConfigData {
    arm9: SafeDsdSyncModule,
    autoloads: Vec<SafeDsdSyncAutoload>,
    arm9_overlays: Vec<SafeDsdSyncOverlay>,
}

pub struct SafeDsdSyncModule {
    base_address: u32,
    sections: Vec<SafeDsdSyncSection>,
    files: Vec<SafeDsdSyncDelinkFile>,
}

pub struct SafeDsdSyncAutoload {
    kind: DsdSyncAutoloadKind,
    index: u32,
    module: SafeDsdSyncModule,
}

pub struct SafeDsdSyncOverlay {
    id: u16,
    module: SafeDsdSyncModule,
}

pub struct SafeDsdSyncBaseSection {
    name: String,
    start_address: u32,
    end_address: u32,
    kind: SectionKind,
}

pub struct SafeDsdSyncSection {
    base: SafeDsdSyncBaseSection,
    functions: Vec<SafeDsdSyncFunction>,
    symbols: Vec<SafeDsdSyncDataSymbol>,
    relocations: Vec<SafeDsdSyncRelocation>,
}

pub struct SafeDsdSyncDelinkFile {
    name: String,
    sections: Vec<SafeDsdSyncBaseSection>,
}

pub struct SafeDsdSyncFunction {
    name: String,
    thumb: bool,
    start: u32,
    end: u32,
    data_ranges: Vec<DsdSyncDataRange>,
    pool_constants: Vec<u32>,
}

pub struct SafeDsdSyncDataSymbol {
    name: String,
    address: u32,
    kind: DsdSyncDataKind,
    count: u32,
}

pub struct SafeDsdSyncRelocation {
    from: u32,
    to: u32,
    kind: RelocationKind,
    module: DsdSyncRelocationModule,
    indices: Vec<u16>,
    conditional: bool,
}

impl SafeDsdConfigData {
    pub fn from_config<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let config = Config::from_file(path)?;
        let config_path = path.parent().unwrap();

        let rom = Rom::load(
            config_path.join(&config.rom_config),
            RomLoadOptions {
                key: None,
                compress: false,
                encrypt: false,
                load_files: false,
                load_banner: false,
                load_header: false,
            },
        )?;

        let arm9 = SafeDsdSyncModule::new(ModuleKind::Arm9, config_path, &config.main_module, rom.arm9().code()?, false)?;
        let rom_autoloads = rom.arm9().autoloads()?;
        let autoloads = config
            .autoloads
            .iter()
            .map(|autoload| {
                let code = rom_autoloads
                    .iter()
                    .find(|a| a.kind() == autoload.kind)
                    .with_context(|| format!("Autoload {} not present in ROM", autoload.kind))?
                    .code();

                let index = if let AutoloadKind::Unknown(index) = autoload.kind { index } else { 0 };

                Ok(SafeDsdSyncAutoload {
                    kind: match autoload.kind {
                        AutoloadKind::Itcm => DsdSyncAutoloadKind::Itcm,
                        AutoloadKind::Dtcm => DsdSyncAutoloadKind::Dtcm,
                        AutoloadKind::Unknown(_) => DsdSyncAutoloadKind::Unknown,
                    },
                    index,
                    module: SafeDsdSyncModule::new(
                        ModuleKind::Autoload(autoload.kind),
                        config_path,
                        &autoload.module,
                        code,
                        false,
                    )?,
                })
            })
            .collect::<Result<_>>()?;
        let arm9_overlays = config
            .overlays
            .iter()
            .map(|overlay| {
                let code = rom.arm9_overlays()[overlay.id as usize].code();
                Ok(SafeDsdSyncOverlay {
                    id: overlay.id,
                    module: SafeDsdSyncModule::new(
                        ModuleKind::Overlay(overlay.id),
                        config_path,
                        &overlay.module,
                        code,
                        overlay.signed,
                    )?,
                })
            })
            .collect::<Result<_>>()?;

        Ok(Self { arm9, autoloads, arm9_overlays })
    }
}

impl TryIntoUnsafe for SafeDsdConfigData {
    type UnsafeType = DsdSyncData;

    fn try_into_unsafe(self) -> Result<Self::UnsafeType> {
        Ok(DsdSyncData {
            arm9: self.arm9.try_into_unsafe()?,
            autoloads: self.autoloads.try_into_unsafe()?,
            arm9_overlays: self.arm9_overlays.try_into_unsafe()?,
        })
    }
}

impl SafeDsdSyncModule {
    pub fn new<P: AsRef<Path>>(
        module_kind: ModuleKind,
        root_path: P,
        config_module: &ConfigModule,
        code: &[u8],
        signed: bool,
    ) -> Result<Self> {
        let root_path = root_path.as_ref();

        let mut symbol_map = SymbolMap::from_file(root_path.join(&config_module.symbols))?;
        let delinks = Delinks::from_file(root_path.join(&config_module.delinks), module_kind)?;
        let relocs = Relocations::from_file(root_path.join(&config_module.relocations))?;

        let module = match module_kind {
            ModuleKind::Arm9 => Module::new_arm9(config_module.name.clone(), &mut symbol_map, relocs, delinks.sections, code),
            ModuleKind::Overlay(id) => Module::new_overlay(
                config_module.name.clone(),
                &mut symbol_map,
                relocs,
                delinks.sections,
                OverlayModuleOptions { id, code, signed },
            ),
            ModuleKind::Autoload(kind) => {
                Module::new_autoload(config_module.name.clone(), &mut symbol_map, relocs, delinks.sections, kind, code)
            }
        }?;

        let sections =
            module.sections().iter().map(|section| SafeDsdSyncSection::new(section, &module, &symbol_map)).collect::<Vec<_>>();

        let files = delinks
            .files
            .iter()
            .map(|file| SafeDsdSyncDelinkFile {
                name: file.name.clone(),
                sections: file.sections.iter().map(SafeDsdSyncBaseSection::new).collect(),
            })
            .collect();

        Ok(Self { base_address: module.base_address(), sections, files })
    }
}

impl TryIntoUnsafe for SafeDsdSyncModule {
    type UnsafeType = DsdSyncModule;

    fn try_into_unsafe(self) -> Result<Self::UnsafeType> {
        Ok(DsdSyncModule {
            base_address: self.base_address,
            sections: self.sections.try_into_unsafe()?,
            files: self.files.try_into_unsafe()?,
        })
    }
}

impl TryIntoUnsafe for SafeDsdSyncAutoload {
    type UnsafeType = DsdSyncAutoload;

    fn try_into_unsafe(self) -> Result<Self::UnsafeType> {
        Ok(DsdSyncAutoload { kind: self.kind, index: self.index, module: self.module.try_into_unsafe()? })
    }
}

impl TryIntoUnsafe for SafeDsdSyncOverlay {
    type UnsafeType = DsdSyncOverlay;

    fn try_into_unsafe(self) -> Result<Self::UnsafeType> {
        Ok(DsdSyncOverlay { id: self.id, module: self.module.try_into_unsafe()? })
    }
}

impl SafeDsdSyncBaseSection {
    pub fn new(section: &Section) -> Self {
        Self {
            name: section.name().into(),
            start_address: section.start_address(),
            end_address: section.end_address(),
            kind: section.kind(),
        }
    }
}

impl TryIntoUnsafe for SafeDsdSyncBaseSection {
    type UnsafeType = DsdSyncBaseSection;

    fn try_into_unsafe(self) -> Result<Self::UnsafeType> {
        Ok(DsdSyncBaseSection {
            name: self.name.try_into_unsafe()?,
            start_address: self.start_address.try_into_unsafe()?,
            end_address: self.end_address.try_into_unsafe()?,
            kind: self.kind,
        })
    }
}

impl SafeDsdSyncSection {
    pub fn new(section: &Section, module: &Module, symbol_map: &SymbolMap) -> Self {
        let functions = section
            .functions()
            .values()
            .map(|function| {
                let name = demangle(function.name());
                let mut data_ranges = vec![];
                for inline_table in function.inline_tables().values() {
                    data_ranges
                        .push(DsdSyncDataRange { start: inline_table.address, end: inline_table.address + inline_table.size });
                }
                for &pool_constant in function.pool_constants() {
                    data_ranges.push(DsdSyncDataRange { start: pool_constant, end: pool_constant + 4 })
                }
                for jump_table in function.jump_tables() {
                    if !jump_table.code {
                        data_ranges
                            .push(DsdSyncDataRange { start: jump_table.address, end: jump_table.address + jump_table.size });
                    }
                }
                SafeDsdSyncFunction {
                    name,
                    thumb: function.is_thumb(),
                    start: function.first_instruction_address(),
                    end: function.end_address(),
                    data_ranges,
                    pool_constants: function.pool_constants().iter().copied().collect(),
                }
            })
            .collect();

        let symbols = if section.kind().is_initialized() {
            let mut data_symbols = vec![];
            let mut iter = symbol_map
                .iter_by_address(section.address_range())
                .filter_map(
                    |symbol| {
                        if let SymbolKind::Data(sym_data) = symbol.kind {
                            Some((sym_data, symbol))
                        } else {
                            None
                        }
                    },
                )
                .peekable();
            while let Some((sym_data, symbol)) = iter.next() {
                let size = if let Some((_, next_symbol)) = iter.peek() {
                    next_symbol.addr - symbol.addr
                } else {
                    section.end_address() - symbol.addr
                };
                let (kind, count) = DsdSyncDataKind::new(&sym_data, size);
                data_symbols.push(SafeDsdSyncDataSymbol { name: demangle(&symbol.name), address: symbol.addr, kind, count });
            }
            data_symbols
        } else {
            symbol_map
                .iter_by_address(section.address_range())
                .filter_map(|symbol| {
                    if let SymbolKind::Bss(sym_bss) = symbol.kind {
                        Some(SafeDsdSyncDataSymbol {
                            name: demangle(&symbol.name),
                            address: symbol.addr,
                            kind: DsdSyncDataKind::Any,
                            count: sym_bss.size.unwrap_or(0),
                        })
                    } else {
                        None
                    }
                })
                .collect()
        };

        let relocations = module
            .relocations()
            .iter_range(section.address_range())
            .map(|(_, relocation)| {
                let (reloc_module, indices) = match relocation.module() {
                    RelocationModule::None => (DsdSyncRelocationModule::None, vec![]),
                    RelocationModule::Overlay { id } => (DsdSyncRelocationModule::Overlays, vec![*id]),
                    RelocationModule::Overlays { ids } => (DsdSyncRelocationModule::Overlays, ids.clone()),
                    RelocationModule::Main => (DsdSyncRelocationModule::Main, vec![]),
                    RelocationModule::Itcm => (DsdSyncRelocationModule::Itcm, vec![]),
                    RelocationModule::Dtcm => (DsdSyncRelocationModule::Dtcm, vec![]),
                    RelocationModule::Autoload { index } => (DsdSyncRelocationModule::Autoload, vec![*index as u16]),
                };
                let conditional = match relocation.kind() {
                    RelocationKind::ArmCall | RelocationKind::ArmCallThumb | RelocationKind::ArmBranch => {
                        let start = relocation.from_address() - module.base_address();
                        let end = start + 4;
                        let code = &module.code()[start as usize..end as usize];
                        let code = u32::from_le_bytes([code[0], code[1], code[2], code[3]]);
                        let ins = arm::Ins::new(code, &Default::default());
                        ins.is_conditional()
                    }
                    RelocationKind::ThumbCall | RelocationKind::ThumbCallArm => false,
                    RelocationKind::Load => false,
                };
                SafeDsdSyncRelocation {
                    from: relocation.from_address(),
                    to: (relocation.to_address() as i32 + relocation.addend_value()) as u32,
                    kind: relocation.kind(),
                    module: reloc_module,
                    indices,
                    conditional,
                }
            })
            .collect();

        Self { base: SafeDsdSyncBaseSection::new(section), functions, symbols, relocations }
    }
}

fn demangle(s: &str) -> String {
    if s.starts_with("_Z") {
        match cpp_demangle::Symbol::new(s) {
            Ok(demangled) => demangled.to_string(),
            Err(_) => s.into(),
        }
    } else {
        s.into()
    }
}

impl TryIntoUnsafe for SafeDsdSyncSection {
    type UnsafeType = DsdSyncSection;

    fn try_into_unsafe(self) -> Result<Self::UnsafeType> {
        Ok(DsdSyncSection {
            base: self.base.try_into_unsafe()?,
            functions: self.functions.try_into_unsafe()?,
            symbols: self.symbols.try_into_unsafe()?,
            relocations: self.relocations.try_into_unsafe()?,
        })
    }
}

impl TryIntoUnsafe for SafeDsdSyncDelinkFile {
    type UnsafeType = DsdSyncDelinkFile;

    fn try_into_unsafe(self) -> Result<Self::UnsafeType> {
        Ok(DsdSyncDelinkFile { name: self.name.try_into_unsafe()?, sections: self.sections.try_into_unsafe()? })
    }
}

impl TryIntoUnsafe for SafeDsdSyncFunction {
    type UnsafeType = DsdSyncFunction;

    fn try_into_unsafe(self) -> Result<Self::UnsafeType> {
        Ok(DsdSyncFunction {
            name: self.name.try_into_unsafe()?,
            thumb: self.thumb.into(),
            start: self.start,
            end: self.end,
            data_ranges: self.data_ranges.try_into_unsafe()?,
            pool_constants: self.pool_constants.try_into_unsafe()?,
        })
    }
}

impl TryIntoUnsafe for DsdSyncDataRange {
    type UnsafeType = DsdSyncDataRange;

    fn try_into_unsafe(self) -> Result<Self::UnsafeType> {
        Ok(self)
    }
}

impl TryIntoUnsafe for SafeDsdSyncDataSymbol {
    type UnsafeType = DsdSyncDataSymbol;

    fn try_into_unsafe(self) -> Result<Self::UnsafeType> {
        Ok(DsdSyncDataSymbol { name: self.name.try_into_unsafe()?, address: self.address, kind: self.kind, count: self.count })
    }
}

impl TryIntoUnsafe for SafeDsdSyncRelocation {
    type UnsafeType = DsdSyncRelocation;

    fn try_into_unsafe(self) -> Result<Self::UnsafeType> {
        Ok(DsdSyncRelocation {
            from: self.from,
            to: self.to,
            kind: self.kind,
            module: self.module,
            overlays: self.indices.try_into_unsafe()?,
            conditional: self.conditional.into(),
        })
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct DsdSyncData {
    arm9: DsdSyncModule,
    autoloads: UnsafeList<DsdSyncAutoload>,
    arm9_overlays: UnsafeList<DsdSyncOverlay>,
}

#[repr(C)]
#[derive(Clone)]
pub struct DsdSyncModule {
    base_address: u32,
    sections: UnsafeList<DsdSyncSection>,
    files: UnsafeList<DsdSyncDelinkFile>,
}

#[repr(C)]
#[derive(Clone)]
pub struct DsdSyncAutoload {
    kind: DsdSyncAutoloadKind,
    index: u32,
    module: DsdSyncModule,
}

#[repr(C)]
#[derive(Clone)]
pub enum DsdSyncAutoloadKind {
    Itcm,
    Dtcm,
    Unknown,
}

#[repr(C)]
#[derive(Clone)]
pub struct DsdSyncOverlay {
    id: u16,
    module: DsdSyncModule,
}

#[repr(C)]
#[derive(Clone)]
pub struct DsdSyncBaseSection {
    name: UnsafeString,
    start_address: u32,
    end_address: u32,
    kind: SectionKind,
}

#[repr(C)]
#[derive(Clone)]
pub struct DsdSyncSection {
    base: DsdSyncBaseSection,
    functions: UnsafeList<DsdSyncFunction>,
    symbols: UnsafeList<DsdSyncDataSymbol>,
    relocations: UnsafeList<DsdSyncRelocation>,
}

#[repr(C)]
#[derive(Clone)]
pub struct DsdSyncDelinkFile {
    name: UnsafeString,
    sections: UnsafeList<DsdSyncBaseSection>,
}

#[repr(C)]
#[derive(Clone)]
pub struct DsdSyncFunction {
    name: UnsafeString,
    thumb: Bool32,
    start: u32,
    end: u32,
    data_ranges: UnsafeList<DsdSyncDataRange>,
    pool_constants: UnsafeList<u32>,
}

#[repr(C)]
#[derive(Clone)]
pub struct DsdSyncDataRange {
    start: u32,
    end: u32,
}

#[repr(C)]
#[derive(Clone)]
pub struct DsdSyncDataSymbol {
    name: UnsafeString,
    address: u32,
    kind: DsdSyncDataKind,
    count: u32,
}

#[repr(C)]
#[derive(Clone)]
pub enum DsdSyncDataKind {
    Any,
    Byte,
    Short,
    Word,
}

#[repr(C)]
#[derive(Clone)]
pub struct DsdSyncRelocation {
    from: u32,
    to: u32,
    kind: RelocationKind,
    module: DsdSyncRelocationModule,
    overlays: UnsafeList<u16>,
    conditional: Bool32,
}

#[repr(C)]
#[derive(Clone)]
pub enum DsdSyncRelocationModule {
    None,
    Overlays,
    Main,
    Itcm,
    Dtcm,
    Autoload,
}

impl TryIntoSafe for DsdSyncData {
    type SafeType = SafeDsdConfigData;

    unsafe fn try_into_safe(self) -> Result<Self::SafeType> {
        Ok(SafeDsdConfigData {
            arm9: self.arm9.try_into_safe()?,
            autoloads: self.autoloads.try_into_safe()?,
            arm9_overlays: self.arm9_overlays.try_into_safe()?,
        })
    }
}

impl TryIntoSafe for DsdSyncModule {
    type SafeType = SafeDsdSyncModule;

    unsafe fn try_into_safe(self) -> Result<Self::SafeType> {
        Ok(SafeDsdSyncModule {
            base_address: self.base_address,
            sections: self.sections.try_into_safe()?,
            files: self.files.try_into_safe()?,
        })
    }
}

impl TryIntoSafe for DsdSyncAutoload {
    type SafeType = SafeDsdSyncAutoload;

    unsafe fn try_into_safe(self) -> Result<Self::SafeType> {
        Ok(SafeDsdSyncAutoload { kind: self.kind, index: self.index, module: self.module.try_into_safe()? })
    }
}

impl TryIntoSafe for DsdSyncOverlay {
    type SafeType = SafeDsdSyncOverlay;

    unsafe fn try_into_safe(self) -> Result<Self::SafeType> {
        Ok(SafeDsdSyncOverlay { id: self.id, module: self.module.try_into_safe()? })
    }
}

impl TryIntoSafe for DsdSyncBaseSection {
    type SafeType = SafeDsdSyncBaseSection;

    unsafe fn try_into_safe(self) -> Result<Self::SafeType> {
        Ok(SafeDsdSyncBaseSection {
            name: self.name.try_into_safe()?,
            start_address: self.start_address.try_into_safe()?,
            end_address: self.end_address.try_into_safe()?,
            kind: self.kind,
        })
    }
}

impl TryIntoSafe for DsdSyncSection {
    type SafeType = SafeDsdSyncSection;

    unsafe fn try_into_safe(self) -> Result<Self::SafeType> {
        Ok(SafeDsdSyncSection {
            base: self.base.try_into_safe()?,
            functions: self.functions.try_into_safe()?,
            symbols: self.symbols.try_into_safe()?,
            relocations: self.relocations.try_into_safe()?,
        })
    }
}

impl TryIntoSafe for DsdSyncDelinkFile {
    type SafeType = SafeDsdSyncDelinkFile;

    unsafe fn try_into_safe(self) -> Result<Self::SafeType> {
        Ok(SafeDsdSyncDelinkFile { name: self.name.try_into_safe()?, sections: self.sections.try_into_safe()? })
    }
}

impl TryIntoSafe for DsdSyncFunction {
    type SafeType = SafeDsdSyncFunction;

    unsafe fn try_into_safe(self) -> Result<Self::SafeType> {
        Ok(SafeDsdSyncFunction {
            name: self.name.try_into_safe()?,
            thumb: self.thumb.into(),
            start: self.start,
            end: self.end,
            data_ranges: self.data_ranges.try_into_safe()?,
            pool_constants: self.pool_constants.try_into_safe()?,
        })
    }
}

impl TryIntoSafe for DsdSyncDataRange {
    type SafeType = DsdSyncDataRange;

    unsafe fn try_into_safe(self) -> Result<Self::SafeType> {
        Ok(self)
    }
}

impl TryIntoSafe for DsdSyncDataSymbol {
    type SafeType = SafeDsdSyncDataSymbol;

    unsafe fn try_into_safe(self) -> Result<Self::SafeType> {
        Ok(SafeDsdSyncDataSymbol {
            name: self.name.try_into_safe()?,
            address: self.address,
            kind: self.kind,
            count: self.count,
        })
    }
}

impl DsdSyncDataKind {
    pub fn new(sym_data: &SymData, size: u32) -> (Self, u32) {
        match sym_data {
            SymData::Any => (Self::Any, 0),
            SymData::Byte { count } => (Self::Byte, count.unwrap_or(size)),
            SymData::Short { count } => (Self::Short, count.unwrap_or(size / 2)),
            SymData::Word { count } => (Self::Word, count.unwrap_or(size / 4)),
        }
    }
}

impl TryIntoSafe for DsdSyncRelocation {
    type SafeType = SafeDsdSyncRelocation;

    unsafe fn try_into_safe(self) -> Result<Self::SafeType> {
        Ok(SafeDsdSyncRelocation {
            from: self.from,
            to: self.to,
            kind: self.kind,
            module: self.module,
            indices: self.overlays.try_into_safe()?,
            conditional: self.conditional.into(),
        })
    }
}
