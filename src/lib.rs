use binaryninja::{
    binaryview::{BinaryView, BinaryViewBase, BinaryViewExt},
    command::*,
    interaction::*,
    logger
};

use log::{info, warn, error, LevelFilter};

use std::num::Wrapping;

struct LazyHasher {
    file_select: bool,
}

impl LazyHasher {
    fn hash_single(value: u32, character: u8, prime: u32) -> u32 {
        (Wrapping(prime) * (Wrapping(value) ^ Wrapping(character as u32))).0
    }
    
    fn hash(string: &[u8], offset: u32, prime: u32) -> u32 {
        let mut value = offset;
    
        for i in 0..string.len() {
            value = Self::hash_single(value, string[i], prime);
        }
    
        value
    }
    
    fn hash_all(imports: &Vec<String>, seed: u32, real_hash: u32, prime: u32) -> Option<&String> {
        for import in imports {
            if Self::hash(import.as_bytes(), seed, prime) == real_hash {
                return Some(import);
            }
        }
    
        None
    }

    fn get_symbols(view: &BinaryView) -> Vec<String> {
        let mut imports = Vec::new();
    
        for import in view.symbols().iter() {
            imports.push(import.raw_name().to_string());
        }
    
        imports
    }
}

impl AddressCommand for LazyHasher {
    fn action(&self, view: &BinaryView, addr: u64) {
        let mut imports: Vec<String> = Vec::new();

        if self.file_select {
            if let Some(path) = get_open_filename_input("Select the dll that you want to scan", "*.dll") {
                match binaryninja::open_view(path.to_str().unwrap().to_string()) {
                    Ok(file_view) => {
                        imports = LazyHasher::get_symbols(&file_view);
                    }

                    Err(err) => {
                        error!("{}!", err);
                        return;
                    }
                }
            }
        }
        else {
            imports = LazyHasher::get_symbols(view);
        }

        let prime = if let Some(x) = get_integer_input("Enter the prime number used in the hash", "Prime Number (optional)") {
            x
        }
        else {
            warn!("Prime not provided, using default");

            // default prime number used in LI
            0x1000193
        };

        if let Some(seed) = get_integer_input("Enter the hash seed", "Seed") {
            if let Some(function_hash) = get_integer_input("Enter the import hash", "Function Hash") {
                let import = LazyHasher::hash_all(&imports, seed as u32, function_hash as u32, prime as u32);

                view.functions().iter().for_each(|func| {
                    if addr >= func.start() && addr <= func.highest_address() {
                        if let Some(import) = import {
                            info!("Import found! {}", import);
                            func.set_comment_at(addr, format!("{} (lazy-evaluator)", import).to_string());
                        }
                        else {
                            error!("Import could not be resolved! Try to manually select the dll that you want to scan");
                        }
                    }
                });
            }
            else {
                error!("Invalid hash!");
            }
        }
        else {
            error!("Seed is required");
        }
    }

    fn valid(&self, view: &BinaryView, addr: u64) -> bool {
        view.offset_executable(addr) && view.functions().iter().any(|func| func.start() <= addr && addr <= func.highest_address())
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn UIPluginInit() -> bool {
    logger::init(LevelFilter::Trace).unwrap();
    
    register_for_address(r"Lazy evaluator\Evaluate", "resolves the import name by comparing the lazy-import hash with the program's imports", LazyHasher{ file_select: false });
    register_for_address(r"Lazy evaluator\Evaluate (file select)", "resolves the import name by comparing hashes of the exports in the selected dll", LazyHasher{ file_select: true });
    true
}