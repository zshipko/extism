use std::collections::HashMap;
use std::fmt::Write as FmtWrite;

use tracing::trace;

use sha2::Digest;

use crate::*;

/// Defines an input type for Wasm data.
///
/// Types that implement `Into<WasmInput>` can be passed directly into `Plugin::new`
pub enum WasmInput<'a> {
    /// Raw Wasm module
    Data(std::borrow::Cow<'a, [u8]>),
    /// Owned manifest
    Manifest(Manifest),
    /// Borrowed manifest
    ManifestRef(&'a Manifest),
}

impl<'a> From<Manifest> for WasmInput<'a> {
    fn from(value: Manifest) -> Self {
        WasmInput::Manifest(value)
    }
}

impl<'a> From<&'a Manifest> for WasmInput<'a> {
    fn from(value: &'a Manifest) -> Self {
        WasmInput::ManifestRef(value)
    }
}

impl<'a> From<&'a mut Manifest> for WasmInput<'a> {
    fn from(value: &'a mut Manifest) -> Self {
        WasmInput::ManifestRef(value)
    }
}

impl<'a> From<&'a [u8]> for WasmInput<'a> {
    fn from(value: &'a [u8]) -> Self {
        WasmInput::Data(value.into())
    }
}

impl<'a> From<&'a str> for WasmInput<'a> {
    fn from(value: &'a str) -> Self {
        WasmInput::Data(value.as_bytes().into())
    }
}

impl<'a> From<Vec<u8>> for WasmInput<'a> {
    fn from(value: Vec<u8>) -> Self {
        WasmInput::Data(value.into())
    }
}

impl<'a> From<&'a Vec<u8>> for WasmInput<'a> {
    fn from(value: &'a Vec<u8>) -> Self {
        WasmInput::Data(value.into())
    }
}

fn hex(data: &[u8]) -> String {
    let mut s = String::new();
    for &byte in data {
        write!(&mut s, "{:02x}", byte).unwrap();
    }
    s
}

fn check_hash(hash: &Option<String>, data: &[u8]) -> Result<Option<String>, Error> {
    match hash {
        None => Ok(None),
        Some(hash) => {
            let digest = sha2::Sha256::digest(data);
            let hex = hex(&digest);
            if &hex != hash {
                return Err(anyhow::format_err!(
                    "Hash mismatch, found {} but expected {}",
                    hex,
                    hash
                ));
            }
            Ok(Some(hex))
        }
    }
}

/// Convert from manifest to a wasmtime Module
async fn to_module(
    engine: &wasmtime::Engine,
    wasm: &extism_manifest::Wasm,
) -> Result<(String, wasmtime::Module), Error> {
    match wasm {
        extism_manifest::Wasm::File { path, meta } => {
            if cfg!(not(feature = "register-filesystem")) {
                return Err(anyhow::format_err!("File-based registration is disabled"));
            }

            let name = meta.name.as_deref().unwrap_or("main").to_string();

            // Load file
            let buf = tokio::fs::read(path).await.map_err(|err| {
                Error::msg(format!(
                    "Unable to load Wasm file \"{}\": {}",
                    path.display(),
                    err.kind()
                ))
            })?;

            check_hash(&meta.hash, &buf)?;
            Ok((name, wasmtime::Module::new(engine, buf)?))
        }
        extism_manifest::Wasm::Data { meta, data } => {
            check_hash(&meta.hash, data)?;
            Ok((
                meta.name.as_deref().unwrap_or("main").to_string(),
                wasmtime::Module::new(engine, data)?,
            ))
        }
        extism_manifest::Wasm::Url {
            req:
                extism_manifest::HttpRequest {
                    url,
                    headers,
                    method,
                },
            meta,
        } => {
            // Use the configured name or `MAIN_KEY`
            let name = meta.name.as_deref().unwrap_or(MAIN_KEY).to_string();

            #[cfg(not(feature = "register-http"))]
            {
                return anyhow::bail!("HTTP registration is disabled");
            }

            #[cfg(feature = "register-http")]
            {
                // Setup request
                let mut req = reqwest::Client::new()
                    .request(method.as_deref().unwrap_or("GET").parse()?, url);

                for (k, v) in headers.iter() {
                    req = req.header(k, v);
                }

                // Fetch WASM code
                let r = req.send().await?.bytes().await?;
                let data = r.to_vec();

                // Check hash against manifest
                check_hash(&meta.hash, &data)?;

                // Convert fetched data to module
                let module = wasmtime::Module::new(engine, data)?;

                Ok((name.to_string(), module))
            }
        }
    }
}

const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6d];

pub(crate) async fn load(
    engine: &wasmtime::Engine,
    input: WasmInput<'_>,
) -> Result<(extism_manifest::Manifest, HashMap<String, wasmtime::Module>), Error> {
    let mut mods = HashMap::new();

    match input {
        WasmInput::Data(data) => {
            let has_magic = data.len() >= 4 && data[0..4] == WASM_MAGIC;
            let s = std::str::from_utf8(&data);
            let is_wat = s.is_ok_and(|s| {
                let s = s.trim_start();
                let starts_with_module = s.len() > 2
                    && data[0] == b'('   // First character is `(`
                    && s[1..].trim_start().starts_with("module"); // Then `module` (after any whitespace)
                starts_with_module || s.starts_with(";;") || s.starts_with("(;")
            });

            if !has_magic && !is_wat {
                trace!("Loading manifest");
                if let Ok(s) = s {
                    if let Ok(t) = serde_json::from_str::<extism_manifest::Manifest>(s) {
                        trace!("Manifest is JSON");
                        modules(engine, &t, &mut mods).await?;
                        return Ok((t, mods));
                    } else {
                        anyhow::bail!("Unknown manifest format");
                    };
                }
            }

            let m = wasmtime::Module::new(engine, data)?;
            mods.insert(MAIN_KEY.to_string(), m);
            Ok((Default::default(), mods))
        }
        WasmInput::Manifest(m) => {
            trace!("Loading from existing manifest");
            modules(engine, &m, &mut mods).await?;
            Ok((m, mods))
        }
        WasmInput::ManifestRef(m) => {
            trace!("Loading from existing manifest");
            modules(engine, m, &mut mods).await?;
            Ok((m.clone(), mods))
        }
    }
}

const MAIN_KEY: &'static str = "main";

pub(crate) async fn modules(
    engine: &wasmtime::Engine,
    manifest: &extism_manifest::Manifest,
    modules: &mut HashMap<String, wasmtime::Module>,
) -> Result<(), Error> {
    if manifest.wasm.is_empty() {
        return Err(anyhow::format_err!(
            "No wasm files specified in Extism manifest"
        ));
    }

    // If there's only one module, it should be called `main`
    if manifest.wasm.len() == 1 {
        let (_, m) = to_module(engine, &manifest.wasm[0]).await?;
        modules.insert(MAIN_KEY.to_string(), m);
        return Ok(());
    }

    for (i, f) in manifest.wasm.iter().enumerate() {
        let (mut name, m) = to_module(engine, f).await?;
        // Rename the last module to `main` if no main is defined already
        if i == manifest.wasm.len() - 1 && !modules.contains_key(MAIN_KEY) {
            name = MAIN_KEY.to_string();
        }
        if modules.contains_key(&name) {
            anyhow::bail!("Duplicate module name found in Extism manifest: {name}");
        }
        trace!("Found module {}", name);
        modules.insert(name, m);
    }

    Ok(())
}
