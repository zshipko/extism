use std::path::PathBuf;

use wasmtime::ProfilingStrategy;

use crate::*;

#[derive(Clone)]
pub struct DebugOptions {
    pub profiling_strategy: wasmtime::ProfilingStrategy,
    pub coredump: Option<std::path::PathBuf>,
    pub memdump: Option<std::path::PathBuf>,
    pub debug_info: bool,
}

pub(crate) enum CacheConfig {
    Disable,
    Default,
    Path(PathBuf),
}

pub(crate) fn profiling_strategy() -> ProfilingStrategy {
    match std::env::var("EXTISM_PROFILE").as_deref() {
        Ok("perf") => ProfilingStrategy::PerfMap,
        Ok("jitdump") => ProfilingStrategy::JitDump,
        Ok("vtune") => ProfilingStrategy::VTune,
        Ok(x) => {
            tracing::warn!("Invalid value for EXTISM_PROFILE: {x}");
            ProfilingStrategy::None
        }
        Err(_) => ProfilingStrategy::None,
    }
}

impl Default for DebugOptions {
    fn default() -> Self {
        let debug_info = std::env::var("EXTISM_DEBUG").is_ok();
        let coredump = if let Ok(x) = std::env::var("EXTISM_COREDUMP") {
            Some(std::path::PathBuf::from(x))
        } else {
            None
        };
        let memdump = if let Ok(x) = std::env::var("EXTISM_MEMDUMP") {
            Some(std::path::PathBuf::from(x))
        } else {
            None
        };
        DebugOptions {
            profiling_strategy: profiling_strategy(),
            coredump,
            memdump,
            debug_info,
        }
    }
}

/// PluginBuilder is used to configure and create `Plugin` instances
pub struct PluginBuilder<'a> {
    source: WasmInput<'a>,
    wasi: bool,
    functions: Vec<Function>,
    debug_options: DebugOptions,
    cache_config: CacheConfig,
}

impl<'a> PluginBuilder<'a> {
    /// Create a new `PluginBuilder` from a `Manifest` or raw Wasm bytes
    pub fn new(plugin: impl Into<WasmInput<'a>>) -> Self {
        PluginBuilder {
            source: plugin.into(),
            wasi: false,
            functions: vec![],
            debug_options: DebugOptions::default(),
            cache_config: CacheConfig::Default,
        }
    }

    /// Enables WASI if the argument is set to `true`
    pub fn with_wasi(mut self, wasi: bool) -> Self {
        self.wasi = wasi;
        self
    }

    /// Add a single host function
    pub fn with_function<F>(
        mut self,
        module: impl Into<String>,
        name: impl Into<String>,
        args: impl IntoIterator<Item = ValType>,
        returns: impl IntoIterator<Item = ValType>,
        f: F,
    ) -> Self
    where
        F: 'static + Fn(CurrentPlugin, &[Val], &mut [Val]) -> FunctionResult + Sync + Send,
    {
        self.functions
            .push(Function::new(module, name, args, returns, f));
        self
    }

    pub fn with_function_sync<F>(
        mut self,
        module: impl Into<String>,
        name: impl Into<String>,
        args: impl IntoIterator<Item = ValType>,
        returns: impl IntoIterator<Item = ValType>,
        f: F,
    ) -> Self
    where
        F: 'static + Fn(CurrentPlugin, &[Val], &mut [Val]) -> Result<(), Error> + Sync + Send,
    {
        self.functions
            .push(Function::new_sync(module, name, args, returns, f));
        self
    }

    /// Add multiple host functions
    pub fn with_functions(mut self, f: impl IntoIterator<Item = Function>) -> Self {
        self.functions.extend(f);
        self
    }

    /// Set profiling strategy
    pub fn with_profiling_strategy(mut self, p: wasmtime::ProfilingStrategy) -> Self {
        self.debug_options.profiling_strategy = p;
        self
    }

    /// Enable Wasmtime coredump on trap
    pub fn with_coredump(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.debug_options.coredump = Some(path.into());
        self
    }

    /// Enable Extism memory dump when plugin calls return an error
    pub fn with_memdump(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.debug_options.memdump = Some(path.into());
        self
    }

    /// Compile with debug info
    pub fn with_debug_info(mut self) -> Self {
        self.debug_options.debug_info = true;
        self
    }

    /// Configure debug options
    pub fn with_debug_options(mut self, options: DebugOptions) -> Self {
        self.debug_options = options;
        self
    }

    /// Set wasmtime compilation cache config path
    pub fn with_cache_config(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cache_config = CacheConfig::Path(dir.into());
        self
    }

    /// Turn wasmtime compilation caching off
    pub fn with_cache_disabled(mut self) -> Self {
        self.cache_config = CacheConfig::Disable;
        self
    }

    /// Generate a new plugin with the configured settings
    pub async fn build(self) -> Result<Plugin, Error> {
        Plugin::new_ex(
            self.source,
            self.functions,
            self.wasi,
            self.debug_options,
            self.cache_config,
        )
        .await
    }
}
