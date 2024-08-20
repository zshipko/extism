use std::path::PathBuf;

use crate::*;

use convert::{FromBytes, ToBytes};
use futures::StreamExt;
use futures_time::{prelude::*, time::Duration};

use self::plugin_builder::CacheConfig;

pub struct Plugin {
    pub(crate) id: uuid::Uuid,
    pub(crate) store: wasmtime::Store<CallContext>,
    pub(crate) linker: wasmtime::Linker<CallContext>,
    pub(crate) instance: Option<wasmtime::Instance>,
    pub(crate) modules: HashMap<String, wasmtime::Module>,
    pub(crate) timeout: Option<Duration>,
    pub(crate) cancel: Option<(CancelHandle, futures_time::channel::Receiver<()>)>,
    pub(crate) debug_options: DebugOptions,
    pub(crate) instantiations: usize,
    pub(crate) require_new_instance: bool,
    pub(crate) runtime: Option<GuestRuntime>,
    pub(crate) allowed_paths: Option<BTreeMap<String, PathBuf>>,
    pub(crate) allowed_hosts: Option<Vec<String>>,
    pub(crate) functions: Vec<Function>,
}

#[derive(Clone)]
pub(crate) enum GuestRuntime {
    Haskell {
        init: wasmtime::Func,
        reactor_init: Option<wasmtime::Func>,
    },
    Wasi {
        init: wasmtime::Func,
    },
}

#[derive(Clone)]
pub struct CancelHandle(futures_time::channel::Sender<()>, uuid::Uuid);

unsafe impl Send for CancelHandle {}
unsafe impl Sync for CancelHandle {}

impl CancelHandle {
    pub fn id(&self) -> uuid::Uuid {
        self.1
    }

    pub async fn cancel(&self) -> Result<(), Error> {
        self.0.send(()).await?;
        Ok(())
    }

    pub(crate) fn cancel_blocking(&self) -> Result<(), Error> {
        self.0.send_blocking(())?;
        Ok(())
    }
}

fn link_modules<'a>(
    mut store: &'a mut wasmtime::Store<CallContext>,
    linker: &'a mut wasmtime::Linker<CallContext>,
    name: &'a str,
    module: wasmtime::Module,
    modules: &'a HashMap<String, wasmtime::Module>,
    linked: &'a mut HashSet<String>,
) -> std::pin::Pin<Box<dyn 'a + std::future::Future<Output = Result<(), Error>>>> {
    Box::pin(async move {
        for import in module.imports() {
            let mname = import.module();

            if !linked.contains(mname) {
                if let Some(m) = modules.get(mname).cloned() {
                    link_modules(&mut store, linker, mname, m, modules, linked).await?;
                }
            }
        }

        linker.module_async(store, name, &module).await?;
        linked.insert(name.to_string());

        Ok(())
    })
}

async fn relink(
    engine: wasmtime::Engine,
    id: uuid::Uuid,
    max_pages: Option<u32>,
    max_http_response_bytes: Option<u64>,
    max_var_bytes: Option<u64>,
    with_wasi: bool,
    allowed_paths: &Option<BTreeMap<String, PathBuf>>,
    allowed_hosts: &Option<Vec<String>>,
    config: BTreeMap<String, String>,
    modules: &HashMap<String, wasmtime::Module>,
    imports: &[Function],
) -> Result<(wasmtime::Linker<CallContext>, wasmtime::Store<CallContext>), Error> {
    let memory_limiter = if let Some(pgs) = max_pages {
        let n = pgs as usize * 65536;
        Some(call_context::MemoryLimiter {
            max_bytes: n,
            bytes_left: n,
        })
    } else {
        None
    };

    let wasi_ctx = if with_wasi {
        let mut wasi = wasmtime_wasi::WasiCtxBuilder::new();

        if std::env::var("EXTISM_ENABLE_WASI_OUTPUT").is_ok() {
            wasi.inherit_stdout().inherit_stderr();
        }

        if let Some(p) = allowed_paths {
            for (k, v) in p.iter() {
                if k.starts_with("ro:") {
                    let k = &k[3..];
                    wasi.preopened_dir(
                        k,
                        v.to_string_lossy(),
                        wasmtime_wasi::DirPerms::READ,
                        wasmtime_wasi::FilePerms::READ,
                    )?;
                } else {
                    wasi.preopened_dir(
                        k,
                        v.to_string_lossy(),
                        wasmtime_wasi::DirPerms::READ | wasmtime_wasi::DirPerms::MUTATE,
                        wasmtime_wasi::FilePerms::READ | wasmtime_wasi::FilePerms::WRITE,
                    )?;
                };
            }
        }

        Some(wasi.build_p1())
    } else {
        None
    };

    let mut store = wasmtime::Store::new(
        &engine,
        CallContext {
            id,
            stack: Stack::new(),
            http_response: None,
            http_response_status: 0,
            config,
            vars: HashMap::default(),
            memory_limiter,
            wasi_ctx,
            max_http_response_bytes,
            max_var_bytes,
            main_memory: None,
        },
    );
    let mut linked = HashSet::new();
    let mut linker = wasmtime::Linker::new(&engine);

    if with_wasi {
        wasmtime_wasi::preview1::add_to_linker_async(&mut linker, |x: &mut CallContext| {
            x.wasi_ctx.as_mut().unwrap()
        })?;
    };

    pdk::add_functions(&engine, &mut linker, allowed_hosts.clone())?;
    for f in imports.iter() {
        let ft = wasmtime::FuncType::new(&engine, f.params.clone(), f.results.clone());
        let f = f.clone();
        linker.func_new_async(
            f.module.as_str(),
            f.name.as_str(),
            ft,
            move |caller, params, results| {
                let g = unsafe {
                    &*(f.callback.as_ref() as *const function::FunctionInner
                        as *const function::FunctionInnerOriginal)
                };
                g(caller, params, results)
            },
        )?;
    }

    if let Some(main) = modules.get("main").cloned() {
        link_modules(&mut store, &mut linker, "main", main, &modules, &mut linked).await?;
    } else {
        anyhow::bail!("no main module provided")
    };

    if max_pages.is_some() {
        store.limiter_async(|internal| internal.memory_limiter.as_mut().unwrap());
    }

    Ok((linker, store))
}

impl Plugin {
    pub fn id(&self) -> uuid::Uuid {
        self.id
    }

    pub(crate) async fn new_ex<'a>(
        wasm: impl Into<WasmInput<'a>>,
        imports: impl IntoIterator<Item = Function>,
        with_wasi: bool,
        debug_options: DebugOptions,
        cache_config: crate::plugin_builder::CacheConfig,
    ) -> Result<Self, Error> {
        let id = uuid::Uuid::new_v4();
        let mut config = wasmtime::Config::new();
        config
            .debug_info(debug_options.debug_info)
            .coredump_on_trap(debug_options.coredump.is_some())
            .profiler(debug_options.profiling_strategy)
            .wasm_tail_call(true)
            .wasm_function_references(true)
            .wasm_gc(true)
            .async_support(true);

        match cache_config {
            CacheConfig::Disable => (),
            CacheConfig::Path(path) => {
                config.cache_config_load(path)?;
            }
            CacheConfig::Default => {
                if let Ok(env) = std::env::var("EXTISM_CACHE_CONFIG") {
                    if !env.is_empty() {
                        config.cache_config_load(&env)?;
                    }
                } else {
                    config.cache_config_load_default()?;
                }
            }
        }
        let engine = wasmtime::Engine::new(&config)?;
        let (manifest, modules) = manifest::load(&engine, wasm.into()).await?;
        let imports: Vec<_> = imports.into_iter().collect();

        let (linker, store) = relink(
            engine,
            id,
            manifest.memory.max_pages,
            manifest.memory.max_http_response_bytes,
            manifest.memory.max_var_bytes,
            with_wasi,
            &manifest.allowed_paths,
            &manifest.allowed_hosts,
            manifest.config,
            &modules,
            &imports,
        )
        .await?;

        Ok(Plugin {
            id,
            store,
            linker,
            modules,
            instance: None,
            timeout: manifest.timeout_ms.map(Duration::from_millis),
            cancel: None,
            debug_options,
            instantiations: 0,
            runtime: None,
            require_new_instance: false,
            allowed_paths: manifest.allowed_paths,
            allowed_hosts: manifest.allowed_hosts,
            functions: imports,
        })
    }

    pub async fn new<'a>(
        wasm: impl Into<WasmInput<'a>>,
        imports: impl IntoIterator<Item = Function>,
        with_wasi: bool,
    ) -> Result<Self, Error> {
        Self::new_ex(
            wasm,
            imports,
            with_wasi,
            Default::default(),
            CacheConfig::Default,
        )
        .await
    }

    pub fn input(&mut self) -> Pipe {
        self.store.data_mut().stack.current().input()
    }

    pub fn with_input(&mut self, buf: impl AsRef<[u8]>, close: bool) -> Result<&mut Self, Error> {
        let mut input = self.input();
        input.write_all(buf.as_ref())?;
        if close {
            input.close()
        }
        Ok(self)
    }

    pub fn cancel_handle(&mut self) -> CancelHandle {
        if let Some((s, _)) = &self.cancel {
            return s.clone();
        }

        let (tx, rx) = futures_time::channel::bounded(1);
        self.cancel = Some((CancelHandle(tx, self.id), rx));
        self.cancel.as_ref().unwrap().0.clone()
    }

    async fn reset_store(&mut self) -> Result<(), Error> {
        let engine = self.store.engine().clone();
        let internal = self.store.data();
        let with_wasi = internal.wasi_ctx.is_some();

        let (linker, store) = relink(
            engine,
            self.id,
            internal
                .memory_limiter
                .as_ref()
                .map(|x| (x.max_bytes / 65536) as u32),
            internal.max_http_response_bytes,
            internal.max_var_bytes,
            with_wasi,
            &self.allowed_paths,
            &self.allowed_hosts,
            internal.config.clone(),
            &self.modules,
            &self.functions,
        )
        .await?;
        self.store = store;
        self.linker = linker;
        self.instantiations = 0;
        Ok(())
    }

    pub(crate) async fn instantiate(&mut self) -> Result<(), Error> {
        if self.instance.is_none() || self.require_new_instance {
            if self.instantiations > 1000 {
                self.reset_store().await?;
            }

            self.instance = Some(
                self.linker
                    .instantiate_async(&mut self.store, self.modules.get("main").unwrap())
                    .await?,
            );
            self.store.data_mut().main_memory = Some(
                self.instance
                    .as_ref()
                    .unwrap()
                    .get_export(&mut self.store, "memory")
                    .unwrap()
                    .into_memory()
                    .unwrap()
                    .clone(),
            );

            self.detect_guest_runtime();
            self.initialize_guest_runtime().await?;

            self.instantiations += 1;
        }

        Ok(())
    }

    pub(crate) async fn raw_call(
        &mut self,
        name: impl AsRef<str>,
        params: &[Val],
        results: &mut [Val],
    ) -> Result<(), Error> {
        self.instantiate().await?;

        // Ensure stack has a frame available
        self.store.data().stack.current();

        let f = self
            .instance
            .as_mut()
            .unwrap()
            .get_func(&mut self.store, name.as_ref())
            .unwrap();

        let res = if let (Some(t), Some(c)) = (&self.timeout, &mut self.cancel) {
            // Timeout and cancellation token
            match f
                .call_async(&mut self.store, params, results)
                .timeout(t.clone())
                .timeout(c.1.next())
                .await
            {
                Ok(Err(_)) => Err(Error::msg("timeout")),
                Err(_) => Err(Error::msg("cancelled")),
                Ok(Ok(Err(e))) => Err(e),
                Ok(Ok(Ok(()))) => Ok(()),
            }
        } else if let Some(t) = &self.timeout {
            // Only timeout
            match f
                .call_async(&mut self.store, params, results)
                .timeout(t.clone())
                .await
            {
                Err(_) => Err(Error::msg("timeout")),
                Ok(Err(e)) => Err(e),
                Ok(Ok(())) => Ok(()),
            }
        } else if let Some(c) = &mut self.cancel {
            // Only cancellation token
            match f
                .call_async(&mut self.store, params, results)
                .timeout(c.1.next())
                .await
            {
                Err(_) => Err(Error::msg("cancelled")),
                Ok(Err(e)) => Err(e),
                Ok(Ok(())) => Ok(()),
            }
        } else {
            // No timeout or cancellation token
            f.call_async(&mut self.store, params, results).await
        };

        self.require_new_instance = name.as_ref() == "_start";

        let res = match res {
            Ok(()) => Ok(()),
            Err(e) => {
                tracing::error!(
                    plugin = self.id.to_string(),
                    "call to {} encountered an error: {e:?}",
                    name.as_ref()
                );
                if let Some(coredump) = e.downcast_ref::<wasmtime::WasmCoreDump>() {
                    if let Some(file) = self.debug_options.coredump.clone() {
                        tracing::debug!(
                            plugin = self.id.to_string(),
                            "saving coredump to {}",
                            file.display()
                        );

                        if let Err(e) =
                            std::fs::write(file, coredump.serialize(&mut self.store, "extism"))
                        {
                            tracing::error!(
                                plugin = self.id.to_string(),
                                "unable to write coredump: {:?}",
                                e
                            );
                        }
                    }
                }

                if let Some(file) = &self.debug_options.memdump.clone() {
                    tracing::trace!(plugin = self.id.to_string(), "memory dump enabled");
                    if let Some(memory) =
                        self.instance.unwrap().get_memory(&mut self.store, "memory")
                    {
                        tracing::debug!(
                            plugin = self.id.to_string(),
                            "dumping memory to {}",
                            file.display()
                        );
                        let data = memory.data(&mut self.store);
                        if let Err(e) = std::fs::write(file, data) {
                            tracing::error!(
                                plugin = self.id.to_string(),
                                "unable to write memory dump: {:?}",
                                e
                            );
                        }
                    } else {
                        tracing::error!(
                            plugin = self.id.to_string(),
                            "unable to get extism memory for writing to disk",
                        );
                    }
                }

                Err(e)
            }
        };

        // Reset input
        self.store.data_mut().stack.current().input().reset();

        res
    }

    pub async fn call_with_args<Output: FromBytesOwned>(
        &mut self,
        name: impl AsRef<str>,
        params: &[Val],
        results: &mut [Val],
    ) -> Result<Output, Error> {
        self.raw_call(name, params, results).await?;
        self.output()
    }

    pub async fn call<'a, Input: ToBytes<'a>, Output: FromBytesOwned>(
        &mut self,
        name: impl AsRef<str>,
        input: Input,
    ) -> Result<Output, Error> {
        self.with_input(input.to_bytes()?.as_ref(), true)?
            .call_with_args(name, &[], &mut [])
            .await
    }

    pub(crate) fn take_output(&self) -> Vec<u8> {
        self.store.data().stack.current().output().take()
    }

    pub(crate) fn output<Output: FromBytesOwned>(&mut self) -> Result<Output, Error> {
        // Get output a clear the buffer
        let out = self.take_output();
        Output::from_bytes_owned(&out)
    }

    // Do a best-effort attempt to detect any guest runtime.
    fn detect_guest_runtime(&mut self) {
        let instance = match &mut self.instance {
            None => return,
            Some(x) => x,
        };
        // Check for Haskell runtime initialization functions
        // Initialize Haskell runtime if `hs_init` is present,
        // by calling the `hs_init` export

        if let Some(init) = instance.get_func(&mut self.store, "hs_init") {
            let reactor_init = if let Some(init) = instance.get_func(&mut self.store, "_initialize")
            {
                if init.typed::<(), ()>(&self.store).is_err() {
                    tracing::trace!(
                        plugin = self.id.to_string(),
                        "_initialize function found with type {:?}",
                        init.ty(&self.store)
                    );
                    None
                } else {
                    tracing::trace!(plugin = self.id.to_string(), "WASI reactor module detected");
                    Some(init)
                }
            } else {
                None
            };
            self.runtime = Some(GuestRuntime::Haskell { init, reactor_init });
            return;
        }

        // Check for `__wasm_call_ctors` or `_initialize`, this is used by WASI to
        // initialize certain interfaces.
        let init = if let Some(init) = instance.get_func(&mut self.store, "__wasm_call_ctors") {
            if init.typed::<(), ()>(&self.store).is_err() {
                tracing::trace!(
                    plugin = self.id.to_string(),
                    "__wasm_call_ctors function found with type {:?}",
                    init.ty(&self.store)
                );
                return;
            }
            tracing::trace!(plugin = self.id.to_string(), "WASI runtime detected");
            init
        } else if let Some(init) = instance.get_func(&mut self.store, "_initialize") {
            if init.typed::<(), ()>(&self.store).is_err() {
                tracing::trace!(
                    plugin = self.id.to_string(),
                    "_initialize function found with type {:?}",
                    init.ty(&self.store)
                );
                return;
            }
            tracing::trace!(plugin = self.id.to_string(), "reactor module detected");
            init
        } else {
            return;
        };

        self.runtime = Some(GuestRuntime::Wasi { init });

        tracing::trace!(plugin = self.id.to_string(), "no runtime detected");
    }

    // Initialize the guest runtime
    pub(crate) async fn initialize_guest_runtime(&mut self) -> Result<(), Error> {
        let mut store = &mut self.store;
        if let Some(runtime) = &self.runtime {
            tracing::trace!(plugin = self.id.to_string(), "Plugin::initialize_runtime");
            match runtime {
                GuestRuntime::Haskell { init, reactor_init } => {
                    if let Some(reactor_init) = reactor_init {
                        reactor_init.call_async(&mut store, &[], &mut []).await?;
                    }
                    let mut results = vec![Val::I32(0); init.ty(&store).results().len()];
                    init.call(
                        &mut store,
                        &[Val::I32(0), Val::I32(0)],
                        results.as_mut_slice(),
                    )?;
                    tracing::debug!(
                        plugin = self.id.to_string(),
                        "initialized Haskell language runtime"
                    );
                }
                GuestRuntime::Wasi { init } => {
                    init.call_async(&mut store, &[], &mut []).await?;
                    tracing::debug!(plugin = self.id.to_string(), "initialied WASI runtime");
                }
            }
        }

        Ok(())
    }
}

pub struct CallBuilder<'a> {
    plugin: &'a mut Plugin,
    params: Vec<Val>,
    results: Vec<Val>,
}

pub trait IntoVal {
    fn into_val(self, store: &mut wasmtime::Store<CallContext>) -> Val;
}

impl IntoVal for i32 {
    fn into_val(self, _store: &mut wasmtime::Store<CallContext>) -> Val {
        Val::I32(self)
    }
}

impl IntoVal for i64 {
    fn into_val(self, _store: &mut wasmtime::Store<CallContext>) -> Val {
        Val::I64(self)
    }
}

impl IntoVal for u32 {
    fn into_val(self, _store: &mut wasmtime::Store<CallContext>) -> Val {
        Val::I32(self as i32)
    }
}

impl IntoVal for u64 {
    fn into_val(self, _store: &mut wasmtime::Store<CallContext>) -> Val {
        Val::I64(self as i64)
    }
}

impl IntoVal for i128 {
    fn into_val(self, _store: &mut wasmtime::Store<CallContext>) -> Val {
        Val::V128((self as u128).into())
    }
}

impl IntoVal for u128 {
    fn into_val(self, _store: &mut wasmtime::Store<CallContext>) -> Val {
        Val::V128(self.into())
    }
}

impl IntoVal for f32 {
    fn into_val(self, _store: &mut wasmtime::Store<CallContext>) -> Val {
        Val::F32(self as u32)
    }
}

impl IntoVal for f64 {
    fn into_val(self, _store: &mut wasmtime::Store<CallContext>) -> Val {
        Val::F64(self as u64)
    }
}

impl<T: Send + Sync + 'static> IntoVal for std::sync::Arc<T> {
    fn into_val(self, mut store: &mut wasmtime::Store<CallContext>) -> Val {
        let x = wasmtime::ExternRef::new(&mut store, self).unwrap();
        Val::ExternRef(Some(x))
    }
}

impl<T: Send + Sync + 'static> IntoVal for std::sync::Mutex<T> {
    fn into_val(self, mut store: &mut wasmtime::Store<CallContext>) -> Val {
        let x = wasmtime::ExternRef::new(&mut store, self).unwrap();
        Val::ExternRef(Some(x))
    }
}

impl<T: Send + Sync + 'static> IntoVal for std::sync::RwLock<T> {
    fn into_val(self, mut store: &mut wasmtime::Store<CallContext>) -> Val {
        let x = wasmtime::ExternRef::new(&mut store, self).unwrap();
        Val::ExternRef(Some(x))
    }
}

impl<'a> CallBuilder<'a> {
    pub fn new(plugin: &'a mut Plugin) -> Self {
        CallBuilder {
            plugin,
            params: vec![],
            results: vec![],
        }
    }

    pub fn result(mut self, x: ValType) -> Self {
        let v = match x {
            ValType::I32 => Val::I32(0),
            ValType::I64 => Val::I64(0),
            ValType::F32 => Val::F32(0),
            ValType::F64 => Val::F64(0),
            ValType::V128 => Val::V128(wasmtime::V128::from(0)),
            ValType::Ref(_) => Val::ExternRef(None),
            // TODO: handle other ref types
        };

        self.results.push(v);
        self
    }

    pub fn param(mut self, x: impl IntoVal) -> Self {
        self.params.push(x.into_val(&mut self.plugin.store));
        self
    }

    pub fn input<'b, T: ToBytes<'b>>(self, x: T) -> Result<Self, Error> {
        self.plugin.with_input(x.to_bytes()?, true)?;
        Ok(self)
    }

    pub async fn call<T: FromBytesOwned>(mut self, name: impl AsRef<str>) -> Result<T, Error> {
        self.plugin
            .call_with_args(name, &self.params, &mut self.results)
            .await
    }

    pub async fn call_with_results<'b, T: 'b + FromBytes<'b>>(
        mut self,
        name: impl AsRef<str>,
    ) -> Result<CallResults<'b, T>, Error> {
        self.plugin
            .raw_call(name, &self.params, &mut self.results)
            .await?;
        Ok(CallResults {
            output: self.plugin.take_output(),
            results: self.results,
            _t: Default::default(),
        })
    }
}

pub struct CallResults<'a, T: FromBytes<'a>> {
    output: Vec<u8>,
    results: Vec<Val>,
    _t: std::marker::PhantomData<&'a T>,
}

impl<'a, T: FromBytes<'a>> CallResults<'a, T> {
    pub fn results(&self) -> &[Val] {
        &self.results
    }

    pub fn output_bytes(&self) -> &[u8] {
        &self.output
    }

    pub fn output(&'a self) -> Result<T, Error> {
        T::from_bytes(&self.output)
    }
}
