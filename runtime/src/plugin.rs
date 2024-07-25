use crate::*;

use convert::ToBytes;
use futures::StreamExt;
use futures_time::{prelude::*, time::Duration};

use self::plugin_builder::CacheConfig;

#[repr(transparent)]
pub struct CurrentPlugin<'a>(pub(crate) wasmtime::Caller<'a, CallContext>);

impl<'a> CurrentPlugin<'a> {
    pub fn input(&self) -> Pipe {
        self.0.data().stack.current().input()
    }

    pub fn output(&self) -> Pipe {
        self.0.data().stack.current().output()
    }

    pub fn input_bytes(&self) -> Vec<u8> {
        self.0.data().stack.current().input().take()
    }

    pub fn output_bytes(&self, data: impl AsRef<[u8]>) -> Result<(), Error> {
        self.0
            .data()
            .stack
            .current()
            .output()
            .write_all(data.as_ref())?;
        Ok(())
    }

    pub fn handle_data(&mut self, h: u64) -> Result<&mut [u8], Error> {
        let (offs, len) = pdk::handle(h);
        let offs = offs as usize;
        let len = len as usize;
        let data = self
            .0
            .get_export("memory")
            .unwrap()
            .into_memory()
            .unwrap()
            .data_mut(&mut self.0);
        if offs > data.len() || offs + len > data.len() {
            anyhow::bail!("Invalid memory handle: offs={}, len={}", offs, len);
        }
        Ok(&mut data[offs..offs + len])
    }
}

pub struct Plugin {
    pub(crate) id: uuid::Uuid,
    pub(crate) store: wasmtime::Store<CallContext>,
    pub(crate) linker: wasmtime::Linker<CallContext>,
    pub(crate) instance: Option<wasmtime::Instance>,
    pub(crate) modules: HashMap<String, wasmtime::Module>,
    pub(crate) timeout: Option<Duration>,
    pub(crate) cancel: Option<(CancelHandle, futures_time::channel::Receiver<()>)>,
    pub(crate) debug_options: DebugOptions,
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

async fn link_modules(
    mut store: &mut wasmtime::Store<CallContext>,
    linker: &mut wasmtime::Linker<CallContext>,
    name: &str,
    module: wasmtime::Module,
    modules: &HashMap<String, wasmtime::Module>,
    linked: &mut HashSet<String>,
) -> Result<(), Error> {
    for import in module.imports() {
        let mname = import.module();

        if !linked.contains(mname) {
            if let Some(m) = modules.get(mname).cloned() {
                linker.module_async(&mut store, name, &m).await?;
                linked.insert(mname.to_string());
            }
        }
    }

    linker.module_async(store, name, &module).await?;
    linked.insert(name.to_string());

    Ok(())
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
        cache_config: CacheConfig,
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

        let memory_limiter = if let Some(pgs) = &manifest.memory.max_pages {
            let n = *pgs as usize * 65536;
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

            if let Some(p) = &manifest.allowed_paths {
                for (k, v) in p.iter() {
                    wasi.preopened_dir(
                        k,
                        v.to_string_lossy(),
                        wasmtime_wasi::DirPerms::READ | wasmtime_wasi::DirPerms::MUTATE,
                        wasmtime_wasi::FilePerms::READ | wasmtime_wasi::FilePerms::WRITE,
                    )?;
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
                config: manifest.config,
                vars: HashMap::default(),
                memory_limiter,
                wasi_ctx,
                max_http_response_bytes: manifest.memory.max_http_response_bytes,
                max_var_bytes: manifest.memory.max_var_bytes,
            },
        );
        let mut linked = HashSet::new();
        let imports: Vec<_> = imports.into_iter().collect();

        let mut linker = wasmtime::Linker::new(&engine);

        if with_wasi {
            wasmtime_wasi::preview1::add_to_linker_async(&mut linker, |x: &mut CallContext| {
                x.wasi_ctx.as_mut().unwrap()
            })?;
        };

        pdk::add_functions(&engine, &mut linker, manifest.allowed_hosts)?;
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

        if manifest.memory.max_pages.is_some() {
            store.limiter_async(|internal| internal.memory_limiter.as_mut().unwrap());
        }

        Ok(Plugin {
            id,
            store,
            linker,
            modules,
            instance: None,
            timeout: manifest.timeout_ms.map(Duration::from_millis),
            cancel: None,
            debug_options,
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

    pub(crate) async fn raw_call(
        &mut self,
        name: impl AsRef<str>,
        params: &[Val],
        results: &mut [Val],
    ) -> Result<(), Error> {
        if self.instance.is_none() {
            self.instance = Some(
                self.linker
                    .instantiate_async(&mut self.store, self.modules.get("main").unwrap())
                    .await?,
            );
        }

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
}
