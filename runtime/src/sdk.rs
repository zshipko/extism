#![allow(clippy::missing_safety_doc)]

use std::{
    ffi::{c_void, CString},
    os::raw::c_char,
    str::FromStr,
};

use wasmtime::ExternRef;

use crate::*;

pub struct ExtismCurrentPlugin<'a>(CurrentPlugin<'a>);
pub type ExtismMemoryHandle = u64;
pub type Size = u32;

pub struct ExtismPlugin {
    plugin: Plugin,
    error: std::ffi::CString,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum ExtismValType {
    I32,
    I64,
    F32,
    F64,
    ExternRef,
}

impl From<ExtismValType> for wasmtime::ValType {
    fn from(value: ExtismValType) -> Self {
        match value {
            ExtismValType::I32 => wasmtime::ValType::I32,
            ExtismValType::I64 => wasmtime::ValType::I64,
            ExtismValType::F32 => wasmtime::ValType::F32,
            ExtismValType::F64 => wasmtime::ValType::F64,
            ExtismValType::ExternRef => wasmtime::ValType::EXTERNREF,
        }
    }
}

impl From<wasmtime::ValType> for ExtismValType {
    fn from(value: wasmtime::ValType) -> Self {
        match value {
            wasmtime::ValType::I32 => ExtismValType::I32,
            wasmtime::ValType::I64 => ExtismValType::I64,
            wasmtime::ValType::F32 => ExtismValType::F32,
            wasmtime::ValType::F64 => ExtismValType::F64,
            t if t.is_externref() => ExtismValType::ExternRef,
            _ => todo!(),
        }
    }
}

pub struct ExtismFunction(
    std::cell::Cell<Option<Function>>,
    CVoidContainer,
    Option<unsafe extern "C" fn(*mut c_void)>,
);

/// The return code used to specify a successful plugin call
// pub static EXTISM_SUCCESS: i32 = 0;

/// A union type for host function argument/return values
#[repr(C)]
pub union ExtismValUnion {
    i32: i32,
    i64: i64,
    f32: f32,
    f64: f64,
    externref: *mut c_void,
    // TODO: v128, ExternRef, FuncRef
}

/// `ExtismVal` holds the type and value of a function argument/return
#[repr(C)]
pub struct ExtismVal {
    t: ExtismValType,
    v: ExtismValUnion,
}

/// Host function signature
pub type ExtismFunctionType = extern "C" fn(
    plugin: *mut ExtismCurrentPlugin,
    inputs: *const ExtismVal,
    n_inputs: Size,
    outputs: *mut ExtismVal,
    n_outputs: Size,
    data: *mut std::ffi::c_void,
);

/// Log drain callback
pub type ExtismLogDrainFunctionType = extern "C" fn(data: *const std::ffi::c_char, size: Size);

impl ExtismVal {
    fn from_val(value: &wasmtime::Val, mut ctx: impl wasmtime::AsContextMut) -> Self {
        match value.ty(&ctx) {
            Ok(wasmtime::ValType::I32) => ExtismVal {
                t: ExtismValType::I32,
                v: ExtismValUnion {
                    i32: value.unwrap_i32(),
                },
            },
            Ok(wasmtime::ValType::I64) => ExtismVal {
                t: ExtismValType::I64,
                v: ExtismValUnion {
                    i64: value.unwrap_i64(),
                },
            },
            Ok(wasmtime::ValType::F32) => ExtismVal {
                t: ExtismValType::F32,
                v: ExtismValUnion {
                    f32: value.unwrap_f32(),
                },
            },
            Ok(wasmtime::ValType::F64) => ExtismVal {
                t: ExtismValType::F64,
                v: ExtismValUnion {
                    f64: value.unwrap_f64(),
                },
            },
            Ok(t) if t.matches(&wasmtime::ValType::EXTERNREF) => ExtismVal {
                t: ExtismValType::ExternRef,
                v: ExtismValUnion {
                    externref: unsafe {
                        value.unwrap_externref().unwrap().to_raw(&mut ctx).unwrap() as *mut c_void
                    },
                },
            },
            t => todo!("{:?}", t),
        }
    }
}

/// Get a plugin's ID, the returned bytes are a 16 byte buffer that represent a UUIDv4
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_id(plugin: *mut ExtismPlugin) -> *const u8 {
    if plugin.is_null() {
        return std::ptr::null_mut();
    }

    let plugin = &mut *plugin;
    plugin.plugin.id.as_bytes().as_ptr()
}

/// Returns a pointer to the memory of the currently running plugin
/// NOTE: this should only be called from host functions.
#[no_mangle]
pub unsafe extern "C" fn extism_current_plugin_memory(plugin: *mut ExtismCurrentPlugin) -> *mut u8 {
    if plugin.is_null() {
        return std::ptr::null_mut();
    }

    let plugin = &mut *plugin;
    let mem = (plugin.0)
        .0
        .get_export("memory")
        .unwrap()
        .into_memory()
        .unwrap();
    mem.data_ptr(&mut (plugin.0).0)
}

/// Get the length of an Extism handle
/// NOTE: this should only be called from host functions.
#[no_mangle]
pub unsafe extern "C" fn extism_current_plugin_memory_length(
    plugin: *mut ExtismCurrentPlugin,
    n: ExtismMemoryHandle,
) -> Size {
    if plugin.is_null() {
        return 0;
    }

    (n & 0xffffffff) as u32
}

/// Create a new host function
///
/// Arguments
/// - `module_name`: this should be valid UTF-8
/// - `name`: function name, this should be valid UTF-8
/// - `inputs`: argument types
/// - `n_inputs`: number of argument types
/// - `outputs`: return types
/// - `n_outputs`: number of return types
/// - `func`: the function to call
/// - `user_data`: a pointer that will be passed to the function when it's called
///    this value should live as long as the function exists
/// - `free_user_data`: a callback to release the `user_data` value when the resulting
///   `ExtismFunction` is freed.
///
/// Returns a new `ExtismFunction` or `null` if the `name` argument is invalid.
#[no_mangle]
pub unsafe extern "C" fn extism_function_new(
    module_name: *const std::ffi::c_char,
    name: *const std::ffi::c_char,
    inputs: *const ExtismValType,
    n_inputs: Size,
    outputs: *const ExtismValType,
    n_outputs: Size,
    func: ExtismFunctionType,
    user_data: *mut std::ffi::c_void,
    free_user_data: Option<unsafe extern "C" fn(_: *mut std::ffi::c_void)>,
) -> *mut ExtismFunction {
    let module_name = match std::ffi::CStr::from_ptr(module_name).to_str() {
        Ok(x) => x.to_string(),
        Err(_) => {
            return std::ptr::null_mut();
        }
    };

    let name = match std::ffi::CStr::from_ptr(name).to_str() {
        Ok(x) => x.to_string(),
        Err(_) => {
            return std::ptr::null_mut();
        }
    };

    let inputs = if inputs.is_null() || n_inputs == 0 {
        vec![]
    } else {
        std::slice::from_raw_parts(inputs, n_inputs as usize)
            .iter()
            .copied()
            .map(From::from)
            .collect::<Vec<_>>()
    };

    let output_types = if outputs.is_null() || n_outputs == 0 {
        vec![]
    } else {
        std::slice::from_raw_parts(outputs, n_outputs as usize)
            .iter()
            .copied()
            .map(From::from)
            .collect::<Vec<_>>()
    };

    let u = CVoidContainer(user_data);
    let user_data = std::sync::Arc::new(std::sync::Mutex::new(CVoidContainer(user_data)));

    let f = Function::new_sync(
        module_name.clone(),
        name.clone(),
        inputs.clone(),
        output_types.clone(),
        move |mut plugin, inputs, outputs| {
            let inputs: Vec<_> = inputs
                .iter()
                .map(|x| ExtismVal::from_val(x, &mut plugin.0))
                .collect();
            let mut output_tmp: Vec<_> = output_types
                .iter()
                .map(|t| ExtismVal {
                    t: t.clone().into(),
                    v: match t {
                        ValType::I32 => ExtismValUnion { i32: 0 },
                        ValType::I64 => ExtismValUnion { i64: 0 },
                        ValType::F32 => ExtismValUnion { f32: 0.0 },
                        ValType::F64 => ExtismValUnion { f64: 0.0 },
                        t if t.matches(&ValType::EXTERNREF) => ExtismValUnion {
                            externref: std::ptr::null_mut(),
                        },
                        _ => ExtismValUnion { i32: 0 },
                    },
                })
                .collect();
            let mut p = ExtismCurrentPlugin(plugin);
            func(
                &mut p,
                inputs.as_ptr(),
                inputs.len() as Size,
                output_tmp.as_mut_ptr(),
                output_tmp.len() as Size,
                user_data.lock().unwrap().0,
            );

            for (tmp, out) in output_tmp.iter().zip(outputs.iter_mut()) {
                match tmp.t {
                    ExtismValType::I32 => *out = Val::I32(tmp.v.i32),
                    ExtismValType::I64 => *out = Val::I64(tmp.v.i64),
                    ExtismValType::F32 => *out = Val::F32(tmp.v.f32 as u32),
                    ExtismValType::F64 => *out = Val::F64(tmp.v.f64 as u64),
                    ExtismValType::ExternRef => {
                        *out = Val::ExternRef(Some(
                            ExternRef::new(&mut (p.0).0, CVoidContainer(tmp.v.externref)).unwrap(),
                        ))
                    }
                }
            }

            Ok(())
        },
    );
    Box::into_raw(Box::new(ExtismFunction(
        std::cell::Cell::new(Some(f)),
        u,
        free_user_data,
    )))
}

/// Free `ExtismFunction`
#[no_mangle]
pub unsafe extern "C" fn extism_function_free(f: *mut ExtismFunction) {
    if f.is_null() {
        return;
    }

    let f = Box::from_raw(f);
    if let Some(free) = f.2 {
        free((f.1).0)
    }
}

/// Create a new plugin with host functions, the functions passed to this function no longer need to be manually freed using
///
/// `wasm`: is a WASM module (wat or wasm) or a JSON encoded manifest
/// `wasm_size`: the length of the `wasm` parameter
/// `functions`: an array of `ExtismFunction*`
/// `n_functions`: the number of functions provided
/// `with_wasi`: enables/disables WASI
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_new(
    wasm: *const u8,
    wasm_size: Size,
    functions: *mut *const ExtismFunction,
    n_functions: Size,
    with_wasi: bool,
    errmsg: *mut *mut std::ffi::c_char,
) -> *mut ExtismPlugin {
    tracing::trace!("Call to extism_plugin_new with wasm pointer {:?}", wasm);
    let data = std::slice::from_raw_parts(wasm, wasm_size as usize);
    let mut funcs = vec![];

    if !functions.is_null() {
        for i in 0..n_functions {
            unsafe {
                let f = *functions.add(i as usize);
                if f.is_null() {
                    continue;
                }
                if let Some(f) = (*f).0.take() {
                    funcs.push(f);
                } else {
                    let e = std::ffi::CString::new(
                        "Function cannot be registered with multiple different Plugins",
                    )
                    .unwrap();
                    *errmsg = e.into_raw();
                }
            }
        }
    }

    let manifest = match serde_json::from_slice(&data) {
        Ok(m) => m,
        Err(_) => Manifest::new([Wasm::data(data)]),
    };

    let plugin = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(Plugin::new(manifest, funcs, with_wasi));
    match plugin {
        Err(e) => {
            if !errmsg.is_null() {
                let e = std::ffi::CString::new(format!("Unable to create Extism plugin: {}", e))
                    .unwrap();
                *errmsg = e.into_raw();
            }
            std::ptr::null_mut()
        }
        Ok(p) => Box::into_raw(Box::new(ExtismPlugin {
            plugin: p,
            error: CString::default(),
        })),
    }
}

/// Free the error returned by `extism_plugin_new`, errors returned from `extism_plugin_error` don't need to be freed
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_new_error_free(err: *mut std::ffi::c_char) {
    if err.is_null() {
        return;
    }
    drop(std::ffi::CString::from_raw(err))
}

/// Remove a plugin from the registry and free associated memory
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_free(plugin: *mut ExtismPlugin) {
    if plugin.is_null() {
        return;
    }

    let plugin = Box::from_raw(plugin);
    tracing::trace!(
        plugin = plugin.plugin.id.to_string(),
        "called extism_plugin_free"
    );
    drop(plugin)
}

/// Get handle for plugin cancellation
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_cancel_handle(
    plugin: *mut ExtismPlugin,
) -> *const CancelHandle {
    if plugin.is_null() {
        return std::ptr::null();
    }
    let plugin = &mut *plugin;
    tracing::trace!(
        plugin = plugin.plugin.id.to_string(),
        "called extism_plugin_cancel_handle"
    );
    plugin.plugin.cancel_handle();
    &plugin.plugin.cancel.as_ref().unwrap().0
}

/// Cancel a running plugin
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_cancel(handle: *const CancelHandle) -> bool {
    let handle = &*handle;
    tracing::trace!(
        plugin = handle.id().to_string(),
        "called extism_plugin_cancel"
    );

    handle.cancel_blocking().is_ok()
}

// Returns true if `func_name` exists
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_function_exists(
    plugin: *mut ExtismPlugin,
    func_name: *const c_char,
) -> bool {
    if plugin.is_null() {
        return false;
    }
    let plugin = &mut *plugin;

    let name = std::ffi::CStr::from_ptr(func_name);
    tracing::trace!(
        plugin = plugin.plugin.id.to_string(),
        "extism_plugin_function_exists: {:?}",
        name
    );

    let name = match name.to_str() {
        Ok(x) => x,
        Err(_e) => return false,
    };

    plugin
        .plugin
        .modules
        .get("main")
        .unwrap()
        .get_export(name)
        .is_some_and(|x| matches!(x, wasmtime::ExternType::Func(_)))
}

const INVALID_PLUGIN: &'static str = "invalid plugin\0";

/// Call a function
///
/// `func_name`: is the function to call
/// `data`: is the input data
/// `data_len`: is the length of `data`
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_call(
    plugin: *mut ExtismPlugin,
    func_name: *const c_char,
    data: *const u8,
    data_len: Size,
) -> *const c_char {
    if plugin.is_null() {
        return INVALID_PLUGIN.as_ptr() as *const _;
    }
    let plugin = &mut *plugin;

    // Get function name
    let name = std::ffi::CStr::from_ptr(func_name);
    let name = match name.to_str() {
        Ok(name) => name,
        Err(e) => {
            plugin.error = CString::new(e.to_string()).unwrap();
            return plugin.error.as_ptr();
        }
    };

    tracing::trace!(
        plugin = plugin.plugin.id.to_string(),
        "calling function {} using extism_plugin_call",
        name
    );
    let input = std::slice::from_raw_parts(data, data_len as usize);
    let res = tokio::runtime::Runtime::new().unwrap().block_on(
        plugin
            .plugin
            .with_input(input, true)
            .unwrap()
            .raw_call(name, &[], &mut []),
    );
    match res {
        Err(e) => {
            plugin.error = CString::new(e.to_string()).unwrap();
            return plugin.error.as_ptr();
        }
        Ok(()) => std::ptr::null(),
    }
}

#[derive(Clone)]
#[repr(transparent)]
struct CVoidContainer(*mut std::ffi::c_void);

// "You break it, you buy it."
unsafe impl Send for CVoidContainer {}
unsafe impl Sync for CVoidContainer {}

/// Get the error associated with a `Plugin`
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_error(plugin: *mut ExtismPlugin) -> *const c_char {
    if plugin.is_null() {
        return std::ptr::null();
    }
    let plugin = &mut *plugin;

    plugin.error.as_ptr()
}

// Get the length of a plugin's output data
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_output_length(plugin: *mut ExtismPlugin) -> Size {
    if plugin.is_null() {
        return 0;
    }
    let plugin = &mut *plugin;
    tracing::trace!(
        plugin = plugin.plugin.id.to_string(),
        "extism_plugin_output_length",
    );
    let out = plugin.plugin.store.data().stack.current().output();
    let out = out.data.read().unwrap();
    out.len() as Size
}

// Get a pointer to the output data
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_output_data(plugin: *mut ExtismPlugin) -> *const u8 {
    if plugin.is_null() {
        return std::ptr::null();
    }
    let plugin = &mut *plugin;
    tracing::trace!(
        plugin = plugin.plugin.id.to_string(),
        "extism_plugin_output_data",
    );
    let out = plugin.plugin.store.data().stack.current().output();
    let out = out.data.read().unwrap();
    let ptr = out.as_ptr();
    ptr
}

/// Set log file and level.
/// The log level can be either one of: info, error, trace, debug, warn or a more
/// complex filter like `extism=trace,cranelift=debug`
/// The file will be created if it doesn't exist.
#[no_mangle]
pub unsafe extern "C" fn extism_log_file(
    filename: *const c_char,
    log_level: *const c_char,
) -> bool {
    let file = if !filename.is_null() {
        let file = std::ffi::CStr::from_ptr(filename);
        match file.to_str() {
            Ok(x) => x,
            Err(_) => {
                return false;
            }
        }
    } else {
        "stderr"
    };

    let level = if !log_level.is_null() {
        let level = std::ffi::CStr::from_ptr(log_level);
        match level.to_str() {
            Ok(x) => x,
            Err(_) => {
                return false;
            }
        }
    } else {
        "error"
    };

    set_log_file(file, level).is_ok()
}

// Set the log file Extism will use, this is a global configuration
fn set_log_file(log_file: impl Into<std::path::PathBuf>, filter: &str) -> Result<(), Error> {
    let log_file = log_file.into();
    let s = log_file.to_str();

    let is_level = tracing::Level::from_str(filter).is_ok();
    let cfg = tracing_subscriber::FmtSubscriber::builder().with_env_filter({
        let x = tracing_subscriber::EnvFilter::builder()
            .with_default_directive(tracing::Level::ERROR.into());
        if is_level {
            x.parse_lossy(format!("extism={}", filter))
        } else {
            x.parse_lossy(filter)
        }
    });

    let res = if s == Some("-") || s == Some("stderr") {
        cfg.with_ansi(true).with_writer(std::io::stderr).try_init()
    } else if s == Some("stdout") {
        cfg.with_ansi(true).with_writer(std::io::stdout).try_init()
    } else {
        let log_file = log_file.to_path_buf();
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)
            .expect("Open log file");
        cfg.with_ansi(false)
            .with_writer(move || f.try_clone().unwrap())
            .try_init()
    };

    if let Err(e) = res {
        return Err(Error::msg(e.to_string()));
    }
    Ok(())
}

static mut LOG_BUFFER: Option<LogBuffer> = None;

/// Enable a custom log handler, this will buffer logs until `extism_log_drain` is called
/// Log level should be one of: info, error, trace, debug, warn
#[no_mangle]
pub unsafe extern "C" fn extism_log_custom(log_level: *const c_char) -> bool {
    let level = if !log_level.is_null() {
        let level = std::ffi::CStr::from_ptr(log_level);
        match level.to_str() {
            Ok(x) => x,
            Err(_) => {
                return false;
            }
        }
    } else {
        "error"
    };
    set_log_buffer(level).is_ok()
}

unsafe fn set_log_buffer(filter: &str) -> Result<(), Error> {
    let is_level = tracing::Level::from_str(filter).is_ok();
    let cfg = tracing_subscriber::FmtSubscriber::builder().with_env_filter({
        let x = tracing_subscriber::EnvFilter::builder()
            .with_default_directive(tracing::Level::ERROR.into());
        if is_level {
            x.parse_lossy(format!("extism={}", filter))
        } else {
            x.parse_lossy(filter)
        }
    });
    LOG_BUFFER = Some(LogBuffer::default());
    let buf = LOG_BUFFER.clone().unwrap();
    cfg.with_ansi(false)
        .with_writer(move || buf.clone())
        .try_init()
        .map_err(|x| Error::msg(x.to_string()))?;
    Ok(())
}

#[no_mangle]
/// Calls the provided callback function for each buffered log line.
/// This is only needed when `extism_log_custom` is used.
pub unsafe extern "C" fn extism_log_drain(handler: ExtismLogDrainFunctionType) {
    if let Some(buf) = LOG_BUFFER.as_mut() {
        if let Ok(mut buf) = buf.buffer.lock() {
            for (line, len) in buf.drain(..) {
                handler(line.as_ptr(), len as Size);
            }
        }
    }
}

#[derive(Default, Clone)]
struct LogBuffer {
    buffer:
        std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<(std::ffi::CString, usize)>>>,
}

unsafe impl Send for LogBuffer {}
unsafe impl Sync for LogBuffer {}

impl std::io::Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(s) = std::str::from_utf8(buf) {
            if let Ok(mut buf) = self.buffer.lock() {
                buf.push_back((std::ffi::CString::new(s)?, s.len()));
            }
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

/// Get the Extism version string
#[no_mangle]
pub unsafe extern "C" fn extism_version() -> *const c_char {
    VERSION.as_ptr() as *const _
}
