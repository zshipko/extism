use std::{io::Read, str::FromStr};

use bytes::Buf;

use crate::*;

pub(crate) fn handle(handle: u64) -> (u32, u32) {
    let offs = handle >> 32 & 0xffffffff;
    let len = handle & 0xffffffff;
    (offs as u32, len as u32)
}

#[repr(u8)]
enum Stream {
    Input = 0,
    Output = 1,
}

impl TryFrom<u8> for Stream {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Stream::Input),
            1 => Ok(Stream::Output),
            _ => anyhow::bail!("invalid pipe: {value}"),
        }
    }
}

pub(crate) fn add_functions(
    engine: &wasmtime::Engine,
    linker: &mut wasmtime::Linker<CallContext>,
    allowed_hosts: Option<Vec<String>>,
) -> Result<(), Error> {
    let ft = wasmtime::FuncType::new(&engine, [ValType::I32, HANDLE], [ValType::I64]);
    linker.func_new_async(
        "extism:host/env",
        "read",
        ft,
        |mut caller, params, results| {
            Box::new(async move {
                let pipe = Stream::try_from(params[0].unwrap_i32() as u8)?;
                let (offs, len) = handle(params[1].unwrap_i64() as u64);
                let mem = caller.get_export("memory").unwrap().into_memory().unwrap();
                let ctx: &mut CallContext = caller.data_mut();
                let pipe = match pipe {
                    Stream::Input => ctx.stack.current().input(),
                    Stream::Output => ctx.stack.current().output(),
                };
                let data: Vec<u8> = if let Ok(mut r) = pipe.data.write() {
                    let size = r.len();
                    if size == 0 {
                        if pipe.is_closed() {
                            results[0] = wasmtime::Val::I64(-1);
                        } else {
                            results[0] = wasmtime::Val::I64(0);
                        }
                        return Ok(());
                    }
                    let n = size.min(len as usize);
                    r.drain(0..n).collect()
                } else {
                    anyhow::bail!("unable to read from input stream");
                };
                mem.write(&mut caller, offs as usize, &data)?;
                results[0] = wasmtime::Val::I64(data.len() as i64);
                Ok(())
            })
        },
    )?;

    let ft = wasmtime::FuncType::new(&engine, [ValType::I32], [ValType::I64]);
    linker.func_new_async(
        "extism:host/env",
        "bytes_remaining",
        ft,
        |mut caller, params, results| {
            Box::new(async move {
                let pipe = Stream::try_from(params[0].unwrap_i32() as u8)?;
                let ctx: &mut CallContext = caller.data_mut();
                let pipe = match pipe {
                    Stream::Input => ctx.stack.current().input(),
                    Stream::Output => ctx.stack.current().output(),
                };
                results[0] = wasmtime::Val::I64(pipe.data.read().unwrap().len() as i64);
                Ok(())
            })
        },
    )?;

    let ft = wasmtime::FuncType::new(&engine, [ValType::I32, HANDLE], [ValType::I64]);
    linker.func_new_async(
        "extism:host/env",
        "write",
        ft,
        |mut caller, params, results| {
            Box::new(async move {
                let pipe = Stream::try_from(params[0].unwrap_i32() as u8)?;
                let (offs, len) = handle(params[1].unwrap_i64() as u64);
                let pipe = {
                    let ctx: &mut CallContext = caller.data_mut();
                    let pipe = match pipe {
                        Stream::Input => ctx.stack.current().input(),
                        Stream::Output => ctx.stack.current().output(),
                    };
                    if pipe.is_closed() {
                        results[0] = Val::I64(-1);
                        return Ok(());
                    }
                    pipe
                };
                let mem = caller.get_export("memory").unwrap().into_memory().unwrap();
                let mut data = vec![0u8; len as usize];
                mem.read(&mut caller, offs as usize, &mut data)?;
                if let Ok(mut r) = pipe.data.write() {
                    r.extend(data);
                } else {
                    anyhow::bail!("unable to write to output stream");
                }
                results[0] = Val::I64(len as i64);
                Ok(())
            })
        },
    )?;

    let ft = wasmtime::FuncType::new(&engine, [ValType::I32], []);
    linker.func_new_async(
        "extism:host/env",
        "close",
        ft,
        |mut caller, params, _results| {
            Box::new(async move {
                let ctx: &mut CallContext = caller.data_mut();
                let pipe = Stream::try_from(params[0].unwrap_i32() as u8)?;
                let pipe = match pipe {
                    Stream::Input => ctx.stack.current().input(),
                    Stream::Output => ctx.stack.current().output(),
                };
                pipe.close();
                Ok(())
            })
        },
    )?;

    let ft = wasmtime::FuncType::new(&engine, [], []);
    linker.func_new_async(
        "extism:host/env",
        "stack_push",
        ft,
        |caller, _params, _results| {
            Box::new(async move {
                caller.data().stack.push();
                Ok(())
            })
        },
    )?;

    let ft = wasmtime::FuncType::new(&engine, [], []);
    linker.func_new_async(
        "extism:host/env",
        "stack_pop",
        ft,
        |caller, _params, _results| {
            Box::new(async move {
                caller.data().stack.pop();
                Ok(())
            })
        },
    )?;

    let ft = wasmtime::FuncType::new(&engine, [HANDLE], []);
    linker.func_new_async(
        "extism:host/env",
        "error",
        ft,
        |mut caller, params, _results| {
            Box::new(async move {
                let (offs, len) = handle(params[0].unwrap_i64() as u64);
                let mem = caller.get_export("memory").unwrap().into_memory().unwrap();
                let mut data = vec![0u8; len as usize];
                mem.read(&mut caller, offs as usize, &mut data)?;
                let msg = String::from_utf8(data)?;
                Err(Error::msg(msg))
            })
        },
    )?;

    let ft = wasmtime::FuncType::new(&engine, [HANDLE], [ValType::I64]);
    linker.func_new_async(
        "extism:host/env",
        "config_length",
        ft,
        |mut caller, params, results| {
            Box::new(async move {
                let (offs, len) = handle(params[0].unwrap_i64() as u64);
                let mem = caller.get_export("memory").unwrap().into_memory().unwrap();
                let mut data = vec![0u8; len as usize];
                mem.read(&mut caller, offs as usize, &mut data)?;
                let key = String::from_utf8(data)?;
                let ctx = caller.data();
                let len = if let Some(v) = ctx.config.get(&key) {
                    v.len() as i64
                } else {
                    -1
                };
                results[0] = Val::I64(len);
                Ok(())
            })
        },
    )?;

    let ft = wasmtime::FuncType::new(&engine, [HANDLE, HANDLE], [ValType::I64]);
    linker.func_new_async(
        "extism:host/env",
        "config_read",
        ft,
        |mut caller, params, results| {
            Box::new(async move {
                let (offs, len) = handle(params[0].unwrap_i64() as u64);
                let mem = caller.get_export("memory").unwrap().into_memory().unwrap();
                let mut key = vec![0u8; len as usize];
                mem.read(&mut caller, offs as usize, &mut key)?;
                let key = String::from_utf8(key)?;
                let ctx = caller.data();
                let v = ctx.config.get(&key);
                let len = if let Some(v) = v {
                    let n = v.len().min(len as usize);
                    unsafe {
                        mem.data_ptr(&caller)
                            .add(offs as usize)
                            .copy_from(v.as_ptr(), v.len())
                    }
                    n as i64
                } else {
                    -1
                };
                results[0] = Val::I64(len);
                Ok(())
            })
        },
    )?;

    let ft = wasmtime::FuncType::new(&engine, [ValType::I32, HANDLE], []);
    linker.func_new_async(
        "extism:host/env",
        "log",
        ft,
        |mut caller, params, _results| {
            Box::new(async move {
                let mem = caller.get_export("memory").unwrap().into_memory().unwrap();
                let level = params[0].unwrap_i32();
                let (msg_offs, msg_len) = handle(params[1].unwrap_i64() as u64);
                let msg =
                    &mem.data(&caller)[msg_offs as usize..msg_offs as usize + msg_len as usize];
                let msg = std::str::from_utf8(msg)?;
                let id = caller.data().id.to_string();
                match level {
                    0 => {
                        tracing::error!(plugin = id, "{}", msg)
                    }
                    1 => {
                        tracing::warn!(plugin = id, "{}", msg)
                    }
                    2 => {
                        tracing::info!(plugin = id, "{}", msg)
                    }
                    3 => {
                        tracing::debug!(plugin = id, "{}", msg)
                    }
                    4 => {
                        tracing::trace!(plugin = id, "{}", msg)
                    }
                    x => {
                        anyhow::bail!("Invalid log level: {}", x);
                    }
                }
                Ok(())
            })
        },
    )?;

    let ft = wasmtime::FuncType::new(&engine, [HANDLE, HANDLE], [ValType::I64]);
    linker.func_new_async(
        "extism:host/env",
        "http_request",
        ft,
        move |mut caller, params, results| {
            let allowed_hosts = allowed_hosts.clone();
            Box::new(async move {
                let (offs, len) = handle(params[0].unwrap_i64() as u64);
                let mem = caller.get_export("memory").unwrap().into_memory().unwrap();
                let req =
                    &mem.data(&caller)[offs as usize..offs as usize + len as usize];
                let r: extism_manifest::HttpRequest = serde_json::from_slice(&req)?;
                let url = reqwest::Url::parse(&r.url)?;
                let host = url.host_str().unwrap_or_default();

                if let Some(h) = allowed_hosts.clone() {
                    let mut ok = false;
                    for allowed_host in h {
                        if glob::Pattern::new(allowed_host.as_str())?.matches(host) {
                            ok = true;
                            break;
                        }
                    }
                    if !ok {
                        anyhow::bail!(
                            "the host {} is not included in the allowed_hosts field of the manifest",
                            host
                        );
                    }
                } else {
                    anyhow::bail!(
                        "the host {} is not included in the allowed_hosts field of the manifest",
                        host
                    );
                }
                let mut req = reqwest::Client::new().request(
                    reqwest::Method::from_str(
                        &r.method.as_deref().unwrap_or("GET").to_ascii_uppercase(),
                    )?,
                    reqwest::Url::parse(&r.url)?,
                );

                for (k, v) in r.headers {
                    req = req.header(k, v);
                }

                let body = params[0].unwrap_i64() as u64;
                if body != 0 {
                    let (offs, len) = handle(body);
                    let mut b = vec![0u8; len as usize];
                    mem.read(&mut caller, offs as usize, &mut b)?;
                    req = req.body(b);
                }

                let res = req.send().await?;
                let status = res.status();
                let body = if let Some(max) = caller.data().max_http_response_bytes {
                    let mut data = vec![];
                    res.bytes().await?.take(max as usize).reader().read_to_end(&mut data)?;
                    data
                    } else {
                    res.bytes().await?.to_vec()
                };
                let ctx = caller.data_mut();
                let len = body.len() as i64;
                ctx.http_response = Some(body);
                ctx.http_response_status = status.as_u16();

                results[0] = Val::I64(len);

                Ok(())
            })
        },
    )?;

    let ft = wasmtime::FuncType::new(&engine, [HANDLE], [ValType::I64]);
    linker.func_new_async(
        "extism:host/env",
        "http_body",
        ft,
        |mut caller, params, results| {
            Box::new(async move {
                let (offs, len) = handle(params[0].unwrap_i64() as u64);
                let mem = caller.get_export("memory").unwrap().into_memory().unwrap();
                let ctx = caller.data_mut();
                let mut finished = false;
                if let Some(h) = &mut ctx.http_response {
                    if h.len() == 0 {
                        results[0] = Val::I64(-1);
                        finished = true;
                    } else {
                        let data = h.drain(..len as usize).collect::<Vec<_>>();
                        mem.write(&mut caller, offs as usize, &data)?;
                        results[0] = Val::I64(len as i64);
                    }
                } else {
                    results[0] = Val::I64(-1);
                }
                if finished {
                    let ctx = caller.data_mut();
                    ctx.http_response = None;
                }
                Ok(())
            })
        },
    )?;

    let ft = wasmtime::FuncType::new(&engine, [], [ValType::I32]);
    linker.func_new_async(
        "extism:host/env",
        "http_status_code",
        ft,
        |caller, _params, results| {
            Box::new(async move {
                let status = caller.data().http_response_status;
                results[0] = Val::I32(status as i32);
                Ok(())
            })
        },
    )?;

    Ok(())
}
