use extism::*;

// pretend this is redis or something :)
type KVStore = std::collections::BTreeMap<String, Vec<u8>>;

// When a first argument separated with a semicolon is provided to `host_fn` it is used as the
// variable name and type for the `UserData` parameter
// fn kv_read(key: String) -> Result<(), Error> {
//     let kv = kv.lock().unwrap();
//     let value = kv
//         .get(&key)
//         .map(|x| u32::from_le_bytes(x.clone().try_into().unwrap()))
//         .unwrap_or_else(|| 0u32);
//     Ok(value)
// }

// host_fn!(kv_write(user_data: KVStore; key: String, value: u32) {
//     let kv = user_data.get()?;
//     let mut kv = kv.lock().unwrap();
//     kv.insert(key, value.to_le_bytes().to_vec());
//     Ok(())
// });

#[tokio::main]
async fn main() {
    let kv_store = std::sync::Arc::new(std::sync::Mutex::new(KVStore::default()));
    let kv = kv_store.clone();

    let url = Wasm::url(
        "https://github.com/extism/plugins/releases/latest/download/count_vowels_kvstore.wasm",
    );
    let manifest = Manifest::new([url]);
    let mut plugin = PluginBuilder::new(manifest)
        .with_wasi(true)
        .with_function_sync(
            "extism:host/user",
            "kv_read",
            [HANDLE],
            [ValType::I32],
            move |mut plugin, params, results| {
                let kv_store = kv.clone();
                let key = plugin.handle_data(params[0].unwrap_i64() as u64)?;
                let key = std::str::from_utf8(key)?;
                let kv = kv_store.lock().unwrap();
                let value = kv
                    .get(key)
                    .map(|x| u32::from_le_bytes(x.clone().try_into().unwrap()))
                    .unwrap_or_else(|| 0u32);
                results[0] = Val::I32(value as i32);
                Ok(())
            },
        )
        .with_function_sync(
            "extism:host/user",
            "kv_write",
            [HANDLE, ValType::I32],
            [],
            move |mut plugin, params, _results| {
                let kv_store = kv_store.clone();
                let key = plugin.handle_data(params[0].unwrap_i64() as u64)?;
                let key = std::str::from_utf8(key)?;
                let mut kv = kv_store.lock().unwrap();
                kv.insert(
                    key.to_string(),
                    (params[0].unwrap_i32() as u32).to_le_bytes().to_vec(),
                );
                Ok(())
            },
        )
        // .with_function(
        //     "kv_write",
        //     [ValType::I64, ValType::I64],
        //     [],
        //     kv_store.clone(),
        //     kv_write,
        // )
        .build()
        .await
        .unwrap();

    for _ in 0..5 {
        let res = plugin
            .call::<&str, String>("count_vowels", "Hello, world!")
            .await
            .unwrap();
        println!("{}", res);
    }
}
