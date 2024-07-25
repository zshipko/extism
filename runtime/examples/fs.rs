use extism::*;

#[tokio::main]
async fn main() {
    let url = Wasm::file("../wasm/read_write.wasm");
    let manifest = Manifest::new([url])
        .with_allowed_path("ro:src/tests/data".to_string(), "/data")
        .with_config_key("path", "/data/data.txt");

    let mut plugin = PluginBuilder::new(manifest)
        .with_wasi(true)
        .build()
        .await
        .unwrap();

    println!("trying to read file: ");

    let res = plugin.call::<&str, String>("try_read", "").await.unwrap();

    println!("{:?}", res);

    println!("-----------------------------------------------------");

    println!("trying to write file: ");
    let line = format!(
        "Hello World at {:?}\n",
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
    );
    let res2 = plugin
        .call::<&str, String>("try_write", &line)
        .await
        .unwrap();

    println!("{:?}", res2);

    println!("done!");
}
