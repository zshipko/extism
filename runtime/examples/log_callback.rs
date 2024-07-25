use extism::*;

static LOGS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn handle_logs(msg: &str) {
    LOGS.lock().unwrap().push(msg.to_string())
}

#[tokio::main]
async fn main() {
    set_log_callback(handle_logs, "extism=trace,log_callback=trace").unwrap();
    let url = Wasm::file("../wasm/code.wasm");
    let manifest = Manifest::new([url]);
    let mut plugin = PluginBuilder::new(manifest)
        .with_wasi(true)
        .build()
        .await
        .unwrap();

    for _ in 0..5 {
        let res: String = CallBuilder::new(&mut plugin)
            .input("Hello, world!")
            .unwrap()
            .call("count_vowels")
            .await
            .unwrap();
        tracing::debug!("{}", res);
    }

    println!("Dumping logs");

    for line in LOGS.lock().unwrap().iter() {
        print!("{}", line);
    }
}
