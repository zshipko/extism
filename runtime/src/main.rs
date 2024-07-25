use extism::*;

#[tokio::main(flavor = "current_thread")]
pub async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt().init();
    let args: Vec<_> = std::env::args().skip(1).collect();
    let f = Function::new(
        "extism:host/user",
        "test",
        [ValType::I32],
        [ValType::F32],
        move |_caller, params, results| {
            let n = params[0].unwrap_i32();
            results[0] = Val::F32(((n * 2) as f32) as u32);
            Box::new(async { Ok(()) })
        },
    );
    let mut plugin = Plugin::new(Manifest::new([Wasm::file(&args[0])]), [f], true).await?;

    for _ in 0..std::env::var("LOOP")
        .map(|x| x.parse().unwrap_or(1))
        .unwrap_or(1)
    {
        let s: String = plugin.call(&args[1], &args[2]).await?;
        println!("{}", s);
    }
    Ok(())
}
