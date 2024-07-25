use crate::*;

pub type FunctionResult = Box<dyn std::future::Future<Output = Result<(), Error>> + Send>;

pub(crate) type FunctionInner = dyn Fn(
        CurrentPlugin,
        &[Val],
        &mut [Val],
    ) -> Box<dyn std::future::Future<Output = Result<(), Error>> + Send>
    + Sync
    + Send;
pub(crate) type FunctionInnerOriginal = dyn Fn(
        wasmtime::Caller<CallContext>,
        &[Val],
        &mut [Val],
    ) -> Box<dyn std::future::Future<Output = Result<(), Error>> + Send>
    + Sync
    + Send;

#[derive(Clone)]
pub struct Function {
    pub(crate) name: String,
    pub(crate) module: String,
    pub(crate) params: Vec<ValType>,
    pub(crate) results: Vec<ValType>,
    pub(crate) callback: std::sync::Arc<FunctionInner>,
}

impl Function {
    pub fn new(
        module: impl Into<String>,
        name: impl Into<String>,
        params: impl IntoIterator<Item = ValType>,
        results: impl IntoIterator<Item = ValType>,
        callback: impl 'static + Fn(CurrentPlugin, &[Val], &mut [Val]) -> FunctionResult + Sync + Send,
    ) -> Self {
        Self {
            module: module.into(),
            name: name.into(),
            params: params.into_iter().collect(),
            results: results.into_iter().collect(),
            callback: std::sync::Arc::new(callback),
        }
    }

    pub fn new_sync(
        module: impl Into<String>,
        name: impl Into<String>,
        params: impl IntoIterator<Item = ValType>,
        results: impl IntoIterator<Item = ValType>,
        callback: impl 'static
            + Fn(CurrentPlugin, &[Val], &mut [Val]) -> Result<(), Error>
            + Sync
            + Send,
    ) -> Self {
        Self::new(
            module,
            name,
            params,
            results,
            move |plugin, params, results| {
                let r = callback(plugin, params, results);
                Box::new(async { r })
            },
        )
    }
}

// #[macro_export]
// macro_rules! host_fn {
//     // ($pub:vis $name: ident  ($($arg:ident : $argty:ty),*) $(-> $ret:ty)? $b:block) => {
//     //    $crate::host_fn!($pub $name (user_data: (); $($arg : $argty),*) $(-> $ret)? {$b});
//     // };
//     ($pub:vis $name: ident  ($($arg:ident : $argty:ty),*) $(-> $ret:ty)? $b:block) => {
//         $pub fn $name(
//             plugin: $crate::CurrentPlugin,
//             inputs: &[$crate::Val],
//             outputs: &mut [$crate::Val],
//         ) -> $crate::FunctionResult {
//             let data = plugin.input();
//             Box::new(async move {
//                 let output = {
//                     let mut index = 0;
//                     $(
//                         let $arg: $argty = plugin.memory_get_val(&inputs[index])?;
//                         #[allow(unused_assignments)]
//                         {
//                             index += 1;
//                         }
//                     )*
//                     move || -> Result<_, $crate::Error> { $b }
//                 };
//                 let output = output()?;
//                 let output: $crate::convert::MemoryHandle = plugin.memory_new(&output)?;
//                 if !outputs.is_empty() {
//                     outputs[0] = plugin.memory_to_val(output);
//                 }
//                 Ok(())
//             })
//         }
//     };
// }
