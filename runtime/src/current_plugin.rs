use crate::*;

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

    pub fn val_handle_data(&mut self, h: &Val) -> Result<&mut [u8], Error> {
        let h = match h.i64() {
            Some(x) => x as u64,
            None => anyhow::bail!("Invalid handle val: {:?}", h),
        };
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

    pub fn val_handle<T: FromBytesOwned>(&mut self, h: &Val) -> Result<T, Error> {
        let h = match h.i64() {
            Some(x) => x as u64,
            None => anyhow::bail!("Invalid handle val: {:?}", h),
        };
        self.handle(h)
    }

    pub fn handle<T: FromBytesOwned>(&mut self, h: u64) -> Result<T, Error> {
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
        T::from_bytes_owned(&mut data[offs..offs + len])
    }
}
