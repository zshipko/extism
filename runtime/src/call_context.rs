use crate::*;

pub struct CallContext {
    pub id: uuid::Uuid,
    pub stack: Stack,
    pub http_response: Option<Vec<u8>>,
    pub http_response_status: u16,
    pub config: BTreeMap<String, String>,
    pub vars: HashMap<String, Vec<u8>>,
    pub(crate) memory_limiter: Option<MemoryLimiter>,
    pub wasi_ctx: Option<wasmtime_wasi::preview1::WasiP1Ctx>,
    pub max_http_response_bytes: Option<u64>,
    pub max_var_bytes: Option<u64>,
    pub main_memory: Option<wasmtime::Memory>,
}

pub(crate) struct MemoryLimiter {
    pub(crate) bytes_left: usize,
    #[allow(unused)]
    pub(crate) max_bytes: usize,
}

impl MemoryLimiter {
    #[allow(unused)]
    pub(crate) fn reset(&mut self) {
        self.bytes_left = self.max_bytes;
    }
}

#[async_trait::async_trait]
impl wasmtime::ResourceLimiterAsync for MemoryLimiter {
    async fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool, Error> {
        if let Some(max) = maximum {
            if desired >= max {
                return Err(Error::msg("oom"));
            }
        }

        let d = desired - current;
        if d > self.bytes_left {
            return Err(Error::msg("oom"));
        }

        self.bytes_left -= d;
        Ok(true)
    }

    async fn table_growing(
        &mut self,
        _current: u32,
        desired: u32,
        maximum: Option<u32>,
    ) -> Result<bool, Error> {
        if let Some(max) = maximum {
            return Ok(desired <= max);
        }

        Ok(true)
    }
}
