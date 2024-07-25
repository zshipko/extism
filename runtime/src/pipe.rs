use crate::*;

#[derive(Default, Clone)]
pub struct Pipe {
    pub(crate) data: std::sync::Arc<std::sync::RwLock<Vec<u8>>>,
    pub(crate) closed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub(crate) max_bytes: Option<usize>,
}

#[derive(Default, Clone)]
pub struct Frame {
    input: Pipe,
    output: Pipe,
}

impl Frame {
    pub fn input(&self) -> Pipe {
        self.input.clone()
    }

    pub fn output(&self) -> Pipe {
        self.output.clone()
    }
}

#[derive(Default, Clone)]
pub struct Stack {
    frames: std::cell::RefCell<Vec<Frame>>,
}

impl Stack {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn push(&self) -> Frame {
        let input = Pipe::new();
        let output = Pipe::new();
        let frame = Frame { input, output };
        self.frames.borrow_mut().push(frame.clone());
        frame
    }

    pub fn pop(&self) -> Option<Frame> {
        self.frames.borrow_mut().pop()
    }

    pub fn current(&self) -> Frame {
        let len = self.frames.borrow().len();
        if len == 0 {
            self.push()
        } else {
            self.frames.borrow().get(len - 1).unwrap().clone()
        }
    }

    pub fn reset(&self) -> &Self {
        self.frames.borrow_mut().clear();
        self
    }
}

impl Pipe {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn close(&self) {
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn reset(&self) {
        self.closed
            .store(false, std::sync::atomic::Ordering::SeqCst);
        *self.data.write().unwrap() = vec![];
    }

    pub fn take(&self) -> Vec<u8> {
        let mut out = vec![];
        std::mem::swap(&mut *self.data.write().unwrap(), &mut out);
        out
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn write<'a, T: extism_convert::ToBytes<'a>>(&mut self, x: T) -> Result<(), Error> {
        let b = x.to_bytes()?;
        self.write_all(b.as_ref())?;
        Ok(())
    }
}

impl std::io::Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let full = if let Some(b) = &self.max_bytes {
            let len = self.data.read().unwrap().len();
            b.saturating_sub(len) == 0
        } else {
            false
        };

        if full {
            return Err(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "pipe is full",
            ));
        }

        if self.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "pipe is closed",
            ));
        }
        self.data.write().unwrap().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.data.write().unwrap().flush()
    }
}

impl std::io::Read for Pipe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        println!("READ");
        let dest_len = buf.len();
        let src = &mut *self.data.write().unwrap();
        let n = dest_len.min(src.len());
        buf[..n].copy_from_slice(&src.drain(..n).collect::<Vec<_>>());
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;
    #[test]
    fn test_pipe() {
        let mut pipe = Pipe::new();
        pipe.write_all(b"test").unwrap();
        pipe.write_all(b"test").unwrap();
        pipe.close();
        assert!(pipe.write_all(b"test").is_err());

        let mut s = String::new();
        pipe.read_to_string(&mut s).unwrap();
        assert_eq!(s, "testtest");
    }
}
