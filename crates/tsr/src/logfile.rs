//! A size-capped log file for running in the background.
//!
//! Once the file reaches `LIMIT` bytes it is renamed to `<name>.1` (replacing
//! any older copy) and a fresh file is started, so a tsr that runs for months
//! can't fill the disk.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const LIMIT: u64 = 10 << 20;

pub struct LogFile {
    path: PathBuf,
    file: File,
    len: u64,
}

impl LogFile {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let len = file.metadata()?.len();
        Ok(Self {
            path: path.into(),
            file,
            len,
        })
    }

    fn rotate(&mut self) -> io::Result<()> {
        let mut old = self.path.clone().into_os_string();
        old.push(".1");
        // Rust opens files with FILE_SHARE_DELETE on Windows, so renaming
        // while our own handle is open works.
        std::fs::rename(&self.path, &old)?;
        *self = Self::open(&self.path)?;
        Ok(())
    }
}

impl Write for LogFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.len >= LIMIT && self.rotate().is_err() {
            // Something else holds the file open; try again after another LIMIT bytes.
            self.len = 0;
        }
        let n = self.file.write(buf)?;
        self.len += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_at_limit() {
        let dir = std::env::temp_dir().join(format!("tsr-logfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tsr.log");
        let mut log = LogFile::open(&path).unwrap();
        let line = vec![b'x'; 1 << 20];
        for _ in 0..11 {
            log.write_all(&line).unwrap();
        }
        log.write_all(b"after\n").unwrap();
        assert_eq!(
            std::fs::metadata(dir.join("tsr.log.1")).unwrap().len(),
            LIMIT
        );
        assert_eq!(std::fs::read(&path).unwrap().len(), (1 << 20) + 6);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
