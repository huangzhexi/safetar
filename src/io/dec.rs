//! Compression-aware reader helpers.

use std::io::{self, BufRead, BufReader, Read};

use flate2::read::MultiGzDecoder;
use xz2::read::XzDecoder;
use zstd::stream::read::Decoder as ZstdDecoder;

use super::Compression;

/// Wrap a reader with auto-detected compression.
pub fn wrap_reader<R>(reader: R) -> io::Result<CompressionReader>
where
    R: Read + Send + 'static,
{
    let mut buf = BufReader::new(reader);
    let header = {
        let available = buf.fill_buf()?;
        let len = available.len().min(8);
        available[..len].to_vec()
    };
    let codec = Compression::detect(&header);
    let inner: Box<dyn Read + Send> = match codec {
        Compression::None => Box::new(buf),
        Compression::Gzip => Box::new(MultiGzDecoder::new(buf)),
        Compression::Xz => Box::new(XzDecoder::new(buf)),
        Compression::Zstd => {
            let decoder = ZstdDecoder::new(buf).map_err(io::Error::other)?;
            Box::new(decoder)
        }
    };
    Ok(CompressionReader { codec, inner })
}

/// Reader that decodes according to a detected compression codec.
pub struct CompressionReader {
    codec: Compression,
    inner: Box<dyn Read + Send>,
}

impl CompressionReader {
    /// Access the detected codec.
    #[must_use]
    pub fn codec(&self) -> Compression {
        self.codec
    }
}

impl Read for CompressionReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.as_mut().read(buf)
    }
}
