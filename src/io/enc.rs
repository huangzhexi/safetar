//! Compression-aware writer helpers.

use std::io::{self, BufWriter, Write};

use flate2::write::GzEncoder;
use flate2::Compression as GzipLevel;
use xz2::write::XzEncoder;
use zstd::stream::write::Encoder as ZstdEncoder;

use super::Compression;

/// Wrap a writer with the requested compression codec.
pub fn wrap_writer<W>(writer: W, codec: Compression) -> io::Result<CompressionWriter<W>>
where
    W: Write,
{
    let buf = BufWriter::new(writer);
    let inner = match codec {
        Compression::None => CompressionWriterInner::Plain(buf),
        Compression::Gzip => {
            CompressionWriterInner::Gzip(GzEncoder::new(buf, GzipLevel::default()))
        }
        Compression::Xz => CompressionWriterInner::Xz(XzEncoder::new(buf, 6)),
        Compression::Zstd => {
            let encoder = ZstdEncoder::new(buf, 3).map_err(io::Error::other)?;
            CompressionWriterInner::Zstd(encoder)
        }
    };
    Ok(CompressionWriter { codec, inner })
}

/// Writer with codec-aware finalisation.
pub struct CompressionWriter<W: Write> {
    codec: Compression,
    inner: CompressionWriterInner<W>,
}

impl<W: Write> CompressionWriter<W> {
    /// Finish encoding and flush buffers.
    pub fn finish(self) -> io::Result<()> {
        match self.inner {
            CompressionWriterInner::Plain(mut inner) => inner.flush(),
            CompressionWriterInner::Gzip(inner) => {
                let mut writer = inner.finish()?;
                writer.flush()
            }
            CompressionWriterInner::Xz(inner) => {
                let mut writer = inner.finish()?;
                writer.flush()
            }
            CompressionWriterInner::Zstd(inner) => {
                let mut writer = inner.finish().map_err(io::Error::other)?;
                writer.flush()
            }
        }
    }

    /// Access the active codec.
    #[must_use]
    pub fn codec(&self) -> Compression {
        self.codec
    }
}

impl<W: Write> Write for CompressionWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.inner {
            CompressionWriterInner::Plain(inner) => inner.write(buf),
            CompressionWriterInner::Gzip(inner) => inner.write(buf),
            CompressionWriterInner::Xz(inner) => inner.write(buf),
            CompressionWriterInner::Zstd(inner) => inner.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.inner {
            CompressionWriterInner::Plain(inner) => inner.flush(),
            CompressionWriterInner::Gzip(inner) => inner.flush(),
            CompressionWriterInner::Xz(inner) => inner.flush(),
            CompressionWriterInner::Zstd(inner) => inner.flush(),
        }
    }
}

enum CompressionWriterInner<W: Write> {
    Plain(BufWriter<W>),
    Gzip(GzEncoder<BufWriter<W>>),
    Xz(XzEncoder<BufWriter<W>>),
    Zstd(ZstdEncoder<'static, BufWriter<W>>),
}
