//! Bounded streaming ingestion for physical JSON Lines records.

use std::{
    io::{self, BufRead},
    iter::FusedIterator,
    num::NonZeroU64,
};

use thiserror::Error as ThisError;

use crate::{codec, ir::ValidatedRecord, limits::Limits};

const BUFFER_GROWTH_BYTES: usize = 8 * 1024;

/// One decoded record paired with its one-based physical line number.
pub struct LocatedRecord {
    line: NonZeroU64,
    record: ValidatedRecord,
}

impl LocatedRecord {
    /// Return the one-based physical line number.
    #[must_use]
    pub const fn line(&self) -> NonZeroU64 {
        self.line
    }

    /// Borrow the validated record.
    #[must_use]
    pub const fn record(&self) -> &ValidatedRecord {
        &self.record
    }

    /// Consume the location wrapper.
    #[must_use]
    pub fn into_record(self) -> ValidatedRecord {
        self.record
    }
}

/// Stable, content-redacted failures from bounded JSONL ingestion.
#[derive(Clone, Debug, Eq, PartialEq, ThisError)]
#[non_exhaustive]
pub enum ReadError {
    /// The underlying reader failed. Its potentially sensitive message is dropped.
    #[error("I/O error of kind {kind:?} while reading line {line}")]
    Io {
        /// Prospective one-based physical line.
        line: NonZeroU64,
        /// Stable I/O category without the source message.
        kind: io::ErrorKind,
    },
    /// A physical payload exceeded the per-record byte ceiling.
    #[error("line {line} exceeds payload limit {maximum}")]
    LineTooLong {
        /// One-based physical line.
        line: NonZeroU64,
        /// Configured payload ceiling, excluding LF or CRLF.
        maximum: usize,
    },
    /// An additional physical record exceeded the trace record ceiling.
    #[error("line {line} exceeds trace record limit {maximum}")]
    RecordLimit {
        /// One-based physical line that could not be admitted.
        line: NonZeroU64,
        /// Configured record ceiling.
        maximum: u64,
    },
    /// Reading another physical byte exceeded the trace byte ceiling.
    #[error("line {line} exceeds trace byte limit {maximum}")]
    TraceBytes {
        /// One-based physical line being read.
        line: NonZeroU64,
        /// Configured ceiling including line terminators.
        maximum: u64,
    },
    /// Reserving the bounded line buffer failed.
    #[error("unable to allocate bounded buffer for line {line}")]
    BufferAllocation {
        /// One-based physical line being read.
        line: NonZeroU64,
    },
    /// A bounded physical line failed strict record decoding.
    #[error("record at line {line} failed decoding: {error}")]
    Codec {
        /// One-based physical line.
        line: NonZeroU64,
        /// Already-redacted codec failure.
        error: codec::Error,
    },
    /// The next one-based line number could not fit in `u64`.
    #[error("physical line number overflow")]
    LineNumberOverflow,
}

impl ReadError {
    /// Return a machine-stable error code without trace-derived text.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Io { .. } => "io",
            Self::LineTooLong { .. } => "line_too_long",
            Self::RecordLimit { .. } => "record_limit",
            Self::TraceBytes { .. } => "trace_bytes",
            Self::BufferAllocation { .. } => "buffer_allocation",
            Self::Codec { error, .. } => error.code(),
            Self::LineNumberOverflow => "line_number_overflow",
        }
    }

    /// Return the affected line when one can be represented.
    #[must_use]
    pub const fn line(&self) -> Option<NonZeroU64> {
        match self {
            Self::Io { line, .. }
            | Self::LineTooLong { line, .. }
            | Self::RecordLimit { line, .. }
            | Self::TraceBytes { line, .. }
            | Self::BufferAllocation { line }
            | Self::Codec { line, .. } => Some(*line),
            Self::LineNumberOverflow => None,
        }
    }
}

/// Fused iterator over strictly bounded, validated physical JSONL records.
pub struct JsonlReader<R> {
    inner: R,
    limits: Limits,
    records_read: u64,
    bytes_read: u64,
    scratch: Vec<u8>,
    finished: bool,
}

impl<R> JsonlReader<R> {
    /// Wrap a buffered reader with explicit finite trace limits.
    #[must_use]
    pub const fn new(inner: R, limits: Limits) -> Self {
        Self {
            inner,
            limits,
            records_read: 0,
            bytes_read: 0,
            scratch: Vec::new(),
            finished: false,
        }
    }

    /// Return the number of records decoded successfully.
    #[must_use]
    pub const fn records_read(&self) -> u64 {
        self.records_read
    }

    /// Return the number of physical bytes consumed, including terminators.
    #[must_use]
    pub const fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Recover the wrapped reader.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: BufRead> Iterator for JsonlReader<R> {
    type Item = Result<LocatedRecord, ReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        match self.read_record() {
            Ok(Some(record)) => Some(Ok(record)),
            Ok(None) => {
                self.finished = true;
                None
            }
            Err(error) => {
                self.finished = true;
                Some(Err(error))
            }
        }
    }
}

impl<R: BufRead> FusedIterator for JsonlReader<R> {}

impl<R: BufRead> JsonlReader<R> {
    fn read_record(&mut self) -> Result<Option<LocatedRecord>, ReadError> {
        let line = next_line_number(self.records_read)?;
        if self.records_read >= self.limits.max_records_per_trace {
            return self.ensure_record_limit_or_eof(line);
        }

        self.scratch.clear();
        let mut pending_cr = false;
        loop {
            let available = self
                .inner
                .fill_buf()
                .map_err(|error| redacted_io(line, &error))?;
            if available.is_empty() {
                if pending_cr {
                    push_bounded(&mut self.scratch, b'\r', self.limits.max_line_bytes)
                        .map_err(|error| map_push_error(line, self.limits.max_line_bytes, error))?;
                }
                if self.scratch.is_empty() {
                    return Ok(None);
                }
                return self.decode_scratch(line).map(Some);
            }

            let mut consumed = 0;
            let mut complete = false;
            let mut failure = None;
            for byte in available.iter().copied() {
                if pending_cr && byte != b'\n' {
                    if let Err(error) =
                        push_bounded(&mut self.scratch, b'\r', self.limits.max_line_bytes)
                    {
                        failure = Some(map_push_error(line, self.limits.max_line_bytes, error));
                        break;
                    }
                    pending_cr = false;
                }
                if self.bytes_read >= self.limits.max_trace_bytes {
                    failure = Some(ReadError::TraceBytes {
                        line,
                        maximum: self.limits.max_trace_bytes,
                    });
                    break;
                }
                self.bytes_read = self
                    .bytes_read
                    .checked_add(1)
                    .ok_or(ReadError::TraceBytes {
                        line,
                        maximum: self.limits.max_trace_bytes,
                    })?;
                consumed += 1;

                if pending_cr {
                    pending_cr = false;
                    complete = true;
                    break;
                }

                match byte {
                    b'\n' => {
                        complete = true;
                        break;
                    }
                    b'\r' => pending_cr = true,
                    _ => {
                        if let Err(error) =
                            push_bounded(&mut self.scratch, byte, self.limits.max_line_bytes)
                        {
                            failure = Some(map_push_error(line, self.limits.max_line_bytes, error));
                            break;
                        }
                    }
                }
            }
            self.inner.consume(consumed);

            if let Some(error) = failure {
                return Err(error);
            }
            if complete {
                return self.decode_scratch(line).map(Some);
            }
        }
    }

    fn ensure_record_limit_or_eof(
        &mut self,
        line: NonZeroU64,
    ) -> Result<Option<LocatedRecord>, ReadError> {
        let available = self
            .inner
            .fill_buf()
            .map_err(|error| redacted_io(line, &error))?;
        if available.is_empty() {
            Ok(None)
        } else {
            Err(ReadError::RecordLimit {
                line,
                maximum: self.limits.max_records_per_trace,
            })
        }
    }

    fn decode_scratch(&mut self, line: NonZeroU64) -> Result<LocatedRecord, ReadError> {
        let record = codec::decode_line(&self.scratch, &self.limits)
            .map_err(|error| ReadError::Codec { line, error })?;
        self.records_read = self
            .records_read
            .checked_add(1)
            .ok_or(ReadError::LineNumberOverflow)?;
        Ok(LocatedRecord { line, record })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PushError {
    TooLong,
    Allocation,
}

fn push_bounded(buffer: &mut Vec<u8>, byte: u8, maximum: usize) -> Result<(), PushError> {
    if buffer.len() == maximum {
        return Err(PushError::TooLong);
    }
    if buffer.len() == buffer.capacity() {
        let growth = maximum
            .saturating_sub(buffer.len())
            .min(BUFFER_GROWTH_BYTES);
        buffer
            .try_reserve_exact(growth)
            .map_err(|_| PushError::Allocation)?;
    }
    buffer.push(byte);
    Ok(())
}

const fn map_push_error(line: NonZeroU64, maximum: usize, error: PushError) -> ReadError {
    match error {
        PushError::TooLong => ReadError::LineTooLong { line, maximum },
        PushError::Allocation => ReadError::BufferAllocation { line },
    }
}

fn redacted_io(line: NonZeroU64, error: &io::Error) -> ReadError {
    ReadError::Io {
        line,
        kind: error.kind(),
    }
}

const fn next_line_number(records_read: u64) -> Result<NonZeroU64, ReadError> {
    let Some(next) = records_read.checked_add(1) else {
        return Err(ReadError::LineNumberOverflow);
    };
    match NonZeroU64::new(next) {
        Some(line) => Ok(line),
        None => Err(ReadError::LineNumberOverflow),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, BufRead, BufReader, Cursor, Read};

    use super::{JsonlReader, PushError, ReadError, next_line_number, push_bounded};
    use crate::{codec, limits::Limits};

    const HEADER: &str = r#"{"kind":"trace_header","format":"kvcrucible.trace/v1alpha1","trace_id":"t","redaction":"omitted","created_by":"c","extensions":{}}"#;

    fn reader(
        input: &[u8],
        capacity: usize,
        limits: Limits,
    ) -> JsonlReader<BufReader<Cursor<&[u8]>>> {
        JsonlReader::new(
            BufReader::with_capacity(capacity, Cursor::new(input)),
            limits,
        )
    }

    fn next_error<R: BufRead>(reader: &mut JsonlReader<R>) -> ReadError {
        reader
            .next()
            .expect("reader should yield one result")
            .err()
            .expect("result should be an error")
    }

    #[test]
    fn tiny_buffers_preserve_lf_crlf_and_eof_framing() {
        for capacity in [1, 2, 3, 7] {
            for input in [
                HEADER.as_bytes().to_vec(),
                format!("{HEADER}\n").into_bytes(),
                format!("{HEADER}\r\n").into_bytes(),
            ] {
                let mut records = reader(&input, capacity, Limits::default());
                let located = records.next().unwrap().unwrap();
                assert_eq!(located.line().get(), 1);
                assert!(records.next().is_none());
                assert!(records.next().is_none());
            }
        }
    }

    #[test]
    fn mixed_terminators_and_split_utf8_preserve_physical_lines() {
        let unicode = HEADER.replace(r#""created_by":"c""#, r#""created_by":"é""#);
        let input = format!("{HEADER}\r\n{unicode}\n{HEADER}");
        let records = reader(input.as_bytes(), 1, Limits::default())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(records.len(), 3);
        assert_eq!(records[0].line().get(), 1);
        assert_eq!(records[1].line().get(), 2);
        assert_eq!(records[2].line().get(), 3);
    }

    #[test]
    fn empty_input_is_eof_but_blank_lines_are_records() {
        let mut empty = reader(b"", 1, Limits::default());
        assert!(empty.next().is_none());
        assert!(empty.next().is_none());

        for input in [b"\n".as_slice(), b"\r\n", b" \t\n"] {
            let mut records = reader(input, 1, Limits::default());
            assert!(matches!(
                next_error(&mut records),
                ReadError::Codec {
                    line,
                    error: codec::Error::EmptyLine
                } if line.get() == 1
            ));
            assert!(records.next().is_none());
        }
    }

    #[test]
    fn exact_payload_limit_excludes_lf_and_crlf() {
        let exact = Limits {
            max_line_bytes: HEADER.len(),
            ..Limits::default()
        };
        for input in [
            HEADER.as_bytes().to_vec(),
            format!("{HEADER}\n").into_bytes(),
            format!("{HEADER}\r\n").into_bytes(),
        ] {
            assert_eq!(
                reader(&input, 1, exact)
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap()
                    .len(),
                1
            );
        }

        for suffix in [" ", "\rX", "\r"] {
            let input = format!("{HEADER}{suffix}");
            let mut records = reader(input.as_bytes(), 1, exact);
            assert!(matches!(
                next_error(&mut records),
                ReadError::LineTooLong { maximum, .. } if maximum == HEADER.len()
            ));
        }

        let input = format!("{HEADER}\rX");
        let mut records = reader(input.as_bytes(), 1, exact);
        assert!(matches!(
            next_error(&mut records),
            ReadError::LineTooLong { .. }
        ));
        assert_eq!(
            records.bytes_read(),
            u64::try_from(HEADER.len() + 1).unwrap()
        );
        let mut inner = records.into_inner();
        assert_eq!(inner.fill_buf().unwrap(), b"X");
    }

    #[test]
    fn zero_payload_limit_distinguishes_empty_lines_from_content() {
        let limits = Limits {
            max_line_bytes: 0,
            ..Limits::default()
        };
        for input in [b"\n".as_slice(), b"\r\n"] {
            let mut records = reader(input, 1, limits);
            assert!(matches!(
                next_error(&mut records),
                ReadError::Codec {
                    error: codec::Error::EmptyLine,
                    ..
                }
            ));
        }
        let mut records = reader(b"x\n", 1, limits);
        assert!(matches!(
            next_error(&mut records),
            ReadError::LineTooLong { maximum: 0, .. }
        ));
    }

    #[test]
    fn record_limit_checks_for_eof_without_allocating_another_line() {
        let zero = Limits {
            max_records_per_trace: 0,
            ..Limits::default()
        };
        assert!(reader(b"", 1, zero).next().is_none());
        let mut rejected = reader(b"\n", 1, zero);
        assert!(matches!(
            next_error(&mut rejected),
            ReadError::RecordLimit {
                maximum: 0,
                line
            } if line.get() == 1
        ));

        let one = Limits {
            max_records_per_trace: 1,
            ..Limits::default()
        };
        for input in [HEADER.to_owned(), format!("{HEADER}\n")] {
            assert_eq!(
                reader(input.as_bytes(), 2, one)
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap()
                    .len(),
                1
            );
        }
        let input = format!("{HEADER}\n\n");
        let mut rejected = reader(input.as_bytes(), 2, one);
        assert!(rejected.next().unwrap().is_ok());
        assert!(matches!(
            next_error(&mut rejected),
            ReadError::RecordLimit { line, maximum: 1 } if line.get() == 2
        ));
    }

    #[test]
    fn trace_byte_limit_counts_terminators() {
        let limits = Limits {
            max_trace_bytes: u64::try_from(HEADER.len()).unwrap(),
            ..Limits::default()
        };
        assert_eq!(
            reader(HEADER.as_bytes(), 3, limits)
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .len(),
            1
        );
        let input = format!("{HEADER}\n");
        let mut rejected = reader(input.as_bytes(), 3, limits);
        assert!(matches!(
            next_error(&mut rejected),
            ReadError::TraceBytes { maximum, .. }
                if maximum == u64::try_from(HEADER.len()).unwrap()
        ));
    }

    #[test]
    fn counters_and_cumulative_trace_limit_are_exact_across_records() {
        let input = format!("{HEADER}\r\n{HEADER}");
        let total = u64::try_from(input.len()).unwrap();
        let exact = Limits {
            max_trace_bytes: total,
            ..Limits::default()
        };
        let mut records = reader(input.as_bytes(), 1, exact);

        assert!(records.next().unwrap().is_ok());
        assert_eq!(records.records_read(), 1);
        assert_eq!(
            records.bytes_read(),
            u64::try_from(HEADER.len() + 2).unwrap()
        );
        assert!(records.next().unwrap().is_ok());
        assert_eq!(records.records_read(), 2);
        assert_eq!(records.bytes_read(), total);
        assert!(records.next().is_none());

        let short = Limits {
            max_trace_bytes: total - 1,
            ..Limits::default()
        };
        let mut rejected = reader(input.as_bytes(), 1, short);
        assert!(rejected.next().unwrap().is_ok());
        assert!(matches!(
            next_error(&mut rejected),
            ReadError::TraceBytes { maximum, line }
                if maximum == total - 1 && line.get() == 2
        ));
        assert_eq!(rejected.records_read(), 1);
        assert_eq!(rejected.bytes_read(), total - 1);
    }

    #[test]
    fn invalid_second_record_reports_line_two_and_then_fuses() {
        let input = format!("{HEADER}\n{{\n{HEADER}\n");
        let mut records = reader(input.as_bytes(), 2, Limits::default());
        assert!(records.next().unwrap().is_ok());
        let error = next_error(&mut records);
        assert_eq!(error.line().unwrap().get(), 2);
        assert_eq!(error.code(), "json_syntax");
        assert!(records.next().is_none());
        assert!(records.next().is_none());
    }

    #[test]
    fn bounded_push_never_reserves_or_appends_n_plus_one() {
        let mut bytes = Vec::new();
        push_bounded(&mut bytes, b'a', 1).unwrap();
        let capacity = bytes.capacity();

        assert_eq!(push_bounded(&mut bytes, b'b', 1), Err(PushError::TooLong));
        assert_eq!(bytes, b"a");
        assert_eq!(bytes.capacity(), capacity);
    }

    #[test]
    fn line_number_overflow_is_explicit() {
        assert_eq!(
            next_line_number(u64::MAX),
            Err(ReadError::LineNumberOverflow)
        );
    }

    struct SecretErrorReader;

    impl Read for SecretErrorReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("DO_NOT_ECHO_SECRET_61c90f"))
        }
    }

    impl BufRead for SecretErrorReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Err(io::Error::other("DO_NOT_ECHO_SECRET_61c90f"))
        }

        fn consume(&mut self, _amount: usize) {}
    }

    #[test]
    fn io_error_messages_are_redacted() {
        let mut records = JsonlReader::new(SecretErrorReader, Limits::default());
        let error = next_error(&mut records);
        let rendered = format!("{error:?} {error}");

        assert!(matches!(
            error,
            ReadError::Io {
                kind: io::ErrorKind::Other,
                ..
            }
        ));
        assert!(!rendered.contains("DO_NOT_ECHO_SECRET_61c90f"));
    }
}
