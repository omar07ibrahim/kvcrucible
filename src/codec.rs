//! Strict, bounded JSON Lines decoding and RFC 8785 encoding.
//!
//! The decoder applies structural budgets before constructing the typed IR and
//! rejects duplicate decoded object keys. The JSON parser may allocate scratch
//! space for one escaped string or key before its visitor runs; that allocation
//! remains bounded by [`Limits::max_line_bytes`].

use std::{fmt, io, str};

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use thiserror::Error as ThisError;

use crate::{
    ir::{Record, ValidatedRecord, ValidationError},
    limits::{Limits, MAX_JSON_DEPTH},
};

const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const POLICY_ERROR_SENTINEL: &str = "strict JSON policy violation";

/// A bounded resource consumed while decoding or encoding one record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Resource {
    /// UTF-8 payload bytes, excluding the line terminator.
    LineBytes,
    /// Nested JSON value depth, with the root at depth one.
    JsonDepth,
    /// Scalar and container JSON values; object keys are not values.
    JsonValues,
    /// Decoded UTF-8 bytes in one string value or object key.
    StringBytes,
    /// Decoded UTF-8 bytes across all string values and object keys.
    TotalStringBytes,
    /// Elements in one JSON array.
    ArrayItems,
    /// Members in one JSON object.
    ObjectMembers,
}

impl fmt::Display for Resource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::LineBytes => "line_bytes",
            Self::JsonDepth => "json_depth",
            Self::JsonValues => "json_values",
            Self::StringBytes => "string_bytes",
            Self::TotalStringBytes => "total_string_bytes",
            Self::ArrayItems => "array_items",
            Self::ObjectMembers => "object_members",
        };
        formatter.write_str(name)
    }
}

/// Stable, redacted failures from the strict record codec.
#[derive(Clone, Debug, Eq, PartialEq, ThisError)]
#[non_exhaustive]
pub enum Error {
    /// The physical line had no JSON payload.
    #[error("JSONL record is empty")]
    EmptyLine,
    /// More than one physical line or an invalid terminator was supplied.
    #[error("JSONL framing is invalid")]
    InvalidFraming,
    /// The payload was not valid UTF-8.
    #[error("input is not valid UTF-8 at byte {valid_up_to}")]
    InvalidUtf8 {
        /// Length of the valid UTF-8 prefix.
        valid_up_to: usize,
    },
    /// JSON syntax was malformed or contained trailing data.
    #[error("JSON syntax error at line {line}, column {column}")]
    JsonSyntax {
        /// Parser line number; physical JSONL records normally remain line one.
        line: usize,
        /// Parser column number.
        column: usize,
    },
    /// Two object member names decoded to the same Unicode string.
    #[error("JSON object contains a duplicate decoded key")]
    DuplicateKey,
    /// The IR forbids floating-point JSON numbers, even integral-looking forms.
    #[error("floating-point JSON numbers are unsupported")]
    NonIntegerNumber,
    /// An ordinary JSON integer exceeded the interoperable safe range.
    #[error("JSON integer is outside the interoperable range")]
    UnsafeInteger,
    /// One configured structural budget was exceeded.
    #[error("{resource} exceeds limit {maximum} with observed value {observed}")]
    ResourceLimit {
        /// Resource whose budget was exhausted.
        resource: Resource,
        /// Configured inclusive maximum.
        maximum: usize,
        /// First observed value known to exceed the maximum.
        observed: usize,
    },
    /// The configured JSON depth exceeded the decoder's stack-safety ceiling.
    #[error("configured JSON depth exceeds supported maximum {maximum}")]
    InvalidLimits {
        /// Hard maximum supported by this decoder.
        maximum: usize,
    },
    /// Valid JSON did not match the versioned record schema.
    #[error("JSON does not match the trace record schema")]
    Schema,
    /// The typed record violated a record-local semantic invariant.
    #[error("record failed semantic validation: {0}")]
    Validation(#[from] ValidationError),
    /// A validated record could not be serialized canonically.
    #[error("canonical JSON serialization failed")]
    Canonicalization,
}

impl Error {
    /// Return a machine-stable error code without input-derived text.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::EmptyLine => "empty_line",
            Self::InvalidFraming => "invalid_framing",
            Self::InvalidUtf8 { .. } => "invalid_utf8",
            Self::JsonSyntax { .. } => "json_syntax",
            Self::DuplicateKey => "duplicate_key",
            Self::NonIntegerNumber => "non_integer_number",
            Self::UnsafeInteger => "unsafe_integer",
            Self::ResourceLimit { .. } => "resource_limit",
            Self::InvalidLimits { .. } => "invalid_limits",
            Self::Schema => "schema",
            Self::Validation(error) => error.code(),
            Self::Canonicalization => "canonicalization",
        }
    }
}

/// Decode exactly one physical JSONL record under explicit resource limits.
///
/// The input may omit its final terminator or use LF or CRLF. Canonical output
/// always uses one LF. Embedded physical line breaks and multiple values are
/// rejected. Structural limits are enforced before typed-IR construction; the
/// caller remains responsible for bounding acquisition of the input buffer.
///
/// # Errors
///
/// Returns a stable [`Error`] for framing, UTF-8, syntax, duplicate-key,
/// resource, schema, or semantic-validation failures.
pub fn decode_line(input: &[u8], limits: &Limits) -> Result<ValidatedRecord, Error> {
    validate_limits(limits)?;
    enforce_line_limit(payload_length(input), limits.max_line_bytes)?;
    let payload = split_payload(input)?;
    if payload.iter().all(|byte| matches!(byte, b' ' | b'\t')) {
        return Err(Error::EmptyLine);
    }

    let text = str::from_utf8(payload).map_err(|error| Error::InvalidUtf8 {
        valid_up_to: error.valid_up_to(),
    })?;
    let value = decode_value(text, limits)?;
    let record: Record = serde_json::from_value(value).map_err(|_| Error::Schema)?;
    ValidatedRecord::new(record, limits).map_err(Error::from)
}

/// Encode one validated record as RFC 8785 JSON followed by exactly one LF.
///
/// The record is checked again because it may have been validated previously
/// under more permissive limits. A streaming serialization preflight enforces
/// the line and structural budgets before the buffered canonical writer runs.
///
/// # Errors
///
/// Returns [`Error::Validation`] if the record violates the supplied limits,
/// [`Error::ResourceLimit`] if canonical payload bytes exceed the line ceiling,
/// or [`Error::Canonicalization`] if serialization fails.
pub fn encode_line(record: &ValidatedRecord, limits: &Limits) -> Result<Vec<u8>, Error> {
    validate_limits(limits)?;
    record.as_record().validate(limits)?;
    preflight_record(record, limits)?;

    let mut writer = CappedWriter::new(limits.max_line_bytes);
    let result = serde_json_canonicalizer::to_writer(record, &mut writer);
    if let Some(observed) = writer.exceeded_at() {
        return Err(Error::ResourceLimit {
            resource: Resource::LineBytes,
            maximum: limits.max_line_bytes,
            observed,
        });
    }
    result.map_err(|_| Error::Canonicalization)?;

    let mut output = writer.into_inner();
    output.push(b'\n');
    Ok(output)
}

fn preflight_record(record: &ValidatedRecord, limits: &Limits) -> Result<(), Error> {
    let mut writer = CappedWriter::new(limits.max_line_bytes);
    let result = serde_json::to_writer(&mut writer, record);
    if let Some(observed) = writer.exceeded_at() {
        return Err(Error::ResourceLimit {
            resource: Resource::LineBytes,
            maximum: limits.max_line_bytes,
            observed,
        });
    }
    result.map_err(|_| Error::Canonicalization)?;

    let bytes = writer.into_inner();
    let text = str::from_utf8(&bytes).map_err(|_| Error::Canonicalization)?;
    drop(decode_value(text, limits)?);
    Ok(())
}

const fn validate_limits(limits: &Limits) -> Result<(), Error> {
    if limits.max_depth > MAX_JSON_DEPTH {
        return Err(Error::InvalidLimits {
            maximum: MAX_JSON_DEPTH,
        });
    }
    Ok(())
}

fn split_payload(input: &[u8]) -> Result<&[u8], Error> {
    let payload = input
        .strip_suffix(b"\r\n")
        .or_else(|| input.strip_suffix(b"\n"))
        .unwrap_or(input);
    if payload.contains(&b'\n') || payload.contains(&b'\r') {
        return Err(Error::InvalidFraming);
    }
    if payload.is_empty() {
        return Err(Error::EmptyLine);
    }
    Ok(payload)
}

fn payload_length(input: &[u8]) -> usize {
    if input.ends_with(b"\r\n") {
        input.len().saturating_sub(2)
    } else if input.ends_with(b"\n") {
        input.len().saturating_sub(1)
    } else {
        input.len()
    }
}

const fn enforce_line_limit(actual: usize, maximum: usize) -> Result<(), Error> {
    if actual > maximum {
        return Err(Error::ResourceLimit {
            resource: Resource::LineBytes,
            maximum,
            observed: actual,
        });
    }
    Ok(())
}

fn decode_value(text: &str, limits: &Limits) -> Result<Value, Error> {
    classify_numbers(text)?;
    let mut state = DecodeState::new(limits);
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let parsed = ValueSeed {
        state: &mut state,
        depth: 1,
    }
    .deserialize(&mut deserializer);

    let value = match parsed {
        Ok(value) => value,
        Err(error) => {
            return Err(state
                .failure
                .take()
                .map_or_else(|| syntax_error(&error), DecodeFailure::into_error));
        }
    };
    deserializer.end().map_err(|error| syntax_error(&error))?;
    Ok(value)
}

fn syntax_error(error: &serde_json::Error) -> Error {
    Error::JsonSyntax {
        line: error.line(),
        column: error.column(),
    }
}

fn classify_numbers(text: &str) -> Result<(), Error> {
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    let mut previous_significant = None;

    while let Some(&byte) = bytes.get(index) {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
                previous_significant = Some(byte);
            }
            index = index.saturating_add(1);
            continue;
        }

        if byte == b'"' {
            in_string = true;
            index = index.saturating_add(1);
            continue;
        }
        if is_json_whitespace(byte) {
            index = index.saturating_add(1);
            continue;
        }
        if is_number_start(byte)
            && is_value_position(previous_significant)
            && let Some(number) = scan_number(bytes, index)
        {
            if number.non_integer {
                return Err(Error::NonIntegerNumber);
            }
            if integer_exceeds_safe_range(&bytes[number.integer_start..number.integer_end]) {
                return Err(Error::UnsafeInteger);
            }
            previous_significant = number
                .end
                .checked_sub(1)
                .and_then(|last| bytes.get(last))
                .copied();
            index = number.end;
            continue;
        }

        previous_significant = Some(byte);
        index = index.saturating_add(1);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct NumberToken {
    end: usize,
    integer_start: usize,
    integer_end: usize,
    non_integer: bool,
}

fn scan_number(bytes: &[u8], start: usize) -> Option<NumberToken> {
    let mut index = start;
    if bytes.get(index) == Some(&b'-') {
        index = index.checked_add(1)?;
    }
    let integer_start = index;
    match bytes.get(index).copied()? {
        b'0' => index = index.checked_add(1)?,
        b'1'..=b'9' => {
            index = consume_digits(bytes, index.checked_add(1)?);
        }
        _ => return None,
    }
    let integer_end = index;
    let mut non_integer = false;

    if bytes.get(index) == Some(&b'.') {
        let fraction_start = index.checked_add(1)?;
        if !bytes.get(fraction_start).is_some_and(u8::is_ascii_digit) {
            return None;
        }
        non_integer = true;
        index = consume_digits(bytes, fraction_start);
    }
    if matches!(bytes.get(index), Some(b'e' | b'E')) {
        non_integer = true;
        index = index.checked_add(1)?;
        if matches!(bytes.get(index), Some(b'+' | b'-')) {
            index = index.checked_add(1)?;
        }
        if !bytes.get(index).is_some_and(u8::is_ascii_digit) {
            return None;
        }
        index = consume_digits(bytes, index);
    }
    if bytes
        .get(index)
        .is_some_and(|byte| !is_value_delimiter(*byte))
    {
        return None;
    }

    Some(NumberToken {
        end: index,
        integer_start,
        integer_end,
        non_integer,
    })
}

fn consume_digits(bytes: &[u8], mut index: usize) -> usize {
    while bytes.get(index).is_some_and(u8::is_ascii_digit) {
        index = index.saturating_add(1);
    }
    index
}

fn integer_exceeds_safe_range(digits: &[u8]) -> bool {
    const MAX_SAFE_DIGITS: &[u8] = b"9007199254740991";
    digits.len() > MAX_SAFE_DIGITS.len()
        || (digits.len() == MAX_SAFE_DIGITS.len() && digits > MAX_SAFE_DIGITS)
}

const fn is_number_start(byte: u8) -> bool {
    byte == b'-' || byte.is_ascii_digit()
}

const fn is_value_position(previous: Option<u8>) -> bool {
    matches!(previous, None | Some(b'[' | b':' | b','))
}

const fn is_json_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

const fn is_value_delimiter(byte: u8) -> bool {
    is_json_whitespace(byte) || matches!(byte, b',' | b']' | b'}')
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DecodeFailure {
    DuplicateKey,
    NonIntegerNumber,
    UnsafeInteger,
    ResourceLimit {
        resource: Resource,
        maximum: usize,
        observed: usize,
    },
}

impl DecodeFailure {
    const fn into_error(self) -> Error {
        match self {
            Self::DuplicateKey => Error::DuplicateKey,
            Self::NonIntegerNumber => Error::NonIntegerNumber,
            Self::UnsafeInteger => Error::UnsafeInteger,
            Self::ResourceLimit {
                resource,
                maximum,
                observed,
            } => Error::ResourceLimit {
                resource,
                maximum,
                observed,
            },
        }
    }
}

struct DecodeState<'limits> {
    limits: &'limits Limits,
    values: usize,
    total_string_bytes: usize,
    failure: Option<DecodeFailure>,
}

impl<'limits> DecodeState<'limits> {
    const fn new(limits: &'limits Limits) -> Self {
        Self {
            limits,
            values: 0,
            total_string_bytes: 0,
            failure: None,
        }
    }

    fn enter_value<E>(&mut self, depth: usize) -> Result<(), E>
    where
        E: de::Error,
    {
        if depth > self.limits.max_depth {
            return Err(self.fail(DecodeFailure::ResourceLimit {
                resource: Resource::JsonDepth,
                maximum: self.limits.max_depth,
                observed: depth,
            }));
        }
        let observed = self.values.saturating_add(1);
        if observed > self.limits.max_values {
            return Err(self.fail(DecodeFailure::ResourceLimit {
                resource: Resource::JsonValues,
                maximum: self.limits.max_values,
                observed,
            }));
        }
        self.values = observed;
        Ok(())
    }

    fn account_string<E>(&mut self, value: &str) -> Result<(), E>
    where
        E: de::Error,
    {
        let length = value.len();
        if length > self.limits.max_string_bytes {
            return Err(self.fail(DecodeFailure::ResourceLimit {
                resource: Resource::StringBytes,
                maximum: self.limits.max_string_bytes,
                observed: length,
            }));
        }
        let observed = self.total_string_bytes.saturating_add(length);
        if observed > self.limits.max_total_string_bytes {
            return Err(self.fail(DecodeFailure::ResourceLimit {
                resource: Resource::TotalStringBytes,
                maximum: self.limits.max_total_string_bytes,
                observed,
            }));
        }
        self.total_string_bytes = observed;
        Ok(())
    }

    fn reject_number<E>(&mut self, failure: DecodeFailure) -> Result<Value, E>
    where
        E: de::Error,
    {
        Err(self.fail(failure))
    }

    fn fail<E>(&mut self, failure: DecodeFailure) -> E
    where
        E: de::Error,
    {
        if self.failure.is_none() {
            self.failure = Some(failure);
        }
        E::custom(POLICY_ERROR_SENTINEL)
    }
}

struct ValueSeed<'state, 'limits> {
    state: &'state mut DecodeState<'limits>,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for ValueSeed<'_, '_> {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        self.state.enter_value::<D::Error>(self.depth)?;
        deserializer.deserialize_any(ValueVisitor {
            state: self.state,
            depth: self.depth,
        })
    }
}

struct ValueVisitor<'state, 'limits> {
    state: &'state mut DecodeState<'limits>,
    depth: usize,
}

impl<'de> Visitor<'de> for ValueVisitor<'_, '_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.unsigned_abs() > MAX_SAFE_JSON_INTEGER {
            return self.state.reject_number(DecodeFailure::UnsafeInteger);
        }
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value > MAX_SAFE_JSON_INTEGER {
            return self.state.reject_number(DecodeFailure::UnsafeInteger);
        }
        Ok(Value::Number(value.into()))
    }

    fn visit_i128<E>(self, value: i128) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let narrowed = i64::try_from(value)
            .ok()
            .filter(|number| number.unsigned_abs() <= MAX_SAFE_JSON_INTEGER);
        narrowed.map_or_else(
            || self.state.reject_number(DecodeFailure::UnsafeInteger),
            |number| Ok(Value::Number(number.into())),
        )
    }

    fn visit_u128<E>(self, value: u128) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let narrowed = u64::try_from(value)
            .ok()
            .filter(|number| *number <= MAX_SAFE_JSON_INTEGER);
        narrowed.map_or_else(
            || self.state.reject_number(DecodeFailure::UnsafeInteger),
            |number| Ok(Value::Number(number.into())),
        )
    }

    fn visit_f32<E>(self, value: f32) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.classify() == std::num::FpCategory::Zero && value.is_sign_negative() {
            return Ok(Value::Number(0.into()));
        }
        self.state.reject_number(DecodeFailure::NonIntegerNumber)
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.classify() == std::num::FpCategory::Zero && value.is_sign_negative() {
            return Ok(Value::Number(0.into()));
        }
        self.state.reject_number(DecodeFailure::NonIntegerNumber)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.state.account_string::<E>(value)?;
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.state.account_string::<E>(&value)?;
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        loop {
            let Some(value) = sequence.next_element_seed(ArrayElementSeed {
                state: &mut *self.state,
                depth: self.depth.saturating_add(1),
                index: values.len(),
            })?
            else {
                break;
            };
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut entries: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = Map::new();
        while let Some(key) = entries.next_key_seed(ObjectKeySeed {
            state: &mut *self.state,
            index: object.len(),
        })? {
            if object.contains_key(&key) {
                return Err(self.state.fail(DecodeFailure::DuplicateKey));
            }
            let value = entries.next_value_seed(ValueSeed {
                state: &mut *self.state,
                depth: self.depth.saturating_add(1),
            })?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

struct ObjectKeySeed<'state, 'limits> {
    state: &'state mut DecodeState<'limits>,
    index: usize,
}

impl<'de> DeserializeSeed<'de> for ObjectKeySeed<'_, '_> {
    type Value = String;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.index >= self.state.limits.max_object_members {
            return Err(self.state.fail(DecodeFailure::ResourceLimit {
                resource: Resource::ObjectMembers,
                maximum: self.state.limits.max_object_members,
                observed: self.index.saturating_add(1),
            }));
        }
        deserializer.deserialize_string(ObjectKeyVisitor { state: self.state })
    }
}

struct ObjectKeyVisitor<'state, 'limits> {
    state: &'state mut DecodeState<'limits>,
}

impl Visitor<'_> for ObjectKeyVisitor<'_, '_> {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object key")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.state.account_string::<E>(value)?;
        Ok(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.state.account_string::<E>(&value)?;
        Ok(value)
    }
}

struct ArrayElementSeed<'state, 'limits> {
    state: &'state mut DecodeState<'limits>,
    depth: usize,
    index: usize,
}

impl<'de> DeserializeSeed<'de> for ArrayElementSeed<'_, '_> {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.index >= self.state.limits.max_array_items {
            return Err(self.state.fail(DecodeFailure::ResourceLimit {
                resource: Resource::ArrayItems,
                maximum: self.state.limits.max_array_items,
                observed: self.index.saturating_add(1),
            }));
        }
        ValueSeed {
            state: self.state,
            depth: self.depth,
        }
        .deserialize(deserializer)
    }
}

struct CappedWriter {
    bytes: Vec<u8>,
    maximum: usize,
    exceeded_at: Option<usize>,
}

impl CappedWriter {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(maximum.min(4_096)),
            maximum,
            exceeded_at: None,
        }
    }

    const fn exceeded_at(&self) -> Option<usize> {
        self.exceeded_at
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl io::Write for CappedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let observed = self.bytes.len().saturating_add(buffer.len());
        if observed > self.maximum {
            self.exceeded_at = Some(observed);
            return Err(io::Error::other(
                "canonical output exceeds configured limit",
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use proptest::prelude::*;

    use super::{Error, Resource, decode_line, decode_value, encode_line};
    use crate::{
        TRACE_FORMAT_VERSION,
        ir::{IrValue, Record, RedactionMode, TraceHeader, ValidatedRecord},
        limits::Limits,
    };

    const HEADER: &str = r#"{"kind":"trace_header","format":"kvcrucible.trace/v1alpha1","trace_id":"t","redaction":"omitted","created_by":"c","extensions":{}}"#;

    fn header_with_extensions(extensions: &str) -> String {
        format!(
            r#"{{"kind":"trace_header","format":"kvcrucible.trace/v1alpha1","trace_id":"t","redaction":"omitted","created_by":"c","extensions":{extensions}}}"#,
        )
    }

    fn assert_resource(error: &Error, resource: Resource, maximum: usize, observed: usize) {
        assert_eq!(
            error,
            &Error::ResourceLimit {
                resource,
                maximum,
                observed,
            }
        );
    }

    fn decode_error(input: &[u8], limits: &Limits) -> Error {
        decode_line(input, limits)
            .err()
            .expect("input should fail strict decoding")
    }

    #[test]
    fn framing_accepts_eof_lf_and_crlf_but_emits_one_lf() {
        let limits = Limits::default();
        let eof = decode_line(HEADER.as_bytes(), &limits).unwrap();
        let lf = decode_line(format!("{HEADER}\n").as_bytes(), &limits).unwrap();
        let crlf = decode_line(format!("{HEADER}\r\n").as_bytes(), &limits).unwrap();

        assert!(eof == lf);
        assert!(lf == crlf);
        let canonical = encode_line(&eof, &limits).unwrap();
        assert!(canonical.ends_with(b"\n"));
        assert!(!canonical.ends_with(b"\n\n"));
        assert!(!canonical.contains(&b'\r'));
    }

    #[test]
    fn invalid_framing_and_empty_records_fail_closed() {
        let limits = Limits::default();
        for input in [b"".as_slice(), b"\n", b"\r\n", b" \t\n"] {
            assert_eq!(decode_error(input, &limits), Error::EmptyLine);
        }
        for input in [b"{}\r".as_slice(), b"{}\n{}", b"{}\n\n"] {
            assert_eq!(decode_error(input, &limits), Error::InvalidFraming);
        }
    }

    #[test]
    fn invalid_utf8_syntax_and_trailing_values_are_distinct() {
        let limits = Limits::default();
        assert_eq!(
            decode_error(&[b'{', 0xff, b'}'], &limits),
            Error::InvalidUtf8 { valid_up_to: 1 }
        );
        assert!(matches!(
            decode_line(b"{", &limits),
            Err(Error::JsonSyntax { .. })
        ));
        assert!(matches!(
            decode_line(format!("{HEADER} {{}}").as_bytes(), &limits),
            Err(Error::JsonSyntax { .. })
        ));
        assert!(matches!(
            decode_line(b"\x0c", &limits),
            Err(Error::JsonSyntax { .. })
        ));
    }

    #[test]
    fn duplicate_decoded_keys_are_rejected_at_every_depth() {
        let limits = Limits::default();
        let cases = [
            format!(
                "{{\"kind\":\"trace_header\",\"\\u006bind\":\"trace_header\",\"format\":\"{TRACE_FORMAT_VERSION}\",\"trace_id\":\"t\",\"redaction\":\"omitted\",\"created_by\":\"c\",\"extensions\":{{}}}}"
            ),
            header_with_extensions(r#"{"a":1,"\u0061":2}"#),
            header_with_extensions(r#"{"nested":{"é":1,"\u00e9":2}}"#),
            header_with_extensions(r#"{"items":[{"/":1,"\/":2}]}"#),
            header_with_extensions(r#"{"😀":1,"\ud83d\ude00":2}"#),
        ];

        for input in cases {
            assert_eq!(decode_error(input.as_bytes(), &limits), Error::DuplicateKey);
        }
    }

    #[test]
    fn unicode_normalization_is_not_applied_to_keys() {
        let limits = Limits::default();
        let input = header_with_extensions(r#"{"é":1,"e\u0301":2}"#);
        let record = decode_line(input.as_bytes(), &limits).unwrap();
        let output = String::from_utf8(encode_line(&record, &limits).unwrap()).unwrap();
        let decomposed = format!("e{}", '\u{301}');
        let expected = format!(r#""extensions":{{"{decomposed}":2,"é":1}}"#);

        assert!(output.contains(&expected));
    }

    #[test]
    fn integer_only_policy_has_exact_safe_boundaries() {
        let limits = Limits::default();
        for number in ["0", "-0", "-1", "9007199254740991", "-9007199254740991"] {
            let input = header_with_extensions(&format!(r#"{{"n":{number}}}"#));
            assert!(decode_line(input.as_bytes(), &limits).is_ok());
        }
        for number in [
            "9007199254740992",
            "-9007199254740992",
            "18446744073709551616",
            "99999999999999999999999999999999999999",
        ] {
            let input = header_with_extensions(&format!(r#"{{"n":{number}}}"#));
            assert_eq!(
                decode_error(input.as_bytes(), &limits),
                Error::UnsafeInteger
            );
        }
        for number in ["0.0", "-0.0", "1.0", "1e0", "1E+0", "-1e2", "1e400"] {
            let input = header_with_extensions(&format!(r#"{{"n":{number}}}"#));
            assert_eq!(
                decode_error(input.as_bytes(), &limits),
                Error::NonIntegerNumber
            );
        }

        let negative_zero = header_with_extensions(r#"{"n":-0}"#);
        let record = decode_line(negative_zero.as_bytes(), &limits).unwrap();
        let canonical = String::from_utf8(encode_line(&record, &limits).unwrap()).unwrap();
        assert!(canonical.contains(r#""extensions":{"n":0}"#));
    }

    #[test]
    fn malformed_json_numbers_remain_syntax_errors() {
        let limits = Limits::default();
        for number in ["NaN", "Infinity", "+1", "01", ".1", "1."] {
            let input = header_with_extensions(&format!(r#"{{"n":{number}}}"#));
            assert!(matches!(
                decode_line(input.as_bytes(), &limits),
                Err(Error::JsonSyntax { .. })
            ));
        }
    }

    #[test]
    fn every_raw_json_budget_accepts_n_and_rejects_n_plus_one() {
        let limits = Limits {
            max_depth: 2,
            ..Limits::default()
        };
        assert!(decode_value("[0]", &limits).is_ok());
        assert_resource(
            &decode_value("[[0]]", &limits).unwrap_err(),
            Resource::JsonDepth,
            2,
            3,
        );

        let limits = Limits {
            max_values: 3,
            ..Limits::default()
        };
        assert!(decode_value(r#"{"a":[true]}"#, &limits).is_ok());
        assert_resource(
            &decode_value(r#"{"a":[true,false]}"#, &limits).unwrap_err(),
            Resource::JsonValues,
            3,
            4,
        );

        let limits = Limits {
            max_string_bytes: 2,
            ..Limits::default()
        };
        assert!(decode_value(r#""\u00e9""#, &limits).is_ok());
        assert!(decode_value(r#""é""#, &limits).is_ok());
        assert!(decode_value(r#"{"\u00e9":0}"#, &limits).is_ok());
        assert_resource(
            &decode_value(r#""abc""#, &limits).unwrap_err(),
            Resource::StringBytes,
            2,
            3,
        );

        let limits = Limits {
            max_total_string_bytes: 3,
            ..Limits::default()
        };
        assert!(decode_value(r#"{"a":"é"}"#, &limits).is_ok());
        assert_resource(
            &decode_value(r#"{"ab":"é"}"#, &limits).unwrap_err(),
            Resource::TotalStringBytes,
            3,
            4,
        );

        let limits = Limits {
            max_array_items: 1,
            ..Limits::default()
        };
        assert!(decode_value("[0]", &limits).is_ok());
        assert_resource(
            &decode_value("[0,1]", &limits).unwrap_err(),
            Resource::ArrayItems,
            1,
            2,
        );

        let limits = Limits {
            max_object_members: 1,
            ..Limits::default()
        };
        assert!(decode_value(r#"{"a":0}"#, &limits).is_ok());
        assert_resource(
            &decode_value(r#"{"a":0,"b":1}"#, &limits).unwrap_err(),
            Resource::ObjectMembers,
            1,
            2,
        );
    }

    #[test]
    fn line_budget_excludes_the_terminator_and_caps_encoding() {
        let limits = Limits {
            max_line_bytes: HEADER.len(),
            ..Limits::default()
        };
        let record = decode_line(format!("{HEADER}\r\n").as_bytes(), &limits).unwrap();

        let limits = Limits {
            max_line_bytes: HEADER.len() - 1,
            ..Limits::default()
        };
        assert_resource(
            &decode_error(HEADER.as_bytes(), &limits),
            Resource::LineBytes,
            HEADER.len() - 1,
            HEADER.len(),
        );
        assert_resource(
            &decode_error(
                format!(" {HEADER}").as_bytes(),
                &Limits {
                    max_line_bytes: HEADER.len(),
                    ..Limits::default()
                },
            ),
            Resource::LineBytes,
            HEADER.len(),
            HEADER.len() + 1,
        );
        assert_resource(
            &decode_error(
                &[0xff, 0xff],
                &Limits {
                    max_line_bytes: 1,
                    ..Limits::default()
                },
            ),
            Resource::LineBytes,
            1,
            2,
        );

        let canonical_length = encode_line(&record, &Limits::default()).unwrap().len() - 1;
        let limits = Limits {
            max_line_bytes: canonical_length - 1,
            ..Limits::default()
        };
        let error = encode_line(&record, &limits).unwrap_err();
        assert!(matches!(
            error,
            Error::ResourceLimit {
                resource: Resource::LineBytes,
                maximum,
                observed
            } if maximum == canonical_length - 1 && observed > maximum
        ));
    }

    #[test]
    fn encoding_rechecks_every_serialized_structural_budget() {
        let defaults = Limits::default();
        let header = decode_line(HEADER.as_bytes(), &defaults).unwrap();
        let cases = [
            (
                Limits {
                    max_depth: 1,
                    ..defaults
                },
                Resource::JsonDepth,
            ),
            (
                Limits {
                    max_values: 1,
                    ..defaults
                },
                Resource::JsonValues,
            ),
            (
                Limits {
                    max_string_bytes: 16,
                    ..defaults
                },
                Resource::StringBytes,
            ),
            (
                Limits {
                    max_total_string_bytes: 2,
                    ..defaults
                },
                Resource::TotalStringBytes,
            ),
            (
                Limits {
                    max_object_members: 5,
                    ..defaults
                },
                Resource::ObjectMembers,
            ),
        ];

        for (limits, expected) in cases {
            assert!(matches!(
                encode_line(&header, &limits),
                Err(Error::ResourceLimit { resource, .. }) if resource == expected
            ));
        }

        let envelope = decode_line(
            include_bytes!("../tests/fixtures/codec/envelope.canonical.jsonl"),
            &defaults,
        )
        .unwrap();
        let array_limits = Limits {
            max_array_items: 0,
            ..defaults
        };
        assert!(matches!(
            encode_line(&envelope, &array_limits),
            Err(Error::ResourceLimit {
                resource: Resource::ArrayItems,
                ..
            })
        ));
    }

    #[test]
    fn canonical_envelope_matches_the_golden_bytes() {
        let limits = Limits::default();
        let input = include_bytes!("../tests/fixtures/codec/envelope.noncanonical.jsonl");
        let record = decode_line(input, &limits).unwrap();
        let expected = include_bytes!("../tests/fixtures/codec/envelope.canonical.jsonl");

        assert_eq!(encode_line(&record, &limits).unwrap(), expected);
    }

    #[test]
    fn canonical_keys_follow_utf16_code_units_not_rust_string_order() {
        let limits = Limits::default();
        let input = header_with_extensions(
            r#"{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}"#,
        );
        let record = decode_line(input.as_bytes(), &limits).unwrap();
        let expected = concat!(
            "{\"created_by\":\"c\",\"extensions\":{",
            "\"\\r\":\"Carriage Return\",",
            "\"1\":\"One\",",
            "\"\u{80}\":\"Control\",",
            "\"ö\":\"Latin Small Letter O With Diaeresis\",",
            "\"€\":\"Euro Sign\",",
            "\"😀\":\"Emoji: Grinning Face\",",
            "\"דּ\":\"Hebrew Letter Dalet With Dagesh\"},",
            "\"format\":\"kvcrucible.trace/v1alpha1\",",
            "\"kind\":\"trace_header\",\"redaction\":\"omitted\",",
            "\"trace_id\":\"t\"}\n",
        );

        assert_eq!(encode_line(&record, &limits).unwrap(), expected.as_bytes());
    }

    #[test]
    fn canonical_strings_use_the_rfc8785_escape_set() {
        let limits = Limits::default();
        let input = header_with_extensions(r#"{"x":"\u0000\b\t\n\f\r\"\\\/€"}"#);
        let record = decode_line(input.as_bytes(), &limits).unwrap();
        let output = String::from_utf8(encode_line(&record, &limits).unwrap()).unwrap();

        assert!(output.contains(r#""extensions":{"x":"\u0000\b\t\n\f\r\"\\/€"}"#));
    }

    #[test]
    fn schema_and_policy_errors_never_echo_untrusted_values() {
        let secret = "DO_NOT_ECHO_SECRET_8a1544d9";
        let limits = Limits::default();
        let unknown = format!(
            "{{\"kind\":\"trace_header\",\"format\":\"{TRACE_FORMAT_VERSION}\",\"trace_id\":\"t\",\"redaction\":\"omitted\",\"created_by\":\"c\",\"extensions\":{{}},\"{secret}\":1}}"
        );
        let duplicate = header_with_extensions(&format!("{{\"{secret}\":1,\"{secret}\":2}}"));

        for error in [
            decode_error(unknown.as_bytes(), &limits),
            decode_error(duplicate.as_bytes(), &limits),
        ] {
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains(secret));
        }
    }

    #[test]
    fn unsupported_configured_depth_is_explicit() {
        let limits = Limits {
            max_depth: 65,
            ..Limits::default()
        };
        assert_eq!(
            decode_error(HEADER.as_bytes(), &limits),
            Error::InvalidLimits { maximum: 64 }
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]

        #[test]
        fn arbitrary_bounded_bytes_never_panic(input in prop::collection::vec(any::<u8>(), 0..=256)) {
            let _result = decode_line(&input, &Limits::default());
        }

        #[test]
        fn validated_records_have_an_idempotent_canonical_round_trip(
            key in ".{0,16}",
            value in ".{0,32}",
            number in -9_007_199_254_740_991_i64..=9_007_199_254_740_991_i64,
        ) {
            let mut nested = BTreeMap::new();
            nested.insert("number".to_owned(), IrValue::Integer(number));
            nested.insert("value".to_owned(), IrValue::String(value));
            let mut extensions = BTreeMap::new();
            extensions.insert(key, IrValue::Object(nested));
            let raw = Record::TraceHeader(TraceHeader {
                format: TRACE_FORMAT_VERSION.to_owned(),
                trace_id: "property-trace".to_owned(),
                redaction: RedactionMode::Omitted,
                created_by: "proptest".to_owned(),
                extensions,
            });
            let validated = ValidatedRecord::new(raw, &Limits::default()).unwrap();
            let first = encode_line(&validated, &Limits::default()).unwrap();
            let decoded = decode_line(&first, &Limits::default()).unwrap();
            let second = encode_line(&decoded, &Limits::default()).unwrap();

            prop_assert!(decoded == validated);
            prop_assert_eq!(second, first);
        }
    }
}
