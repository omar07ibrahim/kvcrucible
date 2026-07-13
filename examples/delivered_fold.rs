use std::{
    error::Error,
    io::{BufReader, Cursor},
};

use kvcrucible::{
    jsonl::{JsonlReader, LocatedRecord},
    limits::Limits,
    state::{BaselineAuthority, Certainty, EnvelopeNormalizer, StreamState},
    trace::TraceValidator,
};

const TRACE: &[u8] = concat!(
    r#"{"kind":"trace_header","format":"kvcrucible.trace/v1alpha1","trace_id":"fold-demo","redaction":"omitted","created_by":"synthetic-example","extensions":{}}"#,
    "\n",
    r#"{"kind":"stream","stream_id":"s","engine":"synthetic","engine_version":"1","engine_instance":"demo","publisher":"p","data_parallel_rank":0,"epoch":"e","initial_cursor":"0","baseline":{"kind":"empty_at_engine_start"},"extensions":{}}"#,
    "\n",
    r#"{"kind":"envelope","envelope_id":"e0","stream_id":"s","cursor":"0","origin":"live","mutations":[{"op":"store_run","hashes":[{"encoding":"u64","value":"101"}],"group":{"kind":"unspecified"},"medium":{"kind":"unspecified"},"metadata":{}}],"extensions":{}}"#,
    "\n",
    r#"{"kind":"envelope","envelope_id":"e2","stream_id":"s","cursor":"2","origin":"live","mutations":[{"op":"store_run","hashes":[{"encoding":"u64","value":"103"}],"group":{"kind":"unspecified"},"medium":{"kind":"unspecified"},"metadata":{}}],"extensions":{}}"#,
    "\n",
    r#"{"kind":"envelope","envelope_id":"e1","stream_id":"s","cursor":"1","origin":"replay","mutations":[{"op":"store_run","hashes":[{"encoding":"u64","value":"102"}],"group":{"kind":"unspecified"},"medium":{"kind":"unspecified"},"metadata":{}}],"extensions":{}}"#,
    "\n",
)
.as_bytes();

fn main() -> Result<(), Box<dyn Error>> {
    let limits = Limits::default();
    let records = JsonlReader::new(BufReader::new(Cursor::new(TRACE)), limits)
        .map(|located| located.map(LocatedRecord::into_record))
        .collect::<Result<Vec<_>, _>>()?;

    let mut validator = TraceValidator::new(limits)?;
    for record in &records {
        validator.push(record)?;
    }
    let structural = validator.finish()?;
    assert_eq!(structural.envelopes(), 3);

    let mut normalizer = EnvelopeNormalizer::new(limits)?;
    let mut state = StreamState::new(
        &records[1],
        BaselineAuthority::TrustDeclaredEmpty,
        &mut normalizer,
    )?;

    for record in &records[2..] {
        let prepared = normalizer.prepare(record.clone())?;
        println!("{:?}", state.admit(prepared)?);
    }

    let sealed = normalizer.seal()?;
    let summary = state.finish(&sealed)?;
    assert_eq!(summary.certainty(), Certainty::Exact);
    assert_eq!(summary.frontier(), Some(2));
    assert_eq!(summary.cache_view().key_count(), 3);
    println!(
        "certainty={:?} frontier={:?} keys={}",
        summary.certainty(),
        summary.frontier(),
        summary.cache_view().key_count()
    );

    Ok(())
}
