use std::{
    error::Error,
    io::{BufReader, Cursor},
};

use kvcrucible::{
    ir::Record,
    jsonl::{JsonlReader, LocatedRecord},
    limits::Limits,
    scenario::{ConvergenceVerdict, TraceAssembler},
    state::{BaselineAuthority, Certainty},
};
use serde::Serialize;

const CONVERGED_TRACE: &[u8] = concat!(
    r#"{"kind":"trace_header","format":"kvcrucible.trace/v1alpha1","trace_id":"converged-demo","redaction":"omitted","created_by":"synthetic-example","extensions":{}}"#,
    "\n",
    r#"{"kind":"stream","stream_id":"s","engine":"synthetic","engine_version":"1","engine_instance":"demo","publisher":"p","data_parallel_rank":0,"epoch":"e","initial_cursor":"0","baseline":{"kind":"empty_at_engine_start"},"extensions":{}}"#,
    "\n",
    r#"{"kind":"envelope","envelope_id":"e0","stream_id":"s","cursor":"0","origin":"live","mutations":[{"op":"store_run","hashes":[{"encoding":"u64","value":"101"}],"group":{"kind":"unspecified"},"medium":{"kind":"unspecified"},"metadata":{}}],"extensions":{}}"#,
    "\n",
    r#"{"kind":"envelope","envelope_id":"e1","stream_id":"s","cursor":"1","origin":"live","mutations":[{"op":"store_run","hashes":[{"encoding":"u64","value":"102"}],"group":{"kind":"unspecified"},"medium":{"kind":"unspecified"},"metadata":{}}],"extensions":{}}"#,
    "\n",
    r#"{"kind":"envelope","envelope_id":"e2","stream_id":"s","cursor":"2","origin":"live","mutations":[{"op":"store_run","hashes":[{"encoding":"u64","value":"103"}],"group":{"kind":"unspecified"},"medium":{"kind":"unspecified"},"metadata":{}}],"extensions":{}}"#,
    "\n",
    r#"{"kind":"fault_schedule","schedule_id":"reorder-and-duplicate","actions":[{"action":"duplicate","target":{"envelope_id":"e1","occurrence":0},"copies":1},{"action":"move_before","target":{"envelope_id":"e2","occurrence":0},"anchor":{"envelope_id":"e0","occurrence":0}}],"extensions":{}}"#,
    "\n",
)
.as_bytes();

const DIVERGED_TRACE: &[u8] = concat!(
    r#"{"kind":"trace_header","format":"kvcrucible.trace/v1alpha1","trace_id":"diverged-demo","redaction":"omitted","created_by":"synthetic-example","extensions":{}}"#,
    "\n",
    r#"{"kind":"stream","stream_id":"s","engine":"synthetic","engine_version":"1","engine_instance":"demo","publisher":"p","data_parallel_rank":0,"epoch":"e","initial_cursor":"0","baseline":{"kind":"empty_at_engine_start"},"extensions":{}}"#,
    "\n",
    r#"{"kind":"envelope","envelope_id":"first","stream_id":"s","cursor":"0","origin":"live","mutations":[{"op":"store_run","hashes":[{"encoding":"u64","value":"201"}],"group":{"kind":"unspecified"},"medium":{"kind":"unspecified"},"metadata":{}}],"extensions":{}}"#,
    "\n",
    r#"{"kind":"envelope","envelope_id":"second","stream_id":"s","cursor":"0","origin":"live","mutations":[{"op":"store_run","hashes":[{"encoding":"u64","value":"202"}],"group":{"kind":"unspecified"},"medium":{"kind":"unspecified"},"metadata":{}}],"extensions":{}}"#,
    "\n",
    r#"{"kind":"fault_schedule","schedule_id":"select-second","actions":[{"action":"drop","target":{"envelope_id":"first","occurrence":0}}],"extensions":{}}"#,
    "\n",
)
.as_bytes();

const INELIGIBLE_TRACE: &[u8] = concat!(
    r#"{"kind":"trace_header","format":"kvcrucible.trace/v1alpha1","trace_id":"ineligible-demo","redaction":"omitted","created_by":"synthetic-example","extensions":{}}"#,
    "\n",
    r#"{"kind":"stream","stream_id":"s","engine":"synthetic","engine_version":"1","engine_instance":"demo","publisher":"p","data_parallel_rank":0,"epoch":"e","initial_cursor":"0","baseline":{"kind":"empty_at_engine_start"},"extensions":{}}"#,
    "\n",
    r#"{"kind":"envelope","envelope_id":"e0","stream_id":"s","cursor":"0","origin":"live","mutations":[{"op":"store_run","hashes":[{"encoding":"u64","value":"301"}],"group":{"kind":"unspecified"},"medium":{"kind":"unspecified"},"metadata":{}}],"extensions":{}}"#,
    "\n",
    r#"{"kind":"envelope","envelope_id":"e1","stream_id":"s","cursor":"1","origin":"live","mutations":[{"op":"store_run","hashes":[{"encoding":"u64","value":"302"}],"group":{"kind":"unspecified"},"medium":{"kind":"unspecified"},"metadata":{}}],"extensions":{}}"#,
    "\n",
    r#"{"kind":"envelope","envelope_id":"e2","stream_id":"s","cursor":"2","origin":"live","mutations":[{"op":"store_run","hashes":[{"encoding":"u64","value":"303"}],"group":{"kind":"unspecified"},"medium":{"kind":"unspecified"},"metadata":{}}],"extensions":{}}"#,
    "\n",
    r#"{"kind":"fault_schedule","schedule_id":"drop-middle","actions":[{"action":"drop","target":{"envelope_id":"e1","occurrence":0}}],"extensions":{}}"#,
    "\n",
)
.as_bytes();

#[derive(Serialize)]
struct Evidence {
    fixture: &'static str,
    schedule: &'static str,
    verdict: &'static str,
    pristine: ExecutionEvidence,
    faulted: ExecutionEvidence,
    ineligibility: IneligibilityEvidence,
}

#[derive(Serialize)]
struct ExecutionEvidence {
    deliveries: usize,
    certainty: &'static str,
    frontier: Option<u64>,
    keys: usize,
}

#[derive(Serialize)]
struct IneligibilityEvidence {
    pristine_inexact: bool,
    faulted_inexact: bool,
    frontier_mismatch: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let evidence = [
        run(
            "synthetic/reorder-and-duplicate",
            "reorder-and-duplicate",
            CONVERGED_TRACE,
            &Limits::default(),
        )?,
        run(
            "synthetic/same-cursor-selection",
            "select-second",
            DIVERGED_TRACE,
            &Limits {
                max_recent_fingerprints_per_stream: 0,
                ..Limits::default()
            },
        )?,
        run(
            "synthetic/missing-middle-envelope",
            "drop-middle",
            INELIGIBLE_TRACE,
            &Limits::default(),
        )?,
    ];

    assert_eq!(evidence[0].verdict, "Converged");
    assert_eq!(evidence[1].verdict, "Diverged");
    assert_eq!(evidence[2].verdict, "Ineligible");
    println!("{}", serde_json::to_string_pretty(&evidence)?);
    Ok(())
}

fn run(
    fixture: &'static str,
    schedule: &'static str,
    trace: &[u8],
    limits: &Limits,
) -> Result<Evidence, Box<dyn Error>> {
    let records = JsonlReader::new(BufReader::new(Cursor::new(trace)), *limits)
        .map(|located| located.map(LocatedRecord::into_record))
        .collect::<Result<Vec<_>, _>>()?;

    let mut assembler = TraceAssembler::new(*limits)?;
    for record in records {
        let authority = matches!(record.as_record(), Record::Stream(_))
            .then_some(BaselineAuthority::TrustDeclaredEmpty);
        assembler.push(record, authority)?;
    }

    let comparison = assembler.finish()?.compare_schedule(0)?;
    let stream = comparison
        .stream(0)
        .expect("each evidence fixture declares one visible stream");
    let pristine = comparison
        .pristine()
        .stream(0)
        .expect("the pristine execution finalizes the visible stream");
    let faulted = comparison
        .faulted()
        .stream(0)
        .expect("the faulted execution finalizes the visible stream");
    let ineligibility = stream.ineligibility();

    Ok(Evidence {
        fixture,
        schedule,
        verdict: verdict_name(stream.verdict()),
        pristine: ExecutionEvidence {
            deliveries: comparison.pristine().delivery_count(),
            certainty: certainty_name(pristine.certainty()),
            frontier: pristine.frontier(),
            keys: pristine.cache_view().key_count(),
        },
        faulted: ExecutionEvidence {
            deliveries: comparison.faulted().delivery_count(),
            certainty: certainty_name(faulted.certainty()),
            frontier: faulted.frontier(),
            keys: faulted.cache_view().key_count(),
        },
        ineligibility: IneligibilityEvidence {
            pristine_inexact: ineligibility.pristine_inexact(),
            faulted_inexact: ineligibility.faulted_inexact(),
            frontier_mismatch: ineligibility.frontier_mismatch(),
        },
    })
}

const fn verdict_name(verdict: ConvergenceVerdict) -> &'static str {
    match verdict {
        ConvergenceVerdict::Converged => "Converged",
        ConvergenceVerdict::Diverged => "Diverged",
        ConvergenceVerdict::Ineligible => "Ineligible",
    }
}

const fn certainty_name(certainty: Certainty) -> &'static str {
    match certainty {
        Certainty::Exact => "Exact",
        Certainty::Recovering => "Recovering",
        Certainty::Unknown => "Unknown",
    }
}
