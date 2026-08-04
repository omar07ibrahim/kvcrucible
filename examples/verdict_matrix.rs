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
    schedule: String,
    stream: String,
    verdict: &'static str,
    pristine: ExecutionEvidence,
    faulted: ExecutionEvidence,
    ineligibility: IneligibilityEvidence,
}

#[derive(Serialize)]
struct ExecutionEvidence {
    processed_deliveries: usize,
    certainty: &'static str,
    frontier: Option<u64>,
    keys: usize,
    fingerprint_window: usize,
    stale_unverifiable: u64,
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

    assert_converged(&evidence[0]);
    assert_diverged(&evidence[1]);
    assert_ineligible(&evidence[2]);
    println!("{}", serde_json::to_string_pretty(&evidence)?);
    Ok(())
}

fn assert_converged(evidence: &Evidence) {
    assert_eq!(evidence.fixture, "synthetic/reorder-and-duplicate");
    assert_eq!(evidence.schedule, "reorder-and-duplicate");
    assert_eq!(evidence.stream, "s");
    assert_eq!(evidence.verdict, "Converged");
    assert_execution(&evidence.pristine, 3, "Exact", Some(2), 3, 4_096, 0);
    assert_execution(&evidence.faulted, 4, "Exact", Some(2), 3, 4_096, 0);
    assert_ineligibility(&evidence.ineligibility, false, false, false);
}

fn assert_diverged(evidence: &Evidence) {
    assert_eq!(evidence.fixture, "synthetic/same-cursor-selection");
    assert_eq!(evidence.schedule, "select-second");
    assert_eq!(evidence.stream, "s");
    assert_eq!(evidence.verdict, "Diverged");
    assert_execution(&evidence.pristine, 2, "Exact", Some(0), 1, 0, 1);
    assert_execution(&evidence.faulted, 1, "Exact", Some(0), 1, 0, 0);
    assert_ineligibility(&evidence.ineligibility, false, false, false);
}

fn assert_ineligible(evidence: &Evidence) {
    assert_eq!(evidence.fixture, "synthetic/missing-middle-envelope");
    assert_eq!(evidence.schedule, "drop-middle");
    assert_eq!(evidence.stream, "s");
    assert_eq!(evidence.verdict, "Ineligible");
    assert_execution(&evidence.pristine, 3, "Exact", Some(2), 3, 4_096, 0);
    assert_execution(&evidence.faulted, 2, "Unknown", Some(0), 1, 4_096, 0);
    assert_ineligibility(&evidence.ineligibility, false, true, true);
}

fn assert_execution(
    evidence: &ExecutionEvidence,
    processed_deliveries: usize,
    certainty: &str,
    frontier: Option<u64>,
    keys: usize,
    fingerprint_window: usize,
    stale_unverifiable: u64,
) {
    assert_eq!(evidence.processed_deliveries, processed_deliveries);
    assert_eq!(evidence.certainty, certainty);
    assert_eq!(evidence.frontier, frontier);
    assert_eq!(evidence.keys, keys);
    assert_eq!(evidence.fingerprint_window, fingerprint_window);
    assert_eq!(evidence.stale_unverifiable, stale_unverifiable);
}

fn assert_ineligibility(
    evidence: &IneligibilityEvidence,
    pristine_inexact: bool,
    faulted_inexact: bool,
    frontier_mismatch: bool,
) {
    assert_eq!(evidence.pristine_inexact, pristine_inexact);
    assert_eq!(evidence.faulted_inexact, faulted_inexact);
    assert_eq!(evidence.frontier_mismatch, frontier_mismatch);
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

    let sealed = assembler.finish()?;
    assert_eq!(
        sealed.stream_count(),
        1,
        "evidence fixtures have one stream"
    );
    assert_eq!(
        sealed.schedule_count(),
        1,
        "evidence fixtures have one schedule"
    );
    assert_eq!(
        sealed.schedule_id(0),
        Some(schedule),
        "fixture label must match the parsed schedule"
    );
    assert_eq!(sealed.stream_id(0), Some("s"));
    assert_eq!(sealed.schedule_stream_prefix(0), Some(1));
    let actual_schedule = sealed
        .schedule_id(0)
        .expect("the reviewed schedule exists")
        .to_owned();
    let actual_stream = sealed
        .stream_id(0)
        .expect("the reviewed stream exists")
        .to_owned();
    let source_prefix = sealed
        .schedule_source_prefix(0)
        .expect("the reviewed schedule has a source prefix");

    let comparison = sealed.compare_schedule(0)?;
    assert_eq!(
        comparison.stream_count(),
        1,
        "evidence comparison must expose one stream"
    );
    assert_eq!(comparison.pristine().stream_count(), 1);
    assert_eq!(comparison.faulted().stream_count(), 1);
    assert_eq!(comparison.pristine().schedule_id(), schedule);
    assert_eq!(comparison.faulted().schedule_id(), schedule);
    assert_eq!(comparison.pristine().stream_prefix(), 1);
    assert_eq!(comparison.faulted().stream_prefix(), 1);
    assert_eq!(comparison.pristine().source_prefix(), source_prefix);
    assert_eq!(comparison.faulted().source_prefix(), source_prefix);
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
        schedule: actual_schedule,
        stream: actual_stream,
        verdict: verdict_name(stream.verdict()),
        pristine: ExecutionEvidence {
            processed_deliveries: comparison.pristine().delivery_count(),
            certainty: certainty_name(pristine.certainty()),
            frontier: pristine.frontier(),
            keys: pristine.cache_view().key_count(),
            fingerprint_window: pristine.fingerprint_window(),
            stale_unverifiable: pristine.diagnostics().stale_unverifiable(),
        },
        faulted: ExecutionEvidence {
            processed_deliveries: comparison.faulted().delivery_count(),
            certainty: certainty_name(faulted.certainty()),
            frontier: faulted.frontier(),
            keys: faulted.cache_view().key_count(),
            fingerprint_window: faulted.fingerprint_window(),
            stale_unverifiable: faulted.diagnostics().stale_unverifiable(),
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
