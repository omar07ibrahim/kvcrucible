use std::{
    error::Error,
    io::{BufReader, Cursor},
    sync::Arc,
};

use kvcrucible::{
    ir::Record,
    jsonl::{JsonlReader, LocatedRecord},
    limits::Limits,
    scenario::{ConvergenceVerdict, TraceAssembler},
    state::{BaselineAuthority, Certainty},
};

const TRACE: &[u8] = concat!(
    r#"{"kind":"trace_header","format":"kvcrucible.trace/v1alpha1","trace_id":"fault-demo","redaction":"omitted","created_by":"synthetic-example","extensions":{}}"#,
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

fn main() -> Result<(), Box<dyn Error>> {
    let limits = Limits::default();
    let records = JsonlReader::new(BufReader::new(Cursor::new(TRACE)), limits)
        .map(|located| located.map(LocatedRecord::into_record))
        .collect::<Result<Vec<_>, _>>()?;

    let mut assembler = TraceAssembler::new(limits)?;
    for record in records {
        let authority = matches!(record.as_record(), Record::Stream(_))
            .then_some(BaselineAuthority::TrustDeclaredEmpty);
        assembler.push(record, authority)?;
    }

    let sealed = assembler.finish()?;
    let schedule = sealed.materialize(0)?;
    let mut state = sealed.start_stream(0)?;
    for delivery in schedule.deliveries() {
        let disposition = state.admit(Arc::clone(delivery.source()))?;
        println!(
            "{}#{} {:?}",
            delivery.envelope_id(),
            delivery.occurrence(),
            disposition
        );
    }

    let summary = sealed.finish_stream(state)?;
    assert_eq!(summary.certainty(), Certainty::Exact);
    assert_eq!(summary.frontier(), Some(2));
    assert_eq!(summary.cache_view().key_count(), 3);
    println!(
        "certainty={:?} frontier={:?} keys={}",
        summary.certainty(),
        summary.frontier(),
        summary.cache_view().key_count()
    );

    let comparison = sealed.compare_schedule(0)?;
    let verdict = comparison
        .stream(0)
        .expect("the synthetic trace declares one visible stream")
        .verdict();
    assert_eq!(verdict, ConvergenceVerdict::Converged);
    println!(
        "verdict={verdict:?} pristine_deliveries={} faulted_deliveries={}",
        comparison.pristine().delivery_count(),
        comparison.faulted().delivery_count()
    );

    Ok(())
}
