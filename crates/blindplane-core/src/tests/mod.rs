//! Unit tests for sealing, batching, indexing and pinned verification.

use blindplane_wire::RecordContext;

mod batch_and_index_tests;
mod pinned_tests;
mod sealing_tests;

fn context() -> RecordContext {
    RecordContext {
        tenant: "acme".into(),
        object_id: "patient-42".into(),
        field: "diagnosis".into(),
        epoch: 1,
        version: 1,
        schema_version: 1,
    }
}
