use blindplane_wire::SealedRecord;

/// Identity of one stored record.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RecordKey {
    /// Tenant or workspace.
    pub tenant: String,
    /// Object identifier.
    pub object_id: String,
    /// Field or security zone.
    pub field: String,
}

impl RecordKey {
    /// Build a key from its three parts.
    pub fn new(
        tenant: impl Into<String>,
        object_id: impl Into<String>,
        field: impl Into<String>,
    ) -> Self {
        Self {
            tenant: tenant.into(),
            object_id: object_id.into(),
            field: field.into(),
        }
    }

    pub(crate) fn of(record: &SealedRecord) -> Self {
        Self {
            tenant: record.context.tenant.clone(),
            object_id: record.context.object_id.clone(),
            field: record.context.field.clone(),
        }
    }
}
