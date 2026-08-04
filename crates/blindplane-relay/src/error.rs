use blindplane_wire::WireError;

/// What a relay refuses to do.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayError {
    /// The record failed keyless validation.
    Invalid(WireError),
    /// The route and the record's own context disagree.
    RouteContextMismatch,
    /// The write does not strictly advance the stored version chain.
    StaleWrite {
        /// Version the relay already holds.
        stored_version: u64,
        /// Version the client offered.
        offered_version: u64,
    },
    /// No record exists at this key.
    NotFound,
}

impl core::fmt::Display for RelayError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Invalid(error) => write!(f, "{error}"),
            Self::RouteContextMismatch => {
                f.write_str("route does not match the record's authenticated context")
            }
            Self::StaleWrite {
                stored_version,
                offered_version,
            } => write!(
                f,
                "stale write: stored version {stored_version}, offered {offered_version}"
            ),
            Self::NotFound => f.write_str("record not found"),
        }
    }
}

impl std::error::Error for RelayError {}

impl From<WireError> for RelayError {
    fn from(error: WireError) -> Self {
        Self::Invalid(error)
    }
}
