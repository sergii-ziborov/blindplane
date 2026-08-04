use blazingly::prelude::*;

use blindplane_relay::RelayError;

/// Failures a relay can report.
///
/// None of these distinguish "wrong key" from "tampered": the relay has no key
/// and cannot tell, which is the point.
#[api_error]
pub enum BlindplaneError {
    /// The record failed keyless validation.
    #[status(400)]
    #[code("record_invalid")]
    #[message("The record failed keyless validation.")]
    RecordInvalid,
    /// The route and the record's authenticated context disagree.
    #[status(400)]
    #[code("route_context_mismatch")]
    #[message("The route does not match the record's authenticated context.")]
    RouteContextMismatch,
    /// The body was not valid base64 or hex.
    #[status(400)]
    #[code("malformed_encoding")]
    #[message("A field was not valid base64 or hexadecimal.")]
    MalformedEncoding,
    /// The write does not advance the stored version.
    #[status(409)]
    #[code("stale_write")]
    #[message("The write does not advance the stored version.")]
    StaleWrite,
    /// No record exists at this identity.
    #[status(404)]
    #[code("record_not_found")]
    #[message("No record exists at this identity.")]
    NotFound,
}

impl From<RelayError> for BlindplaneError {
    fn from(error: RelayError) -> Self {
        match error {
            RelayError::Invalid(_) => Self::RecordInvalid,
            RelayError::RouteContextMismatch => Self::RouteContextMismatch,
            RelayError::StaleWrite { .. } => Self::StaleWrite,
            RelayError::NotFound => Self::NotFound,
        }
    }
}
