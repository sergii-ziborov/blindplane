use std::rc::Rc;

use blindplane_relay::Relay;
use blindplane_wire::ValidationPolicy;

/// Shared relay state, injected into every operation.
#[derive(Clone)]
pub struct RelayState(Rc<Relay>);

impl RelayState {
    /// Build state around a policy.
    pub fn new(policy: ValidationPolicy) -> Self {
        Self(Rc::new(Relay::new(policy)))
    }

    /// The underlying relay.
    pub fn relay(&self) -> &Relay {
        &self.0
    }
}
