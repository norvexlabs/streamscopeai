//! Dialect-specific wire codecs. Each dialect module converts between its
//! JSON shapes and the protocol-agnostic `a2a::model` types; the dispatcher
//! selects the codec from the negotiated `A2A-Version`. v1 ships `v1_0`
//! only — a 0.3 dialect is a sibling module, zero dispatcher change.

pub mod v1_0;
