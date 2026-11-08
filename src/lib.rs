//! wmng model layer.
//!
//! Platform-independent by contract (DESIGN.md, layering invariants): no
//! Win32 calls here, ever. Everything that parses, formats, merges or
//! normalizes an ACL lives in this crate so it can be unit-tested on any
//! OS. The bin target (`wmng.exe`) reaches Windows through providers/.

pub mod model;
pub mod ops;
pub mod proc;
pub mod time;
