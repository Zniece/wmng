//! Every applet, one module each. Applets do CLI parsing and formatting;
//! domain logic lives in wmng_model, Windows calls in providers.

pub mod getfacl;
pub mod power;
pub mod setfacl;

/// Applet names in a stable order, for `wmng --list`.
pub const APPLETS: &[&str] = &["getfacl", "poweroff", "reboot", "setfacl", "shutdown"];
