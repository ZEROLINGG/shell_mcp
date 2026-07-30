// src/protocol/params/mod.rs
mod exec;
mod io;
mod pty;
mod session;

pub use exec::ExecParams;
pub use io::{OutputParams, SendParams, WaitForParams};
pub use pty::{ControlParams, MoveCursorParams, ResizeParams, SendKeysParams, SnapshotParams};
pub use session::{SpawnParams, TagParams};
