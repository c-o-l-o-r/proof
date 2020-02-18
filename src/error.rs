use super::NodeIndex;
use crate::path::PathElement;

/// An enum of errors that can occur when interacting with proof.
#[derive(Debug, PartialEq)]
pub enum Error {
    // Invalid path element
    InvalidPath(PathElement),
    // The path accesses an unintialized element
    IndexOutOfBounds(u64),
    // Missing chunk
    ChunkNotLoaded(NodeIndex),
    // Path provided was empty
    EmptyPath(),
}

pub type Result<T> = std::result::Result<T, Error>;


pub type ExitCode = usize;
pub const OK: usize = 0;
pub const ERR: usize = 1;