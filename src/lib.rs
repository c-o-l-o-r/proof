//! Merkle proof partials are a format for inclusion proofs of specific leaves in a merkle tree.
//!
//! This library is written to conform with the evolving Ethereum 2.0 specification for
//! [merkle proofs](https://github.com/ethereum/eth2.0-specs/blob/dev/specs/light_client/merkle_proofs.md#merklepartial).
//! It provides implementations for the all SSZ primitives, as well as `FixedVectors` and
//! `VariableLists`. Custom contianers can be derived using the `merkle_partial_derive` macro,
//! assuming that each of the child objects have implemented the
//! [`MerkleTreeOverlay`](trait.MerkleTreeOverlay.html) trait.

pub mod cache;
mod error;
mod merkle_tree_overlay;
pub mod node;
mod path;
mod proof;
mod ser;
pub mod tree_arithmetic;
pub mod types;

pub use crate::cache::hash_children;
pub use crate::error::Error;
pub use crate::merkle_tree_overlay::{impls, MerkleTreeOverlay};
pub use crate::path::PathElement;
pub use crate::proof::Proof;
pub use crate::ser::SerializedProof;

/// General index for a node in a merkle tree.
pub type NodeIndex = u64;

pub const BYTES_PER_CHUNK: usize = 32;
