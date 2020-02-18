//! Merkle proof partials are a format for inclusion proofs of specific leaves in a merkle tree.
//!
//! This library is written to conform with the evolving Ethereum 2.0 specification for
//! [merkle proofs](https://github.com/ethereum/eth2.0-specs/blob/dev/specs/light_client/merkle_proofs.md#merklepartial).
//! It provides implementations for the all SSZ primitives, as well as `FixedVectors` and
//! `VariableLists`. Custom contianers can be derived using the `merkle_partial_derive` macro,
//! assuming that each of the child objects have implemented the
//! [`MerkleTreeOverlay`](trait.MerkleTreeOverlay.html) trait.

#[cfg(feature = "generate")]
extern crate alloc;

#[cfg(feature = "generate")]
pub mod list;
pub mod reflist;

pub mod backend;
mod error;
mod merkle_tree_overlay;
pub mod node;
mod path;
mod proof;
mod ser;
pub mod tree_arithmetic;
pub mod types;

pub use crate::backend::hash_children;
pub use crate::merkle_tree_overlay::{impls, MerkleTreeOverlay};
pub use crate::path::PathElement;
pub use crate::proof::Proof;
pub use crate::ser::SerializedProof;

/// General index for a node in a merkle tree.
pub type NodeIndex = u64;

pub const BYTES_PER_CHUNK: usize = 32;

type Index = u128;

pub mod number {
    pub trait Number {
        fn val() -> usize;
    }

    macro_rules! make_num {
        ($name:ident, $val:expr) => {
            #[derive(Clone)]
            pub struct $name;

            impl Number for $name {
                fn val() -> usize {
                    $val
                }
            }
        };
    }

    make_num!(U2, 2);
    make_num!(U3, 3);
    make_num!(U4, 4);
    make_num!(U5, 5);
}

