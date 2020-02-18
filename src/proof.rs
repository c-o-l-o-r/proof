use super::{NodeIndex, SerializedProof, BYTES_PER_CHUNK};
use crate::backend::Backend;
use crate::error::{Error, Result};
use crate::merkle_tree_overlay::MerkleTreeOverlay;
use crate::path::PathElement;
use crate::tree_arithmetic::zeroed::sibling_index;

use std::marker::PhantomData;

/// A `Proof` is generated from a `SerializedProof` and can manipulate / verify data in the
/// merkle tree.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Proof<T: MerkleTreeOverlay> {
    db: Backend,
    _phantom: PhantomData<T>,
}

impl<T: MerkleTreeOverlay> Proof<T> {
    /// Initialize `Proof` directly from a `SerializedProof`.
    pub fn new(proof: SerializedProof) -> Self {
        let mut ret = Self {
            db: Backend::new(),
            _phantom: PhantomData,
        };

        // This will always return `Ok(())` since the `db` is starting empty.
        ret.load(proof).unwrap();

        ret
    }

    /// Populate the struct's cache with a `SerializedProof`.
    pub fn load(&mut self, proof: SerializedProof) -> Result<()> {
        for (i, index) in proof.indices.iter().enumerate() {
            let chunk = proof.chunks[i * BYTES_PER_CHUNK..(i + 1) * BYTES_PER_CHUNK].to_vec();
            self.db.insert(*index, chunk.clone());
        }

        Ok(())
    }

    /// Generates a `SerializedProof` proving that `path` is a part of the current merkle tree.
    pub fn extract(&self, path: Vec<PathElement>) -> Result<SerializedProof> {
        if path.is_empty() {
            return Err(Error::EmptyPath());
        }

        let node = T::get_node(path)?;

        let mut visitor = node.index;
        let mut indices: Vec<NodeIndex> = vec![visitor];
        let mut chunks: Vec<u8> = self
            .db
            .get(visitor)
            .ok_or(Error::ChunkNotLoaded(visitor))?
            .clone();

        while visitor > 0 {
            let sibling = sibling_index(visitor);
            let left = 2 * sibling + 1;
            let right = 2 * sibling + 2;

            if !(indices.contains(&left) && indices.contains(&right)) {
                indices.push(sibling);
                chunks.extend(self.db.get(sibling).ok_or(Error::ChunkNotLoaded(sibling))?);
            }

            // visitor /= 2, when 1 indexed
            visitor = (visitor + 1) / 2 - 1;
        }

        Ok(SerializedProof { indices, chunks })
    }

    /// Returns the bytes representation of the object associated with `path`
    pub fn get_bytes(&self, path: Vec<PathElement>) -> Result<Vec<u8>> {
        if path.is_empty() {
            return Err(Error::EmptyPath());
        }

        let (index, begin, end) = bytes_at_path_helper::<T>(path)?;

        Ok(self.db.get(index).ok_or(Error::ChunkNotLoaded(index))?[begin..end].to_vec())
    }

    /// Replaces the bytes at `path` with `bytes`.
    pub fn set_bytes(&mut self, path: Vec<PathElement>, bytes: Vec<u8>) -> Result<()> {
        if path.is_empty() {
            return Err(Error::EmptyPath());
        }

        let (index, begin, end) = bytes_at_path_helper::<T>(path)?;

        let chunk = self
            .db
            .get(index)
            .ok_or(Error::ChunkNotLoaded(index))?
            .to_vec()
            .iter()
            .cloned()
            .enumerate()
            .map(|(i, b)| {
                if i >= begin && i < end {
                    bytes[i - begin]
                } else {
                    b
                }
            })
            .collect();

        self.db.insert(index, chunk);
        Ok(())
    }

    /// Determines if the current merkle tree is valid.
    pub fn is_valid(&self, root: Vec<u8>) -> bool {
        self.db.is_valid(root)
    }

    /// Inserts missing nodes into the merkle tree that can be generated from existing nodes.
    pub fn fill(&mut self) -> Result<()> {
        self.db.fill()
    }

    /// Returns the root node of the proof if it has been calculated.
    pub fn root(&self) -> Option<&Vec<u8>> {
        self.db.get(0)
    }

    /// Recalculates all intermediate nodes and root using the available leaves.
    pub fn refresh(&mut self) -> Result<()> {
        self.db.refresh()
    }
}

/// Recursively traverse the tree structure, matching the appropriate `path` element with its index,
/// eventually returning the chunk index, beginning offset, and end offset of the associated value.
fn bytes_at_path_helper<T: MerkleTreeOverlay + ?Sized>(
    path: Vec<PathElement>,
) -> Result<(NodeIndex, usize, usize)> {
    if path.is_empty() {
        return Err(Error::EmptyPath());
    }

    let node = T::get_node(path)?;

    Ok((
        node.index,
        node.offset.into(),
        (node.offset + node.size).into(),
    ))
}
