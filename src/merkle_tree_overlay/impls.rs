use super::MerkleTreeOverlay;
use crate::error::{Error, Result};
use crate::node::Node;
use crate::path::PathElement;
use crate::tree_arithmetic::zeroed::{left_most_leaf, subtree_index_to_general};
use crate::tree_arithmetic::{log_base_two, next_power_of_two};
use crate::types::{FixedVector, VariableList};
use crate::{NodeIndex, BYTES_PER_CHUNK};
use ethereum_types::U256;
use typenum::Unsigned;

macro_rules! impl_merkle_overlay_for_basic_type {
    ($type: ident, $bit_size: expr) => {
        impl MerkleTreeOverlay for $type {
            fn height() -> u64 {
                0
            }

            fn min_repr_size() -> u64 {
                ($bit_size / 8) as u64
            }

            fn is_list() -> bool {
                false
            }

            fn get_node(path: Vec<PathElement>) -> Result<Node> {
                if path.len() == 0 {
                    Ok(Node {
                        ident: PathElement::from_ident_str(""),
                        index: 0,
                        size: ($bit_size / 32) as u8,
                        offset: 0,
                        height: 0,
                        is_list: false,
                    })
                } else {
                    Err(Error::InvalidPath(path[0].clone()))
                }
            }
        }
    };
}

impl_merkle_overlay_for_basic_type!(bool, 8);
impl_merkle_overlay_for_basic_type!(u8, 8);
impl_merkle_overlay_for_basic_type!(u16, 16);
impl_merkle_overlay_for_basic_type!(u32, 32);
impl_merkle_overlay_for_basic_type!(u64, 64);
impl_merkle_overlay_for_basic_type!(u128, 128);
impl_merkle_overlay_for_basic_type!(U256, 256);
impl_merkle_overlay_for_basic_type!(usize, std::mem::size_of::<usize>());

/// Implements the `MerkleTreeOverlay` trait for SSZ Vector and List types.
///
/// The full specification of the merkle tree structure can be found in the SSZ documentation:
/// https://github.com/ethereum/eth2.0-specs/blob/dev/specs/simple-serialize.md#merkleization
///
/// Below is a visual representation of the merkle tree for variable length Lists:
///
///             root
///           /      \
///      data_root   len
///        /   \
///       *     *           <= intermediate nodes
///      / \   / \
///     x   x x   x         <= leaf nodes
///
/// And a visual representation of the merkle tree for fixed length Vectors:
///
///             root(0)
///             /     \
///            *       *    <= intermediate nodes
///           / \     / \
///          x   x   x   x  <= leaf nodes

macro_rules! impl_merkle_overlay_for_collection_type {
    ($type: ident, $is_variable_length: expr) => {
        impl<T: MerkleTreeOverlay, N: Unsigned> MerkleTreeOverlay for $type<T, N> {
            fn height() -> u64 {
                let items_per_chunk = BYTES_PER_CHUNK as u64 / T::min_repr_size();
                // TODO: what if division is 0?
                let num_leaves = next_power_of_two(N::to_u64() / items_per_chunk);
                let data_tree_height = log_base_two(num_leaves);

                if $is_variable_length {
                    // Add one to account for the data root and the length of the list.
                    data_tree_height + 1
                } else {
                    data_tree_height
                }
            }

            fn min_repr_size() -> u64 {
                if Self::height() > 0 {
                    32
                } else {
                    T::min_repr_size() * N::to_u64()
                }
            }

            fn is_list() -> bool {
                $is_variable_length
            }

            fn get_node(path: Vec<PathElement>) -> Result<Node> {
                match path.first() {
                    // If the first element of the path is an index, it should exactly match the
                    // index of one of the leaf nodes in the current tree.
                    Some(PathElement::Index(position)) => {
                        // If the position in the collection is greater than the max number of
                        // elements, return an error.
                        if *position >= N::to_u64() {
                            return Err(Error::IndexOutOfBounds(*position));
                        }

                        let first_leaf = left_most_leaf(0, Self::height() as u64);
                        let items_per_chunk = (BYTES_PER_CHUNK as u64 / T::min_repr_size()) as u64;
                        let leaf_index = first_leaf + (position / items_per_chunk);

                        // If the path terminates here, return the node in the current tree.
                        if path.len() == 1 {
                            let items_per_chunk = BYTES_PER_CHUNK as u64 / T::min_repr_size();

                            Ok(Node {
                                ident: path[0].clone(),
                                index: (1 << Self::height()) + (position / items_per_chunk) - 1,
                                size: T::min_repr_size() as u8,
                                offset: ((position % items_per_chunk) * T::min_repr_size()) as u8,
                                height: T::height(),
                                is_list: T::is_list(),
                            })

                        // If the path does not terminate, recursively call the child `T` to
                        // continue matching the path. Translate the child's return index to
                        // the current general index space.
                        } else {
                            let node = T::get_node(path[1..].to_vec())?;
                            let index = subtree_index_to_general(leaf_index, node.index);

                            Ok(replace_index(node.clone(), index))
                        }
                    }
                    // The only possible match for idents in a collection is when the collection is
                    // of dynamic length and the ident == "len". Otherwise, it is invalid.
                    Some(PathElement::Ident(i)) => {
                        if $is_variable_length && i == "len" {
                            Ok(Node {
                                ident: PathElement::from_ident_str("len"),
                                index: 2,
                                size: 32,
                                offset: 0,
                                height: 0,
                                is_list: false,
                            })
                        } else {
                            Err(Error::InvalidPath(path[0].clone()))
                        }
                    }
                    // If there is no first element, return an error.
                    None => Err(Error::EmptyPath()),
                }
            }
        }
    };
}

impl_merkle_overlay_for_collection_type!(VariableList, true);
impl_merkle_overlay_for_collection_type!(FixedVector, false);

/// Returns a copy of `node` with all its index values changed to `index`.
pub fn replace_index(node: Node, index: NodeIndex) -> Node {
    Node {
        ident: node.ident.clone(),
        index,
        size: node.size,
        offset: node.offset,
        height: node.height,
        is_list: node.is_list,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use typenum::{U1, U16, U2, U32, U4, U8};

    #[test]
    fn variable_list_overlay() {
        // Merkle structure for `VariableList<U256, U8>`
        //
        //                 +---------- 0 ----------+                 <= composite
        //                /           -+            \
        //          +--- 1 ---+        |        +--- 2 ---+          <= length
        //         /           \       |       /           \
        //        3             4      |- I   5             6        -+
        //      /   \         /   \    |    /   \         /   \       |
        //     7     8       9    10   |   11   12       13   14      |- unattacted
        //    / \   / \     / \   / \ -+  / \   / \     / \   / \     |
        //   15 16 17 18   19 20 21 22   23 24 25 26   27 28 29 30   -+
        //  |________________________|
        //              +
        //              |
        //              +--------------- leaves
        type T = VariableList<U256, U8>;

        // TESTING LENGTH NODE
        assert_eq!(
            T::get_node(vec![PathElement::from_ident_str("len")]),
            Ok(Node {
                ident: PathElement::from_ident_str("len"),
                index: 2,
                size: 32,
                offset: 0,
                height: 0,
                is_list: false,
            })
        );

        // TESTING LEAF NODES
        assert_eq!(
            T::get_node(vec![PathElement::Index(0)]),
            Ok(Node {
                ident: PathElement::Index(0),
                index: 15,
                size: 32,
                offset: 0,
                height: 0,
                is_list: false,
            })
        );

        assert_eq!(
            T::get_node(vec![PathElement::Index(3)]),
            Ok(Node {
                ident: PathElement::Index(3),
                index: 18,
                size: 32,
                offset: 0,
                height: 0,
                is_list: false,
            })
        );

        assert_eq!(
            T::get_node(vec![PathElement::Index(7)]),
            Ok(Node {
                ident: PathElement::Index(7),
                index: 22,
                size: 32,
                offset: 0,
                height: 0,
                is_list: false,
            })
        );

        // TESTING OUT-OF-BOUNDS INDEX
        assert_eq!(
            T::get_node(vec![PathElement::Index(9)]),
            Err(Error::IndexOutOfBounds(9))
        );
    }

    #[test]
    fn nested_variable_list_overlay() {
        type T = VariableList<VariableList<VariableList<U256, U2>, U2>, U4>;

        // TESTING LENGTH NODE
        // root list length
        assert_eq!(
            T::get_node(vec![PathElement::from_ident_str("len")]),
            Ok(Node {
                ident: PathElement::from_ident_str("len"),
                index: 2,
                size: 32,
                offset: 0,
                height: 0,
                is_list: false,
            })
        );

        // position 0 list length
        assert_eq!(
            T::get_node(vec![
                PathElement::Index(0),
                PathElement::from_ident_str("len")
            ]),
            Ok(Node {
                ident: PathElement::from_ident_str("len"),
                index: 16,
                size: 32,
                offset: 0,
                height: 0,
                is_list: false,
            })
        );

        // position 3 list length
        assert_eq!(
            T::get_node(vec![
                PathElement::Index(3),
                PathElement::from_ident_str("len")
            ]),
            Ok(Node {
                ident: PathElement::from_ident_str("len"),
                index: 22,
                size: 32,
                offset: 0,
                height: 0,
                is_list: false,
            })
        );

        // TESTING LEAF NODES
        assert_eq!(
            T::get_node(vec![
                PathElement::Index(0),
                PathElement::Index(1),
                PathElement::Index(0)
            ]),
            Ok(Node {
                ident: PathElement::Index(0),
                index: 131,
                size: 32,
                offset: 0,
                height: 0,
                is_list: false,
            })
        );
        assert_eq!(
            T::get_node(vec![
                PathElement::Index(2),
                PathElement::Index(1),
                PathElement::Index(0)
            ]),
            Ok(Node {
                ident: PathElement::Index(0),
                index: 163,
                size: 32,
                offset: 0,
                height: 0,
                is_list: false,
            })
        );

        assert_eq!(
            T::get_node(vec![
                PathElement::Index(3),
                PathElement::Index(0),
                PathElement::Index(1)
            ]),
            Ok(Node {
                ident: PathElement::Index(1),
                index: 176,
                size: 32,
                offset: 0,
                height: 0,
                is_list: false,
            })
        );

        // TESTING OUT-OF-BOUNDS
        assert_eq!(
            T::get_node(vec![PathElement::Index(4)]),
            Err(Error::IndexOutOfBounds(4))
        );
        assert_eq!(
            T::get_node(vec![PathElement::Index(3), PathElement::Index(2)]),
            Err(Error::IndexOutOfBounds(2))
        );
        assert_eq!(
            T::get_node(vec![
                PathElement::Index(3),
                PathElement::Index(1),
                PathElement::Index(2)
            ]),
            Err(Error::IndexOutOfBounds(2))
        );
    }

    #[test]
    fn simple_fixed_vector() {
        type T = FixedVector<U256, U8>;

        // Merkle structure for `FixedVector<U256, U8>`
        //
        //            ___ 0 ___              <= composite
        //           /         \            -+
        //          1           2            |
        //        /   \       /   \          |- intermediate
        //       3     4     5     6         |
        //      / \   / \   / \   / \       -+
        //     7   8 9  10 11 12 13 14      <= leaf

        assert_eq!(T::height(), 3);

        for i in 7..=14 {
            assert_eq!(
                T::get_node(vec![PathElement::Index(i - 7)]),
                Ok(Node {
                    ident: PathElement::Index(i - 7),
                    index: i,
                    size: 32,
                    offset: 0,
                    height: 0,
                    is_list: false,
                })
            );
        }

        // TESTING OUT-OF-BOUNDS
        assert_eq!(
            T::get_node(vec![PathElement::Index(8)]),
            Err(Error::IndexOutOfBounds(8))
        );

        // TESTING LENGTH
        assert_eq!(
            T::get_node(vec![PathElement::from_ident_str("len")]),
            Err(Error::InvalidPath(PathElement::from_ident_str("len")))
        );
    }

    #[test]
    fn another_simple_fixed_vector() {
        type T = FixedVector<u8, U32>;

        assert_eq!(T::height(), 0);

        // TESTING ALL PATHS
        for i in 0..32 {
            assert_eq!(
                T::get_node(vec![PathElement::Index(i)]),
                Ok(Node {
                    ident: PathElement::Index(i),
                    index: 0,
                    size: 1,
                    offset: i as u8,
                    height: 0,
                    is_list: false,
                })
            );
        }
    }

    #[test]
    fn nested_fixed_vector() {
        type T = FixedVector<FixedVector<FixedVector<U256, U16>, U2>, U1>;

        // Merkle structure for `FixedVector<FixedVector<FixedVector<U256, U2>, U2>, U1>`
        //
        //                           +-------------------- 0 --------------------+                             <= composite
        //                          /                                             \
        //               +-------- 1 --------+                           +-------- 2 --------+                 <= composite
        //              /                     \                         /                     \
        //         +-- 3 --+               +-- 4 --+               +-- 5 --+               +-- 6 --+           <= intermediate
        //        /         \             /         \             /         \             /         \
        //       7           8           9          10           11         12           13         14         <= intermediate
        //     /   \       /   \       /   \       /   \       /   \       /   \       /   \       /   \
        //    15   16     17   18     19   20     21   22     23   24     25   26     27   28     29   30      <= intermediate
        //   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \
        //  31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62    <= leaves

        assert_eq!(T::height(), 0);

        assert_eq!(
            T::get_node(vec![PathElement::Index(0)]),
            Ok(Node {
                ident: PathElement::Index(0),
                index: 0,
                size: 32,
                offset: 0,
                height: 1,
                is_list: false,
            })
        );

        // TEST ALL PATHS
        for i in 0..2 {
            assert_eq!(
                T::get_node(vec![PathElement::Index(0), PathElement::Index(i)]),
                Ok(Node {
                    ident: PathElement::Index(i),
                    index: i + 1,
                    size: 32,
                    offset: 0,
                    height: 4,
                    is_list: false,
                })
            );

            for j in 0..16 {
                assert_eq!(
                    T::get_node(vec![
                        PathElement::Index(0),
                        PathElement::Index(i),
                        PathElement::Index(j)
                    ]),
                    Ok(Node {
                        ident: PathElement::Index(j),
                        index: j + 31 + (i * 16),
                        size: 32,
                        offset: 0,
                        height: 0,
                        is_list: false,
                    })
                );
            }
        }

        // TEST OUT-OF-BOUNDS
        assert_eq!(
            T::get_node(vec![PathElement::Index(1)]),
            Err(Error::IndexOutOfBounds(1))
        );
        assert_eq!(
            T::get_node(vec![PathElement::Index(0), PathElement::Index(2)]),
            Err(Error::IndexOutOfBounds(2))
        );
        assert_eq!(
            T::get_node(vec![
                PathElement::Index(0),
                PathElement::Index(0),
                PathElement::Index(16)
            ]),
            Err(Error::IndexOutOfBounds(16))
        );
        assert_eq!(
            T::get_node(vec![
                PathElement::Index(0),
                PathElement::Index(1),
                PathElement::Index(16)
            ]),
            Err(Error::IndexOutOfBounds(16))
        );
    }
}
