use crate::flat::*;

/// R-Tree specification
pub trait Spec {
    /// R-Tree node
    type Node: Copy + Send + Sync + Zerocopyable;
    /// R-Tree leaf
    type Leaf: Copy + Send + Sync + Zerocopyable;
}

/// Packed R-Tree
#[derive(Debug, Clone)]
pub struct RTree<'storage, S: Spec> {
    /// node_size = 1 << node_size_order
    pub node_size_order: u64,

    pub leaves: &'storage [S::Leaf],
    pub nodes: &'storage [S::Node],

    /// Sub-slices of `self.nodes` per level
    pub node_levels: Vec<&'storage [S::Node]>,

    /// Bounding box of all leaves
    pub bbox: S::Node,
}

impl<'storage, S: Spec> RTree<'storage, S> {
    /// Number of intermediate node level (without leaves)
    pub fn depth(&self) -> usize {
        self.node_levels.len()
    }

    /// Nodes of the root level, returns [None] if there are less leaves than `node_size`)
    pub fn root_nodes(&self) -> Option<&'storage [S::Node]> {
        self.node_levels.get(0).copied()
    }
}
