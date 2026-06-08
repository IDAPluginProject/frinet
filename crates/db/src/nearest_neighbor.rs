use std::{cmp::Reverse, collections::BinaryHeap};

use crate::rtree::{RTree, Spec};

/// Generic nearest neighbor search through a [RTree]
pub fn nearest_neighbor<'s, S: Spec, K: Ord + Copy>(
    rtree: &RTree<'s, S>,
    visit_node: impl Fn(&S::Node) -> Status<K>,
    visit_leaf: impl Fn(&S::Leaf) -> Status<K>,
) -> Option<&'s S::Leaf> {
    let mut heap = BinaryHeap::<Item<K>>::new();
    let group_size = 1_usize << rtree.node_size_order;

    if let Some(nodes) = rtree.root_nodes() {
        assert!(nodes.len() <= group_size);
        visit_nodes(rtree, &mut heap, &visit_node, nodes, 0, 0);
    } else {
        assert!(rtree.leaves.len() <= group_size);
        visit_leaves(rtree, &mut heap, &visit_leaf, 0);
    }

    while let Some(item) = heap.pop() {
        // Check if the item is a node or a leaf
        if item.level < rtree.node_levels.len() {
            let next_start = item.idx << rtree.node_size_order;

            match rtree.node_levels.get(item.level + 1) {
                Some(next_level) => {
                    visit_nodes(
                        rtree,
                        &mut heap,
                        &visit_node,
                        *next_level,
                        item.level + 1,
                        next_start,
                    );
                }
                None => {
                    visit_leaves(rtree, &mut heap, &visit_leaf, next_start);
                }
            }
        } else {
            return Some(&rtree.leaves[item.idx]);
        }
    }

    None
}

fn visit_nodes<'s, S: Spec, K: Ord + Copy>(
    rtree: &RTree<'s, S>,
    heap: &mut BinaryHeap<Item<K>>,
    visit_node: &impl Fn(&S::Node) -> Status<K>,
    level_nodes: &'s [S::Node],
    level: usize,
    start_idx: usize,
) {
    let group_size = 1_usize << rtree.node_size_order;

    for (idx, node) in level_nodes
        .iter()
        .enumerate()
        .skip(start_idx)
        .take(group_size)
    {
        match visit_node(node) {
            Status::Keep(min_key) => {
                heap.push(Item {
                    level,
                    idx,
                    min_key,
                });
            }
            Status::Ignore => {}
        }
    }
}

fn visit_leaves<'s, S: Spec, K: Ord + Copy>(
    rtree: &RTree<'s, S>,
    heap: &mut BinaryHeap<Item<K>>,
    visit_leaf: &impl Fn(&S::Leaf) -> Status<K>,
    start_idx: usize,
) {
    let level = rtree.node_levels.len();
    let group_size = 1_usize << rtree.node_size_order;

    for (idx, leaf) in rtree
        .leaves
        .iter()
        .enumerate()
        .skip(start_idx)
        .take(group_size)
    {
        match visit_leaf(leaf) {
            Status::Keep(min_key) => {
                heap.push(Item {
                    level,
                    idx,
                    min_key,
                });
            }
            Status::Ignore => {}
        }
    }
}

pub enum Status<K> {
    Keep(K),
    Ignore,
}

struct Item<K> {
    level: usize,
    idx: usize,
    min_key: K,
}

impl<K: Ord + Copy> Item<K> {
    fn ord_key(&self) -> impl Ord {
        // First minimise the key, then maximise the level
        (Reverse(self.min_key), self.level)
    }
}

impl<K: Ord + Copy> PartialEq for Item<K> {
    fn eq(&self, other: &Self) -> bool {
        self.ord_key().eq(&other.ord_key())
    }
}

impl<K: Ord + Copy> Eq for Item<K> {}

impl<K: Ord + Copy> PartialOrd for Item<K> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.ord_key().partial_cmp(&other.ord_key())
    }
}

impl<K: Ord + Copy> Ord for Item<K> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.ord_key().cmp(&other.ord_key())
    }
}
