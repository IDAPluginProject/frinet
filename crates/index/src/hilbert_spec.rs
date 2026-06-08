use std::hash::Hash;

use frinet_db::flat::{Addr, MemNode, RegLeaf, RegNode, Time};
use frinet_db::irange::IRange;
use frinet_db::memory::{MemReadSpec, MemWriteSpec};
use frinet_db::register::RegSpec;
use frinet_db::rtree::Spec;

pub trait HilbertSpec: Spec {
    type Key: Copy + Send + Sync + Ord + Hash;

    fn bbox_of_leaves(leaves: &[Self::Leaf]) -> Self::Node;
    fn bbox_of_nodes(nodes: &[Self::Node]) -> Self::Node;
    fn hilbert_key(leaf: &Self::Leaf, bbox: &Self::Node) -> Self::Key;
    fn hilbert_partition_key(leaf: &Self::Leaf, bbox: &Self::Node) -> u8;
    fn leaf_time_range(leaf: &Self::Leaf) -> IRange<Time>;
}

impl HilbertSpec for MemWriteSpec {
    type Key = u128;

    fn bbox_of_leaves(leaves: &[Self::Leaf]) -> Self::Node {
        let mut iter = leaves.iter();
        let mut bbox = iter.next().expect("bbox of empty list").node;
        for leaf in iter {
            bbox.extends_to_contain(&leaf.node);
        }
        bbox
    }

    fn bbox_of_nodes(nodes: &[Self::Node]) -> Self::Node {
        let mut iter = nodes.iter();
        let mut bbox = *iter.next().expect("bbox of empty list");
        for node in iter {
            bbox.extends_to_contain(node);
        }
        bbox
    }

    fn hilbert_key(leaf: &Self::Leaf, bbox: &Self::Node) -> Self::Key {
        let [addr, time] = mem_hilbert_coordinates(&leaf.node, bbox);
        fast_hilbert::xy2h(addr, time, 64)
    }

    fn hilbert_partition_key(leaf: &Self::Leaf, bbox: &Self::Node) -> u8 {
        let [addr, time] = mem_hilbert_coordinates(&leaf.node, bbox);

        // keep high 4-bits
        let addr = (addr >> 60) as u8;
        let time = (time >> 60) as u8;

        fast_hilbert::xy2h(addr, time, 4) as u8
    }

    fn leaf_time_range(leaf: &Self::Leaf) -> IRange<Time> {
        leaf.time_range()
    }
}

impl HilbertSpec for MemReadSpec {
    type Key = u128;

    fn bbox_of_leaves(leaves: &[Self::Leaf]) -> Self::Node {
        let mut iter = leaves.iter();
        let mut bbox = iter.next().expect("bbox of empty list").node();
        for leaf in iter {
            bbox.extends_to_contain(&leaf.node());
        }
        bbox
    }

    fn bbox_of_nodes(nodes: &[Self::Node]) -> Self::Node {
        MemWriteSpec::bbox_of_nodes(nodes)
    }

    fn hilbert_key(leaf: &Self::Leaf, bbox: &Self::Node) -> Self::Key {
        let [addr, time] = mem_hilbert_coordinates(&leaf.node(), bbox);
        fast_hilbert::xy2h(addr, time, 64)
    }

    fn hilbert_partition_key(leaf: &Self::Leaf, bbox: &Self::Node) -> u8 {
        let [addr, time] = mem_hilbert_coordinates(&leaf.node(), bbox);

        // keep high 4-bits
        let addr = (addr >> 60) as u8;
        let time = (time >> 60) as u8;

        fast_hilbert::xy2h(addr, time, 4) as u8
    }

    fn leaf_time_range(leaf: &Self::Leaf) -> IRange<Time> {
        IRange::one(leaf.time)
    }
}

fn mem_hilbert_coordinates(node: &MemNode, bbox: &MemNode) -> [u64; 2] {
    let addr_bits = bbox.addr_range().span_bits();
    let time_bits = bbox.time_range().span_bits();

    let mut addr = node.addr_min.midpoint(node.addr_max);
    let mut time = node.time_min.midpoint(node.time_max);

    // spread coordinate across the bounding box
    addr -= bbox.addr_min;
    time -= bbox.time_min;
    addr <<= Addr::BITS - addr_bits;
    time <<= Time::BITS - time_bits;

    // spread time over 64 bit
    let time = (time as u64) << 32;

    [addr, time]
}

impl HilbertSpec for RegSpec {
    type Key = u128;

    fn bbox_of_leaves(leaves: &[Self::Leaf]) -> Self::Node {
        let mut iter = leaves.iter();
        let mut bbox = iter.next().expect("bbox of empty list").node();
        for leaf in iter {
            bbox.value_min = bbox.value_min.min(leaf.value);
            bbox.value_max = bbox.value_max.max(leaf.value);
            bbox.time_min = bbox.time_min.min(leaf.time_min);
            bbox.time_max = bbox.time_max.max(leaf.time_max);
        }
        bbox
    }

    fn bbox_of_nodes(nodes: &[Self::Node]) -> Self::Node {
        let mut iter = nodes.iter();
        let mut bbox = *iter.next().expect("bbox of empty list");
        for nodes in nodes {
            bbox.value_min = bbox.value_min.min(nodes.value_min);
            bbox.value_max = bbox.value_max.max(nodes.value_max);
            bbox.time_min = bbox.time_min.min(nodes.time_min);
            bbox.time_max = bbox.time_max.max(nodes.time_max);
        }
        bbox
    }

    fn hilbert_key(leaf: &Self::Leaf, bbox: &Self::Node) -> Self::Key {
        let [value, time] = reg_hilbert_coordinates(leaf, bbox);
        fast_hilbert::xy2h(value, time, 64)
    }

    fn hilbert_partition_key(leaf: &Self::Leaf, bbox: &Self::Node) -> u8 {
        let [value, time] = reg_hilbert_coordinates(leaf, bbox);

        // keep high 4-bits
        let value = (value >> 60) as u8;
        let time = (time >> 60) as u8;

        fast_hilbert::xy2h(value, time, 4) as u8
    }

    fn leaf_time_range(leaf: &Self::Leaf) -> IRange<Time> {
        leaf.time_range()
    }
}

fn reg_hilbert_coordinates(leaf: &RegLeaf, bbox: &RegNode) -> [u64; 2] {
    let value_bits = bbox.value_range().span_bits();
    let time_bits = bbox.time_range().span_bits();

    let mut value = leaf.value;
    let mut time = leaf.time_min.midpoint(leaf.time_max);

    // spread coordinate across the bounding box
    value -= bbox.value_min;
    time -= bbox.time_min;
    value <<= Addr::BITS - value_bits;
    time <<= Time::BITS - time_bits;

    // spread time over 64 bit
    let time = (time as u64) << 32;

    [value, time]
}
