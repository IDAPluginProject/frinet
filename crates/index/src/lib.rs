use core::mem;

use frinet_db::flat::RTreeHeader;
use frinet_db::memory::{MemReadSpec, MemWriteSpec};
use frinet_db::register::RegSpec;
use frinet_db::rtree::Spec;
use log::debug;
use zerocopy::FromBytes;

use crate::hilbert_spec::HilbertSpec;
use crate::layout::{RTreeListViewMut, build_storage_layout, build_storage_view_mut};
use crate::parser::{Pass, ProgressReporter, TraceParser};
use crate::pass::{RTreeScout, fill_pass, hilbert_partition_pass, scout_pass};
use crate::storage::DbStorage;

mod disjoint;
mod hilbert_spec;
mod layout;
mod pass;

pub mod parser;
pub mod storage;

pub fn build_index(
    parser: &mut (impl TraceParser + Send),
    progress: &mut dyn ProgressReporter,
    db_storage: &mut dyn DbStorage,
    node_size_order: u8,
) {
    assert!(
        (1..=16).contains(&node_size_order),
        "node size order must be in 1..=16"
    );

    progress.start(Pass::Scout);
    let scout = scout_pass(parser, progress, node_size_order);

    debug!("Build storage layout");
    let layout = build_storage_layout(&scout, node_size_order);

    progress.start(Pass::Partitions);
    let partitions = hilbert_partition_pass(parser, progress, &scout);

    /*let mut max_concurrent_leaves = 0;
    for partition in &mem_partitions {
        max_concurrent_leaves += partition.max_concurrent_leaves();
    }
    debug!("Max concurrent leaves : {max_concurrent_leaves}");*/

    // let _leaf_buffers_permit = limiter
    //     .acquire_now(max_concurrent_leaves * flat::MemLeaf::SIZE)
    //     .expect("Need more memory for concurrent leaves");

    let storage = db_storage.allocate(layout.max_storage_size);

    progress.start(Pass::Fill);
    let fill = fill_pass(parser, progress, storage, &scout, &layout, &partitions);
    let data_unused = scout.data_section_required_bytes - fill.data_used;

    let mut sview = build_storage_view_mut(storage, &layout, &partitions);

    *sview.header = layout.header;

    sview
        .metadata
        .copy_from_slice(scout.metadata_json.as_bytes());

    write_rtree_bboxes_and_levels(
        &layout.write_zones,
        &scout.write_zones,
        &mut sview.write_zones,
    );
    write_rtree_bboxes_and_levels(&layout.read_zones, &scout.read_zones, &mut sview.read_zones);
    write_rtree_bboxes_and_levels(&layout.registers, &scout.registers, &mut sview.registers);

    // truncate data section
    sview.header.data.end -= data_unused as u64;
    drop(sview);

    compute_and_write_rtrees_nodes::<RegSpec>(
        node_size_order,
        storage,
        &scout.registers,
        &layout.registers,
    );

    compute_and_write_rtrees_nodes::<MemWriteSpec>(
        node_size_order,
        storage,
        &scout.write_zones,
        &layout.write_zones,
    );

    compute_and_write_rtrees_nodes::<MemReadSpec>(
        node_size_order,
        storage,
        &scout.read_zones,
        &layout.read_zones,
    );

    // truncate unused trailing storage
    db_storage.truncate(layout.max_storage_size - data_unused);

    progress.finish();
}

fn compute_and_write_rtrees_nodes<S: HilbertSpec>(
    node_size_order: u8,
    storage: &mut [u8],
    rtrees: &[RTreeScout<S::Node>],
    headers: &[RTreeHeader],
) {
    for idx in 0..rtrees.len() {
        let header = &headers[idx];
        let bbox = &rtrees[idx].bbox;

        let leaves_range = header.leaves.byte_range();
        let nodes_range = header.nodes.byte_range();

        let [leaves, nodes] = storage
            .get_disjoint_mut([leaves_range, nodes_range])
            .unwrap();

        let leaves = <[S::Leaf]>::ref_from_bytes(leaves).unwrap();
        let nodes = <[S::Node]>::mut_from_bytes(nodes).unwrap();

        debug_assert!(
            leaves.is_sorted_by_key(|leaf| S::hilbert_key(leaf, bbox)),
            "memory : leaves must be sorted at this point"
        );

        build_intermediate_nodes_from_sorted_leaves::<S>(node_size_order, leaves, nodes);
    }
}

fn write_rtree_bboxes_and_levels<S: Spec>(
    headers: &[RTreeHeader],
    rtrees: &[RTreeScout<S::Node>],
    view: &mut RTreeListViewMut<'_, S>,
) {
    view.headers.copy_from_slice(&headers);
    for idx in 0..headers.len() {
        view.bboxes[idx] = rtrees[idx].bbox;

        let levels = &mut view.rtrees[idx].levels;
        levels.copy_from_slice(&rtrees[idx].levels);
    }
}

fn build_intermediate_nodes_from_sorted_leaves<S>(
    node_size_order: u8,
    in_leaves: &[S::Leaf],
    out_nodes: &mut [S::Node],
) where
    S: HilbertSpec,
    S::Node: Copy,
{
    let node_size = 1 << node_size_order;
    let mut out_nodes = out_nodes.iter_mut();

    if in_leaves.len() > node_size {
        let level_size = in_leaves.len().div_ceil(node_size);
        let mut nodes = Vec::with_capacity(level_size);

        // first level : group leaves
        for children in in_leaves.chunks(node_size) {
            let bbox = S::bbox_of_leaves(children);
            *out_nodes.next().unwrap() = bbox;
            nodes.push(bbox);
        }
        assert_eq!(nodes.len(), level_size);

        // next levels : group nodes
        let mut prev_nodes = nodes;
        let mut nodes = Vec::new();
        loop {
            if prev_nodes.len() <= node_size {
                break;
            }

            for children in prev_nodes.chunks(node_size) {
                let bbox = S::bbox_of_nodes(children);
                *out_nodes.next().unwrap() = bbox;
                nodes.push(bbox);
            }

            mem::swap(&mut prev_nodes, &mut nodes);
            nodes.clear();
        }
    }
}
