use core::mem;
use frinet_db::flat::MemWriteLeaf;
use hashbrown::hash_map::RawEntryMut;
use log::trace;

use crate::{
    disjoint::DataCut,
    hilbert_spec::HilbertSpec,
    layout::{RTreeViewMut, StorageLayout, build_storage_view_mut},
    parser::{ProgressReporter, TraceParser},
    pass::{Event, HilbertPartitionPass, PARTITIONS, ScoutPass, parse_and_normalize_events},
};

use super::RTreePartitions;

pub struct FillPass {
    pub data_used: usize,
}

pub fn fill_pass<Parser>(
    parser: &mut Parser,
    progress: &mut dyn ProgressReporter,
    storage: &mut [u8],
    scout: &ScoutPass,
    layout: &StorageLayout,
    partitions: &HilbertPartitionPass,
) -> FillPass
where
    Parser: TraceParser + Send,
{
    let mut sview = build_storage_view_mut(storage, layout, partitions);
    let data_start_ptr = sview.data.as_ptr();

    let mut dedup = DataDedup::new(sview.data);

    let mut mem_leaf_buffers: Vec<_> = partitions
        .write_zones
        .iter()
        .map(|_| Box::new([const { Vec::new() }; PARTITIONS]))
        .collect();

    let mut mem_read_leaf_buffers: Vec<_> = partitions
        .write_zones
        .iter()
        .map(|_| Box::new([const { Vec::new() }; PARTITIONS]))
        .collect();

    let mut register_buffers: Vec<_> = partitions
        .registers
        .iter()
        .map(|_| Box::new([const { Vec::new() }; PARTITIONS]))
        .collect();

    macro_rules! find_zone_containing_addr_range {
        ($partitions:expr, $addr_range:expr) => {{
            $partitions
                .iter()
                .map(|zone| zone.bbox.addr_range())
                .enumerate()
                .find(|(_, zone_range)| !zone_range.is_disjoint(&$addr_range))
                .map(|(idx, _)| idx)
                .expect("no zone found for memory leaf")
        }};
    }

    rayon::in_place_scope(|scope| {
        parse_and_normalize_events(
            parser,
            progress,
            |name| scout.reg_name_mapping[name],
            |bytes| {
                if bytes.len() <= 8 {
                    MaybeInlined::inline(bytes)
                } else {
                    MaybeInlined::Outline(dedup.insert(bytes))
                }
            },
            |item| match item {
                Event::MemoryWrite(leaf) => {
                    let addr_range = leaf.node.addr_range();
                    let idx = find_zone_containing_addr_range!(&partitions.write_zones, addr_range);

                    let leaf = MemWriteLeaf {
                        node: leaf.node,
                        packed_data: match leaf.data {
                            MaybeInlined::Inline { data, .. } => {
                                // Not portable, but will be checked in the index header
                                u64::from_ne_bytes(data)
                            }
                            MaybeInlined::Outline(data) => {
                                (data.as_ptr().addr() - data_start_ptr.addr()) as u64
                            }
                        },
                    };

                    push_leaf_into_partition(
                        scope,
                        &mut sview.write_zones.rtrees[idx],
                        &mut mem_leaf_buffers[idx],
                        &partitions.write_zones[idx],
                        leaf,
                    );
                }
                Event::MemoryRead(leaf) => {
                    let addr_range = leaf.addr_range();
                    let idx = find_zone_containing_addr_range!(&partitions.read_zones, addr_range);

                    push_leaf_into_partition(
                        scope,
                        &mut sview.read_zones.rtrees[idx],
                        &mut mem_read_leaf_buffers[idx],
                        &partitions.read_zones[idx],
                        leaf,
                    );
                }

                Event::Register { idx, leaf } => {
                    push_leaf_into_partition(
                        scope,
                        &mut sview.registers.rtrees[idx],
                        &mut register_buffers[idx],
                        &partitions.registers[idx],
                        leaf,
                    );
                }
                Event::AslrSlide(_) => {}
            },
        );
    });

    // all temporary leaf buffers must be empty after indexing
    for buffers in mem_leaf_buffers {
        for buffer in buffers.iter() {
            assert!(buffer.is_empty());
        }
    }

    let data_used = dedup.bytes_used();

    FillPass { data_used }
}

fn push_leaf_into_partition<'scope, 'storage, S>(
    scope: &rayon::Scope<'scope>,
    zone_view: &mut RTreeViewMut<'storage, S>,
    leaves_buffer: &mut Box<[Vec<S::Leaf>; PARTITIONS]>,
    partitions: &RTreePartitions<S>,
    leaf: S::Leaf,
) where
    'storage: 'scope,
    S: HilbertSpec,
    S::Node: 'scope,
{
    let bbox = partitions.bbox;

    let part_idx = S::hilbert_partition_key(&leaf, &bbox);
    let part_idx = usize::from(part_idx);

    let leaf_buffer = &mut leaves_buffer[part_idx];
    let leaf_partition = &partitions.partitions[part_idx];

    leaf_buffer.push(leaf);

    if leaf_buffer.len() == leaf_partition.leaf_count {
        let mut unsorted_leaves = mem::take(leaf_buffer);
        let out_sorted_leaves = mem::replace(&mut zone_view.leaves[part_idx], &mut [][..]);

        scope.spawn(move |_| {
            trace!("Task partition : partition:{part_idx}");
            unsorted_leaves.sort_by_cached_key(|leaf| S::hilbert_key(leaf, &bbox));
            out_sorted_leaves.copy_from_slice(&unsorted_leaves);
        });
    }
}

#[derive(Debug, Clone, Copy)]
enum MaybeInlined<'s> {
    Inline { len: usize, data: [u8; 8] },
    Outline(&'s [u8]),
}

impl<'s> MaybeInlined<'s> {
    fn inline(data: &[u8]) -> Self {
        assert!(data.len() <= 8);
        let mut new_data = [0; 8];
        new_data[..data.len()].copy_from_slice(data);
        Self::Inline {
            len: data.len(),
            data: new_data,
        }
    }
}

impl<'s> DataCut for MaybeInlined<'s> {
    fn cut(self, cut_left: usize, cut_right: usize) -> Self {
        match self {
            MaybeInlined::Inline { len, data } => {
                debug_assert!(len > cut_left + cut_right);
                let new_len = len - cut_left - cut_right;
                Self::inline(&data[cut_left..][..new_len])
            }
            MaybeInlined::Outline(data) => {
                debug_assert!(data.len() > cut_left + cut_right);
                let new_len = data.len() - cut_left - cut_right;
                let new_data = &data[cut_left..][..new_len];
                if new_len <= 8 {
                    Self::inline(new_data)
                } else {
                    Self::Outline(new_data)
                }
            }
        }
    }
}

/// Raw data deduplication directly inside the memory mapping
struct DataDedup<'storage> {
    used: usize,
    storage_rest: &'storage mut [u8],
    memo: hashbrown::HashMap<&'storage [u8], ()>,
}

impl<'s> DataDedup<'s> {
    fn new(storage: &'s mut [u8]) -> Self {
        Self {
            used: 0,
            memo: Default::default(),
            storage_rest: storage,
        }
    }

    fn bytes_used(&self) -> usize {
        self.used
    }

    /// Insert and deduplicate a byte-slice from anywhere inside the memory mapping
    fn insert(&mut self, data: &'_ [u8]) -> &'s [u8] {
        // raw entry manipulation :
        // - the memo is queried with byte slices from unknown lifetime
        // - the memo is populated with byte slices in the memory mapping

        match self.memo.raw_entry_mut().from_key(data) {
            RawEntryMut::Occupied(some) => some.get_key_value().0,
            RawEntryMut::Vacant(none) => {
                // temporarily steal `self.storage_rest`
                let storage_rest = mem::replace(&mut self.storage_rest, &mut [][..]);

                let (slot, new_rest) = storage_rest.split_at_mut(data.len());
                slot.copy_from_slice(data);
                self.used += data.len();

                // restore `self.storage_rest`
                self.storage_rest = new_rest;

                none.insert(slot, ());

                // return the slice inside the memory mapping
                &*slot
            }
        }
    }
}
