use std::marker::PhantomData;

use frinet_db::flat::*;
use frinet_db::irange::IRange;
use frinet_db::memory::{MemReadSpec, MemWriteSpec};
use frinet_db::register::RegSpec;
use frinet_db::rtree::Spec;

use crate::disjoint::NoData;
use crate::hilbert_spec::HilbertSpec;
use crate::parser::{ProgressReporter, TraceParser};
use crate::pass::{Event, RTreeScout, ScoutPass, parse_and_normalize_events};

pub const BITS_PER_DIM: usize = 4;
pub const PARTITIONS: usize = (1_usize << BITS_PER_DIM).pow(2);

pub struct HilbertPartitionPass {
    pub write_zones: Vec<RTreePartitions<MemWriteSpec>>,
    pub read_zones: Vec<RTreePartitions<MemReadSpec>>,
    pub registers: Vec<RTreePartitions<RegSpec>>,
}

pub fn hilbert_partition_pass<Parser>(
    parser: &mut Parser,
    progress: &mut dyn ProgressReporter,
    scout: &ScoutPass,
) -> HilbertPartitionPass
where
    Parser: TraceParser + Send,
{
    let mut pass = HilbertPartitionPass {
        write_zones: scout
            .write_zones
            .iter()
            .map(|zone| RTreePartitions::new(zone.bbox))
            .collect(),
        read_zones: scout
            .read_zones
            .iter()
            .map(|zone| RTreePartitions::new(zone.bbox))
            .collect(),
        registers: scout
            .registers
            .iter()
            .map(|reg| RTreePartitions::new(reg.bbox))
            .collect(),
    };

    parse_and_normalize_events(
        parser,
        progress,
        |name| scout.reg_name_mapping[name],
        |_| NoData,
        |item| match item {
            Event::MemoryWrite(leaf) => {
                let addr_range = leaf.node.addr_range();
                let idx = find_zone_containing_addr_range(&scout.write_zones, addr_range);
                pass.write_zones[idx].push_leaf(MemWriteLeaf {
                    node: leaf.node,
                    packed_data: 0, // we do not care about `packed_data` in this pass
                });
            }
            Event::MemoryRead(leaf) => {
                let addr_range = leaf.addr_range();
                let idx = find_zone_containing_addr_range(&scout.read_zones, addr_range);
                pass.read_zones[idx].push_leaf(leaf);
            }
            Event::Register { idx, leaf } => {
                pass.registers[idx].push_leaf(leaf);
            }
            Event::AslrSlide(_) => {}
        },
    );

    pass
}

fn find_zone_containing_addr_range(
    zones: &[RTreeScout<MemNode>],
    addr_range: IRange<u64>,
) -> usize {
    zones
        .iter()
        .map(|scout| scout.bbox.addr_range())
        .enumerate()
        .find(|(_, zone_range)| !zone_range.is_disjoint(&addr_range))
        .map(|(idx, _)| idx)
        .expect("no zone found for memory leaf")
}

pub struct RTreePartitions<S: Spec> {
    pub partitions: Box<[Partition; PARTITIONS]>,
    pub bbox: S::Node,
    _phantom: PhantomData<S>,
}

#[derive(Debug, Clone, Copy)]
pub struct Partition {
    pub leaf_count: usize,
    pub time_range: IRange<Time>,
}

impl<S: HilbertSpec> RTreePartitions<S> {
    pub fn new(bbox: S::Node) -> Self {
        Self {
            bbox,
            partitions: Box::new([Partition::default(); _]),
            _phantom: PhantomData,
        }
    }

    pub fn push_leaf(&mut self, leaf: S::Leaf) {
        let key = S::hilbert_partition_key(&leaf, &self.bbox);
        let key = key as usize;

        let partition = &mut self.partitions[key];
        partition.leaf_count += 1;

        let time_range = S::leaf_time_range(&leaf);
        partition.time_range.min = partition.time_range.min.min(time_range.min);
        partition.time_range.max = partition.time_range.max.max(time_range.max);
    }
}

impl Default for Partition {
    fn default() -> Self {
        Self {
            leaf_count: 0,
            time_range: IRange {
                min: Time::MAX,
                max: Time::MIN,
            },
        }
    }
}
