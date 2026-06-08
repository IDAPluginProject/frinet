use frinet_db::{
    db::Metadata,
    flat::{Addr, Level, MemNode, RegNode},
    irange::IRange,
};
use hashbrown::HashMap;
use log::{debug, warn};

use crate::{
    disjoint::{DisjointMemLeaf, NoData},
    parser::{ProgressReporter, TraceParser},
    pass::{Event, parse_and_normalize_events},
};

#[derive(Default)]
pub struct ScoutPass {
    pub reg_name_mapping: HashMap<String, usize>,
    pub data_section_required_bytes: usize,
    pub metadata_json: String,

    pub write_zones: Vec<RTreeScout<MemNode>>,
    pub read_zones: Vec<RTreeScout<MemNode>>,
    pub registers: Vec<RTreeScout<RegNode>>,
}

pub fn scout_pass<Parser>(
    parser: &mut Parser,
    progress: &mut dyn ProgressReporter,
    node_size_order: u8,
) -> ScoutPass
where
    Parser: TraceParser + Send,
{
    let mut scout = ScoutPass::default();
    let mut metadata = Metadata::default();

    let mut next_reg_id = 0;

    parse_and_normalize_events(
        parser,
        progress,
        |reg_name| {
            *scout
                .reg_name_mapping
                .entry_ref(reg_name)
                .or_insert_with(|| {
                    let id = next_reg_id;
                    next_reg_id += 1;
                    id
                })
        },
        |bytes| {
            if bytes.len() > 8 {
                scout.data_section_required_bytes += bytes.len();
            }
            NoData
        },
        |event| match event {
            Event::MemoryWrite(DisjointMemLeaf { node, .. }) => {
                insert_node_into_zones(&mut scout.write_zones, node);
            }
            Event::MemoryRead(leaf) => {
                insert_node_into_zones(&mut scout.read_zones, leaf.node());
            }
            Event::Register { idx, leaf } => {
                let required_len = idx + 1;
                if scout.registers.len() < required_len {
                    scout.registers.resize(required_len, RTreeScout::default());
                }

                let reg = &mut scout.registers[idx];

                if reg.leaf_count == 0 {
                    reg.bbox = leaf.node();
                } else {
                    reg.bbox.extends_to_contain(&leaf.node());
                }

                reg.leaf_count += 1;
            }
            Event::AslrSlide(slide) => metadata.alsr_slide = Some(slide),
        },
    );

    if let Some(slide) = metadata.alsr_slide {
        debug!("ASLR slide : {:#x?}", slide);
    } else {
        warn!("no ASLR slide");
    }

    metadata
        .register_names
        .resize(scout.registers.len(), String::new());

    for (name, idx) in &scout.reg_name_mapping {
        metadata.register_names[*idx] = name.clone();
    }

    debug!("{} memory write zones", scout.write_zones.len());
    for zone in &mut scout.write_zones {
        zone.compute_node_count_and_levels(node_size_order);
    }

    debug!("{} memory read zones", scout.write_zones.len());
    for zone in &mut scout.read_zones {
        zone.compute_node_count_and_levels(node_size_order);
    }

    debug!("{} registers", scout.registers.len());
    for register in &mut scout.registers {
        register.compute_node_count_and_levels(node_size_order);
    }

    scout.metadata_json = serde_json::to_string(&metadata).unwrap();
    scout
}

fn insert_node_into_zones(zones: &mut Vec<RTreeScout<MemNode>>, node: MemNode) {
    let mut was_inserted = false;
    let mut conflict_found = false;

    for zone in zones.iter_mut() {
        let padded = zone.padded_addr_range();
        if !padded.is_disjoint(&node.addr_range()) {
            if was_inserted {
                conflict_found = true;
                break;
            }

            zone.bbox.extends_to_contain(&node);
            zone.leaf_count += 1;

            was_inserted = true;
        }
    }

    if conflict_found {
        let mut at_least_one_conflict_fixed = false;

        'find_conflict: loop {
            for i in 0..zones.len() {
                for j in i + 1..zones.len() {
                    let a = &zones[i];
                    let b = &zones[j];

                    let a_range = a.half_padded_addr_range();
                    let b_range = b.half_padded_addr_range();

                    if !a_range.is_disjoint(&b_range) {
                        debug!("Zone conflict");
                        at_least_one_conflict_fixed = true;

                        // This is OK only if `i < j` and if the iteration restart from the beginning
                        debug_assert!(i < j);
                        let b = zones.swap_remove(j);
                        let a = &mut zones[i];

                        a.bbox.extends_to_contain(&b.bbox);
                        a.leaf_count += b.leaf_count;

                        continue 'find_conflict;
                    }
                }
            }

            debug_assert!(at_least_one_conflict_fixed);

            // no more conflict
            break;
        }
    }

    if !was_inserted {
        zones.push(RTreeScout {
            bbox: node,
            leaf_count: 1,
            node_count: 0,
            levels: Vec::new(),
        });
    }
}

#[derive(Clone, Debug, Default)]
pub struct RTreeScout<Node> {
    pub bbox: Node,
    pub leaf_count: usize,
    pub node_count: usize,
    pub levels: Vec<Level>,
}

/// Minimal address padding between zones
const ZONE_MIN_PADDING: u64 = 128 * GB;
const GB: u64 = 1024 * 1024 * 1024;

impl RTreeScout<MemNode> {
    fn padded_addr_range(&self) -> IRange<Addr> {
        IRange {
            min: self.bbox.addr_min.saturating_sub(ZONE_MIN_PADDING),
            max: self.bbox.addr_max.saturating_add(ZONE_MIN_PADDING),
        }
    }

    fn half_padded_addr_range(&self) -> IRange<Addr> {
        IRange {
            min: self.bbox.addr_min.saturating_sub(ZONE_MIN_PADDING / 2),
            max: self.bbox.addr_max.saturating_add(ZONE_MIN_PADDING / 2),
        }
    }
}

impl<Node> RTreeScout<Node> {
    fn compute_node_count_and_levels(&mut self, node_size_order: u8) {
        let group_size = 1_usize.checked_shl(node_size_order.into()).unwrap();
        let mut prev_level_count = self.leaf_count;
        while prev_level_count > group_size {
            let level_count = prev_level_count.div_ceil(group_size);
            self.levels.push(Level {
                offset: self.node_count as u64,
                size: level_count as u64,
            });
            self.node_count += level_count;
            prev_level_count = level_count;
        }

        self.levels.reverse();
    }
}
