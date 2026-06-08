use std::fmt::Display;
use std::ops::{Deref, IndexMut};

use log::error;
use serde::{Deserialize, Serialize};
use zerocopy::{FromBytes, IntoBytes, KnownLayout};

use crate::irange::IRange;
use crate::memory::{MemReadSpec, MemWriteSpec};

use crate::query::{Query, QueryIter};
use crate::register::RegSpec;
use crate::rtree::{RTree, Spec};
use crate::{DB_MAGIC, DB_VERSION, flat::*};

/// Indexed database of an execution trace
pub struct Db<'s> {
    pub write_zones: Vec<RTree<'s, MemWriteSpec>>,
    pub read_zones: Vec<RTree<'s, MemReadSpec>>,
    pub registers: Vec<RTree<'s, RegSpec>>,
    pub metadata: Metadata,
    pub raw_data: &'s [u8],
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "pyo3", pyo3::pyclass(get_all, skip_from_py_object))]
pub struct Metadata {
    pub alsr_slide: Option<Addr>,
    pub register_names: Vec<String>,
}

#[derive(Debug)]
pub enum LoadError {
    InvalidMagic,
    InvalidVersion { got: u64, expected: u64 },
    Corrupted,
}

impl Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::InvalidMagic => f.write_str("invalid magic"),
            LoadError::InvalidVersion { got, expected } => write!(
                f,
                "unexpected version number, got:{got} expected:{expected}"
            ),
            LoadError::Corrupted => f.write_str("database is corrupted"),
        }
    }
}

impl<Src, Dst> From<zerocopy::SizeError<Src, Dst>> for LoadError
where
    Src: Deref,
    Dst: ?Sized + KnownLayout,
{
    fn from(err: zerocopy::SizeError<Src, Dst>) -> Self {
        error!("Indexed DB is corrupted : {err}");
        LoadError::Corrupted
    }
}

impl<Src, Dst> From<zerocopy::CastError<Src, Dst>> for LoadError
where
    Src: Deref,
    Dst: ?Sized + KnownLayout,
{
    fn from(err: zerocopy::CastError<Src, Dst>) -> Self {
        error!("Indexed DB is corrupted : {err}");
        LoadError::Corrupted
    }
}

impl<'s> Db<'s> {
    pub fn from_aligned_slice(storage: &'s [u8]) -> Result<Self, LoadError> {
        let header = Header::read_from_prefix(storage)?.0;

        if header.magic != DB_MAGIC {
            return Err(LoadError::InvalidMagic);
        }

        if header.version != DB_VERSION {
            return Err(LoadError::InvalidVersion {
                got: header.version,
                expected: DB_VERSION,
            });
        }

        let raw_data = cast_section::<u8>(storage, header.data)?;

        let metadata_json = cast_section::<u8>(storage, header.metadata)?;
        let metadata: Metadata = serde_json::from_slice(metadata_json).unwrap();

        let write_zones = read_rtree_list(storage, &header.write_zones)?;
        let read_zones = read_rtree_list(storage, &header.read_zones)?;
        let registers = read_rtree_list(storage, &header.registers)?;

        Ok(Self {
            write_zones,
            read_zones,
            registers,
            metadata,
            raw_data,
        })
    }

    pub fn mem_write_query<'this, Q>(
        &'this self,
        query: Q,
    ) -> MultiQueryIter<'this, 's, MemWriteSpec, Q>
    where
        Q: Query<MemWriteSpec> + Clone,
    {
        MultiQueryIter::new(query, &self.write_zones)
    }

    pub fn mem_read_query<'this, Q>(
        &'this self,
        query: Q,
    ) -> MultiQueryIter<'this, 's, MemReadSpec, Q>
    where
        Q: Query<MemReadSpec> + Clone,
    {
        MultiQueryIter::new(query, &self.read_zones)
    }

    pub fn mem_write_intersects<'this>(
        &'this self,
        node: MemNode,
    ) -> MultiQueryIter<'this, 's, MemWriteSpec, MemIntersects> {
        self.mem_write_query(MemIntersects { node })
    }

    pub fn mem_read_intersects<'this>(
        &'this self,
        node: MemNode,
    ) -> MultiQueryIter<'this, 's, MemReadSpec, MemIntersects> {
        self.mem_read_query(MemIntersects { node })
    }

    pub fn fetch_at<BA, BS>(&self, addr_range: IRange<Addr>, time: Time) -> Fetch<Time, BA>
    where
        BS: ByteStorage,
        BA: ByteArray<BS>,
    {
        let total_size = addr_range.span_usize();

        let query_rect = MemNode {
            addr_min: addr_range.min,
            addr_max: addr_range.max,
            time_min: time,
            time_max: time,
        };

        let mut array = BA::new(total_size);
        let mut time_start = 0;
        let mut time_end = Time::MAX;

        let mut fill_count = 0;

        for leaf in self.mem_write_intersects(query_rect) {
            let data = self.mem_leaf_data(leaf);

            let node_off;
            let out_off;

            time_start = time_start.max(leaf.node.time_min);
            time_end = time_end.min(leaf.node.time_max);

            if leaf.node.addr_min < query_rect.addr_min {
                out_off = 0;
                node_off = (query_rect.addr_min - leaf.node.addr_min) as usize;
            } else {
                out_off = (leaf.node.addr_min - query_rect.addr_min) as usize;
                node_off = 0;
            }

            let size = array[out_off..].len().min(data[node_off..].len());

            for idx in 0..size {
                array[out_off + idx] = BS::from_byte(data[node_off + idx]);
                fill_count += 1;
            }
        }

        debug_assert!(fill_count <= total_size);
        let is_complete = fill_count == total_size;

        Fetch {
            array,
            is_complete,
            valid_time_range: IRange::new(time_start, time_end),
        }
    }

    pub fn mem_leaf_data(&self, leaf: &'s MemWriteLeaf) -> &'s [u8] {
        let len = leaf.addr_range().span_usize();
        if len <= 8 {
            // NOTE: not portable but endianness will be checked in index header
            &leaf.packed_data.as_bytes()[..len]
        } else {
            let offset = leaf.packed_data as usize;
            &self.raw_data[offset..][..len]
        }
    }

    /* pub fn register_prev_next_in_value_range_at(
        &self,
        id: RegId,
        value_range: IRange<u64>,
        time: Time,
    ) -> (Option<RegLeaf>, Option<RegLeaf>) {
        let rtree = &self.registers[id.index()];

        let prev_range = IRange::new(0, time.saturating_sub(1));
        let next_range = IRange::new(time.saturating_add(1), Time::MAX);

        let prev = walk_first(
            rtree,
            |node| {
                if node.time_range().is_disjoint(&prev_range) {
                    return NodeControlFlow::Ignore;
                }
                if node.value_range().is_disjoint(&value_range) {
                    return NodeControlFlow::Ignore;
                }
                let dist = node.time_range().min_distance(time);
                NodeControlFlow::Enter(dist)
            },
            |leaf| {
                if leaf.time_range().is_disjoint(&prev_range) {
                    return LeafControlFlow::Ignore;
                }
                if leaf.time_range().contains(time) {
                    return LeafControlFlow::Ignore;
                }
                if !value_range.contains(leaf.value) {
                    return LeafControlFlow::Ignore;
                }

                let dist = leaf.time_range().min_distance(time);
                LeafControlFlow::Accept(dist)
            },
        );

        let next = walk_first(
            rtree,
            |node| {
                if node.time_range().is_disjoint(&next_range) {
                    return NodeControlFlow::Ignore;
                }
                if node.value_range().is_disjoint(&value_range) {
                    return NodeControlFlow::Ignore;
                }
                let dist = node.time_range().min_distance(time);
                NodeControlFlow::Enter(dist)
            },
            |leaf| {
                if leaf.time_range().is_disjoint(&next_range) {
                    return LeafControlFlow::Ignore;
                }
                if leaf.time_range().contains(time) {
                    return LeafControlFlow::Ignore;
                }
                if !value_range.contains(leaf.value) {
                    return LeafControlFlow::Ignore;
                }

                let dist = leaf.time_range().min_distance(time);
                LeafControlFlow::Accept(dist)
            },
        );

        (prev.copied(), next.copied())
    }*/
}

fn read_rtree_list<'s, S: Spec>(
    storage: &'s [u8],
    list: &RTreeList,
) -> Result<Vec<RTree<'s, S>>, LoadError> {
    let headers = cast_section::<RTreeHeader>(storage, list.headers)?;
    let bboxes = cast_section::<S::Node>(storage, list.bboxes)?;

    if headers.len() != bboxes.len() {
        error!(
            "RTreeHeader.len() != bboxes.len() : {} != {}",
            headers.len(),
            bboxes.len()
        );
        return Err(LoadError::Corrupted);
    }

    let count = headers.len();

    let mut rtrees = Vec::with_capacity(count);
    for idx in 0..count {
        let header = headers[idx];
        let bbox = bboxes[idx];

        let node_size_order = header.node_size_order;

        let Some(leaves_data) = storage.get(header.leaves.byte_range()) else {
            error!("header.leaves out-of-bounds");
            return Err(LoadError::Corrupted);
        };
        let leaves = <[S::Leaf]>::ref_from_bytes(leaves_data)?;

        let Some(nodes_data) = storage.get(header.nodes.byte_range()) else {
            error!("header.nodes out-of-bounds");
            return Err(LoadError::Corrupted);
        };
        let nodes = <[S::Node]>::ref_from_bytes(nodes_data)?;

        let Some(levels_data) = storage.get(header.levels.byte_range()) else {
            error!("header.levels out-of-bounds");
            return Err(LoadError::Corrupted);
        };
        let levels = <[Level]>::ref_from_bytes(levels_data)?;

        let mut node_levels = Vec::with_capacity(levels.len());
        for level in levels {
            let Some(subset) = nodes.get((level.offset as usize)..) else {
                error!("level.offset out-of-bounds");
                return Err(LoadError::Corrupted);
            };
            let Some(subset) = subset.get(..(level.size as usize)) else {
                error!("level.size out-of-bounds");
                return Err(LoadError::Corrupted);
            };
            node_levels.push(subset)
        }

        rtrees.push(RTree {
            node_size_order,
            leaves,
            nodes,
            node_levels,
            bbox,
        });
    }

    Ok(rtrees)
}

fn cast_section<T>(data: &[u8], section: Section) -> Result<&[T], LoadError>
where
    T: Zerocopyable,
{
    let bytes = &data[section.byte_range()];
    Ok(<[T]>::ref_from_bytes(bytes)?)
}

pub struct MultiQueryIter<'rtree, 'storage, S: Spec, Q> {
    zones: Vec<QueryIter<'rtree, 'storage, S, Q>>,
}

impl<'rtree, 'storage, S: Spec, Q> MultiQueryIter<'rtree, 'storage, S, Q>
where
    S: Spec,
    Q: Query<S> + Clone,
{
    pub fn new(query: Q, rtrees: &'rtree [RTree<'storage, S>]) -> Self {
        let zones = rtrees
            .iter()
            .filter(|zone| query.clone().filter_node(&zone.bbox))
            .map(|zone| zone.query(query.clone()))
            .collect();
        Self { zones }
    }
}

impl<'rtree, 'storage, S: Spec, Q> Iterator for MultiQueryIter<'rtree, 'storage, S, Q>
where
    Q: Query<S>,
{
    type Item = &'storage S::Leaf;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let zone = self.zones.last_mut()?;
            match zone.next() {
                Some(leaf) => {
                    return Some(leaf);
                }
                None => {
                    self.zones.pop();
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MemIntersects {
    node: MemNode,
}

impl Query<MemWriteSpec> for MemIntersects {
    fn filter_node(&mut self, node: &MemNode) -> bool {
        !self.node.is_disjoint(node)
    }
    fn filter_leaf(&mut self, leaf: &MemWriteLeaf) -> bool {
        !self.node.is_disjoint(&leaf.node)
    }
}

impl Query<MemReadSpec> for MemIntersects {
    fn filter_node(&mut self, node: &MemNode) -> bool {
        !self.node.is_disjoint(node)
    }
    fn filter_leaf(&mut self, leaf: &MemReadLeaf) -> bool {
        !self.node.is_disjoint(&leaf.node())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RegIntersects {
    node: RegNode,
}

impl RegIntersects {
    pub fn new(node: RegNode) -> Self {
        Self { node }
    }
}

impl Query<RegSpec> for RegIntersects {
    fn filter_node(&mut self, node: &RegNode) -> bool {
        !self.node.is_disjoint(node)
    }

    fn filter_leaf(&mut self, leaf: &RegLeaf) -> bool {
        self.filter_node(&leaf.node())
    }
}

/// Memory fetch result
pub struct Fetch<Time, BA> {
    /// This time range span between the previous and the next memory update affecting the requested address range
    pub valid_time_range: IRange<Time>,

    /// Loaded data
    pub array: BA,

    /// False if at least one address has no value
    pub is_complete: bool,
}

pub trait ByteArray<S: ByteStorage>
where
    Self: IndexMut<usize, Output = S>,
    Self: IndexMut<core::ops::RangeFrom<usize>, Output = [S]>,
{
    fn new(size: usize) -> Self;
}

impl<S: ByteStorage> ByteArray<S> for Vec<S> {
    fn new(size: usize) -> Self {
        vec![S::default(); size]
    }
}

impl<const LEN: usize, S: ByteStorage> ByteArray<S> for [S; LEN] {
    fn new(size: usize) -> Self {
        assert_eq!(LEN, size);
        [S::default(); LEN]
    }
}

pub trait ByteStorage: Default + Copy + Clone {
    fn from_byte(v: u8) -> Self;
}

impl ByteStorage for u8 {
    fn from_byte(v: u8) -> Self {
        v
    }
}

impl ByteStorage for Option<u8> {
    fn from_byte(v: u8) -> Self {
        Some(v)
    }
}
