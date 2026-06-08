use core::mem;
use std::ops::Range;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub trait Zerocopyable: FromBytes + IntoBytes + Immutable + KnownLayout {}
impl<T: FromBytes + IntoBytes + Immutable + KnownLayout> Zerocopyable for T {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct Header {
    pub magic: u64,
    pub version: u64,
    pub metadata: Section,
    pub data: Section,

    pub write_zones: RTreeList,
    pub read_zones: RTreeList,
    pub registers: RTreeList,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RTreeList {
    pub headers: Section,
    pub bboxes: Section,
}

impl Header {
    /// Size in bytes
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RTreeHeader {
    pub node_size_order: u64,
    pub leaves: Section,
    pub nodes: Section,
    pub levels: Section,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct Level {
    /// Offset in rtree.nodes
    pub offset: u64,
    /// Number of nodes
    pub size: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct Section {
    pub start: u64,
    pub end: u64,
}

impl Section {
    pub fn item_byte_range<T>(&self, idx: usize) -> Range<usize> {
        let size = mem::size_of::<T>();
        let span = (self.end - self.start) as usize;
        assert!(span.is_multiple_of(size));
        let start = self.start as usize + size * idx;
        start..start + idx
    }

    pub fn byte_range(&self) -> Range<usize> {
        self.start as usize..self.end as usize
    }
}

pub type Addr = u64;
pub type Time = u32;
pub type PackedData = u64;

/// Memory R-Tree node
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[cfg_attr(feature = "pyo3", pyo3::pyclass(get_all, skip_from_py_object))]
#[repr(C)]
pub struct MemNode {
    pub addr_min: Addr,
    pub addr_max: Addr,
    pub time_min: Time,
    pub time_max: Time,
}

/// Memory R-Tree leaf
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct MemWriteLeaf {
    pub node: MemNode,
    pub packed_data: PackedData,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct MemReadLeaf {
    pub addr_min: Addr,
    pub addr_max: Addr,
    pub time: Time,
}

/// Register R-Tree node
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RegNode {
    pub value_min: u64,
    pub value_max: u64,
    pub time_min: Time,
    pub time_max: Time,
}

/// Register R-Tree leaf
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RegLeaf {
    pub value: u64,
    pub time_min: Time,
    pub time_max: Time,
}

impl RegLeaf {
    /// Size in bytes
    pub const SIZE: usize = core::mem::size_of::<Self>();
}
