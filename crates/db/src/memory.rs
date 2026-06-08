use crate::db::Db;
use crate::flat::*;
use crate::irange::*;
use crate::matcher::DimMatcher;
use crate::nearest_neighbor::Status;
use crate::nearest_neighbor::nearest_neighbor;
use crate::query::*;
use crate::rtree::*;

#[derive(Clone, Copy)]
pub struct MemWriteSpec;
pub type MemWriteQuery<'rtree, 'storage, Query> = QueryIter<'rtree, 'storage, MemWriteSpec, Query>;
pub type MemWriteRTree<'storage> = RTree<'storage, MemWriteSpec>;

impl Spec for MemWriteSpec {
    type Node = MemNode;
    type Leaf = MemWriteLeaf;
}

#[derive(Clone, Copy)]
pub struct MemReadSpec;
pub type MemReadQuery<'rtree, 'storage, Query> = QueryIter<'rtree, 'storage, MemReadSpec, Query>;
pub type MemReadRTree<'storage> = RTree<'storage, MemReadSpec>;

impl Spec for MemReadSpec {
    type Node = MemNode;
    type Leaf = MemReadLeaf;
}

impl MemNode {
    #[inline]
    pub fn extends_to_contain(&mut self, other: &Self) {
        self.addr_min = self.addr_min.min(other.addr_min);
        self.addr_max = self.addr_max.max(other.addr_max);
        self.time_min = self.time_min.min(other.time_min);
        self.time_max = self.time_max.max(other.time_max);
    }

    #[inline]
    pub fn is_disjoint(&self, other: &Self) -> bool {
        #[cfg(debug_assertions)]
        {
            self.check_invariant();
            other.check_invariant();
        }

        let addr = self.addr_range().is_disjoint(&other.addr_range());
        let time = self.time_range().is_disjoint(&other.time_range());
        addr || time
    }

    #[allow(unused)]
    fn check_invariant(&self) {
        assert!(self.addr_min <= self.addr_max);
        assert!(self.time_min <= self.time_max);
    }

    #[inline]
    pub fn addr_range(&self) -> IRange<Addr> {
        IRange {
            min: self.addr_min,
            max: self.addr_max,
        }
    }

    #[inline]
    pub fn time_range(&self) -> IRange<Time> {
        IRange {
            min: self.time_min,
            max: self.time_max,
        }
    }

    /// Fragment one rectangle by another
    ///
    /// Based on the pseudo-code of the NIR-Tree paper : https://dl.acm.org/doi/10.1145/3468791.3468818
    pub fn fragment_by(&self, other: &Self, fragments: &mut Vec<MemNode>) {
        if self.is_disjoint(other) {
            fragments.push(*self);
            return;
        }

        struct MemPoint {
            pub addr: Addr,
            pub time: Time,
        }

        let mut ceils = MemPoint { addr: 0, time: 0 };
        let mut floors = MemPoint { addr: 0, time: 0 };

        // Address
        {
            let self_floor = self.addr_min;
            let other_floor = other.addr_min;
            floors.addr = other_floor.max(self_floor);

            if other_floor > self_floor {
                fragments.push(MemNode {
                    addr_min: self_floor,
                    time_min: self.time_min,
                    addr_max: other_floor - 1,
                    time_max: self.time_max,
                });
            }

            let self_ceil = self.addr_max;
            let other_ceil = other.addr_max;
            ceils.addr = other_ceil.min(self_ceil);

            if other_ceil < self_ceil {
                fragments.push(MemNode {
                    addr_min: other_ceil + 1,
                    time_min: self.time_min,
                    addr_max: self_ceil,
                    time_max: self.time_max,
                });
            }
        }

        // Time
        {
            let self_floor = self.time_min;
            let other_floor = other.time_min;
            floors.time = other_floor.max(self_floor);

            if other_floor > self_floor {
                fragments.push(MemNode {
                    addr_min: floors.addr,
                    time_min: self_floor,
                    addr_max: ceils.addr,
                    time_max: other_floor - 1,
                });
            }

            let self_ceil = self.time_max;
            let other_ceil = other.time_max;
            ceils.time = other_ceil.min(self_ceil);

            if other_ceil < self_ceil {
                fragments.push(MemNode {
                    addr_min: floors.addr,
                    time_min: other_ceil + 1,
                    addr_max: ceils.addr,
                    time_max: self_ceil,
                });
            }
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for MemWriteLeaf {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let addr_range: IRange<Addr> = u.arbitrary()?;
        let time_range: IRange<Time> = u.arbitrary()?;
        let packed_data = u.arbitrary()?;

        Ok(Self {
            addr_min: addr_range.min,
            addr_max: addr_range.max,
            time_min: time_range.min,
            time_max: time_range.max,
            packed_data,
        })
    }
}

impl MemWriteLeaf {
    #[inline]
    pub fn is_disjoint(&self, other: &Self) -> bool {
        self.node.is_disjoint(&other.node)
    }

    #[inline]
    pub fn addr_range(&self) -> IRange<Addr> {
        self.node.addr_range()
    }

    #[inline]
    pub fn time_range(&self) -> IRange<Time> {
        self.node.time_range()
    }
}

impl MemReadLeaf {
    #[inline]
    pub fn node(&self) -> MemNode {
        MemNode {
            addr_min: self.addr_min,
            addr_max: self.addr_max,
            time_min: self.time,
            time_max: self.time,
        }
    }

    #[inline]
    pub fn is_disjoint(&self, other: &Self) -> bool {
        self.addr_range().is_disjoint(&other.addr_range()) && self.time != other.time
    }

    #[inline]
    pub fn addr_range(&self) -> IRange<Addr> {
        IRange::new(self.addr_min, self.addr_max)
    }
}

impl Db<'_> {
    pub fn prev_mem_write(
        &self,
        time: Time,
        addr_matcher: impl DimMatcher<Addr> + Copy,
    ) -> Option<Time> {
        self.write_zones
            .iter()
            .filter(|rtree| addr_matcher.match_range(rtree.bbox.addr_range()))
            .filter_map(|rtree| rtree.prev_leaf_where_addr_match(time, addr_matcher))
            .max()
    }

    pub fn next_mem_write(
        &self,
        time: Time,
        addr_matcher: impl DimMatcher<Addr> + Copy,
    ) -> Option<Time> {
        self.write_zones
            .iter()
            .filter(|rtree| addr_matcher.match_range(rtree.bbox.addr_range()))
            .filter_map(|rtree| rtree.next_leaf_where_addr_match(time, addr_matcher))
            .min()
    }

    pub fn prev_mem_read(
        &self,
        time: Time,
        addr_matcher: impl DimMatcher<Addr> + Copy,
    ) -> Option<Time> {
        self.read_zones
            .iter()
            .filter(|rtree| addr_matcher.match_range(rtree.bbox.addr_range()))
            .filter_map(|rtree| rtree.prev_leaf_where_addr_match(time, addr_matcher))
            .max()
    }

    pub fn next_mem_read(
        &self,
        time: Time,
        addr_matcher: impl DimMatcher<Addr> + Copy,
    ) -> Option<Time> {
        self.read_zones
            .iter()
            .filter(|rtree| addr_matcher.match_range(rtree.bbox.addr_range()))
            .filter_map(|rtree| rtree.next_leaf_where_addr_match(time, addr_matcher))
            .min()
    }
}

macro_rules! impl_prev_next {
    ($rtree:ident, $node_visitor:ident, $leaf_visitor:ident, $map:expr) => {
        impl $rtree<'_> {
            pub fn prev_leaf_where_addr_match<M>(&self, time: Time, addr_matcher: M) -> Option<Time>
            where
                M: DimMatcher<Addr> + Copy,
            {
                let time_range = IRange::new(0, time.checked_sub(1)?);
                nearest_neighbor(
                    self,
                    $node_visitor(time_range, addr_matcher, time),
                    $leaf_visitor(time_range, addr_matcher, time),
                )
                .map($map)
            }

            pub fn next_leaf_where_addr_match<M>(&self, time: Time, addr_matcher: M) -> Option<Time>
            where
                M: DimMatcher<Addr> + Copy,
            {
                let time_range = IRange::new(time.checked_add(1)?, Time::MAX);
                nearest_neighbor(
                    self,
                    $node_visitor(time_range, addr_matcher, time),
                    $leaf_visitor(time_range, addr_matcher, time),
                )
                .map($map)
            }
        }
    };
}

impl_prev_next!(
    MemReadRTree,
    mem_node_visitor,
    mem_read_leaf_visitor,
    |leaf| leaf.time
);

impl_prev_next!(
    MemWriteRTree,
    mem_node_visitor,
    mem_write_leaf_visitor,
    |leaf| leaf.node.time_min
);

fn mem_node_visitor(
    time_range: IRange<u32>,
    addr_matcher: impl DimMatcher<u64>,
    target_time: u32,
) -> impl Fn(&MemNode) -> Status<Time> {
    move |node| {
        if !time_range.match_range(node.time_range()) {
            return Status::Ignore;
        }
        if !addr_matcher.match_range(node.addr_range()) {
            return Status::Ignore;
        }
        let dist = node.time_range().min_distance(target_time);
        Status::Keep(dist)
    }
}

fn mem_read_leaf_visitor(
    time_range: IRange<u32>,
    addr_matcher: impl DimMatcher<u64>,
    target_time: u32,
) -> impl Fn(&MemReadLeaf) -> Status<Time> {
    move |leaf| {
        if !time_range.match_scalar(leaf.time) {
            return Status::Ignore;
        }
        if !addr_matcher.match_range(leaf.addr_range()) {
            return Status::Ignore;
        }
        let dist = leaf.time.abs_diff(target_time);
        Status::Keep(dist)
    }
}

fn mem_write_leaf_visitor(
    time_range: IRange<u32>,
    addr_matcher: impl DimMatcher<u64>,
    target_time: u32,
) -> impl Fn(&MemWriteLeaf) -> Status<Time> {
    move |leaf| {
        if !time_range.match_scalar(leaf.node.time_min) {
            return Status::Ignore;
        }
        if !addr_matcher.match_range(leaf.addr_range()) {
            return Status::Ignore;
        }
        let dist = leaf.node.time_min.abs_diff(target_time);
        Status::Keep(dist)
    }
}
