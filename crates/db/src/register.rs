use crate::db::Db;
use crate::flat::*;
use crate::irange::*;
use crate::matcher::DimMatcher;
use crate::nearest_neighbor::Status;
use crate::nearest_neighbor::nearest_neighbor;
use crate::query::*;
use crate::rtree::*;

pub type RegRTree<'storage> = RTree<'storage, RegSpec>;

impl<'s> Db<'s> {
    pub fn register_rtree_by_name(&self, name: &str) -> Option<&RegRTree<'s>> {
        let idx = self.register_index_by_name(name)?;
        self.register_rtree_by_index(idx)
    }

    pub fn register_index_by_name(&self, name: &str) -> Option<usize> {
        self.metadata
            .register_names
            .iter()
            .position(|it| it == name)
    }

    pub fn register_rtree_by_index(&self, idx: usize) -> Option<&RegRTree<'s>> {
        self.registers.get(idx)
    }
}

impl<'s> RTree<'s, RegSpec> {
    pub fn leaf_at(&self, time: Time) -> Option<&'s RegLeaf> {
        self.query(RegValueAt { time }).next()
    }

    /// Registre value at a given time, returns [None] before the first write
    pub fn value_at(&self, time: Time) -> Option<u64> {
        Some(self.leaf_at(time)?.value)
    }

    /// Previous write where the register value match
    pub fn prev_time_with(&self, time: Time, value_matcher: impl DimMatcher<u64>) -> Option<Time> {
        let time_range = IRange::new(0, time.checked_sub(1)?);
        register_nearest_neighbor_over_time(self, time, time_range, value_matcher)
    }

    /// Next write where the register value match
    pub fn next_time_with(&self, time: Time, value_matcher: impl DimMatcher<u64>) -> Option<Time> {
        let time_range = IRange::new(time.checked_add(1)?, Time::MAX);
        register_nearest_neighbor_over_time(self, time, time_range, value_matcher)
    }

    /// First write where the register value match
    pub fn first_time_with(&self, value_matcher: impl DimMatcher<u64>) -> Option<Time> {
        let time_range = self.bbox.time_range();
        register_nearest_neighbor_over_time(self, time_range.min, time_range, value_matcher)
    }

    /// Last write where the register value match
    pub fn last_time_with(&self, value_matcher: impl DimMatcher<u64>) -> Option<Time> {
        let time_range = self.bbox.time_range();
        register_nearest_neighbor_over_time(self, time_range.max, time_range, value_matcher)
    }
}

fn register_nearest_neighbor_over_time(
    rtree: &RegRTree<'_>,
    target_time: Time,
    time_range: IRange<Time>,
    value_matcher: impl DimMatcher<u64>,
) -> Option<Time> {
    nearest_neighbor(
        rtree,
        |node| {
            if time_range.is_disjoint(&node.time_range()) {
                return Status::Ignore;
            }
            if !value_matcher.match_range(node.value_range()) {
                return Status::Ignore;
            }
            let dist = node.time_range().min_distance(target_time);
            Status::Keep(dist)
        },
        |leaf| {
            if !time_range.contains(leaf.time_min) {
                return Status::Ignore;
            }
            if !value_matcher.match_scalar(leaf.value) {
                return Status::Ignore;
            }
            let dist = leaf.time_min.abs_diff(target_time);
            Status::Keep(dist)
        },
    )
    .map(|leaf| leaf.time_min)
}

#[derive(Debug, Clone, Copy)]
struct RegValueAt {
    time: Time,
}

impl Query<RegSpec> for RegValueAt {
    fn filter_node(&mut self, node: &RegNode) -> bool {
        node.time_range().contains(self.time)
    }

    fn filter_leaf(&mut self, leaf: &RegLeaf) -> bool {
        leaf.time_range().contains(self.time)
    }
}

#[derive(Clone, Copy)]
pub struct RegSpec;

impl Spec for RegSpec {
    type Node = RegNode;
    type Leaf = RegLeaf;
}

pub type RegQuery<'rtree, 'storage, Query> = QueryIter<'rtree, 'storage, RegSpec, Query>;

impl RegNode {
    #[inline]
    pub fn extends_to_contain(&mut self, other: &Self) {
        self.value_min = self.value_min.min(other.value_min);
        self.value_max = self.value_max.max(other.value_max);
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

        let addr = self.value_range().is_disjoint(&other.value_range());
        let time = self.time_range().is_disjoint(&other.time_range());
        addr || time
    }

    #[allow(unused)]
    fn check_invariant(&self) {
        assert!(self.value_min <= self.value_max);
        assert!(self.time_min <= self.time_max);
    }

    #[inline]
    pub fn value_range(&self) -> IRange<u64> {
        IRange {
            min: self.value_min,
            max: self.value_max,
        }
    }

    #[inline]
    pub fn time_range(&self) -> IRange<Time> {
        IRange {
            min: self.time_min,
            max: self.time_max,
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for RegLeaf {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let time_range: IRange<Time> = u.arbitrary()?;
        let value = u.arbitrary()?;

        Ok(Self {
            time_min: time_range.min,
            time_max: time_range.max,
            value,
        })
    }
}

impl RegLeaf {
    #[inline]
    pub fn node(self) -> RegNode {
        RegNode {
            value_min: self.value,
            value_max: self.value,
            time_min: self.time_min,
            time_max: self.time_max,
        }
    }

    #[inline]
    pub fn is_disjoint(&self, other: &Self) -> bool {
        self.node().is_disjoint(&other.node())
    }

    #[inline]
    pub fn time_range(&self) -> IRange<Time> {
        IRange::new(self.time_min, self.time_max)
    }
}
