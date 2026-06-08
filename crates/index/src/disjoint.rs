use std::collections::BTreeMap;

use frinet_db::{
    flat::{Addr, MemNode, Time},
    irange::IRange,
};
use smallvec::SmallVec;

/// Disjoint leaves
pub struct DisjointPass<D> {
    current_time: Time,
    /// Temporary leaves by start address
    temporaries: BTreeMap<Addr, TemporaryLeaf<D>>,

    // keep vecs around to save some allocations
    to_remove: Vec<Addr>,
    to_add: Vec<TemporaryLeaf<D>>,
    fragments: Vec<MemNode>,
}

impl<D> Default for DisjointPass<D> {
    fn default() -> Self {
        Self {
            current_time: 0,
            temporaries: BTreeMap::default(),
            to_remove: Vec::default(),
            to_add: Vec::default(),
            fragments: Vec::default(),
        }
    }
}

pub struct DisjointMemLeaf<D> {
    pub node: MemNode,
    pub data: D,
}

pub trait DataCut: Copy {
    fn cut(self, cut_left: usize, cut_right: usize) -> Self;
}

#[derive(Debug, Clone, Copy)]
pub struct NoData;

impl DataCut for NoData {
    fn cut(self, _: usize, _: usize) -> Self {
        self
    }
}

struct TemporaryLeaf<D> {
    time_min: Time,
    addr_min: Addr,
    addr_max: Addr,
    bytes: SmallVec<[u8; 8]>,
    data: D,
}

impl<D: DataCut> TemporaryLeaf<D> {
    fn complete(&self, time_max: Time) -> DisjointMemLeaf<D> {
        DisjointMemLeaf {
            node: MemNode {
                time_min: self.time_min,
                time_max,
                addr_min: self.addr_min,
                addr_max: self.addr_max,
            },
            data: self.data,
        }
    }

    fn mask_with_bbox(&self, bbox: MemNode) -> Self {
        debug_assert!(self.addr_min <= bbox.addr_min);
        debug_assert!(bbox.addr_max <= self.addr_max);

        let cut_left = (bbox.addr_min - self.addr_min) as usize;
        let cut_right = (self.addr_max - bbox.addr_max) as usize;

        let data = self.data.cut(cut_left, cut_right);

        let cut_bytes = &self.bytes[cut_left..(self.bytes.len() - cut_right)];
        let cut_bytes = SmallVec::from_slice(cut_bytes);

        Self {
            time_min: bbox.time_min,
            addr_min: bbox.addr_min,
            addr_max: bbox.addr_max,
            data,
            bytes: cut_bytes,
        }
    }
}

impl<D: DataCut> DisjointPass<D> {
    pub fn push_memory_write<EmitLeaf>(
        &mut self,
        time: Time,
        addr: Addr,
        bytes: &[u8],
        data: D,
        can_dedup: bool,
        mut emit_leaf: EmitLeaf,
    ) where
        EmitLeaf: FnMut(DisjointMemLeaf<D>),
    {
        // checked by the caller
        debug_assert!(!bytes.is_empty());
        debug_assert!(self.current_time <= time);

        self.current_time = time;

        if can_dedup {
            if self.is_duplicate_write(addr, bytes) {
                return;
            }
        }

        let addr_range = IRange::from_start_len(addr, bytes.len() as _);

        let new = TemporaryLeaf {
            time_min: time,
            addr_min: addr_range.min,
            addr_max: addr_range.max,
            bytes: SmallVec::from_slice(bytes),
            data,
        };

        let new_rect = new.complete(Time::MAX).node;

        for existing in Self::iter_temporaries_in_range(&self.temporaries, addr_range) {
            let existing_rect = existing.complete(Time::MAX).node;
            debug_assert!(!existing_rect.is_disjoint(&new_rect));

            // track if it will be replaced by a fragment with `.insert(...)`
            let mut will_be_replaced = false;

            existing_rect.fragment_by(&new_rect, &mut self.fragments);

            for fragment in self.fragments.drain(..) {
                debug_assert!(
                    !existing_rect.is_disjoint(&fragment),
                    "'fragment' must be contained inside 'existing'"
                );
                debug_assert!(
                    new_rect.is_disjoint(&fragment),
                    "'fragment' must be disjoint from 'new'"
                );

                let existing_masked = existing.mask_with_bbox(fragment);
                if fragment.time_max == Time::MAX {
                    // add fragment to the working set
                    if existing_rect.addr_min == existing_masked.addr_min {
                        will_be_replaced = true;
                    }
                    self.to_add.push(existing_masked);
                } else {
                    // emit the fragment as a leaf
                    let leaf = existing_masked.complete(fragment.time_max);
                    emit_leaf(leaf);
                }
            }

            if !will_be_replaced {
                self.to_remove.push(existing_rect.addr_min);
            }
        }

        for min_addr in self.to_remove.drain(..) {
            self.temporaries.remove(&min_addr);
        }
        for partial in self.to_add.drain(..) {
            self.temporaries.insert(partial.addr_min, partial);
        }

        self.temporaries.insert(new.addr_min, new);
    }

    pub fn finish<EmitLeaf>(self, mut emit_leaf: EmitLeaf)
    where
        EmitLeaf: FnMut(DisjointMemLeaf<D>),
    {
        for partial in self.temporaries.values() {
            let leaf = partial.complete(self.current_time);
            emit_leaf(leaf);
        }
    }

    fn is_duplicate_write(&self, addr: Addr, check_bytes: &[u8]) -> bool {
        let check_range = IRange::from_start_len(addr, check_bytes.len() as _);

        let mut cursor = check_range.min;
        for tmp in Self::iter_temporaries_in_range(&self.temporaries, check_range) {
            if cursor < tmp.addr_min {
                return false; // the byte at `curr` is unknown
            }

            debug_assert!(tmp.addr_min <= cursor);
            debug_assert!(cursor <= tmp.addr_max);

            let iter_from = cursor;
            let iter_to = tmp.addr_max.min(check_range.max);

            for check_addr in iter_from..=iter_to {
                debug_assert!(tmp.addr_min <= check_addr);
                debug_assert!(check_addr <= tmp.addr_max);

                let check_byte = check_bytes[(check_addr - check_range.min) as usize];
                let tmp_byte = tmp.bytes[(check_addr - tmp.addr_min) as usize];

                if check_byte != tmp_byte {
                    return false;
                }
            }

            if iter_to == check_range.max {
                return true;
            }

            cursor = iter_to + 1;
        }

        return false;
    }

    fn iter_temporaries_in_range(
        temporaries: &BTreeMap<Addr, TemporaryLeaf<D>>,
        query_range: IRange<Addr>,
    ) -> impl Iterator<Item = &TemporaryLeaf<D>> {
        // TODO : rewrite with the cursor api when it become stable
        // (https://github.com/rust-lang/rust/issues/107540)

        let query_min = query_range.min;
        let query_max = query_range.max;

        let mut iter_from = query_min;

        // temporaries are indexes by their `addr_min`,
        // if `query_min` is in the middle of a temporary,
        // include it in the result
        if let Some((_, tmp)) = temporaries.range(..query_min).next_back() {
            if query_min <= tmp.addr_max {
                iter_from = tmp.addr_min;
            }
        }

        temporaries
            .range(iter_from..)
            .map(|it| it.1)
            .take_while(move |it| it.addr_min <= query_max)
    }
}
