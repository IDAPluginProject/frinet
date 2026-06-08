use frinet_db::flat::{self, RTreeHeader, RTreeList, Section};
use frinet_db::memory::MemReadSpec;
use frinet_db::register::RegSpec;
use frinet_db::{DB_MAGIC, DB_VERSION};
use frinet_db::{memory::MemWriteSpec, rtree::Spec};
use zerocopy::FromBytes;

use core::{array, cmp, mem};

use crate::pass::{HilbertPartitionPass, PARTITIONS, RTreePartitions, RTreeScout, ScoutPass};

#[derive(Debug, Clone)]
pub struct StorageLayout {
    pub max_storage_size: usize,
    pub header: flat::Header,
    pub write_zones: Vec<flat::RTreeHeader>,
    pub read_zones: Vec<flat::RTreeHeader>,
    pub registers: Vec<flat::RTreeHeader>,
}

pub fn build_storage_layout(scout: &ScoutPass, node_size_order: u8) -> StorageLayout {
    let rtree_header = RTreeHeader {
        node_size_order: u64::from(node_size_order),
        ..RTreeHeader::default()
    };

    let mut layout = StorageLayout {
        header: flat::Header {
            magic: DB_MAGIC,
            version: DB_VERSION,
            data: Section::default(),
            metadata: Section::default(),
            write_zones: RTreeList::default(),
            read_zones: RTreeList::default(),
            registers: RTreeList::default(),
        },
        write_zones: vec![rtree_header; scout.write_zones.len()],
        read_zones: vec![rtree_header; scout.read_zones.len()],
        registers: vec![rtree_header; scout.registers.len()],
        max_storage_size: 0,
    };
    let header = &mut layout.header;

    let mut builder = LayoutBuilder::default();

    builder.add::<flat::Header>();
    builder.section_slice(&mut header.metadata, &scout.metadata_json.as_bytes());

    // Pack header and levels to improve page caching
    builder.rtree_list_headers(&mut header.write_zones, &scout.write_zones);
    builder.rtree_list_headers(&mut header.read_zones, &scout.read_zones);
    builder.rtree_list_headers(&mut header.registers, &scout.registers);

    builder.rtree_levels(&mut layout.write_zones, &scout.write_zones);
    builder.rtree_levels(&mut layout.read_zones, &scout.read_zones);
    builder.rtree_levels(&mut layout.registers, &scout.registers);

    // nodes & leaves
    builder.rtree_nodes_and_leaves::<MemWriteSpec>(&mut layout.write_zones, &scout.write_zones);
    builder.rtree_nodes_and_leaves::<MemReadSpec>(&mut layout.read_zones, &scout.read_zones);
    builder.rtree_nodes_and_leaves::<RegSpec>(&mut layout.registers, &scout.registers);

    // data section at the end, will be truncated after deduplication
    builder.section::<u8>(&mut header.data, scout.data_section_required_bytes);

    layout.max_storage_size = builder.pos;
    layout
}

#[derive(Default)]
struct LayoutBuilder {
    pos: usize,
}

impl LayoutBuilder {
    fn add<T>(&mut self) {
        self.add_many::<T>(1);
    }

    fn add_many<T>(&mut self, count: usize) {
        let needed_align = mem::align_of::<T>();
        assert!(self.pos.is_multiple_of(needed_align));
        self.pos += count * mem::size_of::<T>();
    }

    fn align<T>(&mut self) {
        let needed_align = mem::align_of::<T>();
        self.pos = self.pos.checked_next_multiple_of(needed_align).unwrap();
    }

    fn section<T>(&mut self, section: &mut Section, count: usize) {
        self.align::<T>();
        section.start = self.pos as u64;
        self.add_many::<T>(count);
        section.end = self.pos as u64;
    }

    fn section_slice<T>(&mut self, section: &mut Section, slice: &[T]) {
        self.section::<T>(section, slice.len());
    }

    fn rtree_list_headers<Node>(
        &mut self,
        flat_list: &mut RTreeList,
        scout_list: &[RTreeScout<Node>],
    ) {
        self.section::<flat::RTreeHeader>(&mut flat_list.headers, scout_list.len());
        self.section::<Node>(&mut flat_list.bboxes, scout_list.len());
    }

    fn rtree_levels<Node>(
        &mut self,
        headers: &mut [RTreeHeader],
        scout_list: &[RTreeScout<Node>],
    ) -> () {
        for (layout, scout) in headers.iter_mut().zip(scout_list.iter()) {
            self.section_slice::<flat::Level>(&mut layout.levels, &scout.levels);
        }
    }

    fn rtree_nodes_and_leaves<S: Spec>(
        &mut self,
        headers: &mut [RTreeHeader],
        scout_list: &[RTreeScout<S::Node>],
    ) -> () {
        for (layout, scout) in headers.iter_mut().zip(scout_list.iter()) {
            self.section::<S::Node>(&mut layout.nodes, scout.node_count);
            self.section::<S::Leaf>(&mut layout.leaves, scout.leaf_count);
        }
    }
}

pub struct StorageViewMut<'s> {
    pub header: &'s mut flat::Header,
    pub metadata: &'s mut [u8],
    pub data: &'s mut [u8],
    pub write_zones: RTreeListViewMut<'s, MemWriteSpec>,
    pub read_zones: RTreeListViewMut<'s, MemReadSpec>,
    pub registers: RTreeListViewMut<'s, RegSpec>,
}

pub struct RTreeListViewMut<'s, S: Spec> {
    pub headers: &'s mut [flat::RTreeHeader],
    pub bboxes: &'s mut [S::Node],
    pub rtrees: Vec<RTreeViewMut<'s, S>>,
}

pub struct RTreeViewMut<'s, S: Spec> {
    pub levels: &'s mut [flat::Level],
    pub leaves: [&'s mut [S::Leaf]; PARTITIONS],
}

pub fn build_storage_view_mut<'s>(
    storage: &'s mut [u8],
    layout: &StorageLayout,
    partitions: &HilbertPartitionPass,
) -> StorageViewMut<'s> {
    let mut storage_ranges = vec![
        0..flat::Header::SIZE,
        layout.header.metadata.byte_range(),
        layout.header.data.byte_range(),
    ];

    assert_eq!(layout.write_zones.len(), partitions.write_zones.len());
    assert_eq!(layout.read_zones.len(), partitions.read_zones.len());
    assert_eq!(layout.registers.len(), partitions.registers.len());

    push_rtree_list_storage_ranges(
        &mut storage_ranges,
        &layout.header.write_zones,
        &layout.write_zones,
        &partitions.write_zones,
    );

    push_rtree_list_storage_ranges(
        &mut storage_ranges,
        &layout.header.read_zones,
        &layout.read_zones,
        &partitions.read_zones,
    );

    push_rtree_list_storage_ranges(
        &mut storage_ranges,
        &layout.header.registers,
        &layout.registers,
        &partitions.registers,
    );

    let views = storage_disjoint_views(storage, storage_ranges);
    let mut views_iter = views.into_iter();

    macro_rules! next_cast {
        ([$ty:ty]) => {{
            let view = views_iter.next().unwrap();
            if !view.is_empty() {
                <[$ty]>::mut_from_bytes(view).unwrap()
            } else {
                &mut [][..]
            }
        }};
        ($ty:ty) => {{
            let view = views_iter.next().unwrap();
            <$ty>::mut_from_bytes(view).unwrap()
        }};
    }

    macro_rules! next_rtree_list {
        ($out:ident, $count:expr, $spec:ty) => {
            let headers = next_cast!([flat::RTreeHeader]);
            let bboxes = next_cast!([<$spec as Spec>::Node]);
            let rtrees = (0..$count)
                .map(|_| RTreeViewMut {
                    levels: next_cast!([flat::Level]),
                    leaves: array::from_fn(|_| next_cast!([<$spec as Spec>::Leaf])),
                })
                .collect();

            let $out = RTreeListViewMut {
                headers,
                bboxes,
                rtrees,
            };
        };
    }

    let header = next_cast!(flat::Header);
    let metadata = next_cast!([u8]);
    let data = next_cast!([u8]);

    next_rtree_list!(write_zones, layout.write_zones.len(), MemWriteSpec);
    next_rtree_list!(read_zones, layout.read_zones.len(), MemReadSpec);
    next_rtree_list!(registers, layout.registers.len(), RegSpec);

    assert_eq!(views_iter.next(), None);

    StorageViewMut {
        header,
        metadata,
        data,
        write_zones,
        read_zones,
        registers,
    }
}

fn push_rtree_list_storage_ranges<S: Spec>(
    storage_ranges: &mut Vec<std::ops::Range<usize>>,
    header: &RTreeList,
    rtrees: &[RTreeHeader],
    partitions: &[RTreePartitions<S>],
) {
    storage_ranges.push(header.headers.byte_range());
    storage_ranges.push(header.bboxes.byte_range());

    for (rtree, partitions) in rtrees.iter().zip(partitions.iter()) {
        storage_ranges.push(rtree.levels.byte_range());

        let mut pos = rtree.leaves.start as usize;
        for part in partitions.partitions.iter() {
            let start = pos;
            let end = start + (part.leaf_count * mem::size_of::<S::Leaf>());
            storage_ranges.push(start..end);
            pos = end;
        }
    }
}

fn storage_disjoint_views<'s>(
    storage: &'s mut [u8],
    ranges: Vec<core::ops::Range<usize>>,
) -> Vec<&'s mut [u8]> {
    let mut views: Vec<&'s mut [u8]> = ranges.iter().map(|_| &mut [][..]).collect();

    let mut ranges: Vec<_> = ranges.into_iter().enumerate().collect();
    ranges.sort_by_key(|(_, range)| cmp::Reverse(range.start));

    let mut storage = storage;
    for (idx, range) in ranges {
        if range.is_empty() {
            continue;
        }
        let (before_and_data, _) = storage.split_at_mut(range.end);
        let (before, view) = before_and_data.split_at_mut(range.start);
        storage = before;
        views[idx] = view;
    }

    views
}
