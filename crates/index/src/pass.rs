use frinet_db::{
    flat::{Addr, MemReadLeaf, RegLeaf, Time},
    irange::IRange,
};

use crate::{
    disjoint::{DataCut, DisjointMemLeaf, DisjointPass},
    parser::{MemoryMode, ProgressReporter, RawEvent, TimedRawEvent, TraceParser},
};

mod hilbert_partition;
pub use hilbert_partition::*;

mod scout;
pub use scout::*;

mod fill;
pub use fill::*;

pub enum Event<D> {
    MemoryWrite(DisjointMemLeaf<D>),
    MemoryRead(MemReadLeaf),
    Register { idx: usize, leaf: RegLeaf },
    AslrSlide(Addr),
}

fn parse_and_normalize_events<Parser, Data, MapData, MapRegName, Emit>(
    parser: &mut Parser,
    progress: &mut dyn ProgressReporter,
    mut map_reg_name: MapRegName,
    mut map_data: MapData,
    mut emit: Emit,
) where
    Emit: FnMut(Event<Data>),
    MapData: FnMut(&[u8]) -> Data,
    MapRegName: FnMut(&str) -> usize,
    Parser: TraceParser,
    Data: DataCut,
{
    let mut curr_time: Time = 0;

    let mut disjoint = DisjointPass::<Data>::default();
    let mut last_reg_leaves: Vec<Option<RegLeaf>> = Vec::new();

    parser.parse(progress, |event| {
        match event {
            RawEvent::AslrSlide(slide) => {
                emit(Event::AslrSlide(slide));
            }
            RawEvent::TimedEvent { time, event } => {
                assert!(curr_time <= time);
                curr_time = time;

                match event {
                    TimedRawEvent::Memory { addr, bytes, mode } => {
                        assert!(!bytes.is_empty());
                        let data = map_data(bytes);

                        let is_read_only = matches!(mode, MemoryMode::Read);
                        let is_read = matches!(mode, MemoryMode::Read | MemoryMode::ReadWrite);

                        disjoint.push_memory_write(
                            time,
                            addr,
                            bytes,
                            data,
                            is_read_only,
                            |disjoint_leaf| emit(Event::MemoryWrite(disjoint_leaf)),
                        );

                        if is_read {
                            let range = IRange::from_start_len(addr, bytes.len() as _);
                            emit(Event::MemoryRead(MemReadLeaf {
                                addr_min: range.min,
                                addr_max: range.max,
                                time,
                            }))
                        }
                    }
                    TimedRawEvent::Register { name, value } => {
                        let idx = map_reg_name(name);

                        let required_len = idx + 1;
                        if last_reg_leaves.len() < required_len {
                            last_reg_leaves.resize(required_len, None);
                        }

                        let last_opt = last_reg_leaves.get_mut(idx).unwrap();
                        if let Some(last) = last_opt {
                            debug_assert!(last.time_min <= last.time_max);
                            debug_assert!(last.time_max <= time);

                            // if multiple write at the same time => keep the last value
                            if last.time_min == time && last.time_max == time {
                                last.value = value;
                                return;
                            }

                            last.time_max = time - 1;
                            emit(Event::Register { idx, leaf: *last });
                            *last_opt = None;
                        }

                        *last_opt = Some(RegLeaf {
                            value,
                            time_min: time,
                            time_max: time,
                        });
                    }
                }
            }
        }
    });

    disjoint.finish(|disjoint_leaf| emit(Event::MemoryWrite(disjoint_leaf)));

    for (idx, opt_last) in last_reg_leaves.into_iter().enumerate() {
        let mut last = opt_last.expect("must be some at this point");
        assert!(last.time_min <= curr_time);
        last.time_max = curr_time;

        emit(Event::Register { idx, leaf: last });
    }
}
