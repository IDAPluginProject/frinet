#![no_main]

use arbitrary::Arbitrary;
use frinet_db::db::Db;
use frinet_index::{
    build_index,
    parser::{RawEvent, StaticEventList, TimedRawEvent},
};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
pub struct Point {
    time: u8,
    value: u8,
}

#[derive(Arbitrary, Debug)]
struct Input {
    writes: Vec<Point>,
    samples: Vec<Point>,
}

fuzz_target!(|input: Input| {
    let mut input = input;
    input.writes.sort_by_key(|e| e.time);

    let mut raw_events = Vec::new();
    for event in &input.writes {
        raw_events.push(RawEvent::TimedEvent {
            time: event.time as _,
            event: TimedRawEvent::Register {
                name: "reg",
                value: event.value as _,
            },
        });
    }

    let mut parser = StaticEventList { events: raw_events };
    let mut storage = Vec::new();
    build_index(&mut parser, &mut (), &mut storage, 2);
    let db = Db::from_aligned_slice(&storage).unwrap();

    let Some(reg) = db.register_rtree_by_name("reg") else {
        assert!(input.writes.is_empty());
        return;
    };

    // keep only the last write of each time
    input.writes.reverse();
    input.writes.dedup_by_key(|e| e.time);
    input.writes.reverse();

    for event in &input.writes {
        assert_eq!(
            event.value as u64,
            reg.value_at(event.time as _).unwrap(),
            "reg.value_at({})",
            event.time
        );
    }

    for point in input.samples {
        let time = u32::from(point.time);
        let value = u64::from(point.value);

        let rtree_next = reg.next_time_with(time, value);
        let iter_next = input
            .writes
            .iter()
            .skip_while(|e| u32::from(e.time) <= time)
            .filter(|e| u64::from(e.value) == value)
            .next()
            .map(|e| u32::from(e.time));

        assert_eq!(rtree_next, iter_next, "reg.next_time({time}, {value})");

        let rtree_prev = reg.prev_time_with(time, value);
        let iter_prev = input
            .writes
            .iter()
            .rev()
            .skip_while(|e| u32::from(e.time) >= time)
            .filter(|e| u64::from(e.value) == value)
            .next()
            .map(|e| u32::from(e.time));

        assert_eq!(rtree_prev, iter_prev, "reg.prev_time({time}, {value})");

        let rtree_first = reg.first_time_with(value);
        let iter_first = input
            .writes
            .iter()
            .find(|e| u64::from(e.value) == value)
            .map(|e| u32::from(e.time));

        assert_eq!(rtree_first, iter_first, "reg.first_time({time}, {value})");

        let rtree_last = reg.last_time_with(value);
        let iter_last = input
            .writes
            .iter()
            .rev()
            .find(|e| u64::from(e.value) == value)
            .map(|e| u32::from(e.time));

        assert_eq!(rtree_last, iter_last, "reg.last_time({time}, {value})");
    }
});
