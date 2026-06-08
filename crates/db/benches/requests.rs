use std::{fs::File, hint::black_box};

use criterion::{BatchSize, Bencher, Criterion, criterion_group, criterion_main};
use frinet_db::{db::Db, irange::IRange};
use rand::{RngExt, rngs::StdRng, seq::IndexedRandom};

criterion_main!(benches);
criterion_group!(benches, criterion_benchmark);

fn criterion_benchmark(c: &mut Criterion) {
    let path = std::env::var("BENCH_DB").expect("Env variable BENCH_DB is required");
    let file = File::open(path).expect("failed to open BENCH_DB");
    let mmap = unsafe {
        memmap2::MmapOptions::new()
            .map(&file)
            .expect("failed to mmap BENCH_DB")
    };
    let db = Db::from_aligned_slice(&mmap).unwrap();

    c.bench_function("Memory fetch 8", |b| fetch_memory_range::<8>(b, &db));
    c.bench_function("Memory fetch 64", |b| fetch_memory_range::<64>(b, &db));
    c.bench_function("Memory fetch 128", |b| fetch_memory_range::<128>(b, &db));
    c.bench_function("Memory fetch 1024", |b| fetch_memory_range::<1024>(b, &db));
    c.bench_function("Memory fetch 4096", |b| fetch_memory_range::<4096>(b, &db));

    c.bench_function("PC prev", |b| pc_prev(b, &db));
    c.bench_function("PC next", |b| pc_next(b, &db));
    c.bench_function("PC first", |b| pc_first(b, &db));
    c.bench_function("PC last", |b| pc_last(b, &db));
    c.bench_function("Fetch all registers", |b| fetch_all_registers(b, &db));

    for name in &db.metadata.register_names {
        c.bench_function(&format!("Fetch register: {}", name), |b| {
            fetch_one_register(b, &db, name)
        });
    }
}

fn fetch_memory_range<const LEN: usize>(b: &mut Bencher, db: &Db) {
    let mut rng: StdRng = rand::make_rng();

    b.iter_batched(
        || {
            let zone = db.write_zones.choose(&mut rng).unwrap();
            let addr = rng.random_range(zone.bbox.addr_min..zone.bbox.addr_max);
            let time = rng.random_range(zone.bbox.time_min..zone.bbox.time_max);
            (IRange::from_start_len(addr, LEN as _), time)
        },
        |(range, time)| black_box(db).fetch_at::<[Option<u8>; LEN], _>(range, time),
        BatchSize::SmallInput,
    );
}

fn pc_prev(b: &mut Bencher, db: &Db) {
    let mut rng: StdRng = rand::make_rng();

    let pc = db.register_rtree_by_name("rip").unwrap();
    let time_range = pc.bbox.time_range();

    b.iter_batched(
        || {
            let time = rng.random_range(time_range.min..time_range.max);
            let pc_time = rng.random_range(time_range.min..time_range.max);
            let value = pc.value_at(pc_time).unwrap();
            (time, value)
        },
        |(time, value)| black_box(pc).prev_time_with(time, value),
        BatchSize::SmallInput,
    );
}

fn pc_next(b: &mut Bencher, db: &Db) {
    let mut rng: StdRng = rand::make_rng();

    let pc = db.register_rtree_by_name("rip").unwrap();
    let time_range = pc.bbox.time_range();

    b.iter_batched(
        || {
            let time = rng.random_range(time_range.min..time_range.max);
            let pc_time = rng.random_range(time_range.min..time_range.max);
            let value = pc.value_at(pc_time).unwrap();
            (time, value)
        },
        |(time, value)| black_box(pc).next_time_with(time, value),
        BatchSize::SmallInput,
    );
}

fn pc_first(b: &mut Bencher, db: &Db) {
    let mut rng: StdRng = rand::make_rng();

    let pc = db.register_rtree_by_name("rip").unwrap();
    let time_range = pc.bbox.time_range();

    b.iter_batched(
        || {
            let time = rng.random_range(time_range.min..time_range.max);
            let value = pc.value_at(time).unwrap();
            value
        },
        |value| black_box(pc).first_time_with(value),
        BatchSize::SmallInput,
    );
}

fn pc_last(b: &mut Bencher, db: &Db) {
    let mut rng: StdRng = rand::make_rng();

    let pc = db.register_rtree_by_name("rip").unwrap();
    let time_range = pc.bbox.time_range();

    b.iter_batched(
        || {
            let time = rng.random_range(time_range.min..time_range.max);
            let value = pc.value_at(time).unwrap();
            value
        },
        |value| black_box(pc).last_time_with(value),
        BatchSize::SmallInput,
    );
}

fn fetch_all_registers(b: &mut Bencher, db: &Db) {
    let mut rng: StdRng = rand::make_rng();

    let time_max = db.registers.iter().map(|x| x.bbox.time_max).max().unwrap();

    b.iter_batched(
        || rng.random_range(0..time_max),
        |time| {
            for rtree in black_box(&db.registers) {
                black_box(rtree.value_at(time));
            }
        },
        BatchSize::SmallInput,
    );
}

fn fetch_one_register(b: &mut Bencher, db: &Db, name: &str) {
    let mut rng: StdRng = rand::make_rng();

    let time_max = db.registers.iter().map(|x| x.bbox.time_max).max().unwrap();
    let rtree = db.register_rtree_by_name(name).unwrap();

    b.iter_batched(
        || rng.random_range(0..time_max),
        |time| black_box(rtree).value_at(time),
        BatchSize::SmallInput,
    );
}
