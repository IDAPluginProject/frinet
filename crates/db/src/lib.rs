pub mod db;
pub mod flat;
pub mod irange;
pub mod matcher;
pub mod memory;
pub mod nearest_neighbor;
pub mod query;
pub mod register;
pub mod rtree;
pub mod search;

pub const DB_MAGIC: u64 = 0xaabbccdd12345678;
pub const DB_VERSION: u64 = 1;
