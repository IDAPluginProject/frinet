use frinet_db::{flat::Time, register::RegRTree};
use pyo3::{PyResult, pyclass, pymethods};

use crate::FrinetDb;

#[pyclass(skip_from_py_object, frozen)]
pub struct RegisterDb {
    pub db: FrinetDb,
    pub rtree: &'static RegRTree<'static>,
}

#[pymethods]
impl RegisterDb {
    pub fn first_time_with(&self, value: u64) -> Option<Time> {
        self.rtree.first_time_with(value)
    }

    pub fn last_time_with(&self, value: u64) -> Option<Time> {
        self.rtree.last_time_with(value)
    }

    pub fn prev_time_with(&self, time: Time, value: u64) -> Option<Time> {
        self.rtree.prev_time_with(time, value)
    }

    pub fn next_time_with(&self, time: Time, value: u64) -> Option<Time> {
        self.rtree.next_time_with(time, value)
    }

    pub fn value_at(&self, time: Time) -> Option<u64> {
        self.rtree.value_at(time)
    }

    pub fn time_bbox(&self) -> (Time, Time) {
        let range = self.rtree.bbox.time_range();
        (range.min, range.max)
    }
}

pub fn compute_all_register_snapshots(frinet_db: &FrinetDb, time: Time) -> AllRegisterSnapshot {
    let registers = frinet_db
        .db
        .registers
        .iter()
        .map(|rtree| compute_one_register_snapshot(rtree, time))
        .collect();

    AllRegisterSnapshot {
        db: frinet_db.clone(),
        time,
        registers,
    }
}

fn compute_one_register_snapshot(rtree: &RegRTree, time: u32) -> OneRegisterSnapshot {
    let bbox = rtree.bbox.time_range();
    match rtree.leaf_at(time) {
        Some(leaf) => {
            let prev_time = if leaf.time_min > 0 {
                Some(leaf.time_min - 1)
            } else {
                None
            };
            let next_time = if leaf.time_max < bbox.max {
                Some(leaf.time_max + 1)
            } else {
                None
            };
            OneRegisterSnapshot {
                value: Some(leaf.value),
                has_just_changed: leaf.time_min == time,
                prev_time,
                next_time,
            }
        }
        None => OneRegisterSnapshot {
            value: None,
            has_just_changed: false,
            prev_time: None,
            next_time: Some(bbox.min),
        },
    }
}

#[pyclass(skip_from_py_object, frozen)]
pub struct AllRegisterSnapshot {
    pub db: FrinetDb,
    pub time: Time,
    pub registers: Vec<OneRegisterSnapshot>,
}

#[pymethods]
impl AllRegisterSnapshot {
    #[getter]
    pub fn time(&self) -> Time {
        self.time
    }

    pub fn reg(&self, name: &str) -> PyResult<Option<OneRegisterSnapshot>> {
        let id = self.db.registers_index_by_name[name];
        Ok(self.registers.get(id).cloned())
    }
}

#[pyclass(get_all, skip_from_py_object, frozen)]
#[derive(Clone)]
pub struct OneRegisterSnapshot {
    pub value: Option<u64>,
    pub has_just_changed: bool,
    pub prev_time: Option<Time>,
    pub next_time: Option<Time>,
}
