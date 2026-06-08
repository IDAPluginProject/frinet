use std::{collections::HashMap, fs::File, ops::Deref, sync::Arc};

use frinet_db::{
    db::{Db, Metadata},
    flat::{Addr, MemNode, Time},
    irange::IRange,
    search::{self, SearchResult},
};
use memmap2::Mmap;
use pyo3::{
    exceptions::{PyRuntimeError, PyValueError},
    prelude::*,
};

use crate::registers::{AllRegisterSnapshot, RegisterDb, compute_all_register_snapshots};

mod registers;

#[pymodule(name = "frinet_db")]
mod py_module {
    #[pymodule_export]
    use super::{FrinetDb, MemNode, Metadata, SearchResult, open};

    #[pymodule_export]
    use super::registers::{AllRegisterSnapshot, OneRegisterSnapshot, RegisterDb};
}

#[pyclass(skip_from_py_object, frozen)]
#[derive(Clone)]
pub struct FrinetDb(Arc<FrinetDbInner>);

impl Deref for FrinetDb {
    type Target = FrinetDbInner;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct FrinetDbInner {
    db: &'static Db<'static>,
    registers_index_by_name: HashMap<&'static str, usize>,
}

#[pymethods]
impl FrinetDb {
    #[getter]
    pub fn metadata(&self) -> Metadata {
        self.db.metadata.clone()
    }

    pub fn registers_snapshot(&self, time: Time) -> AllRegisterSnapshot {
        compute_all_register_snapshots(self, time)
    }

    pub fn search(slf: &Bound<'_, Self>, text: String, regex: bool) -> PyResult<Vec<SearchResult>> {
        let db = &slf.borrow().db;
        if regex {
            search::search_regex(db, &text).map_err(|err| PyValueError::new_err(err.to_string()))
        } else {
            Ok(search::search(db, text.as_bytes()))
        }
    }

    pub fn register(&self, name: &str) -> Option<RegisterDb> {
        let rtree = self.db.register_rtree_by_name(name)?;
        Some(RegisterDb {
            db: self.clone(),
            rtree,
        })
    }

    pub fn memory_bytes_at(&self, time: Time, addr: Addr, len: Addr) -> Vec<Option<u8>> {
        self.db
            .fetch_at(IRange::from_start_len(addr, len), time)
            .array
    }

    pub fn memory_reads(&self, time: Time, addr_range: (Addr, Addr)) -> Vec<MemNode> {
        self.db
            .mem_read_intersects(MemNode {
                addr_min: addr_range.0,
                addr_max: addr_range.1,
                time_min: time,
                time_max: time,
            })
            .map(|leaf| leaf.node())
            .collect()
    }

    pub fn memory_writes(&self, time: Time, addr_range: (Addr, Addr)) -> Vec<MemNode> {
        self.db
            .mem_write_intersects(MemNode {
                addr_min: addr_range.0,
                addr_max: addr_range.1,
                time_min: time,
                time_max: time,
            })
            .map(|leaf| leaf.node)
            .collect()
    }

    pub fn prev_mem_write(&self, time: Time, addr_range: (Addr, Addr)) -> Option<Time> {
        let range = IRange::new(addr_range.0, addr_range.1);
        self.db.prev_mem_write(time, range)
    }

    pub fn next_mem_write(&self, time: Time, addr_range: (Addr, Addr)) -> Option<Time> {
        let range = IRange::new(addr_range.0, addr_range.1);
        self.db.next_mem_write(time, range)
    }

    pub fn prev_mem_read(&self, time: Time, addr_range: (Addr, Addr)) -> Option<Time> {
        let range = IRange::new(addr_range.0, addr_range.1);
        self.db.prev_mem_read(time, range)
    }

    pub fn next_mem_read(&self, time: Time, addr_range: (Addr, Addr)) -> Option<Time> {
        let range = IRange::new(addr_range.0, addr_range.1);
        self.db.next_mem_read(time, range)
    }
}

#[pyfunction]
fn open(path: &str) -> PyResult<FrinetDb> {
    let file = File::open(path)?;
    let mmap = unsafe { memmap2::MmapOptions::new().map(&file)? };

    // TODO : fix
    let mmap: &mut Mmap = Box::leak(Box::new(mmap));

    let db = match Db::from_aligned_slice(mmap) {
        Ok(db) => db,
        Err(err) => {
            return Err(PyRuntimeError::new_err(format!("{err}")));
        }
    };

    // TODO : fix
    let db: &'static Db = Box::leak(Box::new(db));

    let registers_index_by_name = db
        .metadata
        .register_names
        .iter()
        .enumerate()
        .map(|(idx, name)| (name.as_str(), idx))
        .collect();

    let inner = FrinetDbInner {
        db,
        registers_index_by_name,
    };

    Ok(FrinetDb(Arc::new(inner)))
}
