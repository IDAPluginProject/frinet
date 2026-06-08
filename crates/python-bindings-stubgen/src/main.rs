use std::path::PathBuf;

use pyo3_introspection::{introspect_cdylib, module_stub_files};

fn main() {
    let path = std::env::args().skip(1).next().unwrap();
    let module = introspect_cdylib(path, "frinet_db").unwrap();
    let stubs = module_stub_files(&module);
    println!("{}", stubs[&PathBuf::from("__init__.pyi")]);
}
