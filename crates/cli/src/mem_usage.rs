use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering},
};

#[global_allocator]
static ALLOCATOR: TrackAllocator = TrackAllocator;

static MAX_MEM_USAGE: AtomicUsize = AtomicUsize::new(0);
static MEM_USAGE: AtomicUsize = AtomicUsize::new(0);

pub fn reset_mem_usage() {
    MAX_MEM_USAGE.store(0, Ordering::SeqCst);
}

pub fn max_mem_usage() -> usize {
    MAX_MEM_USAGE.load(Ordering::SeqCst)
}

fn increment(x: usize) {
    let val = MEM_USAGE.fetch_add(x, Ordering::Relaxed);
    MAX_MEM_USAGE.fetch_max(val + x, Ordering::Relaxed);
}

fn decrement(x: usize) {
    MEM_USAGE.fetch_sub(x, Ordering::Relaxed);
}

struct TrackAllocator;
unsafe impl GlobalAlloc for TrackAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        increment(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        decrement(layout.size());
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        increment(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let prev_size = layout.size();
        if prev_size < new_size {
            increment(new_size - prev_size);
        } else {
            decrement(prev_size - new_size);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}
