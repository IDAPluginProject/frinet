use std::cell::Cell;

use crate::*;

pub struct Counter {
    next: Cell<State>,
}

impl Counter {
    pub fn new(first_state: State) -> Self {
        Self {
            next: Cell::new(first_state),
        }
    }

    pub fn next(&self) -> State {
        let next = self.next.get();
        self.next.set(next.checked_add(1).expect("State overflow"));
        next
    }
}
