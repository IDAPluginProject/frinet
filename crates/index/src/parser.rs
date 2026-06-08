use frinet_db::flat::{Addr, Time};

mod tenet;
pub use tenet::*;

pub trait TraceParser {
    fn parse<EmitFn>(&mut self, progress: &mut dyn ProgressReporter, emit: EmitFn)
    where
        EmitFn: FnMut(RawEvent);
}

impl ProgressReporter for () {
    fn report(&mut self, _: Progress) {}
}

pub trait ProgressReporter: Send {
    fn report(&mut self, progress: Progress);
    fn start(&mut self, pass: Pass) {
        self.report(Progress::Start(pass));
    }
    fn total(&mut self, total: usize) {
        self.report(Progress::Total(total));
    }
    fn current(&mut self, current: usize) {
        self.report(Progress::Current(current));
    }
    fn finish(&mut self) {
        self.report(Progress::Finish);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    Start(Pass),
    Finish,
    Total(usize),
    Current(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pass {
    Scout,
    Partitions,
    Fill,
}

/// Raw (unprocessed) from the trace parser
#[derive(Debug, Clone, Copy)]
pub enum RawEvent<'a> {
    AslrSlide(Addr),
    TimedEvent {
        time: Time,
        event: TimedRawEvent<'a>,
    },
}

/// Timed raw (unprocessed) event from the trace parser
#[derive(Debug, Clone, Copy)]
pub enum TimedRawEvent<'a> {
    /// A memory event
    Memory {
        /// Base address
        addr: Addr,
        bytes: &'a [u8],
        mode: MemoryMode,
    },
    /// A register update event
    Register { name: &'a str, value: u64 },
}

/// Memory event mode
#[derive(Debug, Clone, Copy)]
pub enum MemoryMode {
    Read,
    Write,
    ReadWrite,
}

/// In-memory list of events for testing/fuzzing purposes
pub struct StaticEventList<'a> {
    pub events: Vec<RawEvent<'a>>,
}

impl TraceParser for StaticEventList<'_> {
    fn parse<EmitFn>(&mut self, progress: &mut dyn ProgressReporter, mut emit: EmitFn)
    where
        EmitFn: FnMut(RawEvent),
    {
        progress.total(self.events.len());
        for (idx, event) in self.events.iter().enumerate() {
            emit(*event);
            progress.current(idx);
        }
    }
}
