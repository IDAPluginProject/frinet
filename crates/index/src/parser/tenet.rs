use std::{fs::File, path::PathBuf};

use frinet_db::flat::Time;
use memmap2::MmapOptions;

use crate::parser::{MemoryMode, ProgressReporter, RawEvent, TimedRawEvent, TraceParser};

pub struct TenetParser {
    path: PathBuf,
}

impl TenetParser {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl TraceParser for TenetParser {
    fn parse<EmitFn>(&mut self, progress: &mut dyn ProgressReporter, mut emit: EmitFn)
    where
        EmitFn: FnMut(RawEvent),
    {
        let file = File::open(&self.path).unwrap();
        let mmap = unsafe { MmapOptions::new().populate().map(&file).unwrap() };
        let buffer = &*mmap;

        progress.total(buffer.len());

        let mut time: Time = 0;

        let mut hex_buffer = Vec::new();

        let mut event_start = 0;
        let mut equal = usize::MAX;

        for idx in memchr::memchr3_iter(b'\n', b'=', b',', buffer) {
            let c = buffer[idx];

            match c {
                b',' | b'\n' => {
                    if c == b'\n' {
                        time += 1;
                        if time.is_multiple_of(1024) {
                            progress.current(idx);
                        }
                    }

                    let event_end = idx;
                    let key = &buffer[event_start..equal];

                    let value = &buffer[equal + "=0x".len()..event_end];
                    let value = str::from_utf8(value).unwrap();

                    match key {
                        b"mr" | b"mw" | b"mrw" => {
                            let mode = match key {
                                b"mr" => MemoryMode::Read,
                                b"mw" => MemoryMode::Write,
                                b"mrw" => MemoryMode::ReadWrite,
                                _ => unreachable!(),
                            };

                            let (addr, data) = value.split_once(":").unwrap();

                            let addr = u64::from_str_radix(addr, 16).unwrap();

                            let required_len = data.len() / 2;
                            hex_buffer.resize(required_len, 0);
                            hex::decode_to_slice(data, &mut hex_buffer).unwrap();

                            emit(RawEvent::TimedEvent {
                                time,
                                event: TimedRawEvent::Memory {
                                    addr,
                                    bytes: &hex_buffer,
                                    mode,
                                },
                            })
                        }
                        _ => {
                            let name = str::from_utf8(key).unwrap();
                            let value = u64::from_str_radix(value, 16).unwrap();

                            if name == "slide" {
                                emit(RawEvent::AslrSlide(value));
                            } else {
                                emit(RawEvent::TimedEvent {
                                    time,
                                    event: TimedRawEvent::Register { name, value },
                                });
                            }
                        }
                    }

                    event_start = idx + 1;
                }
                b'=' => {
                    equal = idx;
                }
                _ => unreachable!(),
            }
        }
    }
}
